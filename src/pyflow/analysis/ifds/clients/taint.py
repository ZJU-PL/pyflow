"""Concrete interprocedural taint analysis over CFG-backed supergraphs."""

from __future__ import annotations

from dataclasses import dataclass
from typing import FrozenSet, Mapping, Sequence

from pyflow.analysis.cfg import graph as cfg_graph
from pyflow.language.python import ast as py_ast

from ._call_model import CallModelRegistry
from ._client_common import AnnotatedFactProblemBase, build_entry_seeds
from ..cfg_adapter import CFGNode, CFGSupergraphAdapter, assigned_locals
from ..problem import IFDSProblem
from ..solver import IFDSSolver
from ..transfers import (
    actual_argument_expressions,
    bind_call_arguments,
)


ZERO_TAINT = "ZERO_TAINT"


@dataclass(frozen=True)
class TaintConfiguration:
    """Name-based taint models for direct-call analyses."""

    source_names: FrozenSet[str] = frozenset()
    sink_names: FrozenSet[str] = frozenset()
    sanitizer_names: FrozenSet[str] = frozenset()


@dataclass(frozen=True)
class TaintFinding:
    """A sink reached by tainted data."""

    sink: CFGNode
    sink_name: str
    tainted_arguments: tuple[py_ast.Local, ...]
    tainted_argument_labels: tuple[str, ...] = ()


@dataclass(frozen=True)
class SlotTaintFact:
    """Taint on a canonical storage slot."""

    slot: object


@dataclass(frozen=True)
class ExpressionTaintFact:
    """Taint on the intermediate result of a specific expression."""

    procedure: cfg_graph.Code
    expression: py_ast.PythonASTNode
    result_index: int = 0


class TaintAnalysisResult:
    """Result wrapper with taint queries and sink findings."""

    def __init__(self, ifds_result, findings: Sequence[TaintFinding], problem) -> None:
        self._ifds_result = ifds_result
        self.findings = tuple(findings)
        self._problem = problem

    def is_tainted(self, node: CFGNode, local: py_ast.Local) -> bool:
        return any(
            self._ifds_result.is_reached(node, SlotTaintFact(slot))
            for slot in self._problem.local_slots(node.procedure, local)
        )

    def tainted_locals_at(self, node: CFGNode):
        return frozenset(
            self._problem.describe_fact(fact)
            for fact in self._ifds_result.facts_at(node)
            if isinstance(fact, SlotTaintFact)
        )

    @property
    def statistics(self):
        return self._ifds_result.statistics

    def explain_fact(self, node: CFGNode, fact: object):
        return self._ifds_result.explain_fact(node, fact)

    def fact_for_local(self, node: CFGNode, local: py_ast.Local) -> SlotTaintFact | None:
        for slot in self._problem.local_slots(node.procedure, local):
            fact = SlotTaintFact(slot)
            if self._ifds_result.is_reached(node, fact):
                return fact
        return None


class InterproceduralTaintProblem(
    AnnotatedFactProblemBase[object],
    IFDSProblem[cfg_graph.Code, CFGNode, object],
):
    """IFDS taint problem over CFG nodes."""

    analysis_name = "IFDS taint"

    def __init__(
        self,
        adapter: CFGSupergraphAdapter,
        configuration: TaintConfiguration,
        entry_nodes: Sequence[CFGNode] | None = None,
    ) -> None:
        self.configuration = configuration
        super().__init__(
            adapter,
            call_models=CallModelRegistry.from_taint_configuration(configuration),
        )
        if entry_nodes is None:
            raise ValueError(
                "IFDS taint requires explicit entry_nodes; "
                "use program-backed IFDS APIs to derive roots automatically."
            )
        self.entry_nodes = tuple(entry_nodes)

    @property
    def supergraph(self):
        return self.adapter.supergraph

    @property
    def zero_fact(self):
        return ZERO_TAINT

    def initial_seeds(self) -> Mapping[CFGNode, frozenset[object]]:
        return build_entry_seeds(self.entry_nodes, ZERO_TAINT)

    def normal_flow(self, node: CFGNode, successor: CFGNode, fact: object):
        del successor
        effect = self.adapter.effect_of(node)
        operation = getattr(effect, "operation", self.adapter.operation_of(node))
        if operation is None:
            return self._identity_outputs(fact, ())

        killed = self._killed_slots_for_node(node)

        if isinstance(operation, (py_ast.Assign, py_ast.UnpackSequence, py_ast.AnnAssign)):
            outputs = set(self._identity_outputs(fact, killed))
            expr = getattr(operation, "expr", None)
            if isinstance(operation, py_ast.AnnAssign):
                expr = operation.value
            targets = assigned_locals(operation)

            direct_fact = self._direct_expression_fact(expr, fact)
            if direct_fact is not None:
                _procedure, _expr, result_index = direct_fact
                outputs.update(
                    self._facts_for_assigned_locals(
                        node.procedure,
                        targets,
                        result_index,
                    )
                )
                return tuple(outputs)
            if expr is not None and self._expr_is_tainted(node.procedure, expr, fact):
                outputs.update(self._facts_for_locals(node.procedure, targets))
            return tuple(outputs)

        if isinstance(operation, py_ast.Return):
            outputs = set(self._identity_outputs(fact, ()))
            if len(operation.exprs) == 1:
                direct_fact = self._direct_expression_fact(operation.exprs[0], fact)
                if direct_fact is not None:
                    _procedure, _expr, result_index = direct_fact
                    outputs.update(
                        self._facts_for_return_slot(
                            node.procedure, result_index
                        )
                    )
                    return tuple(outputs)
            for index, expr in enumerate(operation.exprs):
                if self._expr_is_tainted(node.procedure, expr, fact):
                    outputs.update(self._facts_for_return_slot(node.procedure, index))
            return tuple(outputs)

        if isinstance(
            operation,
            (
                py_ast.SetAttr,
                py_ast.SetSubscript,
                py_ast.SetSlice,
                py_ast.SetGlobal,
                py_ast.SetCellDeref,
                py_ast.Store,
            ),
        ):
            outputs = set(self._identity_outputs(fact, killed))
            value = getattr(operation, "value", None)
            if value is None:
                return tuple(outputs)
            if self._direct_expression_fact(value, fact) is not None or self._expr_is_tainted(
                node.procedure, value, fact
            ):
                outputs.update(self._facts_for_modified_operation(operation))
            return tuple(outputs)

        return self._identity_outputs(fact, killed)

    def call_flow(self, call_node: CFGNode, callee: cfg_graph.Code, fact: object):
        outputs = set()
        if fact == ZERO_TAINT:
            outputs.add(ZERO_TAINT)

        model = self._call_model_for_node(call_node)
        if model is not None and (model.taint_source or model.taint_sanitizer):
            return tuple(outputs)

        call_effect = self._call_effect(call_node)
        call = call_effect.call_expression if call_effect is not None else None
        if call is None:
            return tuple(outputs)

        params = callee.code.codeparameters
        for actual, formal in bind_call_arguments(call, params):
            if self._expr_is_tainted(call_node.procedure, actual, fact):
                outputs.update(self._facts_for_locals(callee, (formal,)))

        return tuple(outputs)

    def return_flow(
        self,
        call_node: CFGNode,
        callee: cfg_graph.Code,
        exit_node: CFGNode,
        return_site: CFGNode,
        call_fact: object,
        exit_fact: object,
    ):
        del exit_node, return_site
        outputs = set()
        if call_fact == ZERO_TAINT and exit_fact == ZERO_TAINT:
            outputs.add(ZERO_TAINT)

        model = self._call_model_for_node(call_node)
        if model is not None and model.taint_sanitizer:
            return tuple(outputs)

        return_index = self._return_fact_index(callee, exit_fact)
        call_effect = self._call_effect(call_node)
        if return_index is not None and call_effect is not None:
            outputs.update(
                self._facts_for_nested_call_result(
                    call_node.procedure,
                    call_effect.operation,
                    call_effect.call_expression,
                    return_index,
                    nested=False,
                )
            )

        return tuple(outputs)

    def call_to_return_flow(self, call_node: CFGNode, return_site: CFGNode, fact: object):
        del return_site
        call_effect = self._call_effect(call_node)
        killed = self._killed_slots_for_node(call_node)
        outputs = set(self._identity_outputs(fact, killed))
        model = self._call_model_for_node(call_node)
        if (
            fact == ZERO_TAINT
            and model is not None
            and model.taint_source
            and call_effect is not None
        ):
            outputs.update(
                self._facts_for_nested_call_result(
                    call_node.procedure,
                    call_effect.operation,
                    call_effect.call_expression,
                    0,
                    nested=False,
                )
            )
        return tuple(outputs)

    def describe_fact(self, fact: object) -> str:
        if isinstance(fact, SlotTaintFact):
            return self.describe_slot(fact.slot)
        if isinstance(fact, ExpressionTaintFact):
            return self.describe_expression(fact.expression)
        return "<expr>"

    def _make_slot_fact(self, slot: object) -> object:
        return SlotTaintFact(slot)

    def _make_expression_fact(
        self,
        procedure: cfg_graph.Code,
        expression: py_ast.PythonASTNode,
        result_index: int = 0,
    ) -> object:
        return ExpressionTaintFact(procedure, expression, result_index)

    def _slot_from_fact(self, fact: object) -> object | None:
        if isinstance(fact, SlotTaintFact):
            return fact.slot
        return None

    def _expression_fact_result(
        self, fact: object
    ) -> tuple[cfg_graph.Code, py_ast.PythonASTNode, int] | None:
        if isinstance(fact, ExpressionTaintFact):
            return (fact.procedure, fact.expression, fact.result_index)
        return None

    def _identity_outputs(self, fact: object, killed: Sequence[object]):
        if fact == ZERO_TAINT:
            return (ZERO_TAINT,)
        if isinstance(fact, SlotTaintFact) and any(fact.slot == target for target in killed):
            return ()
        return (fact,)

    def _expr_is_tainted(
        self, procedure: cfg_graph.Code, expr: object, fact: object
    ) -> bool:
        if fact == ZERO_TAINT:
            return self._expr_contains_source(expr)
        return self._expression_matches(
            expr,
            lambda current: any(
                candidate == fact
                for candidate in self._facts_for_expression_node(procedure, current)
            ),
        )

    def _expr_contains_source(self, expr: object) -> bool:
        return self._expression_matches(
            expr,
            lambda current: (
                (model := self._call_model_for_expression(current)) is not None
                and model.taint_source
            ),
        )

    def _expr_is_sanitized(self, expr: object) -> bool:
        model = self._call_model_for_expression(expr)
        return model is not None and model.taint_sanitizer

    def findings(self, result) -> tuple[TaintFinding, ...]:
        findings: list[TaintFinding] = []
        for node in self.adapter.supergraph.nodes():
            call_effect = self._call_effect(node)
            if call_effect is None:
                continue
            model = self._call_model_for_node(node)
            if model is None or not model.taint_sink:
                continue
            if not result.is_reached(node, ZERO_TAINT):
                continue
            tainted_args, tainted_labels = self._tainted_arguments_for_call(
                node, call_effect.call_expression, result
            )
            if tainted_args or tainted_labels:
                findings.append(
                    TaintFinding(
                        sink=node,
                        sink_name=call_effect.call_name or "<sink>",
                        tainted_arguments=tainted_args,
                        tainted_argument_labels=tainted_labels,
                    )
                )
        return tuple(findings)

    def _tainted_arguments_for_call(self, node: CFGNode, call, result):
        tainted_locals: list[py_ast.Local] = []
        tainted_labels: list[str] = []
        seen_local_names: set[str] = set()
        seen_labels: set[str] = set()

        for actual in actual_argument_expressions(call):
            locals_in_expr = sorted(
                self._matching_locals_in_expression(
                    node.procedure,
                    actual,
                    lambda slot: result.is_reached(node, SlotTaintFact(slot)),
                ),
                key=lambda local: local.name or "",
            )
            for local in locals_in_expr:
                if local.name not in seen_local_names:
                    seen_local_names.add(local.name)
                    tainted_locals.append(local)

            labels_in_expr = sorted(
                self._matching_labels_in_expression(
                    node.procedure,
                    actual,
                    lambda candidate_fact: result.is_reached(node, candidate_fact),
                )
            )
            for label in labels_in_expr:
                if label not in seen_labels:
                    seen_labels.add(label)
                    tainted_labels.append(label)

            if not locals_in_expr and not labels_in_expr and self._expr_contains_source(actual):
                label = self.describe_expression(actual)
                if label not in seen_labels:
                    seen_labels.add(label)
                    tainted_labels.append(label)

        return tuple(tainted_locals), tuple(tainted_labels)

    def _matching_labels_in_expression(
        self, procedure: cfg_graph.Code, expr: object, predicate
    ) -> frozenset[str]:
        found: set[str] = set()

        def visit(current) -> None:
            if current is None or isinstance(current, py_ast.leafTypes):
                return
            if self._expr_is_sanitized(current):
                return
            if not isinstance(current, py_ast.Local):
                facts = self._facts_for_expression_node(procedure, current)
                if facts and any(predicate(candidate_fact) for candidate_fact in facts):
                    found.add(self.describe_expression(current))
            if isinstance(current, (list, tuple)):
                for child in current:
                    visit(child)
                return
            if isinstance(current, py_ast.Code):
                return
            current.visitChildren(visit)

        visit(expr)
        return frozenset(found)

    def _expression_matches(self, expr: object, predicate) -> bool:
        found = False

        def visit(current) -> None:
            nonlocal found
            if found or current is None or isinstance(current, py_ast.leafTypes):
                return
            if self._expr_is_sanitized(current):
                return
            if predicate(current):
                found = True
                return
            if isinstance(current, (list, tuple)):
                for child in current:
                    visit(child)
                return
            if isinstance(current, py_ast.Code):
                return
            current.visitChildren(visit)

        visit(expr)
        return found

    def _matching_locals_in_expression(
        self, procedure: cfg_graph.Code, expr: object, predicate
    ) -> frozenset[py_ast.Local]:
        found: set[py_ast.Local] = set()

        def visit(current) -> None:
            if current is None or isinstance(current, py_ast.leafTypes):
                return
            if self._expr_is_sanitized(current):
                return
            if isinstance(current, py_ast.Local):
                if current.name is not None and any(
                    predicate(slot) for slot in self._slots_for_local(procedure, current)
                ):
                    found.add(current)
                return
            if isinstance(current, (list, tuple)):
                for child in current:
                    visit(child)
                return
            if isinstance(current, py_ast.Code):
                return
            current.visitChildren(visit)

        visit(expr)
        return frozenset(found)



class InterproceduralTaintAnalysis:
    """Concrete taint analysis backed by the IFDS engine."""

    def __init__(
        self,
        adapter: CFGSupergraphAdapter,
        configuration: TaintConfiguration,
        *,
        entry_nodes: Sequence[CFGNode] | None = None,
        record_traces: bool = False,
    ) -> None:
        self.problem = InterproceduralTaintProblem(
            adapter, configuration, entry_nodes=entry_nodes
        )
        self.record_traces = record_traces

    def solve(self) -> TaintAnalysisResult:
        result = IFDSSolver(record_traces=self.record_traces).solve(self.problem)
        return TaintAnalysisResult(result, self.problem.findings(result), self.problem)


def analyze_taint(
    adapter: CFGSupergraphAdapter,
    configuration: TaintConfiguration,
    *,
    entry_nodes: Sequence[CFGNode] | None = None,
    record_traces: bool = False,
) -> TaintAnalysisResult:
    """Convenience entry point for interprocedural taint analysis."""
    return InterproceduralTaintAnalysis(
        adapter,
        configuration,
        entry_nodes=entry_nodes,
        record_traces=record_traces,
    ).solve()
