"""Interprocedural nullness analysis over CFG-backed IFDS supergraphs."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Mapping, Sequence

from pyflow.analysis.cfg import graph as cfg_graph
from pyflow.language.python import ast as py_ast

from ._client_common import AnnotatedFactProblemBase, build_entry_seeds
from ..cfg_adapter import CFGNode, CFGSupergraphAdapter, assigned_locals
from ..problem import IFDSProblem
from ..solver import IFDSSolver
from ..transfers import actual_argument_expressions


ZERO_NULLNESS = "ZERO_NULLNESS"


@dataclass(frozen=True)
class SlotNullFact:
    """A storage slot that may hold ``None``."""

    slot: object


@dataclass(frozen=True)
class ExpressionNullFact:
    """A nullable intermediate result of a specific expression."""

    procedure: cfg_graph.Code
    expression: py_ast.PythonASTNode
    result_index: int = 0


@dataclass(frozen=True)
class NullnessFinding:
    """Potential null-dereference style issue."""

    node: CFGNode
    kind: str
    expression_label: str


class NullnessAnalysisResult:
    """Query wrapper for nullness results."""

    def __init__(self, ifds_result, findings: Sequence[NullnessFinding], problem) -> None:
        self._ifds_result = ifds_result
        self.findings = tuple(findings)
        self._problem = problem

    def may_be_null(self, node: CFGNode, local: py_ast.Local) -> bool:
        return any(
            self._ifds_result.is_reached(node, SlotNullFact(slot))
            for slot in self._problem.local_slots(node.procedure, local)
        )

    def nullable_locals_at(self, node: CFGNode):
        return frozenset(
            self._problem.describe_fact(fact)
            for fact in self._ifds_result.facts_at(node)
            if isinstance(fact, SlotNullFact)
        )

    @property
    def statistics(self):
        return self._ifds_result.statistics

    def explain_fact(self, node: CFGNode, fact: object):
        return self._ifds_result.explain_fact(node, fact)


class InterproceduralNullnessProblem(
    AnnotatedFactProblemBase[object],
    IFDSProblem[cfg_graph.Code, CFGNode, object],
):
    """May-null analysis over CFG nodes."""

    analysis_name = "IFDS nullness"

    def __init__(
        self,
        adapter: CFGSupergraphAdapter,
        entry_nodes: Sequence[CFGNode] | None = None,
    ) -> None:
        super().__init__(adapter)
        if entry_nodes is None:
            raise ValueError(
                "IFDS nullness requires explicit entry_nodes; "
                "use program-backed IFDS APIs to derive roots automatically."
            )
        self.entry_nodes = tuple(entry_nodes)

    @property
    def supergraph(self):
        return self.adapter.supergraph

    @property
    def zero_fact(self):
        return ZERO_NULLNESS

    def initial_seeds(self) -> Mapping[CFGNode, frozenset[object]]:
        return build_entry_seeds(self.entry_nodes, ZERO_NULLNESS)

    def normal_flow(self, node: CFGNode, successor: CFGNode, fact: object):
        condition_outputs = self._condition_outputs(node, successor, fact)
        if condition_outputs is not None:
            return condition_outputs

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
            if expr is not None and self._expr_is_nullable(node.procedure, expr, fact):
                outputs.update(
                    self._facts_for_locals(
                        node.procedure,
                        targets,
                    )
                )
            return tuple(outputs)

        if isinstance(operation, py_ast.Return):
            outputs = set(self._identity_outputs(fact, ()))
            if len(operation.exprs) == 1:
                direct_fact = self._direct_expression_fact(operation.exprs[0], fact)
                if direct_fact is not None:
                    _procedure, _expr, result_index = direct_fact
                    outputs.update(
                        self._facts_for_return_slot(node.procedure, result_index)
                    )
                    return tuple(outputs)
            for index, expr in enumerate(operation.exprs):
                if self._expr_is_nullable(node.procedure, expr, fact):
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
            if self._expr_is_nullable(node.procedure, value, fact):
                outputs.update(self._facts_for_modified_operation(operation))
            return tuple(outputs)

        return self._identity_outputs(fact, killed)

    def call_flow(self, call_node: CFGNode, callee: cfg_graph.Code, fact: object):
        outputs = set()
        if fact == ZERO_NULLNESS:
            outputs.add(ZERO_NULLNESS)

        call_effect = self._call_effect(call_node)
        call = call_effect.call_expression if call_effect is not None else None
        if call is None:
            return tuple(outputs)

        params = callee.code.codeparameters
        from ..transfers import bind_call_arguments  # local import to avoid cycles

        for actual, formal in bind_call_arguments(call, params):
            if self._expr_is_nullable(call_node.procedure, actual, fact):
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
        del exit_node, return_site, call_fact
        outputs = set()
        if exit_fact == ZERO_NULLNESS:
            outputs.add(ZERO_NULLNESS)

        return_index = self._return_fact_index(callee, exit_fact)
        if return_index is not None:
            outputs.update(
                self._facts_for_nested_call_result(
                    call_node.procedure,
                    call_effect.operation if (call_effect := self._call_effect(call_node)) is not None else self.adapter.operation_of(call_node),
                    call_effect.call_expression if call_effect is not None else self.adapter.call_expression_of(call_node),
                    return_index,
                    nested=False,
                )
            )

        return tuple(outputs)

    def call_to_return_flow(self, call_node: CFGNode, return_site: CFGNode, fact: object):
        del return_site
        killed = self._killed_slots_for_node(call_node)
        return self._identity_outputs(fact, killed)

    def findings(self, result) -> tuple[NullnessFinding, ...]:
        findings: list[NullnessFinding] = []
        seen: set[tuple[CFGNode, str, str]] = set()

        def record(node: CFGNode, kind: str, expr) -> None:
            label = self.describe_expression(expr)
            key = (node, kind, label)
            if key in seen:
                return
            seen.add(key)
            findings.append(NullnessFinding(node=node, kind=kind, expression_label=label))

        for node in self.adapter.supergraph.nodes():
            call_effect = self._call_effect(node)
            call = call_effect.call_expression if call_effect is not None else None
            effect = self.adapter.effect_of(node)
            operation = getattr(effect, "operation", self.adapter.operation_of(node))

            if call is not None:
                self._collect_null_risks(node, call, result, record, inspect_calls=True)
            elif operation is not None:
                self._collect_null_risks(node, operation, result, record, inspect_calls=False)

        return tuple(findings)

    def describe_fact(self, fact: object) -> str:
        if isinstance(fact, SlotNullFact):
            return self.describe_slot(fact.slot)
        if isinstance(fact, ExpressionNullFact):
            return self.describe_expression(fact.expression)
        return "<expr>"

    def _make_slot_fact(self, slot: object) -> object:
        return SlotNullFact(slot)

    def _make_expression_fact(
        self,
        procedure: cfg_graph.Code,
        expression: py_ast.PythonASTNode,
        result_index: int = 0,
    ) -> object:
        return ExpressionNullFact(procedure, expression, result_index)

    def _slot_from_fact(self, fact: object) -> object | None:
        if isinstance(fact, SlotNullFact):
            return fact.slot
        return None

    def _expression_fact_result(
        self, fact: object
    ) -> tuple[cfg_graph.Code, py_ast.PythonASTNode, int] | None:
        if isinstance(fact, ExpressionNullFact):
            return (fact.procedure, fact.expression, fact.result_index)
        return None

    def _identity_outputs(self, fact: object, killed: Sequence[object]):
        if fact == ZERO_NULLNESS:
            return (ZERO_NULLNESS,)
        if isinstance(fact, SlotNullFact) and any(fact.slot == target for target in killed):
            return ()
        return (fact,)

    def _expr_is_nullable(
        self, procedure: cfg_graph.Code, expr: object, fact: object
    ) -> bool:
        if fact == ZERO_NULLNESS:
            return self._expr_contains_explicit_null(expr)
        return self._expression_matches(
            expr,
            lambda current: any(
                candidate == fact
                for candidate in self._facts_for_expression_node(procedure, current)
            ),
        )

    def _expr_contains_explicit_null(self, expr: object) -> bool:
        return self._expression_matches(expr, self._is_explicit_null_expression)

    def _is_explicit_null_expression(self, expr: object) -> bool:
        return (
            isinstance(expr, py_ast.Existing)
            and getattr(expr.object, "pyobj", object()) is None
        )

    def _expression_matches(self, expr: object, predicate) -> bool:
        found = False

        def visit(current) -> None:
            nonlocal found
            if found or current is None or isinstance(current, py_ast.leafTypes):
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

    def _condition_outputs(
        self, node: CFGNode, successor: CFGNode, fact: object
    ) -> tuple[object, ...] | None:
        guard_effect = self._guard_effect(node)
        if guard_effect is None:
            return None
        exit_name = node.block.findExit(successor.block)
        if exit_name not in ("true", "false"):
            return None

        target_expr = guard_effect.nullable_target
        true_means_null = guard_effect.true_branch_means_null
        if target_expr is None:
            return None

        slots = tuple(
            slot
            for candidate in self._facts_for_expression_node(node.procedure, target_expr)
            for slot in (self._slot_from_fact(candidate),)
            if slot is not None
        )
        if not slots:
            return None

        branch_means_null = true_means_null if exit_name == "true" else not true_means_null
        target_facts = {SlotNullFact(slot) for slot in slots}
        if branch_means_null:
            outputs = set()
            if fact == ZERO_NULLNESS:
                outputs.add(ZERO_NULLNESS)
                outputs.update(target_facts)
                return tuple(outputs)
            outputs.add(fact)
            return tuple(outputs)

        if fact == ZERO_NULLNESS:
            return (ZERO_NULLNESS,)
        if fact in target_facts:
            return ()
        return (fact,)

    def _nullable_condition_target(self, expr: object):
        if isinstance(expr, py_ast.ConvertToBool):
            return self._nullable_condition_target(expr.expr)
        if isinstance(expr, py_ast.Is):
            if self._is_explicit_null_expression(expr.right):
                return expr.left, True
            if self._is_explicit_null_expression(expr.left):
                return expr.right, True
        call_target = self._nullable_condition_call_target(expr)
        if call_target is not None:
            return call_target
        if isinstance(expr, py_ast.Not):
            target, true_means_null = self._nullable_condition_target(expr.expr)
            if target is not None:
                return target, not true_means_null
        return None, False

    def _nullable_condition_call_target(
        self, expr: object
    ) -> tuple[object, bool] | None:
        if not isinstance(expr, (py_ast.Call, py_ast.DirectCall, py_ast.MethodCall)):
            return None
        call_name = self._call_name_from_expression(expr)
        if call_name not in {"interpreter__is__", "interpreter__is_not__"}:
            return None
        actuals = actual_argument_expressions(expr)
        if len(actuals) != 2:
            return None
        left, right = actuals
        if self._is_explicit_null_expression(right):
            return left, call_name == "interpreter__is__"
        if self._is_explicit_null_expression(left):
            return right, call_name == "interpreter__is__"
        return None

    def _collect_null_risks(
        self,
        node: CFGNode,
        root: object,
        result,
        record,
        *,
        inspect_calls: bool,
    ) -> None:
        def visit(current) -> None:
            if current is None or isinstance(current, py_ast.leafTypes):
                return
            if isinstance(current, py_ast.Call):
                if inspect_calls and self._expr_may_be_null_at(node, current.expr, result):
                    record(node, "call_target", current.expr)
            elif isinstance(current, py_ast.MethodCall):
                if inspect_calls and self._expr_may_be_null_at(node, current.expr, result):
                    record(node, "method_receiver", current.expr)
            elif isinstance(current, (py_ast.GetAttr, py_ast.Load)):
                if self._expr_may_be_null_at(node, current.expr, result):
                    record(node, "attribute_access", current.expr)
            elif isinstance(current, py_ast.GetSubscript):
                if self._expr_may_be_null_at(node, current.expr, result):
                    record(node, "subscript_access", current.expr)
            elif isinstance(
                current,
                (py_ast.SetAttr, py_ast.Store, py_ast.SetSubscript, py_ast.SetSlice),
            ):
                if self._expr_may_be_null_at(node, current.expr, result):
                    record(node, "mutation_target", current.expr)

            if isinstance(current, (list, tuple)):
                for child in current:
                    visit(child)
                return
            if isinstance(current, py_ast.Code):
                return
            current.visitChildren(visit)

        visit(root)

    def _expr_may_be_null_at(self, node: CFGNode, expr: object, result) -> bool:
        if self._expr_contains_explicit_null(expr):
            return True
        return any(
            result.is_reached(node, fact)
            for fact in self._facts_for_expression_node(node.procedure, expr)
        )


class InterproceduralNullnessAnalysis:
    """Concrete nullness analysis backed by the IFDS engine."""

    def __init__(
        self,
        adapter: CFGSupergraphAdapter,
        *,
        entry_nodes: Sequence[CFGNode] | None = None,
        record_traces: bool = False,
    ) -> None:
        self.problem = InterproceduralNullnessProblem(adapter, entry_nodes=entry_nodes)
        self.record_traces = record_traces

    def solve(self) -> NullnessAnalysisResult:
        result = IFDSSolver(record_traces=self.record_traces).solve(self.problem)
        return NullnessAnalysisResult(result, self.problem.findings(result), self.problem)


def analyze_nullness(
    adapter: CFGSupergraphAdapter,
    *,
    entry_nodes: Sequence[CFGNode] | None = None,
    record_traces: bool = False,
) -> NullnessAnalysisResult:
    """Convenience entry point for interprocedural nullness analysis."""
    return InterproceduralNullnessAnalysis(
        adapter,
        entry_nodes=entry_nodes,
        record_traces=record_traces,
    ).solve()
