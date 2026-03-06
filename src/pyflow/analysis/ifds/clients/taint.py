"""Concrete interprocedural taint analysis over CFG-backed supergraphs."""

from __future__ import annotations

from dataclasses import dataclass
from typing import FrozenSet, Iterable, Mapping, Sequence

from pyflow.application.errors import TemporaryLimitation
from pyflow.analysis.cfg import graph as cfg_graph
from pyflow.language.python import ast as py_ast

from ..cfg_adapter import CFGNode, CFGSupergraphAdapter, assigned_locals
from ..problem import IFDSProblem
from ..solver import IFDSSolver
from ..transfers import (
    actual_argument_expressions,
    bind_call_arguments,
    collect_locals,
    resolve_call_name,
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
    IFDSProblem[cfg_graph.Code, CFGNode, object]
):
    """IFDS taint problem over CFG nodes."""

    def __init__(
        self,
        adapter: CFGSupergraphAdapter,
        configuration: TaintConfiguration,
        entry_nodes: Sequence[CFGNode] | None = None,
    ) -> None:
        self.adapter = adapter
        self.configuration = configuration
        self._require_complete_annotations()
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
        return {node: frozenset({ZERO_TAINT}) for node in self.entry_nodes}

    def normal_flow(self, node: CFGNode, successor: CFGNode, fact: object):
        del successor
        operation = self.adapter.operation_of(node)
        if operation is None:
            return self._identity_outputs(fact, ())

        killed = self._killed_slots_for_operation(node.procedure, operation)

        if isinstance(operation, (py_ast.Assign, py_ast.UnpackSequence, py_ast.AnnAssign)):
            outputs = set(self._identity_outputs(fact, killed))
            expr = getattr(operation, "expr", None)
            if isinstance(operation, py_ast.AnnAssign):
                expr = operation.value
            targets = assigned_locals(operation)

            direct_fact = self._direct_expression_fact(expr, fact)
            if direct_fact is not None:
                outputs.update(
                    self._facts_for_assigned_locals(
                        node.procedure,
                        targets,
                        direct_fact.result_index,
                    )
                )
                return tuple(outputs)
            if expr is not None and self._expr_is_tainted(node.procedure, expr, fact):
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
                    outputs.update(
                        self._facts_for_return_slot(
                            node.procedure, direct_fact.result_index
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
                outputs.update(self._facts_for_modified_operation(node.procedure, operation))
            return tuple(outputs)

        return self._identity_outputs(fact, killed)

    def call_flow(self, call_node: CFGNode, callee: cfg_graph.Code, fact: object):
        outputs = set()
        if fact == ZERO_TAINT:
            outputs.add(ZERO_TAINT)

        if self._is_source_call(call_node) or self._is_sanitizer_call(call_node):
            return tuple(outputs)

        call = self.adapter.call_expression_of(call_node)
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

        if self._is_sanitizer_call(call_node):
            return tuple(outputs)

        if self._is_return_fact(callee, exit_fact):
            outputs.update(
                self._facts_for_call_result(
                    call_node.procedure,
                    self.adapter.operation_of(call_node),
                    self.adapter.call_expression_of(call_node),
                    callee,
                    exit_fact,
                )
            )

        return tuple(outputs)

    def call_to_return_flow(self, call_node: CFGNode, return_site: CFGNode, fact: object):
        del return_site
        operation = self.adapter.operation_of(call_node)
        killed = self._killed_slots_for_call_expression(
            call_node.procedure,
            operation,
            self.adapter.call_expression_of(call_node),
        )
        outputs = set(self._identity_outputs(fact, killed))
        if fact == ZERO_TAINT and self._is_source_call(call_node):
            outputs.update(
                self._facts_for_source_call_result(
                    call_node.procedure,
                    operation,
                    self.adapter.call_expression_of(call_node),
                )
            )
        return tuple(outputs)

    def _identity_outputs(self, fact: object, killed: Sequence[object]):
        if fact == ZERO_TAINT:
            return (ZERO_TAINT,)
        if isinstance(fact, SlotTaintFact) and any(fact.slot == target for target in killed):
            return ()
        return (fact,)

    def _direct_expression_fact(self, expr, fact: object) -> ExpressionTaintFact | None:
        if not isinstance(fact, ExpressionTaintFact):
            return None
        if fact.expression is not expr:
            return None
        return fact

    def _killed_slots_for_operation(
        self, procedure: cfg_graph.Code, operation
    ) -> tuple[object, ...]:
        if operation is None:
            return ()
        if isinstance(operation, (py_ast.Assign, py_ast.UnpackSequence, py_ast.AnnAssign)):
            return tuple(
                fact.slot
                for fact in self._facts_for_locals(procedure, assigned_locals(operation))
            )
        if isinstance(operation, py_ast.Delete):
            return tuple(
                fact.slot for fact in self._facts_for_locals(procedure, (operation.lcl,))
            )
        if isinstance(operation, py_ast.InputBlock):
            locals_ = []
            for input_ in getattr(operation, "inputs", ()):
                lcl = getattr(input_, "lcl", None)
                if isinstance(lcl, py_ast.Local):
                    locals_.append(lcl)
            return tuple(fact.slot for fact in self._facts_for_locals(procedure, locals_))
        if isinstance(operation, (py_ast.SetGlobal, py_ast.DeleteGlobal)):
            return tuple(
                fact.slot for fact in self._facts_for_modified_operation(procedure, operation)
            )
        if isinstance(operation, py_ast.SetCellDeref):
            return tuple(
                fact.slot for fact in self._facts_for_modified_operation(procedure, operation)
            )
        return ()

    def _expr_is_tainted(
        self, procedure: cfg_graph.Code, expr, fact: object
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

    def _expr_contains_source(self, expr) -> bool:
        return self._expression_matches(
            expr,
            lambda current: self._call_name_from_expression(current)
            in self.configuration.source_names,
        )

    def _expr_is_sanitized(self, expr) -> bool:
        return self._call_name_from_expression(expr) in self.configuration.sanitizer_names

    def _call_name(self, node: CFGNode) -> str | None:
        call = self.adapter.call_expression_of(node)
        return resolve_call_name(
            call,
            fallback_callee_names=tuple(
                cfg.code.codeName()
                for cfg in self.adapter.callees_of(node)
                if cfg.code is not None
            ),
        )

    def _is_source_call(self, node: CFGNode) -> bool:
        return self._call_name(node) in self.configuration.source_names

    def _is_sanitizer_call(self, node: CFGNode) -> bool:
        return self._call_name(node) in self.configuration.sanitizer_names

    def _is_sink_call(self, node: CFGNode) -> bool:
        return self._call_name(node) in self.configuration.sink_names

    def _actual_arguments(self, call) -> tuple[object, ...]:
        return actual_argument_expressions(call)

    def _facts_for_call_result(
        self,
        procedure: cfg_graph.Code,
        operation,
        call_expression,
        callee: cfg_graph.Code,
        exit_fact: object,
    ):
        return_index = self._return_fact_index(callee, exit_fact)
        if return_index is None or call_expression is None:
            return set()
        return self._facts_for_nested_call_result(
            procedure,
            operation,
            call_expression,
            return_index,
            nested=False,
        )

    def _facts_for_source_call_result(
        self, procedure: cfg_graph.Code, operation, call_expression
    ):
        if call_expression is None:
            return set()
        return self._facts_for_nested_call_result(
            procedure,
            operation,
            call_expression,
            0,
            nested=False,
        )

    def findings(self, result) -> tuple[TaintFinding, ...]:
        findings: list[TaintFinding] = []
        for node in self.adapter.supergraph.nodes():
            if not self._is_sink_call(node):
                continue
            if not result.is_reached(node, ZERO_TAINT):
                continue
            call = self.adapter.call_expression_of(node)
            if call is None:
                continue
            tainted_args, tainted_labels = self._tainted_arguments_for_call(
                node, call, result
            )
            if tainted_args or tainted_labels:
                findings.append(
                    TaintFinding(
                        sink=node,
                        sink_name=self._call_name(node) or "<sink>",
                        tainted_arguments=tainted_args,
                        tainted_argument_labels=tainted_labels,
                    )
                )
        return tuple(findings)

    def local_slots(self, procedure: cfg_graph.Code, local: py_ast.Local) -> tuple[object, ...]:
        return tuple(fact.slot for fact in self._facts_for_locals(procedure, (local,)))

    def _facts_for_locals(self, procedure: cfg_graph.Code, locals_: Iterable[object]):
        facts: set[SlotTaintFact] = set()
        for local in locals_:
            if not isinstance(local, py_ast.Local) or local.name is None:
                continue
            slots = self._slots_for_local(procedure, local)
            facts.update(SlotTaintFact(slot) for slot in slots)
        return facts

    def _facts_for_assigned_locals(
        self,
        procedure: cfg_graph.Code,
        locals_: Sequence[object],
        result_index: int,
    ):
        if result_index >= len(locals_):
            return set()
        return self._facts_for_locals(procedure, (locals_[result_index],))

    def _facts_for_return_slot(self, procedure: cfg_graph.Code, index: int):
        returnparams = tuple(procedure.code.codeparameters.returnparams)
        if index >= len(returnparams):
            return set()
        return self._facts_for_locals(procedure, (returnparams[index],))

    def _facts_for_expression_node(
        self, procedure: cfg_graph.Code, current
    ) -> tuple[object, ...]:
        if current is None or isinstance(current, py_ast.leafTypes):
            return ()
        if isinstance(current, (py_ast.DirectCall, py_ast.Call, py_ast.MethodCall)):
            return (ExpressionTaintFact(procedure, current),)
        return tuple(
            SlotTaintFact(slot) for slot in self._slots_read_by_node(procedure, current)
        )

    def _facts_for_nested_call_result(
        self,
        procedure: cfg_graph.Code,
        operation,
        call_expression,
        return_index: int,
        *,
        nested: bool,
    ) -> set[object]:
        if operation is None or call_expression is None:
            return set()

        if isinstance(operation, (py_ast.Assign, py_ast.UnpackSequence)) and operation.expr is call_expression:
            if not nested:
                return {ExpressionTaintFact(procedure, call_expression, return_index)}
            return self._facts_for_assigned_locals(
                procedure,
                assigned_locals(operation),
                return_index,
            )
        if isinstance(operation, py_ast.AnnAssign) and operation.value is call_expression:
            if not nested:
                return {ExpressionTaintFact(procedure, call_expression, return_index)}
            return self._facts_for_assigned_locals(
                procedure,
                assigned_locals(operation),
                return_index,
            )

        if isinstance(operation, py_ast.Return):
            if not nested:
                return {ExpressionTaintFact(procedure, call_expression, return_index)}
            target_index = self._call_result_target_index(
                operation, call_expression, return_index
            )
            if target_index is not None:
                return self._facts_for_return_slot(procedure, target_index)

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
        ) and getattr(operation, "value", None) is call_expression:
            if not nested:
                return {ExpressionTaintFact(procedure, call_expression, return_index)}
            return self._facts_for_modified_operation(procedure, operation)

        for child in self._nested_operations(operation):
            child_result = self._facts_for_nested_call_result(
                procedure,
                child,
                call_expression,
                return_index,
                nested=True,
            )
            if child_result:
                return child_result

        return {ExpressionTaintFact(procedure, call_expression, return_index)}

    def _killed_slots_for_call_expression(
        self,
        procedure: cfg_graph.Code,
        operation,
        call_expression,
    ) -> tuple[object, ...]:
        if operation is None or call_expression is None:
            return ()

        if isinstance(operation, (py_ast.Assign, py_ast.UnpackSequence)) and operation.expr is call_expression:
            return tuple(
                fact.slot
                for fact in self._facts_for_locals(procedure, assigned_locals(operation))
            )
        if isinstance(operation, py_ast.AnnAssign) and operation.value is call_expression:
            return tuple(
                fact.slot
                for fact in self._facts_for_locals(procedure, assigned_locals(operation))
            )

        if isinstance(operation, py_ast.SetGlobal) and operation.value is call_expression:
            return tuple(
                fact.slot for fact in self._facts_for_modified_operation(procedure, operation)
            )

        if isinstance(operation, py_ast.SetCellDeref) and operation.value is call_expression:
            return tuple(
                fact.slot for fact in self._facts_for_modified_operation(procedure, operation)
            )

        for child in self._nested_operations(operation):
            child_kills = self._killed_slots_for_call_expression(
                procedure, child, call_expression
            )
            if child_kills:
                return child_kills

        # Keep unrelated facts alive until the terminal operation node; this
        # call node only corresponds to one nested call expression.
        return ()

    def _nested_operations(self, operation) -> tuple[object, ...]:
        if isinstance(operation, py_ast.Suite):
            return tuple(operation.blocks)
        if isinstance(operation, py_ast.TryExceptFinally):
            nested = list(operation.body.blocks)
            for handler in operation.handlers:
                nested.extend(handler.preamble.blocks)
                if handler.value is not None:
                    nested.append(handler.value)
                nested.extend(handler.body.blocks)
            if operation.defaultHandler is not None:
                nested.extend(operation.defaultHandler.blocks)
            if operation.else_ is not None:
                nested.extend(operation.else_.blocks)
            if operation.finally_ is not None:
                nested.extend(operation.finally_.blocks)
            return tuple(nested)
        if isinstance(operation, py_ast.ExceptionHandler):
            nested = list(operation.preamble.blocks)
            nested.append(operation.type)
            if operation.value is not None:
                nested.append(operation.value)
            nested.extend(operation.body.blocks)
            return tuple(nested)
        return ()

    def _tainted_arguments_for_call(self, node: CFGNode, call, result):
        tainted_locals: list[py_ast.Local] = []
        tainted_labels: list[str] = []
        seen_local_names: set[str] = set()
        seen_labels: set[str] = set()

        for actual in self._actual_arguments(call):
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
                    lambda fact: result.is_reached(node, fact),
                )
            )
            for label in labels_in_expr:
                if label not in seen_labels:
                    seen_labels.add(label)
                    tainted_labels.append(label)

            if not locals_in_expr and not labels_in_expr and self._expr_contains_source(actual):
                label = self._describe_expression(actual)
                if label not in seen_labels:
                    seen_labels.add(label)
                    tainted_labels.append(label)

        return tuple(tainted_locals), tuple(tainted_labels)

    def _matching_labels_in_expression(
        self, procedure: cfg_graph.Code, expr, predicate
    ) -> frozenset[str]:
        found: set[str] = set()

        def visit(current) -> None:
            if current is None or isinstance(current, py_ast.leafTypes):
                return
            if self._expr_is_sanitized(current):
                return
            if not isinstance(current, py_ast.Local):
                facts = self._facts_for_expression_node(procedure, current)
                if facts and any(predicate(fact) for fact in facts):
                    found.add(self._describe_expression(current))
            if isinstance(current, (list, tuple)):
                for child in current:
                    visit(child)
                return
            if isinstance(current, py_ast.Code):
                return
            current.visitChildren(visit)

        visit(expr)
        return frozenset(found)

    def _call_name_from_expression(self, expr) -> str | None:
        if isinstance(expr, (py_ast.DirectCall, py_ast.Call, py_ast.MethodCall)):
            return resolve_call_name(expr)
        return None

    def _describe_expression(self, expr) -> str:
        call_name = self._call_name_from_expression(expr)
        if call_name is not None:
            return f"{call_name}()"
        if isinstance(expr, py_ast.GetAttr):
            return f"{self._describe_expression(expr.expr)}.{self._path_component(expr.name)}"
        if isinstance(expr, py_ast.Load):
            return f"{self._describe_expression(expr.expr)}.{self._path_component(expr.name)}"
        if isinstance(expr, py_ast.GetSubscript):
            return f"{self._describe_expression(expr.expr)}{self._subscript_component(expr.subscript)}"
        if isinstance(expr, py_ast.GetGlobal):
            return self._global_name(expr.name) or "<global>"
        if isinstance(expr, py_ast.GetCellDeref):
            return expr.cell.name if isinstance(expr.cell, py_ast.Cell) else "<cell>"
        local_names = sorted(
            {local.name for local in collect_locals(expr) if local.name is not None}
        )
        if local_names:
            return ", ".join(local_names)
        return "<expr>"

    def describe_fact(self, fact: object) -> str:
        if isinstance(fact, SlotTaintFact):
            return self._describe_slot(fact.slot)
        if isinstance(fact, ExpressionTaintFact):
            return self._describe_expression(fact.expression)
        return "<expr>"

    def _expression_matches(self, expr, predicate) -> bool:
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
        self, procedure: cfg_graph.Code, expr, predicate
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

    def _is_return_fact(self, procedure: cfg_graph.Code, fact: object) -> bool:
        return self._return_fact_index(procedure, fact) is not None

    def _return_fact_index(
        self, procedure: cfg_graph.Code, fact: object
    ) -> int | None:
        if not isinstance(fact, SlotTaintFact):
            return None
        for index, local in enumerate(procedure.code.codeparameters.returnparams):
            if any(slot == fact.slot for slot in self._slots_for_local(procedure, local)):
                return index
        return None

    def _call_result_target_index(
        self, operation, call_expression, return_index: int
    ) -> int | None:
        if not isinstance(operation, py_ast.Return):
            return return_index
        if len(operation.exprs) <= 1:
            return return_index
        for index, expr in enumerate(operation.exprs):
            if expr is call_expression:
                return index
        return None

    def _facts_for_modified_operation(
        self, procedure: cfg_graph.Code, operation
    ) -> set[SlotTaintFact]:
        slots = self._annotation_slots(getattr(operation.annotation, "opModifies", None))
        return {
            SlotTaintFact(slot)
            for slot in slots
        }

    def _slots_for_local(self, procedure: cfg_graph.Code, local) -> tuple[object, ...]:
        del procedure
        refs = getattr(getattr(local, "annotation", None), "references", None)
        return self._annotation_slots(refs)

    def _slots_read_by_node(
        self, procedure: cfg_graph.Code, node
    ) -> tuple[object, ...]:
        if isinstance(node, py_ast.Local):
            return self._slots_for_local(procedure, node)
        if isinstance(node, py_ast.GetGlobal):
            return self._annotation_slots(getattr(node.annotation, "opReads", None))
        if isinstance(node, py_ast.GetCellDeref):
            return self._annotation_slots(getattr(node.annotation, "opReads", None))
        annotation = getattr(node, "annotation", None)
        return self._annotation_slots(getattr(annotation, "opReads", None))

    def _annotation_slots(self, annotation) -> tuple[object, ...]:
        if annotation is None:
            return ()
        merged = getattr(annotation, "merged", None)
        if merged is None:
            if isinstance(annotation, (str, bytes)):
                return ()
            if isinstance(annotation, (list, tuple, set, frozenset)):
                merged = tuple(annotation)
            else:
                return ()
        return tuple(self._canonical_slot(slot) for slot in merged)

    def _canonical_slot(self, slot):
        get_forward = getattr(slot, "getForward", None)
        if callable(get_forward):
            return get_forward()
        return slot

    def _describe_slot(self, slot) -> str:
        slot_name = getattr(slot, "slotName", None)
        if slot_name is not None:
            if hasattr(slot_name, "isLocal") and slot_name.isLocal():
                local = getattr(slot_name, "local", None)
                name = getattr(local, "name", None)
                if name is not None:
                    return name
            if hasattr(slot_name, "isExisting") and slot_name.isExisting():
                obj = getattr(slot_name, "object", None)
                name = self._object_name(obj)
                if name is not None:
                    return name
        return repr(slot)

    def _object_name(self, obj) -> str | None:
        if obj is None:
            return None
        constant_value = getattr(obj, "constantValue", None)
        if callable(constant_value):
            value = constant_value()
            if value is not None:
                return str(value)
        identifier = getattr(obj, "id", None)
        if isinstance(identifier, str):
            return identifier
        pyobj = getattr(obj, "pyobj", None)
        if isinstance(pyobj, str):
            return pyobj
        return None

    def _path_component(self, node) -> str:
        if isinstance(node, py_ast.Local) and node.name:
            return node.name
        if isinstance(node, py_ast.Existing):
            name = self._object_name(node.object)
            if name is not None:
                return name
        return "*"

    def _subscript_component(self, node) -> str:
        if isinstance(node, py_ast.Existing):
            value = self._object_name(node.object)
            if value is not None:
                return f"[{value!r}]"
        return "[*]"

    def _global_name(self, existing) -> str | None:
        if not isinstance(existing, py_ast.Existing):
            return None
        return self._object_name(existing.object)

    def _require_complete_annotations(self) -> None:
        problems: list[str] = []
        seen_codes: set[object] = set()
        for cfg in self.adapter.cfgs:
            code = getattr(cfg, "code", None)
            if code is None or code in seen_codes:
                continue
            seen_codes.add(code)
            code_annotation = getattr(code, "annotation", None)
            if getattr(code_annotation, "contexts", None) is None:
                problems.append(f"{code.codeName()}: missing code contexts")
                continue

            for node in self._iter_ast_nodes(code):
                annotation = getattr(node, "annotation", None)
                if annotation is None:
                    continue
                if hasattr(annotation, "opReads") and getattr(annotation, "opReads", None) is None:
                    problems.append(f"{code.codeName()}: {type(node).__name__} missing opReads")
                    break
                if hasattr(annotation, "opModifies") and getattr(annotation, "opModifies", None) is None:
                    problems.append(
                        f"{code.codeName()}: {type(node).__name__} missing opModifies"
                    )
                    break
                if hasattr(annotation, "references") and getattr(annotation, "references", None) is None:
                    name = getattr(node, "name", None)
                    problems.append(
                        f"{code.codeName()}: local {name if name is not None else '<anon>'} missing references"
                    )
                    break

        if problems:
            raise TemporaryLimitation(
                "IFDS taint requires annotation-complete programs (run IPA/CPA first): "
                + "; ".join(problems[:5])
            )

    def _iter_ast_nodes(self, node):
        if node is None or isinstance(node, py_ast.leafTypes):
            return
        yield node
        if isinstance(node, (list, tuple)):
            for child in node:
                yield from self._iter_ast_nodes(child)
            return
        if isinstance(node, py_ast.Code):
            params = getattr(node, "codeparameters", None)
            if params is not None:
                yield from self._iter_ast_nodes(getattr(params, "selfparam", None))
                yield from self._iter_ast_nodes(getattr(params, "posonlyparams", ()))
                yield from self._iter_ast_nodes(getattr(params, "params", ()))
                yield from self._iter_ast_nodes(getattr(params, "defaults", ()))
                yield from self._iter_ast_nodes(getattr(params, "vparam", None))
                yield from self._iter_ast_nodes(getattr(params, "kparam", None))
                yield from self._iter_ast_nodes(getattr(params, "returnparams", ()))
            yield from self._iter_ast_nodes(node.ast)
            return

        children: list[object] = []

        def collect(child) -> None:
            children.append(child)

        node.visitChildren(collect)
        for child in children:
            yield from self._iter_ast_nodes(child)



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
