"""Practical resource typestate analysis over CFG-backed IFDS supergraphs."""

from __future__ import annotations

from dataclasses import dataclass
from typing import FrozenSet, Mapping, Sequence

from pyflow.analysis.cfg import graph as cfg_graph
from pyflow.language.python import ast as py_ast

from ._call_model import CallModelRegistry, STATE_CLOSE, STATE_USE
from ._client_common import AnnotatedFactProblemBase, build_entry_seeds
from ..cfg_adapter import CFGNode, CFGSupergraphAdapter, assigned_locals
from ..problem import IFDSProblem
from ..solver import IFDSSolver
from ..transfers import actual_argument_expressions, bind_call_arguments


ZERO_TYPESTATE = "ZERO_TYPESTATE"
STATE_OPEN = "open"
STATE_CLOSED = "closed"


@dataclass(frozen=True)
class TypestateConfiguration:
    """Name-based protocol configuration for resource lifecycles."""

    open_names: FrozenSet[str] = frozenset({"open"})
    close_names: FrozenSet[str] = frozenset({"close"})
    use_names: FrozenSet[str] = frozenset({"read", "write", "send", "recv"})
    resource_arg_positions: FrozenSet[int] = frozenset({0})
    track_method_receiver: bool = True
    collection_mutator_names: FrozenSet[str] = frozenset(
        {"append", "add", "extend", "update"}
    )
    collection_accessor_names: FrozenSet[str] = frozenset({"get"})


@dataclass(frozen=True)
class ResourceStateFact:
    """A resource-bearing slot in a given protocol state."""

    slot: object
    state: str


@dataclass(frozen=True)
class ExpressionResourceFact:
    """A resource-bearing intermediate expression result."""

    procedure: cfg_graph.Code
    expression: py_ast.PythonASTNode
    state: str
    result_index: int = 0


@dataclass(frozen=True)
class TypestateFinding:
    """Potential resource-protocol issue."""

    node: CFGNode
    kind: str
    operation_name: str
    resource_label: str


class TypestateAnalysisResult:
    """Query wrapper for typestate results."""

    def __init__(self, ifds_result, findings: Sequence[TypestateFinding], problem) -> None:
        self._ifds_result = ifds_result
        self.findings = tuple(findings)
        self._problem = problem

    def has_state(self, node: CFGNode, local: py_ast.Local, state: str) -> bool:
        return any(
            self._ifds_result.is_reached(node, ResourceStateFact(slot, state))
            for slot in self._problem.local_slots(node.procedure, local)
        )

    @property
    def statistics(self):
        return self._ifds_result.statistics

    def explain_fact(self, node: CFGNode, fact: object):
        return self._ifds_result.explain_fact(node, fact)


class InterproceduralTypestateProblem(
    AnnotatedFactProblemBase[object],
    IFDSProblem[cfg_graph.Code, CFGNode, object],
):
    """Resource lifecycle analysis over CFG nodes."""

    analysis_name = "IFDS typestate"

    def __init__(
        self,
        adapter: CFGSupergraphAdapter,
        configuration: TypestateConfiguration,
        entry_nodes: Sequence[CFGNode] | None = None,
    ) -> None:
        self.configuration = configuration
        super().__init__(
            adapter,
            call_models=CallModelRegistry.from_typestate_configuration(configuration),
        )
        if entry_nodes is None:
            raise ValueError(
                "IFDS typestate requires explicit entry_nodes; "
                "use program-backed IFDS APIs to derive roots automatically."
            )
        self.entry_nodes = tuple(entry_nodes)

    @property
    def supergraph(self):
        return self.adapter.supergraph

    @property
    def zero_fact(self):
        return ZERO_TYPESTATE

    def initial_seeds(self) -> Mapping[CFGNode, frozenset[object]]:
        return build_entry_seeds(self.entry_nodes, ZERO_TYPESTATE)

    def normal_flow(self, node: CFGNode, successor: CFGNode, fact: object):
        local_call_outputs = self._local_call_outputs(node, fact)
        if local_call_outputs is not None:
            return local_call_outputs

        del successor
        effect = self.adapter.effect_of(node)
        operation = getattr(effect, "operation", self.adapter.operation_of(node))
        if operation is None:
            return self._identity_outputs(fact, ())

        killed = self._killed_slots_for_node(node)
        dynamic_setattr_slots = self._dynamic_setattr_slots(node.procedure, operation)
        if dynamic_setattr_slots:
            outputs = set(self._identity_outputs(fact, killed))
            value = self._dynamic_setattr_value(operation)
            state = self._fact_state(fact)
            if (
                value is not None
                and state is not None
                and self._expr_has_state(node.procedure, value, fact)
            ):
                outputs.update(
                    ResourceStateFact(slot, state) for slot in dynamic_setattr_slots
                )
            return tuple(outputs)

        dynamic_subscript_slots = self._dynamic_subscript_write_slots(
            node.procedure, operation
        )
        if dynamic_subscript_slots:
            outputs = set(self._identity_outputs(fact, killed))
            value = self._dynamic_subscript_value(operation)
            state = self._fact_state(fact)
            if (
                value is not None
                and state is not None
                and self._expr_has_state(node.procedure, value, fact)
            ):
                outputs.update(self._facts_for_modified_operation(operation, state))
                outputs.update(
                    ResourceStateFact(slot, state) for slot in dynamic_subscript_slots
                )
            return tuple(outputs)

        collection_slots, collection_values = self._collection_mutation(
            node.procedure,
            operation,
            self.configuration.collection_mutator_names,
        )
        if collection_slots:
            outputs = set(self._identity_outputs(fact, killed))
            state = self._fact_state(fact)
            if state is not None and any(
                self._expr_has_state(node.procedure, value, fact)
                for value in collection_values
            ):
                outputs.update(
                    ResourceStateFact(slot, state) for slot in collection_slots
                )
            return tuple(outputs)

        if isinstance(operation, (py_ast.Assign, py_ast.UnpackSequence, py_ast.AnnAssign)):
            outputs = set(self._identity_outputs(fact, killed))
            expr = getattr(operation, "expr", None)
            if isinstance(operation, py_ast.AnnAssign):
                expr = operation.value
            targets = assigned_locals(operation)

            direct_fact = self._direct_expression_fact(expr, fact)
            if direct_fact is not None:
                _procedure, _expr, state, result_index = direct_fact
                outputs.update(
                    self._facts_for_assigned_locals(
                        node.procedure,
                        targets,
                        state,
                        result_index,
                    )
                )
                return tuple(outputs)
            if expr is not None and self._expr_has_state(node.procedure, expr, fact):
                state = self._fact_state(fact)
                if state is not None:
                    outputs.update(
                        self._facts_for_locals(
                            node.procedure,
                            targets,
                            state,
                        )
                    )
            state = self._fact_state(fact)
            if state is not None:
                outputs.update(
                    ResourceStateFact(slot, state)
                    for slot in self._aliased_dynamic_slots_for_assignment(
                        node.procedure,
                        operation,
                        fact,
                    )
                )
                for slots, value in self._collection_constructor_writes(
                    node.procedure,
                    operation,
                ):
                    if self._expr_has_state(node.procedure, value, fact):
                        outputs.update(ResourceStateFact(slot, state) for slot in slots)
            return tuple(outputs)

        if isinstance(operation, py_ast.Return):
            outputs = set(self._identity_outputs(fact, ()))
            if len(operation.exprs) == 1:
                direct_fact = self._direct_expression_fact(operation.exprs[0], fact)
                if direct_fact is not None:
                    _procedure, _expr, state, result_index = direct_fact
                    outputs.update(
                        self._facts_for_return_slot(node.procedure, state, result_index)
                    )
                    return tuple(outputs)
            state = self._fact_state(fact)
            if state is None:
                return tuple(outputs)
            for index, expr in enumerate(operation.exprs):
                if self._expr_has_state(node.procedure, expr, fact):
                    outputs.update(self._facts_for_return_slot(node.procedure, state, index))
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
            state = self._fact_state(fact)
            if value is None or state is None:
                return tuple(outputs)
            if self._expr_has_state(node.procedure, value, fact):
                outputs.update(self._facts_for_modified_operation(operation, state))
            return tuple(outputs)

        return self._identity_outputs(fact, killed)

    def call_flow(self, call_node: CFGNode, callee: cfg_graph.Code, fact: object):
        outputs = set()
        if fact == ZERO_TYPESTATE:
            outputs.add(ZERO_TYPESTATE)

        call_effect = self._call_effect(call_node)
        call = call_effect.call_expression if call_effect is not None else None
        if call is None:
            return tuple(outputs)

        state = self._fact_state(fact)
        if state is None:
            return tuple(outputs)

        params = callee.code.codeparameters
        for actual, formal in bind_call_arguments(call, params):
            if self._expr_has_state(call_node.procedure, actual, fact):
                outputs.update(self._facts_for_locals(callee, (formal,), state))

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
        if exit_fact == ZERO_TYPESTATE:
            outputs.add(ZERO_TYPESTATE)

        call_effect = self._call_effect(call_node)
        return_index = self._return_fact_index(callee, exit_fact)
        state = self._fact_state(exit_fact)
        if return_index is not None and state is not None:
            operation = (
                call_effect.operation
                if call_effect is not None
                else self.adapter.operation_of(call_node)
            )
            call_expression = (
                call_effect.call_expression
                if call_effect is not None
                else self.adapter.call_expression_of(call_node)
            )
            outputs.update(
                self._facts_for_nested_call_result(
                    call_node.procedure,
                    operation,
                    call_expression,
                    return_index,
                    state,
                    nested=False,
                )
            )

        formal = self._formal_for_fact(callee, exit_fact)
        call = call_effect.call_expression if call_effect is not None else None
        if formal is not None and state is not None and call is not None:
            for actual, bound_formal in bind_call_arguments(
                call, callee.code.codeparameters
            ):
                if bound_formal is formal:
                    outputs.update(
                        self._facts_for_actual_slots(call_node.procedure, actual, state)
                    )

        return tuple(outputs)

    def call_to_return_flow(self, call_node: CFGNode, return_site: CFGNode, fact: object):
        del return_site
        call_effect = self._call_effect(call_node)
        operation = (
            call_effect.operation
            if call_effect is not None
            else self.adapter.operation_of(call_node)
        )
        call_expression = call_effect.call_expression if call_effect is not None else None
        killed = self._killed_slots_for_node(call_node)
        outputs = set(self._identity_outputs(fact, killed))
        model = self._call_model_for_node(call_node)

        if (
            fact == ZERO_TYPESTATE
            and model is not None
            and STATE_OPEN in model.typestate_actions
        ):
            outputs.update(
                self._facts_for_nested_call_result(
                    call_node.procedure,
                    operation,
                    call_expression,
                    0,
                    STATE_OPEN,
                    nested=False,
                )
            )
            return tuple(outputs)

        state = self._fact_state(fact)
        if state is None or call_expression is None:
            return tuple(outputs)

        resource_slots = self._resource_slots_for_call(
            call_node.procedure,
            call_expression,
            model=model,
        )
        if not resource_slots:
            return tuple(outputs)

        if (
            model is not None
            and STATE_CLOSE in model.typestate_actions
            and state == STATE_OPEN
        ):
            if isinstance(fact, ResourceStateFact) and fact.slot in resource_slots:
                outputs.discard(fact)
                outputs.add(ResourceStateFact(fact.slot, STATE_CLOSED))

        return tuple(outputs)

    def findings(self, result) -> tuple[TypestateFinding, ...]:
        findings: list[TypestateFinding] = []
        seen: set[tuple[CFGNode, str, str, str]] = set()

        def record(
            node: CFGNode, kind: str, operation_name: str, resource_label: str
        ) -> None:
            key = (node, kind, operation_name, resource_label)
            if key in seen:
                return
            seen.add(key)
            findings.append(
                TypestateFinding(
                    node=node,
                    kind=kind,
                    operation_name=operation_name,
                    resource_label=resource_label,
                )
            )

        for node in self.adapter.supergraph.nodes():
            call_effect = self._call_effect(node)
            call = call_effect.call_expression if call_effect is not None else None
            if call is None:
                continue
            model = self._call_model_for_node(node)
            call_name = (
                call_effect.call_name
                if call_effect is not None
                else self._call_name(node)
            ) or "<call>"
            slots = self._resource_slots_for_call(node.procedure, call, model=model)
            if model is not None and STATE_USE in model.typestate_actions:
                for slot in slots:
                    if result.is_reached(node, ResourceStateFact(slot, STATE_CLOSED)):
                        record(
                            node,
                            "use_after_close",
                            call_name,
                            self.describe_slot(slot),
                        )
            if model is not None and STATE_CLOSE in model.typestate_actions:
                for slot in slots:
                    if result.is_reached(node, ResourceStateFact(slot, STATE_CLOSED)):
                        record(node, "double_close", call_name, self.describe_slot(slot))

        for procedure in self.adapter.supergraph.procedures():
            for exit_node in self.adapter.supergraph.exits_of(procedure):
                for fact in result.facts_at(exit_node):
                    if isinstance(fact, ResourceStateFact) and fact.state == STATE_OPEN:
                        record(
                            exit_node,
                            "resource_leak",
                            getattr(procedure.code, "name", "<proc>"),
                            self.describe_slot(fact.slot),
                        )

        return tuple(findings)

    def _local_call_outputs(self, node: CFGNode, fact: object):
        call_effect = self._call_effect(node)
        if call_effect is None or call_effect.callees:
            return None

        call_expression = call_effect.call_expression
        operation = call_effect.operation
        killed = self._killed_slots_for_node(node)
        outputs = set(self._identity_outputs(fact, killed))
        model = self._call_model_for_node(node)

        if fact == ZERO_TYPESTATE and model is not None and STATE_OPEN in model.typestate_actions:
            outputs.update(
                self._facts_for_nested_call_result(
                    node.procedure,
                    operation,
                    call_expression,
                    0,
                    STATE_OPEN,
                    nested=False,
                )
            )
            return tuple(outputs)

        state = self._fact_state(fact)
        if state is None:
            return tuple(outputs)

        resource_slots = self._resource_slots_for_call(
            node.procedure,
            call_expression,
            model=model,
        )
        if (
            model is not None
            and STATE_CLOSE in model.typestate_actions
            and isinstance(fact, ResourceStateFact)
        ):
            if state == STATE_OPEN and fact.slot in resource_slots:
                outputs.discard(fact)
                outputs.add(ResourceStateFact(fact.slot, STATE_CLOSED))

        return tuple(outputs)

    def _make_slot_fact(self, slot: object) -> object:
        return ResourceStateFact(slot, STATE_OPEN)

    def _make_expression_fact(
        self,
        procedure: cfg_graph.Code,
        expression: py_ast.PythonASTNode,
        result_index: int = 0,
    ) -> object:
        return ExpressionResourceFact(procedure, expression, STATE_OPEN, result_index)

    def _slot_from_fact(self, fact: object) -> object | None:
        if isinstance(fact, ResourceStateFact):
            return fact.slot
        return None

    def _expression_fact_result(self, fact: object):
        if isinstance(fact, ExpressionResourceFact):
            return (fact.procedure, fact.expression, fact.state, fact.result_index)
        return None

    def _fact_state(self, fact: object) -> str | None:
        if isinstance(fact, ResourceStateFact):
            return fact.state
        if isinstance(fact, ExpressionResourceFact):
            return fact.state
        return None

    def _identity_outputs(self, fact: object, killed: Sequence[object]):
        if fact == ZERO_TYPESTATE:
            return (ZERO_TYPESTATE,)
        if isinstance(fact, ResourceStateFact) and any(fact.slot == target for target in killed):
            return ()
        return (fact,)

    def _killed_slots_for_operation(
        self, procedure: cfg_graph.Code, operation: object
    ) -> tuple[object, ...]:
        if operation is None:
            return ()
        if isinstance(operation, (py_ast.Assign, py_ast.UnpackSequence, py_ast.AnnAssign)):
            return tuple(
                slot
                for local in assigned_locals(operation)
                for slot in self._slots_for_local(procedure, local)
            )
        if isinstance(operation, py_ast.Delete):
            return tuple(slot for slot in self._slots_for_local(procedure, operation.lcl))
        if isinstance(operation, py_ast.InputBlock):
            locals_ = []
            for input_ in getattr(operation, "inputs", ()):
                lcl = getattr(input_, "lcl", None)
                if isinstance(lcl, py_ast.Local):
                    locals_.append(lcl)
            return tuple(
                slot for local in locals_ for slot in self._slots_for_local(procedure, local)
            )
        if isinstance(
            operation,
            (py_ast.SetGlobal, py_ast.DeleteGlobal, py_ast.SetCellDeref),
        ):
            return tuple(
                slot
                for fact in self._facts_for_modified_operation(operation, STATE_OPEN)
                for slot in (self._slot_from_fact(fact),)
                if slot is not None
            )
        return ()

    def _killed_slots_for_call_expression(
        self,
        procedure: cfg_graph.Code,
        operation: object,
        call_expression: py_ast.PythonASTNode | None,
    ) -> tuple[object, ...]:
        if operation is None or call_expression is None:
            return ()
        if (
            isinstance(operation, (py_ast.Assign, py_ast.UnpackSequence))
            and operation.expr is call_expression
        ):
            return tuple(
                slot
                for local in assigned_locals(operation)
                for slot in self._slots_for_local(procedure, local)
            )
        if isinstance(operation, py_ast.AnnAssign) and operation.value is call_expression:
            return tuple(
                slot
                for local in assigned_locals(operation)
                for slot in self._slots_for_local(procedure, local)
            )
        if (
            isinstance(operation, (py_ast.SetGlobal, py_ast.SetCellDeref))
            and operation.value is call_expression
        ):
            return tuple(
                slot
                for fact in self._facts_for_modified_operation(operation, STATE_OPEN)
                for slot in (self._slot_from_fact(fact),)
                if slot is not None
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

    def _facts_for_locals(
        self,
        procedure: cfg_graph.Code,
        locals_: Sequence[object] | tuple[object, ...],
        state: str,
    ) -> set[object]:
        facts: set[object] = set()
        for local in locals_:
            if not isinstance(local, py_ast.Local) or local.name is None:
                continue
            slots = self._slots_for_local(procedure, local)
            facts.update(ResourceStateFact(slot, state) for slot in slots)
        return facts

    def _facts_for_assigned_locals(
        self,
        procedure: cfg_graph.Code,
        locals_: Sequence[object],
        state: str,
        result_index: int,
    ) -> set[object]:
        if result_index >= len(locals_):
            return set()
        return self._facts_for_locals(procedure, (locals_[result_index],), state)

    def _facts_for_return_slot(
        self, procedure: cfg_graph.Code, state: str, index: int
    ) -> set[object]:
        returnparams = tuple(procedure.code.codeparameters.returnparams)
        if index >= len(returnparams):
            return set()
        return self._facts_for_locals(procedure, (returnparams[index],), state)

    def _facts_for_modified_operation(
        self, operation: object, state: str
    ) -> set[object]:
        slots = self._annotation_slots(
            getattr(getattr(operation, "annotation", None), "opModifies", None)
        )
        return {ResourceStateFact(slot, state) for slot in slots}

    def _facts_for_expression_node(
        self, procedure: cfg_graph.Code, current: object, state: str | None = None
    ) -> tuple[object, ...]:
        if state is None:
            state = STATE_OPEN
        if current is None or isinstance(current, py_ast.leafTypes):
            return ()
        if isinstance(current, (py_ast.DirectCall, py_ast.Call, py_ast.MethodCall)):
            dynamic_facts = tuple(
                ResourceStateFact(slot, state)
                for slot in (
                    *self._dynamic_getattr_slots(procedure, current),
                    *self._dynamic_subscript_read_slots(procedure, current),
                    *self._collection_access_slots(
                        procedure,
                        current,
                        self._collection_accessor_names(),
                    ),
                )
            )
            return (*dynamic_facts, ExpressionResourceFact(procedure, current, state))
        return tuple(
            ResourceStateFact(slot, state)
            for slot in self._slots_read_by_node(procedure, current)
        )

    def _facts_for_nested_call_result(
        self,
        procedure: cfg_graph.Code,
        operation: object,
        call_expression: py_ast.PythonASTNode | None,
        return_index: int,
        state: str,
        *,
        nested: bool,
    ) -> set[object]:
        if operation is None or call_expression is None:
            return set()

        if (
            isinstance(operation, (py_ast.Assign, py_ast.UnpackSequence))
            and operation.expr is call_expression
        ):
            if not nested:
                return {
                    ExpressionResourceFact(
                        procedure, call_expression, state, return_index
                    )
                }
            return self._facts_for_assigned_locals(
                procedure,
                assigned_locals(operation),
                state,
                return_index,
            )
        if isinstance(operation, py_ast.AnnAssign) and operation.value is call_expression:
            if not nested:
                return {
                    ExpressionResourceFact(
                        procedure, call_expression, state, return_index
                    )
                }
            return self._facts_for_assigned_locals(
                procedure,
                assigned_locals(operation),
                state,
                return_index,
            )

        if isinstance(operation, py_ast.Return):
            if not nested:
                return {
                    ExpressionResourceFact(
                        procedure, call_expression, state, return_index
                    )
                }
            target_index = self._call_result_target_index(
                operation, call_expression, return_index
            )
            if target_index is not None:
                return self._facts_for_return_slot(procedure, state, target_index)

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
                return {
                    ExpressionResourceFact(
                        procedure, call_expression, state, return_index
                    )
                }
            return self._facts_for_modified_operation(operation, state)

        for child in self._nested_operations(operation):
            child_result = self._facts_for_nested_call_result(
                procedure,
                child,
                call_expression,
                return_index,
                state,
                nested=True,
            )
            if child_result:
                return child_result

        return {ExpressionResourceFact(procedure, call_expression, state, return_index)}

    def _return_fact_index(self, procedure: cfg_graph.Code, fact: object) -> int | None:
        slot = self._slot_from_fact(fact)
        if slot is None:
            return None
        for index, local in enumerate(procedure.code.codeparameters.returnparams):
            if any(candidate == slot for candidate in self._slots_for_local(procedure, local)):
                return index
        return None

    def _expr_has_state(self, procedure: cfg_graph.Code, expr: object, fact: object) -> bool:
        state = self._fact_state(fact)
        if state is None:
            return False
        return self._expression_matches(
            expr,
            lambda current: any(
                candidate == fact
                for candidate in self._facts_for_expression_node(procedure, current, state)
            ),
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

    def _formal_for_fact(
        self, procedure: cfg_graph.Code, fact: object
    ) -> py_ast.Local | None:
        slot = self._slot_from_fact(fact)
        if slot is None:
            return None
        params = procedure.code.codeparameters
        candidates = []
        if isinstance(params.selfparam, py_ast.Local):
            candidates.append(params.selfparam)
        candidates.extend(
            param for param in params.posonlyparams if isinstance(param, py_ast.Local)
        )
        candidates.extend(param for param in params.params if isinstance(param, py_ast.Local))
        candidates.extend(
            param for param in (params.vparam, params.kparam) if isinstance(param, py_ast.Local)
        )
        for local in candidates:
            if any(
                candidate == slot for candidate in self._slots_for_local(procedure, local)
            ):
                return local
        return None

    def _facts_for_actual_slots(
        self, procedure: cfg_graph.Code, expr: object, state: str
    ) -> set[object]:
        return {
            ResourceStateFact(slot, state)
            for fact in self._facts_for_expression_node(procedure, expr, state)
            for slot in (self._slot_from_fact(fact),)
            if slot is not None
        }

    def _resource_slots_for_call(
        self,
        procedure: cfg_graph.Code,
        call: py_ast.PythonASTNode,
        *,
        model=None,
    ) -> tuple[object, ...]:
        resources: list[object] = []
        seen: set[object] = set()

        def extend_slots(expr: object) -> None:
            for fact in self._facts_for_expression_node(procedure, expr, STATE_OPEN):
                slot = self._slot_from_fact(fact)
                if slot is None:
                    continue
                if slot in seen:
                    continue
                seen.add(slot)
                resources.append(slot)

        track_method_receiver = (
            model.track_method_receiver
            if model is not None
            else self.configuration.track_method_receiver
        )
        resource_arg_positions = (
            model.resource_arg_positions
            if model is not None
            else self.configuration.resource_arg_positions
        )

        if isinstance(call, py_ast.MethodCall) and track_method_receiver:
            extend_slots(call.expr)
        for index, actual in enumerate(actual_argument_expressions(call)):
            if index in resource_arg_positions:
                extend_slots(actual)
        return tuple(resources)


class InterproceduralTypestateAnalysis:
    """Concrete typestate analysis backed by the IFDS engine."""

    def __init__(
        self,
        adapter: CFGSupergraphAdapter,
        configuration: TypestateConfiguration,
        *,
        entry_nodes: Sequence[CFGNode] | None = None,
        record_traces: bool = False,
    ) -> None:
        self.problem = InterproceduralTypestateProblem(
            adapter,
            configuration,
            entry_nodes=entry_nodes,
        )
        self.record_traces = record_traces

    def solve(self) -> TypestateAnalysisResult:
        result = IFDSSolver(record_traces=self.record_traces).solve(self.problem)
        return TypestateAnalysisResult(result, self.problem.findings(result), self.problem)


def analyze_typestate(
    adapter: CFGSupergraphAdapter,
    configuration: TypestateConfiguration,
    *,
    entry_nodes: Sequence[CFGNode] | None = None,
    record_traces: bool = False,
) -> TypestateAnalysisResult:
    """Convenience entry point for interprocedural typestate analysis."""
    return InterproceduralTypestateAnalysis(
        adapter,
        configuration,
        entry_nodes=entry_nodes,
        record_traces=record_traces,
    ).solve()
