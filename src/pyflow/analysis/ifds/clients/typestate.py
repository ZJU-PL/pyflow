"""Practical resource typestate analysis over CFG-backed IFDS supergraphs."""

from __future__ import annotations

from dataclasses import dataclass
from typing import FrozenSet, Mapping, Sequence

from pyflow.analysis.cfg import graph as cfg_graph
from pyflow.language.python import ast as py_ast

from ._call_model import (
    CallModelRegistry,
    STATE_CLOSE,
    STATE_OPEN as ACTION_OPEN,
    STATE_USE,
)
from ._client_common import AnnotatedFactProblemBase, build_entry_seeds
from .typestate_engine import (
    TypestateEngine,
    TypestateProtocol,
    built_in_python_protocols,
    resource_lifecycle_protocol,
)
from ..cfg_adapter import CFGNode, CFGSupergraphAdapter, assigned_locals
from ..problem import IFDSProblem
from ..solver import IFDSSolver, SolverOptions
from ..transfers import actual_argument_expressions

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
    enabled_protocols: FrozenSet[str] = frozenset({"resource"})
    extra_protocols: tuple[TypestateProtocol, ...] = ()
    call_models: CallModelRegistry | None = None


@dataclass(frozen=True)
class ResourceStateFact:
    """A resource-bearing location in a given protocol state."""

    location: object
    state: str
    access_path: tuple[str, ...] = ()
    protocol: str = "resource"


@dataclass(frozen=True)
class ExpressionResourceFact:
    """A resource-bearing intermediate expression result."""

    procedure: cfg_graph.Code
    expression: py_ast.PythonASTNode
    state: str
    result_index: int = 0
    access_path: tuple[str, ...] = ()
    protocol: str = "resource"


@dataclass(frozen=True)
class TypestateFinding:
    """Potential resource-protocol issue."""

    node: CFGNode
    kind: str
    operation_name: str
    resource_label: str
    protocol: str = "resource"
    state: str | None = None


class TypestateAnalysisResult:
    """Query wrapper for typestate results."""

    def __init__(
        self, ifds_result, findings: Sequence[TypestateFinding], problem
    ) -> None:
        self._ifds_result = ifds_result
        self.findings = tuple(findings)
        self._problem = problem

    def has_state(self, node: CFGNode, local: py_ast.Local, state: str) -> bool:
        return any(
            self._ifds_result.is_reached(node, ResourceStateFact(location, state))
            for location in self._problem.local_locations(node.procedure, local)
        )

    def states_at(self, node: CFGNode):
        return frozenset(
            self._problem.describe_fact(fact)
            for fact in self._ifds_result.facts_at(node)
            if isinstance(fact, ResourceStateFact)
        )

    def resource_facts_at(self, node: CFGNode):
        return frozenset(
            fact
            for fact in self._ifds_result.facts_at(node)
            if isinstance(fact, ResourceStateFact)
        )

    @property
    def statistics(self):
        return self._ifds_result.statistics

    def explain_fact(self, node: CFGNode, fact: object):
        return self._ifds_result.explain_fact(node, fact)

    def explain_path(self, node: CFGNode, fact: object):
        return self._ifds_result.explain_path(node, fact)

    @property
    def status(self):
        return self._ifds_result.status

    @property
    def termination_reason(self) -> str | None:
        return self._ifds_result.termination_reason

    @property
    def is_complete(self) -> bool:
        return self._ifds_result.is_complete


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
        protocols: list[TypestateProtocol] = []
        if "resource" in configuration.enabled_protocols:
            protocols.append(
                resource_lifecycle_protocol(
                    open_names=configuration.open_names,
                    close_names=configuration.close_names,
                    use_names=configuration.use_names,
                    resource_arg_positions=configuration.resource_arg_positions,
                    track_method_receiver=configuration.track_method_receiver,
                )
            )
        protocols.extend(
            protocol
            for protocol in built_in_python_protocols()
            if protocol.name in configuration.enabled_protocols
        )
        protocols.extend(configuration.extra_protocols)
        self.engine = TypestateEngine(protocols)
        call_models = self.engine.call_model_registry()
        if configuration.call_models is not None:
            call_models = call_models.merged(configuration.call_models)
        super().__init__(
            adapter,
            call_models=call_models,
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
        if node.kind == "call" and self.adapter.is_exceptional_successor(
            node, successor
        ):
            return self._identity_outputs(fact, ())
        local_call_outputs = self._local_call_outputs(node, fact)
        if local_call_outputs is not None:
            return local_call_outputs

        effect = self.adapter.effect_of(node)
        operation = getattr(effect, "operation", self.adapter.operation_of(node))
        if operation is None:
            return self._identity_outputs(fact, ())

        killed = self._killed_locations_for_node(node)
        dynamic_setattr_locations = self._dynamic_setattr_locations(
            node.procedure, operation
        )
        if dynamic_setattr_locations:
            outputs = set(self._identity_outputs(fact, killed))
            value = self._dynamic_setattr_value(operation)
            state = self._fact_state(fact)
            if (
                value is not None
                and state is not None
                and self._expr_has_state(node.procedure, value, fact)
            ):
                outputs.update(
                    self._make_resource_fact(
                        location, state, protocol=self._fact_protocol(fact)
                    )
                    for location in dynamic_setattr_locations
                )
            return tuple(outputs)

        dynamic_subscript_locations = self._dynamic_subscript_write_locations(
            node.procedure, operation
        )
        if dynamic_subscript_locations:
            outputs = set(self._identity_outputs(fact, killed))
            value = self._dynamic_subscript_value(operation)
            state = self._fact_state(fact)
            if (
                value is not None
                and state is not None
                and self._expr_has_state(node.procedure, value, fact)
            ):
                outputs.update(
                    self._facts_for_modified_operation(
                        operation,
                        state,
                        procedure=node.procedure,
                        protocol=self._fact_protocol(fact),
                    )
                )
                outputs.update(
                    self._make_resource_fact(
                        location, state, protocol=self._fact_protocol(fact)
                    )
                    for location in dynamic_subscript_locations
                )
            return tuple(outputs)

        collection_locations, collection_values = self._collection_mutation(
            node.procedure,
            operation,
            self.configuration.collection_mutator_names,
        )
        if collection_locations:
            outputs = set(self._identity_outputs(fact, killed))
            state = self._fact_state(fact)
            copy_locations, copy_source_locations = self._collection_copy_mutation(
                node.procedure,
                operation,
                self.configuration.collection_mutator_names,
            )
            fact_location = self._location_from_fact(fact)
            if (
                state is not None
                and any(
                    self._expr_has_state(node.procedure, value, fact)
                    for value in collection_values
                )
                or (
                    state is not None
                    and fact_location is not None
                    and fact_location in copy_source_locations
                )
            ):
                outputs.update(
                    self._make_resource_fact(
                        location, state, protocol=self._fact_protocol(fact)
                    )
                    for location in collection_locations
                )
                outputs.update(
                    self._make_resource_fact(
                        location, state, protocol=self._fact_protocol(fact)
                    )
                    for location in copy_locations
                )
            return tuple(outputs)

        if isinstance(
            operation, (py_ast.Assign, py_ast.UnpackSequence, py_ast.AnnAssign)
        ):
            outputs = set(self._identity_outputs(fact, killed))
            expr = getattr(operation, "expr", None)
            if isinstance(operation, py_ast.AnnAssign):
                expr = operation.value
            targets = assigned_locals(operation)
            self._update_aliases_for_assignment(node.procedure, targets, expr)

            direct_fact = self._direct_expression_fact(expr, fact)
            if direct_fact is not None:
                _procedure, _expr, state, result_index, protocol = direct_fact
                outputs.update(
                    self._facts_for_assigned_locals(
                        node.procedure,
                        targets,
                        state,
                        result_index,
                        protocol=protocol,
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
                            self._access_path_for_expression(expr),
                            protocol=self._fact_protocol(fact),
                        )
                    )
            state = self._fact_state(fact)
            if state is not None:
                outputs.update(
                    self._make_resource_fact(
                        location, state, protocol=self._fact_protocol(fact)
                    )
                    for location in self._aliased_dynamic_locations_for_assignment(
                        node.procedure,
                        operation,
                        fact,
                    )
                )
                for locations, value in self._collection_constructor_writes(
                    node.procedure,
                    operation,
                ):
                    if self._expr_has_state(node.procedure, value, fact):
                        outputs.update(
                            self._make_resource_fact(
                                location,
                                state,
                                protocol=self._fact_protocol(fact),
                            )
                            for location in locations
                        )
            return tuple(outputs)

        if isinstance(operation, py_ast.Return):
            outputs = set(self._identity_outputs(fact, ()))
            if len(operation.exprs) == 1:
                direct_fact = self._direct_expression_fact(operation.exprs[0], fact)
                if direct_fact is not None:
                    _procedure, _expr, state, result_index, protocol = direct_fact
                    path = self._access_path_from_fact(fact)
                    outputs.update(
                        self._facts_for_return_location(
                            node.procedure,
                            state,
                            result_index,
                            access_path=path,
                            protocol=protocol,
                        )
                    )
                    return tuple(outputs)
            state = self._fact_state(fact)
            if state is None:
                return tuple(outputs)
            for index, expr in enumerate(operation.exprs):
                if self._expr_has_state(node.procedure, expr, fact):
                    path = self._access_path_for_expression(expr)
                    outputs.update(
                        self._facts_for_return_location(
                            node.procedure,
                            state,
                            index,
                            access_path=path,
                            protocol=self._fact_protocol(fact),
                        )
                    )
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
                path = self._access_path_for_expression(value)
                outputs.update(
                    self._facts_for_modified_operation(
                        operation,
                        state,
                        access_path=path,
                        procedure=node.procedure,
                        protocol=self._fact_protocol(fact),
                    )
                )
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

        self._bind_callee_formals(call_node, callee)
        for actual, formal in self._bind_call_arguments_for_callee(call_node, callee):
            if self._expr_has_state(call_node.procedure, actual, fact):
                path = self._access_path_for_expression(actual)
                outputs.update(
                    self._facts_for_locals(
                        callee,
                        (formal,),
                        state,
                        path,
                        protocol=self._fact_protocol(fact),
                    )
                )

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
                    protocol=self._fact_protocol(exit_fact),
                )
            )

        formal = self._formal_for_fact(callee, exit_fact)
        call = call_effect.call_expression if call_effect is not None else None
        if formal is not None and state is not None and call is not None:
            for actual, bound_formal in self._bind_call_arguments_for_callee(
                call_node,
                callee,
            ):
                if bound_formal is formal:
                    outputs.update(
                        self._facts_for_actual_locations(
                            call_node.procedure,
                            actual,
                            state,
                            protocol=self._fact_protocol(exit_fact),
                        )
                    )
        projected = self._project_constructor_heap_fact_to_caller(call_node, exit_fact)
        if projected is not None:
            outputs.add(projected)

        return tuple(outputs)

    def call_to_return_flow(
        self, call_node: CFGNode, return_site: CFGNode, fact: object
    ):
        del return_site
        call_effect = self._call_effect(call_node)
        operation = (
            call_effect.operation
            if call_effect is not None
            else self.adapter.operation_of(call_node)
        )
        call_expression = (
            call_effect.call_expression if call_effect is not None else None
        )
        self._mark_unresolved_call_arguments_escaped(call_node, call_expression)
        self._materialize_unresolved_call_summary(
            call_node,
            operation,
            call_expression,
        )
        killed = self._killed_locations_for_node(call_node, include_semantic=False)
        outputs = set(self._identity_outputs(fact, killed))
        model = self._call_model_for_node(call_node)

        if fact == ZERO_TYPESTATE:
            for action in self._actions_for_call(call_node, model):
                initial_state = self.engine.initial_state_for_action(action)
                protocol = self.engine.protocol_name_for_action(action)
                if initial_state is None or protocol is None:
                    continue
                outputs.update(
                    self._facts_for_nested_call_result(
                        call_node.procedure,
                        operation,
                        call_expression,
                        0,
                        initial_state,
                        nested=False,
                        protocol=protocol,
                    )
                )
            return tuple(outputs)

        state = self._fact_state(fact)
        if state is None or call_expression is None:
            return tuple(outputs)

        resource_locations = self._resource_locations_for_call(
            call_node.procedure,
            call_expression,
            model=model,
        )
        if not resource_locations:
            return tuple(outputs)

        for action in self._actions_for_call(call_node, model, fact=fact):
            transition = self.engine.transition(action, state)
            if transition is not None and transition.to_state is not None:
                if (
                    isinstance(fact, ResourceStateFact)
                    and fact.location in resource_locations
                ):
                    outputs.discard(fact)
                    outputs.add(
                        self._make_resource_fact(
                            fact.location,
                            transition.to_state,
                            access_path=self._access_path_from_fact(fact),
                            protocol=fact.protocol,
                        )
                    )

        return tuple(outputs)

    def findings(self, result) -> tuple[TypestateFinding, ...]:
        findings: list[TypestateFinding] = []
        seen: set[tuple[CFGNode, str, str, str]] = set()

        def record(
            node: CFGNode,
            kind: str,
            operation_name: str,
            resource_label: str,
            *,
            protocol: str = "resource",
            state: str | None = None,
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
                    protocol=protocol,
                    state=state,
                )
            )

        for node in self.adapter.supergraph.ordered_nodes():
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
            locations = self._resource_locations_for_call(
                node.procedure, call, model=model
            )
            for action in self._actions_for_call(node, model):
                protocol = self.engine.protocol_name_for_action(action)
                if protocol is None:
                    continue
                for location in locations:
                    for fact in result.facts_at(node):
                        if not isinstance(fact, ResourceStateFact):
                            continue
                        if fact.location != location or fact.protocol != protocol:
                            continue
                        if not self._model_matches_call_site(model, node, fact=fact):
                            continue
                        for violation in self.engine.violations_for(action, fact.state):
                            record(
                                node,
                                violation.kind,
                                call_name,
                                self.describe_location(location),
                                protocol=protocol,
                                state=fact.state,
                            )

        for procedure in self.adapter.supergraph.ordered_procedures():
            for exit_node in self.adapter.supergraph.ordered_exits_of(procedure):
                for fact in result.facts_at(exit_node):
                    if not isinstance(fact, ResourceStateFact):
                        continue
                    for obligation in self.engine.exit_violations_for(
                        fact.protocol, fact.state
                    ):
                        if (
                            obligation.suppress_when_escaped
                            and self._fact_transfers_ownership(procedure, fact)
                        ):
                            continue
                        record(
                            exit_node,
                            obligation.kind,
                            getattr(procedure.code, "name", "<proc>"),
                            self.describe_location(fact.location),
                            protocol=fact.protocol,
                            state=fact.state,
                        )

        return tuple(findings)

    def _local_call_outputs(self, node: CFGNode, fact: object):
        call_effect = self._call_effect(node)
        if call_effect is None or call_effect.callees:
            return None

        call_expression = call_effect.call_expression
        operation = call_effect.operation
        killed = self._killed_locations_for_node(node)
        outputs = set(self._identity_outputs(fact, killed))
        model = self._call_model_for_node(node)

        self._mark_unresolved_call_arguments_escaped(node, call_expression)

        if fact == ZERO_TYPESTATE:
            for action in self._actions_for_call(node, model):
                initial_state = self.engine.initial_state_for_action(action)
                protocol = self.engine.protocol_name_for_action(action)
                if initial_state is None or protocol is None:
                    continue
                outputs.update(
                    self._facts_for_nested_call_result(
                        node.procedure,
                        operation,
                        call_expression,
                        0,
                        initial_state,
                        nested=False,
                        protocol=protocol,
                    )
                )
            return tuple(outputs)

        state = self._fact_state(fact)
        if state is None:
            return tuple(outputs)

        resource_locations = self._resource_locations_for_call(
            node.procedure,
            call_expression,
            model=model,
        )
        for action in self._actions_for_call(node, model, fact=fact):
            transition = self.engine.transition(action, state)
            if (
                transition is not None
                and transition.to_state is not None
                and isinstance(fact, ResourceStateFact)
            ):
                if fact.location in resource_locations:
                    outputs.discard(fact)
                    outputs.add(
                        self._make_resource_fact(
                            fact.location,
                            transition.to_state,
                            access_path=self._access_path_from_fact(fact),
                            protocol=fact.protocol,
                        )
                    )

        return tuple(outputs)

    def _make_location_fact(self, location: object) -> object:
        return ResourceStateFact(location, STATE_OPEN)

    def _make_location_fact_with_path(
        self, location: object, access_path: tuple[str, ...]
    ) -> object:
        return ResourceStateFact(location, STATE_OPEN, access_path=access_path)

    def _make_expression_fact(
        self,
        procedure: cfg_graph.Code,
        expression: py_ast.PythonASTNode,
        result_index: int = 0,
    ) -> object:
        return ExpressionResourceFact(procedure, expression, STATE_OPEN, result_index)

    def _make_resource_fact(
        self,
        location: object,
        state: str,
        *,
        access_path: tuple[str, ...] = (),
        protocol: str = "resource",
    ) -> ResourceStateFact:
        return ResourceStateFact(location, state, access_path, protocol)

    def _make_expression_state_fact(
        self,
        procedure: cfg_graph.Code,
        expression: py_ast.PythonASTNode,
        state: str,
        *,
        result_index: int = 0,
        access_path: tuple[str, ...] = (),
        protocol: str = "resource",
    ) -> ExpressionResourceFact:
        return ExpressionResourceFact(
            procedure,
            expression,
            state,
            result_index,
            access_path,
            protocol,
        )

    def _location_from_fact(self, fact: object) -> object | None:
        if isinstance(fact, ResourceStateFact):
            return fact.location
        return None

    def _expression_fact_result(self, fact: object):
        if isinstance(fact, ExpressionResourceFact):
            return (
                fact.procedure,
                fact.expression,
                fact.state,
                fact.result_index,
                fact.protocol,
            )
        return None

    def _fact_state(self, fact: object) -> str | None:
        if isinstance(fact, ResourceStateFact):
            return fact.state
        if isinstance(fact, ExpressionResourceFact):
            return fact.state
        return None

    def _fact_protocol(self, fact: object) -> str:
        if isinstance(fact, (ResourceStateFact, ExpressionResourceFact)):
            return fact.protocol
        return "resource"

    def _actions_from_model(self, model) -> tuple[str, ...]:
        if model is None or not model.typestate_actions:
            return ()
        return tuple(sorted(model.typestate_actions))

    def _actions_for_call(
        self,
        node: CFGNode,
        model,
        *,
        fact: object | None = None,
    ) -> tuple[str, ...]:
        if not self._model_matches_call_site(model, node, fact=fact):
            return ()
        return tuple(
            action
            for action in self._actions_from_model(model)
            if fact is None or self._action_matches_fact(action, fact)
        )

    def _action_matches_fact(self, action: str, fact: object) -> bool:
        protocol = self.engine.protocol_name_for_action(action)
        return protocol is not None and protocol == self._fact_protocol(fact)

    def _model_matches_call_site(
        self,
        model,
        node: CFGNode,
        *,
        fact: object | None = None,
    ) -> bool:
        if model is None:
            return False
        effect = self._call_effect(node)
        callee_names = self._callee_names_for_node(node)
        if model.callee_qualnames:
            if not any(
                self._name_matches_constraint(callee, constraint)
                for callee in callee_names
                for constraint in model.callee_qualnames
            ):
                return False
        if model.module_prefixes:
            if not any(
                callee == prefix or callee.startswith(f"{prefix}.")
                for callee in callee_names
                for prefix in model.module_prefixes
            ):
                return False
        if model.receiver_types:
            if fact is not None:
                return self._fact_matches_receiver_types(fact, model.receiver_types)
            call = effect.call_expression if effect is not None else None
            if getattr(call, "expr", None) is None:
                return True
            return self._call_receiver_matches_types(
                node.procedure,
                call,
                model.receiver_types,
            )
        return True

    def _callee_names_for_node(self, node: CFGNode) -> tuple[str, ...]:
        names: list[str] = []
        effect = self._call_effect(node)
        if effect is not None and effect.call_name is not None:
            names.append(effect.call_name)
        for callee in self.adapter.callees_of(node):
            code = getattr(callee, "code", None)
            if code is None:
                continue
            code_name = getattr(code, "codeName", None)
            if callable(code_name):
                try:
                    name = code_name()
                except Exception:
                    name = None
                if isinstance(name, str):
                    names.append(name)
        return tuple(dict.fromkeys(names))

    def _name_matches_constraint(self, name: str, constraint: str) -> bool:
        return name == constraint or name.endswith(f".{constraint}")

    def _fact_matches_receiver_types(
        self, fact: object, receiver_types: frozenset[str]
    ) -> bool:
        location = self._location_from_fact(fact)
        if location is None:
            return False
        return self._location_matches_receiver_types(location, receiver_types)

    def _call_receiver_matches_types(
        self,
        procedure: cfg_graph.Code,
        call: object,
        receiver_types: frozenset[str],
    ) -> bool:
        receiver = getattr(call, "expr", None)
        if receiver is None:
            return False
        return any(
            self._location_matches_receiver_types(candidate.location, receiver_types)
            for candidate in self._facts_for_expression_node(procedure, receiver)
            if isinstance(candidate, ResourceStateFact)
        )

    def _location_matches_receiver_types(
        self, location: object, receiver_types: frozenset[str]
    ) -> bool:
        locations = [location]
        try:
            locations.extend(self._heap().to_points_to_graph().points_to(location))
        except Exception:
            pass
        candidates: set[str] = set()
        for candidate_location in locations:
            root = getattr(candidate_location, "root", candidate_location)
            type_hint = getattr(root, "type_hint", None)
            label = self.describe_location(candidate_location)
            candidates.update(
                value
                for value in (
                    type_hint,
                    getattr(root, "label", None),
                    label,
                    label.removesuffix("()") if isinstance(label, str) else None,
                )
                if isinstance(value, str)
            )
        return any(
            candidate == receiver_type
            or candidate.endswith(f".{receiver_type}")
            or receiver_type.endswith(f".{candidate}")
            for candidate in candidates
            for receiver_type in receiver_types
        )

    def describe_fact(self, fact: object) -> str:
        if isinstance(fact, ResourceStateFact):
            return self.describe_location(fact.location)
        if isinstance(fact, ExpressionResourceFact):
            return self.describe_expression(fact.expression)
        return "<expr>"

    def _location_escaped(self, location: object) -> bool:
        graph = self._heap().to_points_to_graph()
        try:
            if graph.is_escaped(location):
                return True
            return any(graph.is_escaped(alias) for alias in graph.points_to(location))
        except Exception:
            return False

    def _fact_transfers_ownership(
        self, procedure: cfg_graph.Code, fact: ResourceStateFact
    ) -> bool:
        if self._location_escaped(fact.location):
            return True
        return self._return_fact_index(procedure, fact) is not None

    def _identity_outputs(self, fact: object, killed: Sequence[object]):
        if fact == ZERO_TYPESTATE:
            return (ZERO_TYPESTATE,)
        if isinstance(fact, ResourceStateFact) and any(
            fact.location == target for target in killed
        ):
            return ()
        return (fact,)

    def _killed_locations_for_operation(
        self, procedure: cfg_graph.Code, operation: object
    ) -> tuple[object, ...]:
        if operation is None:
            return ()
        if isinstance(
            operation, (py_ast.Assign, py_ast.UnpackSequence, py_ast.AnnAssign)
        ):
            return tuple(
                location
                for local in assigned_locals(operation)
                for location in self._locations_for_local(procedure, local)
            )
        if isinstance(operation, py_ast.Delete):
            return tuple(
                location
                for location in self._locations_for_local(procedure, operation.lcl)
            )
        if isinstance(operation, py_ast.InputBlock):
            locals_ = []
            for input_ in getattr(operation, "inputs", ()):
                lcl = getattr(input_, "lcl", None)
                if isinstance(lcl, py_ast.Local):
                    locals_.append(lcl)
            return tuple(
                location
                for local in locals_
                for location in self._locations_for_local(procedure, local)
            )
        if isinstance(
            operation,
            (py_ast.SetGlobal, py_ast.DeleteGlobal, py_ast.SetCellDeref),
        ):
            return tuple(
                location
                for fact in self._facts_for_modified_operation(
                    operation,
                    STATE_OPEN,
                    procedure=procedure,
                )
                for location in (self._location_from_fact(fact),)
                if location is not None
            )
        return ()

    def _killed_locations_for_call_expression(
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
                location
                for local in assigned_locals(operation)
                for location in self._locations_for_local(procedure, local)
            )
        if (
            isinstance(operation, py_ast.AnnAssign)
            and operation.value is call_expression
        ):
            return tuple(
                location
                for local in assigned_locals(operation)
                for location in self._locations_for_local(procedure, local)
            )
        if (
            isinstance(operation, (py_ast.SetGlobal, py_ast.SetCellDeref))
            and operation.value is call_expression
        ):
            return tuple(
                location
                for fact in self._facts_for_modified_operation(
                    operation,
                    STATE_OPEN,
                    procedure=procedure,
                )
                for location in (self._location_from_fact(fact),)
                if location is not None
            )
        for child in self._nested_operations(operation):
            child_kills = self._killed_locations_for_call_expression(
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
        access_path: tuple[str, ...] = (),
        *,
        protocol: str = "resource",
    ) -> set[object]:
        facts: set[object] = set()
        for local in locals_:
            if not isinstance(local, py_ast.Local) or local.name is None:
                continue
            locations = self._locations_for_local(procedure, local)
            facts.update(
                self._make_resource_fact(
                    location, state, access_path=access_path, protocol=protocol
                )
                for location in locations
            )
        return facts

    def _facts_for_assigned_locals(
        self,
        procedure: cfg_graph.Code,
        locals_: Sequence[object],
        state: str,
        result_index: int,
        *,
        protocol: str = "resource",
    ) -> set[object]:
        if result_index >= len(locals_):
            return set()
        return self._facts_for_locals(
            procedure,
            (locals_[result_index],),
            state,
            protocol=protocol,
        )

    def _facts_for_return_location(
        self,
        procedure: cfg_graph.Code,
        state: str,
        index: int,
        access_path: tuple[str, ...] = (),
        *,
        protocol: str = "resource",
    ) -> set[object]:
        returnparams = tuple(procedure.code.codeparameters.returnparams)
        if index >= len(returnparams):
            return set()
        return self._facts_for_locals(
            procedure,
            (returnparams[index],),
            state,
            access_path,
            protocol=protocol,
        )

    def _facts_for_modified_operation(
        self,
        operation: object,
        state: str,
        access_path: tuple[str, ...] = (),
        *,
        procedure: cfg_graph.Code | None = None,
        protocol: str = "resource",
    ) -> set[object]:
        locations = tuple(
            dict.fromkeys(
                (
                    *self._annotation_locations(
                        getattr(
                            getattr(operation, "annotation", None), "opModifies", None
                        )
                    ),
                    *self._static_attribute_write_locations(procedure, operation),
                )
            )
        )
        return {
            self._make_resource_fact(
                location, state, access_path=access_path, protocol=protocol
            )
            for location in locations
        }

    def _facts_for_expression_node(
        self,
        procedure: cfg_graph.Code,
        current: object,
        state: str | None = None,
        protocol: str = "resource",
    ) -> tuple[object, ...]:
        if state is None:
            state = STATE_OPEN
        if current is None or isinstance(current, py_ast.leafTypes):
            return ()
        if isinstance(current, (py_ast.DirectCall, py_ast.Call, py_ast.MethodCall)):
            dynamic_facts = tuple(
                self._make_resource_fact(location, state, protocol=protocol)
                for location in (
                    *self._dynamic_getattr_locations(procedure, current),
                    *self._dynamic_subscript_read_locations(procedure, current),
                    *self._collection_access_locations(
                        procedure,
                        current,
                        self._collection_accessor_names(),
                    ),
                )
            )
            return (
                *dynamic_facts,
                self._make_expression_state_fact(
                    procedure, current, state, protocol=protocol
                ),
            )
        return tuple(
            self._make_resource_fact(location, state, protocol=protocol)
            for location in self._locations_read_by_node(procedure, current)
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
        protocol: str = "resource",
    ) -> set[object]:
        if operation is None or call_expression is None:
            return set()
        self._materialize_call_result_location(
            procedure,
            operation,
            call_expression,
            return_index,
        )

        if (
            isinstance(operation, (py_ast.Assign, py_ast.UnpackSequence))
            and operation.expr is call_expression
        ):
            if not nested:
                facts = {
                    self._make_expression_state_fact(
                        procedure,
                        call_expression,
                        state,
                        result_index=return_index,
                        protocol=protocol,
                    )
                }
                if self._heap().policy.bind_call_results:
                    facts.update(
                        self._facts_for_assigned_locals(
                            procedure,
                            assigned_locals(operation),
                            state,
                            return_index,
                            protocol=protocol,
                        )
                    )
                return facts
            return self._facts_for_assigned_locals(
                procedure,
                assigned_locals(operation),
                state,
                return_index,
                protocol=protocol,
            )
        if (
            isinstance(operation, py_ast.AnnAssign)
            and operation.value is call_expression
        ):
            if not nested:
                facts = {
                    self._make_expression_state_fact(
                        procedure,
                        call_expression,
                        state,
                        result_index=return_index,
                        protocol=protocol,
                    )
                }
                if self._heap().policy.bind_call_results:
                    facts.update(
                        self._facts_for_assigned_locals(
                            procedure,
                            assigned_locals(operation),
                            state,
                            return_index,
                            protocol=protocol,
                        )
                    )
                return facts
            return self._facts_for_assigned_locals(
                procedure,
                assigned_locals(operation),
                state,
                return_index,
                protocol=protocol,
            )

        if isinstance(operation, py_ast.Return):
            if not nested:
                return {
                    self._make_expression_state_fact(
                        procedure,
                        call_expression,
                        state,
                        result_index=return_index,
                        protocol=protocol,
                    )
                }
            target_index = self._call_result_target_index(
                operation, call_expression, return_index
            )
            if target_index is not None:
                return self._facts_for_return_location(
                    procedure,
                    state,
                    target_index,
                    protocol=protocol,
                )

        if (
            isinstance(
                operation,
                (
                    py_ast.SetAttr,
                    py_ast.SetSubscript,
                    py_ast.SetSlice,
                    py_ast.SetGlobal,
                    py_ast.SetCellDeref,
                    py_ast.Store,
                ),
            )
            and getattr(operation, "value", None) is call_expression
        ):
            if not nested:
                return {
                    self._make_expression_state_fact(
                        procedure,
                        call_expression,
                        state,
                        result_index=return_index,
                        protocol=protocol,
                    )
                }
            return self._facts_for_modified_operation(
                operation,
                state,
                procedure=procedure,
                protocol=protocol,
            )

        for child in self._nested_operations(operation):
            child_result = self._facts_for_nested_call_result(
                procedure,
                child,
                call_expression,
                return_index,
                state,
                nested=True,
                protocol=protocol,
            )
            if child_result:
                return child_result

        return {
            self._make_expression_state_fact(
                procedure,
                call_expression,
                state,
                result_index=return_index,
                protocol=protocol,
            )
        }

    def _return_fact_index(self, procedure: cfg_graph.Code, fact: object) -> int | None:
        location = self._location_from_fact(fact)
        if location is None:
            return None
        for index, local in enumerate(procedure.code.codeparameters.returnparams):
            if any(
                candidate == location
                for candidate in self._locations_for_local(procedure, local)
            ):
                return index
        return None

    def _expr_has_state(
        self, procedure: cfg_graph.Code, expr: object, fact: object
    ) -> bool:
        state = self._fact_state(fact)
        if state is None:
            return False
        return self._expression_matches(
            expr,
            lambda current: any(
                self._fact_prefix_matches(fact, candidate)
                for candidate in self._facts_for_expression_node(
                    procedure,
                    current,
                    state,
                    protocol=self._fact_protocol(fact),
                )
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
        location = self._location_from_fact(fact)
        if location is None:
            return None
        params = procedure.code.codeparameters
        candidates = []
        if isinstance(params.selfparam, py_ast.Local):
            candidates.append(params.selfparam)
        candidates.extend(
            param for param in params.posonlyparams if isinstance(param, py_ast.Local)
        )
        candidates.extend(
            param for param in params.params if isinstance(param, py_ast.Local)
        )
        candidates.extend(
            param
            for param in (params.vparam, params.kparam)
            if isinstance(param, py_ast.Local)
        )
        for local in candidates:
            if any(
                candidate == location
                for candidate in self._locations_for_local(procedure, local)
            ):
                return local
        return None

    def _facts_for_actual_locations(
        self,
        procedure: cfg_graph.Code,
        expr: object,
        state: str,
        *,
        protocol: str = "resource",
    ) -> set[object]:
        return {
            self._make_resource_fact(location, state, protocol=protocol)
            for fact in self._facts_for_expression_node(
                procedure,
                expr,
                state,
                protocol=protocol,
            )
            for location in (self._location_from_fact(fact),)
            if location is not None
        }

    def _resource_locations_for_call(
        self,
        procedure: cfg_graph.Code,
        call: py_ast.PythonASTNode,
        *,
        model=None,
    ) -> tuple[object, ...]:
        resources: list[object] = []
        seen: set[object] = set()

        def extend_locations(expr: object) -> None:
            for fact in self._facts_for_expression_node(procedure, expr, STATE_OPEN):
                location = self._location_from_fact(fact)
                if location is None:
                    continue
                if location in seen:
                    continue
                seen.add(location)
                resources.append(location)

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
            extend_locations(call.expr)
        for index, actual in enumerate(actual_argument_expressions(call)):
            if index in resource_arg_positions:
                extend_locations(actual)
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
        solver_options: SolverOptions | None = None,
    ) -> None:
        self.problem = InterproceduralTypestateProblem(
            adapter,
            configuration,
            entry_nodes=entry_nodes,
        )
        self.record_traces = record_traces
        self.solver_options = solver_options

    def solve(self) -> TypestateAnalysisResult:
        solver = (
            IFDSSolver(options=self.solver_options)
            if self.solver_options is not None
            else IFDSSolver(record_traces=self.record_traces)
        )
        result = solver.solve(self.problem)
        return TypestateAnalysisResult(
            result, self.problem.findings(result), self.problem
        )


def analyze_typestate(
    adapter: CFGSupergraphAdapter,
    configuration: TypestateConfiguration,
    *,
    entry_nodes: Sequence[CFGNode] | None = None,
    record_traces: bool = False,
    solver_options: SolverOptions | None = None,
) -> TypestateAnalysisResult:
    """Convenience entry point for interprocedural typestate analysis."""
    return InterproceduralTypestateAnalysis(
        adapter,
        configuration,
        entry_nodes=entry_nodes,
        record_traces=record_traces,
        solver_options=solver_options,
    ).solve()
