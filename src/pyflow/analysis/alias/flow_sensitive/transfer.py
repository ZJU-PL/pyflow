"""Standalone heap transfer engine.

This module applies operation-level heap effects to :class:`HeapAbstraction`.
It intentionally stays conservative: unresolved calls escape their arguments,
unknown assigned values break precise local aliases, and modeled constructors
or collection literals allocate fresh heap roots.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from pyflow.language.python import ast as py_ast

from .abstraction import HeapAbstraction, HeapEnvironment
from .heap_effects import (
    DEFAULT_HEAP_INTRINSICS,
    DYNAMIC_SUBSCRIPT_WILDCARD,
    HeapEffectBuilder,
)
from .heap_state import HeapState
from .intrinsics import HeapIntrinsicModels
from .model import HeapLocation, UpdatePolicy

@dataclass(frozen=True)
class _CallSummary:
    state: HeapState
    returns: tuple[tuple[HeapLocation, ...], ...]
    environment: HeapEnvironment | None = None
    normal_state: HeapState | None = None
    normal_environment: HeapEnvironment | None = None
    raise_state: HeapState | None = None
    raise_environment: HeapEnvironment | None = None
    deletes: tuple[HeapLocation, ...] = ()
    raises: tuple[HeapLocation, ...] = ()
    yields: tuple[HeapLocation, ...] = ()
    yield_steps: tuple[
        tuple[HeapState, HeapEnvironment, tuple[HeapLocation, ...]], ...
    ] = ()

    # Maps return index -> formal parameter index when the callee directly
    # returns a formal parameter without modification (e.g., "def id(x): return x").
    # The caller can use this to bind the actual argument's location directly.
    param_returns: dict[int, frozenset[int]] = field(default_factory=dict)

    # Set of formal parameter indices whose locations escape the callee.
    # Callers can use this to precisely mark actual arguments as escaped
    # without relying solely on the merged escaped set in summary.state.
    param_escapes: frozenset[int] = field(default_factory=frozenset)

@dataclass(frozen=True)
class _FlowState:
    """Complete flow value: heap contents plus local binding environment."""

    heap_state: HeapState
    environment: HeapEnvironment
    definition_defaults: dict[tuple[int, int], tuple[HeapLocation, ...]]

@dataclass(frozen=True)
class _FlowOutcome:
    """Normal successor plus path-insensitive abrupt control-flow exits."""

    normal: _FlowState | None
    abrupt: dict[str, _FlowState] = field(default_factory=dict)

@dataclass
class _DeferredActivation:
    callee: py_ast.Code
    actual_bindings: dict[int, tuple[HeapLocation, ...]]
    resume_index: int = 0
    summary: _CallSummary | None = None


from ._transfer_ops import _TransferOpsMixin
from ._transfer_calls import _TransferCallsMixin

class HeapTransferEngine(_TransferOpsMixin, _TransferCallsMixin):
    """Apply Python IR operations to a heap abstraction."""

    def __init__(
        self,
        heap: HeapAbstraction,
        *,
        intrinsics: HeapIntrinsicModels = DEFAULT_HEAP_INTRINSICS,
        collection_mutator_names: frozenset[str] | None = None,
        max_loop_iterations: int = 8,
    ) -> None:
        self.heap = heap
        self.intrinsics = intrinsics
        self.collection_mutator_names = (
            collection_mutator_names
            if collection_mutator_names is not None
            else intrinsics.collection_mutator_names()
        )
        self.max_loop_iterations = max_loop_iterations
        self._module_owners: dict[int, object] = {}
        self._class_definitions: dict[tuple[object, str], HeapLocation] = {}
        self._class_initializers: dict[tuple[object, str], py_ast.Code] = {}
        self._initialized_class_calls: set[int] = set()
        self.program_point_states: dict[int, tuple[HeapState, HeapState]] = {}
        self.effect_builder = HeapEffectBuilder(
            heap,
            self.locations_for_expression,
            intrinsics=intrinsics,
            module_owner=self._module_owner,
        )
        self._active_codes: set[int] = set()
        self._summary_in_progress: set[object] = set()
        self._summary_delete_stack: list[list[HeapLocation]] = []
        self._exception_prefix_stack: list[list[_FlowState]] = []
        self._yield_state_stack: list[
            list[tuple[_FlowState, tuple[HeapLocation, ...]]]
        ] = []
        self._resume_input_stack: list[tuple[HeapLocation, ...]] = []
        self._direct_call_evaluation_cache: dict[
            tuple[object, ...], tuple[HeapLocation, ...]
        ] = {}
        self._direct_call_summary_cache: dict[tuple[object, ...], _CallSummary] = {}
        self._last_direct_call_summary: dict[int, _CallSummary] = {}
        self._last_call_operands: dict[
            int, dict[int, tuple[HeapLocation, ...]]
        ] = {}
        self._operation_expression_caches: list[
            dict[int, tuple[HeapLocation, ...]]
        ] = []
        self._operation_call_raises: list[list[_FlowState]] = []
        self._operation_normal_possible: list[bool] = []
        self._pending_call_results: dict[
            int,
            tuple[
                tuple[py_ast.Local, ...],
                tuple[tuple[HeapLocation, ...], ...],
            ],
        ] = {}
        self._deferred_activations: dict[object, _DeferredActivation] = {}
        self._evaluation_epoch = 0
        self._current_context: tuple[object, ...] = ()
        self._definition_default_locations: dict[
            tuple[int, int], tuple[HeapLocation, ...]
        ] = {}
        self._definition_locals: dict[tuple[int, str], py_ast.Local] = {}
        self._lexical_parents: dict[int, object] = {}
        self._global_declarations: dict[int, set[str]] = {}
        self._nonlocal_declarations: dict[int, set[str]] = {}
        self.state = HeapState()

    def analyze_program(self, program: object) -> None:
        """Analyze every discoverable code object in *program*."""
        declared_entries = getattr(program, "entryPoints", None)
        codes = tuple(
            self.iter_code_objects(
                declared_entries if declared_entries else program
            )
        )
        if len(codes) <= 1:
            for code in codes:
                self.analyze_code(code)
            return
        entry = self._capture_flow_state()
        exits: list[_FlowState] = []
        for code in codes:
            self._restore_flow_state(entry)
            self.analyze_code(code)
            exits.append(self._capture_flow_state())
        self._restore_flow_state(self._join_flow_states(tuple(exits)))

    def analyze_code(self, code: object) -> None:
        """Analyze one ``py_ast.Code`` or code-like object."""
        code_id = id(code)
        if code_id in self._active_codes:
            return
        self._active_codes.add(code_id)
        previous_context = self._current_context
        if not previous_context:
            self._current_context = (self._context_token(code),)
        self.bind_parameters(code)
        try:
            outcome = self.analyze_node(code, getattr(code, "ast", None))
            self._restore_flow_state(self._joined_outcome_state(outcome))
            self._propagate_escapes_transitively()
        finally:
            self._current_context = previous_context
            self._active_codes.discard(code_id)

    def analyze_node(self, procedure: object, node: object) -> _FlowOutcome:
        entry_state = self.state.copy()
        outcome = self._analyze_node(procedure, node)
        if node is not None and not isinstance(node, py_ast.leafTypes):
            self.program_point_states[id(node)] = (
                entry_state,
                self._joined_outcome_state(outcome).heap_state.copy(),
            )
        self._position_outcome(outcome)
        return outcome

    def _analyze_node(self, procedure: object, node: object) -> _FlowOutcome:
        if node is None or isinstance(node, py_ast.leafTypes):
            return self._normal_outcome()
        if isinstance(node, py_ast.Code):
            return self.analyze_node(node, node.ast)
        if isinstance(node, py_ast.Suite):
            abrupt: dict[str, _FlowState] = {}
            for block in node.blocks:
                outcome = self.analyze_node(procedure, block)
                abrupt = self._merge_abrupt_maps(abrupt, outcome.abrupt)
                if outcome.normal is None:
                    return _FlowOutcome(None, abrupt)
            return _FlowOutcome(self._capture_flow_state(), abrupt)
        if isinstance(node, py_ast.Switch):
            return self._analyze_switch(procedure, node)
        if isinstance(node, py_ast.While):
            return self._analyze_while(procedure, node)
        if isinstance(node, py_ast.For):
            return self._analyze_for(procedure, node)
        if isinstance(node, py_ast.TryExceptFinally):
            return self._analyze_try_except_finally(procedure, node)
        if isinstance(node, py_ast.TypeSwitch):
            return self._analyze_type_switch(procedure, node)
        if isinstance(node, py_ast.FunctionDef):
            self._lexical_parents[id(node.code)] = procedure
            self._module_owners[id(node.code)] = self._module_owner(procedure)
            return self.apply_operation(procedure, node)
        if isinstance(node, py_ast.ClassDef):
            self._module_owners[id(node)] = self._module_owner(procedure)
            self._evaluation_epoch += 1
            self._operation_expression_caches.append({})
            self._operation_call_raises.append([])
            self._operation_normal_possible.append(True)
            self._record_exception_prefix()
            header_locations = self._merge_expression_locations(
                procedure,
                *self._definition_header_expressions(node),
            )
            self._record_exception_prefix()
            header_outcome = self._finish_operation_outcome(
                normal_possible=self._operation_normal_possible[-1]
            )
            if header_outcome.normal is None:
                return header_outcome
            self._restore_flow_state(header_outcome.normal)
            outer_environment = self.heap.snapshot_environment()
            body_outcome = self.analyze_node(node, node.body)
            if body_outcome.normal is None:
                return body_outcome
            class_members = self._scope_members(
                node,
                body_outcome.normal.environment,
            )
            self._restore_flow_state(body_outcome.normal)
            outer_environment.object_labels.update(
                body_outcome.normal.environment.object_labels
            )
            outer_environment.escaped_objects.update(
                body_outcome.normal.environment.escaped_objects
            )
            self.heap.restore_environment(outer_environment)
            # The class name is bound only after its body has completed.
            definition = self._apply_definition_transfer(
                procedure,
                node,
                related_locations=header_locations,
            )
            if definition is not None:
                for name, locations in class_members.items():
                    self.state.write(
                        self.heap.dynamic_attribute_location(definition, name),
                        locations,
                        UpdatePolicy.STRONG,
                    )
                for operation in self.iter_operations(node.body):
                    if (
                        isinstance(operation, py_ast.FunctionDef)
                        and operation.name == "__init__"
                    ):
                        self._class_initializers[
                            (self._module_owner(procedure), node.name)
                        ] = operation.code
            self._record_exception_prefix()
            return _FlowOutcome(
                self._capture_flow_state(),
                self._merge_abrupt_maps(
                    header_outcome.abrupt,
                    body_outcome.abrupt,
                ),
            )
        if isinstance(node, py_ast.Condition):
            outcome = self.analyze_node(procedure, node.preamble)
            if outcome.normal is not None:
                conditional = getattr(node, "conditional", None)
                if conditional is not None:
                    self._evaluation_epoch += 1
                    self.locations_for_expression(procedure, conditional)
                return _FlowOutcome(self._capture_flow_state(), outcome.abrupt)
            return outcome
        if isinstance(node, py_ast.Break):
            return self._abrupt_outcome("break")
        if isinstance(node, py_ast.Continue):
            return self._abrupt_outcome("continue")
        if isinstance(node, py_ast.Assert):
            return self._analyze_assert(procedure, node)
        if isinstance(node, py_ast.PythonASTNode):
            operation_outcome = self.apply_operation(procedure, node)
            if isinstance(node, py_ast.Return):
                abrupt = dict(operation_outcome.abrupt)
                if operation_outcome.normal is not None:
                    abrupt = self._merge_abrupt_maps(
                        abrupt,
                        {"return": operation_outcome.normal},
                    )
                return _FlowOutcome(None, abrupt)
            if isinstance(node, py_ast.Raise):
                abrupt = dict(operation_outcome.abrupt)
                if operation_outcome.normal is not None:
                    abrupt = self._merge_abrupt_maps(
                        abrupt,
                        {"raise": operation_outcome.normal},
                    )
                return _FlowOutcome(None, abrupt)
            return operation_outcome
        return self._normal_outcome()

    def _analyze_assert(
        self,
        procedure: object,
        node: py_ast.Assert,
    ) -> _FlowOutcome:
        self._evaluation_epoch += 1
        self._operation_expression_caches.append({})
        self._record_exception_prefix()
        self.locations_for_expression(procedure, node.test)
        normal = self._capture_flow_state()

        self._restore_flow_state(normal)
        message_locations = self.locations_for_expression(
            procedure,
            node.message,
        )
        self.heap.mark_all_escaped(message_locations)
        self.state.mark_escaped(message_locations)
        raised = self._capture_flow_state()
        self._operation_expression_caches.pop()
        self._restore_flow_state(normal)
        return _FlowOutcome(normal, {"raise": raised})

    def bind_parameters(self, procedure: object) -> None:
        code_parameters = getattr(procedure, "codeparameters", None)
        if code_parameters is None:
            return
        parameters = []
        selfparam = getattr(code_parameters, "selfparam", None)
        if isinstance(selfparam, py_ast.Local):
            parameters.append(selfparam)
        parameters.extend(
            param
            for param in getattr(code_parameters, "posonlyparams", ())
            if isinstance(param, py_ast.Local)
        )
        parameters.extend(
            param
            for param in getattr(code_parameters, "params", ())
            if isinstance(param, py_ast.Local)
        )
        vparam = getattr(code_parameters, "vparam", None)
        kparam = getattr(code_parameters, "kparam", None)
        if isinstance(vparam, py_ast.Local):
            parameters.append(vparam)
        if isinstance(kparam, py_ast.Local):
            parameters.append(kparam)
        for index, formal in enumerate(dict.fromkeys(parameters)):
            if not self.heap.locations_for_local(procedure, formal):
                self.heap.bind_parameter(procedure, formal, index, ())
                current = self.heap.locations_for_local(procedure, formal)
                self.heap.bind_local_to_locations(
                    procedure,
                    formal,
                    (*current, self._external_value_location(procedure)),
                    include_raw_fallback=True,
                )

    def apply_operation(self, procedure: object, operation: object) -> _FlowOutcome:
        """Apply the heap transfer for one operation."""
        self._evaluation_epoch += 1
        self._operation_expression_caches.append({})
        self._operation_call_raises.append([])
        self._operation_normal_possible.append(True)
        if isinstance(operation, py_ast.GlobalDecl):
            name = getattr(operation.name, "name", None)
            if name:
                self._global_declarations.setdefault(id(procedure), set()).add(name)
        elif isinstance(operation, py_ast.NonlocalDecl):
            name = getattr(operation.name, "name", None)
            if name:
                self._nonlocal_declarations.setdefault(id(procedure), set()).add(name)
        self._record_exception_prefix()
        if isinstance(operation, py_ast.Discard):
            self.locations_for_expression(procedure, operation.expr)
        elif isinstance(operation, py_ast.Expression):
            self.locations_for_expression(procedure, operation)
        elif isinstance(
            operation,
            (
                py_ast.SetAttr,
                py_ast.SetSubscript,
                py_ast.SetSlice,
                py_ast.SetGlobal,
                py_ast.SetCellDeref,
            ),
        ):
            # Assignment RHS evaluation precedes evaluation of the target.
            # This matters when a named expression or direct call rebinds a
            # local subsequently used as the field/subscript base.
            self.locations_for_expression(procedure, operation.value)
        if not self._operation_normal_possible[-1]:
            return self._finish_operation_outcome(normal_possible=False)
        self._materialize_assignment_result(procedure, operation)
        if not self._operation_normal_possible[-1]:
            return self._finish_operation_outcome(normal_possible=False)
        self._apply_definition_transfer(procedure, operation)
        if not self._operation_normal_possible[-1]:
            return self._finish_operation_outcome(normal_possible=False)
        prepared_writes = self._prepared_target_writes(procedure, operation)
        prepared_deletes = self._prepared_delete_locations(procedure, operation)
        effect = self.effect_builder.operation_effect(
            procedure,
            operation,
            collection_mutator_names=self.collection_mutator_names,
        )
        writes = prepared_writes if prepared_writes is not None else effect.writes
        self._apply_writes(procedure, operation, writes)
        raw_deletes = (
            prepared_deletes
            if prepared_deletes is not None
            else effect.deletes
        )
        deletes = self._effective_deletes(operation, raw_deletes)
        self._record_summary_deletes(deletes)
        self._apply_deletes(deletes)
        immediate_escapes = self._immediate_escape_locations(operation, effect)
        self.heap.mark_all_escaped(immediate_escapes)
        self.state.mark_escaped(immediate_escapes)
        if isinstance(operation, py_ast.Return):
            self._materialize_return_values(procedure, operation, effect.returns)
        if isinstance(operation, py_ast.Raise):
            raised_locations = tuple(
                location
                for expression in self.effect_builder.raise_escape_expressions(operation)
                for location in self.locations_for_expression(procedure, expression)
            )
            if not raised_locations:
                raised_locations = self.state.active_exceptions.get(procedure, ())
            self.state.set_raised(procedure, raised_locations)
        self._apply_call_transfer(procedure, operation)
        if not self._operation_normal_possible[-1]:
            return self._finish_operation_outcome(normal_possible=False)
        self._apply_collection_reorder(procedure, operation)
        self._apply_pending_call_result(procedure, operation)
        self._handle_local_delete(procedure, operation)
        self._materialize_collection_literal_values(procedure, operation)
        self._materialize_function_default_values(procedure, operation)
        if isinstance(operation, py_ast.AnnAssign):
            # CPython evaluates the value/assignment before the annotation.
            annotation_locations = self.locations_for_expression(
                procedure,
                operation.annotation_expr,
            )
            if annotation_locations:
                if isinstance(procedure, py_ast.ClassDef):
                    annotations_root = HeapLocation(
                        self.heap.summary_object(
                            ("class-annotations", id(procedure)),
                            label=f"{procedure.name}.__annotations__",
                        )
                    )
                else:
                    annotations_root = self.effect_builder.global_location(
                        procedure,
                        "__annotations__",
                    )
                self.state.write(
                    self.heap.dynamic_subscript_location(
                        annotations_root,
                        f"[{operation.target.name!r}]",
                    ),
                    annotation_locations,
                    UpdatePolicy.STRONG,
                )
        self._apply_external_boundary_transfer(procedure, operation)
        self._record_exception_prefix()
        return self._finish_operation_outcome(normal_possible=True)

    def _finish_operation_outcome(
        self,
        *,
        normal_possible: bool,
    ) -> _FlowOutcome:
        raise_states = self._operation_call_raises.pop()
        self._operation_normal_possible.pop()
        self._operation_expression_caches.pop()
        abrupt = (
            {"raise": self._join_flow_states(tuple(raise_states))}
            if raise_states
            else {}
        )
        return _FlowOutcome(
            self._capture_flow_state() if normal_possible else None,
            abrupt,
        )

    def _analyze_switch(
        self,
        procedure: object,
        node: py_ast.Switch,
    ) -> _FlowOutcome:
        condition = self.analyze_node(procedure, node.condition)
        if condition.normal is None:
            return condition
        base = condition.normal
        true_outcome = self._outcome_after(procedure, node.t, base)
        false_outcome = self._outcome_after(procedure, node.f, base)
        normal = self._join_optional_flow_states(
            (true_outcome.normal, false_outcome.normal)
        )
        abrupt = self._merge_abrupt_maps(
            condition.abrupt,
            true_outcome.abrupt,
            false_outcome.abrupt,
        )
        return _FlowOutcome(normal, abrupt)

    def _analyze_while(
        self,
        procedure: object,
        node: py_ast.While,
    ) -> _FlowOutcome:
        condition = self.analyze_node(procedure, node.condition)
        if condition.normal is None:
            return condition
        entry = condition.normal
        current = entry
        breaks: list[_FlowState] = []
        abrupt = dict(condition.abrupt)
        for _ in range(self.max_loop_iterations):
            body_outcome = self._outcome_after(procedure, node.body, current)
            if "break" in body_outcome.abrupt:
                breaks.append(body_outcome.abrupt["break"])
            abrupt = self._merge_abrupt_maps(
                abrupt,
                {
                    kind: state
                    for kind, state in body_outcome.abrupt.items()
                    if kind not in {"break", "continue"}
                },
            )
            back_edges = tuple(
                state
                for state in (
                    body_outcome.normal,
                    body_outcome.abrupt.get("continue"),
                )
                if state is not None
            )
            if not back_edges:
                break
            body_state = self._join_flow_states(back_edges)
            next_state = self._join_flow_states((entry, body_state))
            if self._flow_states_equivalent(next_state, current):
                current = next_state
                break
            current = next_state
        else_outcome = self._outcome_after(procedure, node.else_, current)
        normal = self._join_optional_flow_states(
            (else_outcome.normal, *breaks)
        )
        abrupt = self._merge_abrupt_maps(abrupt, else_outcome.abrupt)
        return _FlowOutcome(normal, abrupt)

    def _analyze_for(
        self,
        procedure: object,
        node: py_ast.For,
    ) -> _FlowOutcome:
        preamble = self.analyze_node(procedure, node.loopPreamble)
        if preamble.normal is None:
            return preamble
        self.locations_for_expression(procedure, node.iterator)
        entry = self._capture_flow_state()
        current = entry
        breaks: list[_FlowState] = []
        abrupt = dict(preamble.abrupt)
        for _ in range(self.max_loop_iterations):
            self._restore_flow_state(current)
            self._bind_for_index(procedure, node)
            iteration_entry = self._capture_flow_state()
            body_outcome = self._outcome_after(
                procedure,
                py_ast.Suite([node.bodyPreamble, node.body]),
                iteration_entry,
            )
            if "break" in body_outcome.abrupt:
                breaks.append(body_outcome.abrupt["break"])
            abrupt = self._merge_abrupt_maps(
                abrupt,
                {
                    kind: state
                    for kind, state in body_outcome.abrupt.items()
                    if kind not in {"break", "continue"}
                },
            )
            back_edges = tuple(
                state
                for state in (
                    body_outcome.normal,
                    body_outcome.abrupt.get("continue"),
                )
                if state is not None
            )
            if not back_edges:
                break
            body_state = self._join_flow_states(back_edges)
            next_state = self._join_flow_states((entry, body_state))
            if self._flow_states_equivalent(next_state, current):
                current = next_state
                break
            current = next_state
        else_outcome = self._outcome_after(procedure, node.else_, current)
        normal = self._join_optional_flow_states(
            (else_outcome.normal, *breaks)
        )
        abrupt = self._merge_abrupt_maps(abrupt, else_outcome.abrupt)
        return _FlowOutcome(normal, abrupt)

    def _bind_for_index(self, procedure: object, node: py_ast.For) -> None:
        if not isinstance(node.index, py_ast.Local):
            return
        iter_locations = self.locations_for_expression(procedure, node.iterator)
        if not iter_locations:
            return
        element_locations: list[HeapLocation] = []
        seen: set[HeapLocation] = set()
        for loc in iter_locations:
            wildcard_loc = self.heap.dynamic_subscript_location(
                loc, DYNAMIC_SUBSCRIPT_WILDCARD
            )
            for val in self.state.read_contained(wildcard_loc):
                if val not in seen:
                    seen.add(val)
                    element_locations.append(val)
        if element_locations:
            self._bind_runtime_local(
                procedure,
                node.index,
                tuple(element_locations),
                include_raw_fallback=True,
            )

    def _analyze_try_except_finally(
        self,
        procedure: object,
        node: py_ast.TryExceptFinally,
    ) -> _FlowOutcome:
        base = self._capture_flow_state()
        exception_prefixes = [base]
        self._exception_prefix_stack.append(exception_prefixes)
        try:
            body_outcome = self._outcome_after(procedure, node.body, base)
        finally:
            self._exception_prefix_stack.pop()

        # Any operation in the try body can raise.  Handlers therefore start
        # from the join of all observed prefixes, rather than only the body's
        # final state.
        explicit_raise = body_outcome.abrupt.get("raise")
        if explicit_raise is not None:
            exception_prefixes.append(explicit_raise)
        exception_state = self._join_flow_states(tuple(exception_prefixes))

        normal_states: list[_FlowState] = []
        abrupt = {
            kind: state
            for kind, state in body_outcome.abrupt.items()
            if kind != "raise"
        }

        else_suite = getattr(node, "else_", None)
        if body_outcome.normal is not None:
            if else_suite is None:
                normal_states.append(body_outcome.normal)
            else:
                else_outcome = self._outcome_after(
                    procedure,
                    else_suite,
                    body_outcome.normal,
                )
                if else_outcome.normal is not None:
                    normal_states.append(else_outcome.normal)
                abrupt = self._merge_abrupt_maps(abrupt, else_outcome.abrupt)

        handled_any = False
        for handler in getattr(node, "handlers", ()):
            handled_any = True
            handler_outcome = self._handler_outcome(
                procedure,
                handler,
                exception_state,
            )
            if handler_outcome.normal is not None:
                normal_states.append(handler_outcome.normal)
            abrupt = self._merge_abrupt_maps(abrupt, handler_outcome.abrupt)
        default_handler = getattr(node, "defaultHandler", None)
        if default_handler is not None:
            handled_any = True
            default_outcome = self._outcome_after(
                procedure,
                default_handler,
                exception_state,
            )
            if default_outcome.normal is not None:
                normal_states.append(default_outcome.normal)
            abrupt = self._merge_abrupt_maps(abrupt, default_outcome.abrupt)

        # Typed handlers may not match, and ordinary operations can throw even
        # without an explicit Raise node. Preserve an unhandled exceptional exit.
        if handled_any or exception_prefixes:
            abrupt = self._merge_abrupt_maps(
                abrupt,
                {"raise": exception_state},
            )

        outcome = _FlowOutcome(
            self._join_optional_flow_states(tuple(normal_states)),
            abrupt,
        )
        finally_suite = getattr(node, "finally_", None)
        if finally_suite is None:
            return outcome
        return self._apply_finally_outcome(procedure, finally_suite, outcome)

    def _analyze_type_switch(
        self,
        procedure: object,
        node: py_ast.TypeSwitch,
    ) -> _FlowOutcome:
        conditional_locs: tuple[HeapLocation, ...] = ()
        cond_ref = getattr(node, "conditional", None)
        if cond_ref is not None:
            self._evaluation_epoch += 1
            conditional_locs = self.locations_for_expression(procedure, cond_ref)
        base = self._capture_flow_state()
        normal_states: list[_FlowState] = [base]
        abrupt: dict[str, _FlowState] = {}
        for case in getattr(node, "cases", ()):
            self._restore_flow_state(base)
            if conditional_locs and case.expr is not None:
                self._bind_runtime_local(
                    procedure,
                    case.expr,
                    conditional_locs,
                    include_raw_fallback=True,
                )
            case_outcome = self.analyze_node(procedure, case.body)
            if case_outcome.normal is not None:
                normal_states.append(case_outcome.normal)
            abrupt = self._merge_abrupt_maps(abrupt, case_outcome.abrupt)
        return _FlowOutcome(
            self._join_optional_flow_states(tuple(normal_states)),
            abrupt,
        )

    def _handler_outcome(
        self,
        procedure: object,
        handler: object,
        exception_state: _FlowState,
    ) -> _FlowOutcome:
        previous = self._capture_flow_state()
        self._restore_flow_state(exception_state)
        handler_type = getattr(handler, "type", None)
        if handler_type is not None:
            self.locations_for_expression(procedure, handler_type)
        caught = getattr(handler, "value", None)
        raised = exception_state.heap_state.raised.get(procedure, ())
        if not raised:
            raised = tuple(
                dict.fromkeys(
                    location
                    for locations in exception_state.heap_state.raised.values()
                    for location in locations
                )
            )
        if isinstance(caught, py_ast.Local):
            self._bind_runtime_local(
                procedure,
                caught,
                raised or (self._external_value_location(procedure),),
            )
        self.state.raised.clear()
        self.state.set_active_exception(
            procedure,
            raised or (self._external_value_location(procedure),),
        )
        entry = self._capture_flow_state()
        handler_suite = py_ast.Suite(
            [
                getattr(handler, "preamble", None),
                getattr(handler, "body", None),
            ]
        )
        outcome = self._outcome_after(procedure, handler_suite, entry)
        outcome = _FlowOutcome(
            self._flow_state_without_active_exception(procedure, outcome.normal),
            {
                kind: self._flow_state_without_active_exception(procedure, state)
                for kind, state in outcome.abrupt.items()
            },
        )
        if isinstance(caught, py_ast.Local):
            outcome = _FlowOutcome(
                self._flow_state_after_local_clear(
                    procedure,
                    caught,
                    outcome.normal,
                ),
                {
                    kind: self._flow_state_after_local_clear(
                        procedure,
                        caught,
                        state,
                    )
                    for kind, state in outcome.abrupt.items()
                },
            )
        self._restore_flow_state(previous)
        return outcome

    @staticmethod
    def _flow_state_without_active_exception(
        procedure: object,
        state: _FlowState | None,
    ) -> _FlowState | None:
        if state is None:
            return None
        heap_state = state.heap_state.copy()
        heap_state.active_exceptions.pop(procedure, None)
        return _FlowState(heap_state, state.environment, state.definition_defaults)

    def _flow_state_after_local_clear(
        self,
        procedure: object,
        local: py_ast.Local,
        state: _FlowState | None,
    ) -> _FlowState | None:
        if state is None:
            return None
        previous = self._capture_flow_state()
        self._restore_flow_state(state)
        self._clear_runtime_local(procedure, local)
        cleared = self._capture_flow_state()
        self._restore_flow_state(previous)
        return cleared

    def _apply_finally_outcome(
        self,
        procedure: object,
        finally_suite: object,
        incoming: _FlowOutcome,
    ) -> _FlowOutcome:
        normal_states: list[_FlowState] = []
        abrupt: dict[str, _FlowState] = {}
        if incoming.normal is not None:
            final_outcome = self._outcome_after(
                procedure,
                finally_suite,
                incoming.normal,
            )
            if final_outcome.normal is not None:
                normal_states.append(final_outcome.normal)
            abrupt = self._merge_abrupt_maps(abrupt, final_outcome.abrupt)
        for original_kind, state in incoming.abrupt.items():
            prepared, prior_returns = self._without_procedure_returns(
                procedure,
                state,
            )
            final_outcome = self._outcome_after(
                procedure,
                finally_suite,
                prepared,
            )
            abrupt = self._merge_abrupt_maps(abrupt, final_outcome.abrupt)
            if final_outcome.normal is not None:
                resumed = self._with_procedure_returns(
                    procedure,
                    final_outcome.normal,
                    prior_returns,
                )
                abrupt = self._merge_abrupt_maps(
                    abrupt,
                    {original_kind: resumed},
                )
        return _FlowOutcome(
            self._join_optional_flow_states(tuple(normal_states)),
            abrupt,
        )

    @staticmethod
    def _without_procedure_returns(
        procedure: object,
        state: _FlowState,
    ) -> tuple[
        _FlowState,
        tuple[
            tuple[HeapLocation, ...],
            tuple[tuple[HeapLocation, ...], ...],
        ],
    ]:
        heap_state = state.heap_state.copy()
        prior = (
            heap_state.returns.pop(procedure, ()),
            heap_state.return_slots.pop(procedure, ()),
        )
        return _FlowState(
            heap_state,
            state.environment,
            state.definition_defaults,
        ), prior

    @staticmethod
    def _with_procedure_returns(
        procedure: object,
        state: _FlowState,
        returns: tuple[
            tuple[HeapLocation, ...],
            tuple[tuple[HeapLocation, ...], ...],
        ],
    ) -> _FlowState:
        flat_returns, return_slots = returns
        if not flat_returns and not return_slots:
            return state
        heap_state = state.heap_state.copy()
        heap_state.set_returns(procedure, flat_returns)
        heap_state.set_return_slots(procedure, return_slots)
        return _FlowState(
            heap_state,
            state.environment,
            state.definition_defaults,
        )

    def _outcome_after(
        self,
        procedure: object,
        node: object,
        state: _FlowState,
    ) -> _FlowOutcome:
        previous = self._capture_flow_state()
        self._restore_flow_state(state)
        outcome = self.analyze_node(procedure, node)
        self._restore_flow_state(previous)
        return outcome

    def _state_after(
        self,
        procedure: object,
        node: object,
        state: _FlowState,
    ) -> _FlowState:
        outcome = self._outcome_after(procedure, node, state)
        if outcome.normal is not None:
            return outcome.normal
        return self._join_flow_states(tuple(outcome.abrupt.values()))

    def _capture_flow_state(self) -> _FlowState:
        return _FlowState(
            heap_state=self.state.copy(),
            environment=self.heap.snapshot_environment(),
            definition_defaults=dict(self._definition_default_locations),
        )

    def _record_exception_prefix(self) -> None:
        if not self._exception_prefix_stack:
            return
        prefix = self._capture_flow_state()
        for collector in self._exception_prefix_stack:
            collector.append(prefix)

    def _restore_flow_state(self, state: _FlowState) -> None:
        self.state = state.heap_state.copy()
        self.heap.restore_environment(state.environment)
        self._definition_default_locations = dict(state.definition_defaults)

    def _normal_outcome(self) -> _FlowOutcome:
        return _FlowOutcome(self._capture_flow_state())

    def _abrupt_outcome(self, kind: str) -> _FlowOutcome:
        return _FlowOutcome(None, {kind: self._capture_flow_state()})

    def _position_outcome(self, outcome: _FlowOutcome) -> None:
        if outcome.normal is not None:
            self._restore_flow_state(outcome.normal)
            return
        if outcome.abrupt:
            self._restore_flow_state(
                self._join_flow_states(tuple(outcome.abrupt.values()))
            )

    def _joined_outcome_state(self, outcome: _FlowOutcome) -> _FlowState:
        states = tuple(
            state
            for state in (outcome.normal, *outcome.abrupt.values())
            if state is not None
        )
        return self._join_flow_states(states)

    def _merge_abrupt_maps(
        self,
        *maps: dict[str, _FlowState],
    ) -> dict[str, _FlowState]:
        grouped: dict[str, list[_FlowState]] = {}
        for mapping in maps:
            for kind, state in mapping.items():
                grouped.setdefault(kind, []).append(state)
        return {
            kind: self._join_flow_states(tuple(states))
            for kind, states in grouped.items()
        }

    def _join_optional_flow_states(
        self,
        states: tuple[_FlowState | None, ...],
    ) -> _FlowState | None:
        concrete = tuple(state for state in states if state is not None)
        if not concrete:
            return None
        return self._join_flow_states(concrete)

    def _join_flow_states(self, states: tuple[_FlowState, ...]) -> _FlowState:
        if not states:
            return self._capture_flow_state()
        joined_heap = states[0].heap_state.copy()
        for state in states[1:]:
            joined_heap = joined_heap.join(state.heap_state)
        joined_environment = self.heap.join_environments(
            tuple(state.environment for state in states)
        )
        default_keys = {
            key
            for state in states
            for key in state.definition_defaults
        }
        joined_defaults = {
            key: tuple(
                dict.fromkeys(
                    location
                    for state in states
                    for location in state.definition_defaults.get(key, ())
                )
            )
            for key in default_keys
        }
        return _FlowState(joined_heap, joined_environment, joined_defaults)

    @staticmethod
    def _flow_states_equivalent(a: _FlowState, b: _FlowState) -> bool:
        return (
            a.heap_state.equivalent(b.heap_state)
            and a.environment.storage_overrides == b.environment.storage_overrides
            and a.environment.escaped_objects == b.environment.escaped_objects
            and a.definition_defaults == b.definition_defaults
        )

