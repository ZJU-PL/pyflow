"""Standalone heap transfer engine.

This module applies operation-level heap effects to :class:`HeapAbstraction`.
It intentionally stays conservative: unresolved calls escape their arguments,
unknown assigned values break precise local aliases, and modeled constructors
or collection literals allocate fresh heap roots.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from pyflow.analysis.ir_utils import (
    actual_argument_expressions,
    assigned_locals,
    call_keyword_spreads,
    call_positional_items,
    call_positional_spreads,
    class_cell,
    code_closure_cells,
    code_definition_annotations,
    resolve_call_name,
)
from pyflow.language.python import ast as py_ast
from pyflow.language.python.default_markers import MISSING_DEFAULT

from .abstraction import HeapAbstraction, HeapEnvironment
from .heap_effects import (
    CALL_RETURN_COPY,
    CALL_RETURN_FRESH,
    CALL_RETURN_SUMMARY,
    DEFAULT_HEAP_INTRINSICS,
    DYNAMIC_SUBSCRIPT_WILDCARD,
    HeapEffectBuilder,
)
from .heap_state import HeapState
from .intrinsics import (
    CALL_RETURN_ARG,
    CALL_RETURN_NONE,
    CALL_RETURN_SELF,
    HeapIntrinsicModels,
)
from .model import HeapLocation, HeapObjectKind
from .model import UpdatePolicy


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


class HeapTransferEngine:
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
            self.locations_for_expression(procedure, operation.annotation_expr)
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

    def _prepared_target_writes(
        self,
        procedure: object,
        operation: object,
    ) -> tuple[object, ...] | None:
        bases: tuple[HeapLocation, ...]
        locations: tuple[HeapLocation, ...]
        if isinstance(operation, (py_ast.SetAttr, py_ast.Store)):
            bases = self.locations_for_expression(procedure, operation.expr)
            self.locations_for_expression(procedure, operation.name)
            if isinstance(operation, py_ast.Store) and getattr(
                operation,
                "fieldtype",
                None,
            ) in {"Dictionary", "Array"}:
                locations = self.heap.dynamic_subscript_locations(
                    bases,
                    (f"[{self.effect_builder._path_component(operation.name)}]",),
                )
                self.locations_for_expression(procedure, operation.value)
            else:
                attribute = (
                    self.effect_builder._path_component(operation.name)
                    if isinstance(operation, py_ast.Store)
                    else self.effect_builder._constant_string(operation.name) or "*"
                )
                locations = self.heap.dynamic_attribute_locations(
                    bases,
                    (attribute,),
                )
                if isinstance(operation, py_ast.Store):
                    self.locations_for_expression(procedure, operation.value)
            return self._prepared_writes_for_bases(locations, bases)
        if isinstance(operation, py_ast.SetSubscript):
            bases = self.locations_for_expression(procedure, operation.expr)
            self.locations_for_expression(procedure, operation.subscript)
            subscript = self.effect_builder._constant_subscript(operation.subscript)
            locations = self.heap.dynamic_subscript_locations(
                bases,
                (subscript or DYNAMIC_SUBSCRIPT_WILDCARD,),
            )
            return self._prepared_writes_for_bases(locations, bases)
        if isinstance(operation, py_ast.SetSlice):
            bases = self.locations_for_expression(procedure, operation.expr)
            for component in (operation.start, operation.stop, operation.step):
                self.locations_for_expression(procedure, component)
            locations = self.heap.dynamic_subscript_locations(
                bases,
                (DYNAMIC_SUBSCRIPT_WILDCARD,),
            )
            return self._prepared_writes_for_bases(locations, bases)
        return None

    def _prepared_writes_for_bases(
        self,
        locations: tuple[HeapLocation, ...],
        bases: tuple[HeapLocation, ...],
    ) -> tuple[object, ...]:
        ambiguous = len({base.root for base in bases}) > 1
        return tuple(
            self.heap.write_for_location(
                location,
                policy=UpdatePolicy.WEAK if ambiguous else None,
            )
            for location in locations
        )

    def _prepared_delete_locations(
        self,
        procedure: object,
        operation: object,
    ) -> tuple[HeapLocation, ...] | None:
        if isinstance(operation, py_ast.DeleteAttr):
            bases = self.locations_for_expression(procedure, operation.expr)
            self.locations_for_expression(procedure, operation.name)
            attribute = self.effect_builder._constant_string(operation.name) or "*"
            return self.heap.dynamic_attribute_locations(bases, (attribute,))
        if isinstance(operation, py_ast.DeleteSubscript):
            bases = self.locations_for_expression(procedure, operation.expr)
            self.locations_for_expression(procedure, operation.subscript)
            subscript = self.effect_builder._constant_subscript(operation.subscript)
            return self.heap.dynamic_subscript_locations(
                bases,
                (subscript or DYNAMIC_SUBSCRIPT_WILDCARD,),
            )
        if isinstance(operation, py_ast.DeleteSlice):
            bases = self.locations_for_expression(procedure, operation.expr)
            for component in (operation.start, operation.stop, operation.step):
                self.locations_for_expression(procedure, component)
            return self.heap.dynamic_subscript_locations(
                bases,
                (DYNAMIC_SUBSCRIPT_WILDCARD,),
            )
        return None

    @staticmethod
    def _immediate_escape_locations(
        operation: object,
        effect: object,
    ) -> tuple[HeapLocation, ...]:
        """Return effect escapes that are externally reachable immediately.

        Stores into fields, subscripts, cells, or collection mutators create
        heap reachability edges. The stored values escape only if the
        destination root is, or later becomes, escaped; the fixed-point escape
        propagation handles that through ``HeapState``.
        """
        escapes = getattr(effect, "escapes", ())
        writes = getattr(effect, "writes", ())
        if not writes or not escapes:
            return escapes
        if isinstance(operation, py_ast.SetGlobal):
            return escapes
        if isinstance(
            operation,
            (
                py_ast.SetAttr,
                py_ast.SetSubscript,
                py_ast.SetSlice,
                py_ast.SetCellDeref,
                py_ast.Store,
            ),
        ):
            return ()
        call = HeapTransferEngine._call_expression(operation)
        if call is not None:
            return ()
        return escapes

    def locations_for_expression(
        self,
        procedure: object,
        expression: object,
    ) -> tuple[HeapLocation, ...]:
        cache = (
            self._operation_expression_caches[-1]
            if self._operation_expression_caches
            else None
        )
        cacheable = not isinstance(
            expression,
            (
                HeapLocation,
                py_ast.Local,
                py_ast.GetGlobal,
                py_ast.GetCell,
                py_ast.GetCellDeref,
                py_ast.Cell,
                py_ast.Input,
            ),
        )
        if cache is not None and cacheable:
            cached = cache.get(id(expression))
            if cached is not None:
                return cached
        self._record_exception_prefix()
        result = self._locations_for_expression_impl(procedure, expression)
        self._record_exception_prefix()
        if cache is not None and cacheable:
            cache[id(expression)] = result
        return result

    def _locations_for_expression_impl(
        self,
        procedure: object,
        expression: object,
    ) -> tuple[HeapLocation, ...]:
        """Best-effort locations read by an expression."""
        if expression is None:
            return ()
        if isinstance(expression, HeapLocation):
            return (expression,)
        if isinstance(expression, py_ast.Input):
            return self.locations_for_expression(procedure, expression.lcl)
        if isinstance(expression, py_ast.Cell):
            return (self.effect_builder.cell_location(expression, procedure),)
        if isinstance(expression, py_ast.TypeParam):
            bound = self.locations_for_expression(procedure, expression.bound)
            parameter = HeapLocation(
                self.heap.allocation_object(
                    procedure,
                    expression,
                    label=f"type parameter {expression.name}",
                    context=self._current_context,
                )
            )
            if bound:
                self.state.write(
                    self.heap.dynamic_attribute_location(parameter, "__bound__"),
                    bound,
                    UpdatePolicy.STRONG,
                )
            return tuple(dict.fromkeys((parameter, *bound)))
        if isinstance(expression, py_ast.TypeParams):
            parameters = self._merge_expression_locations(
                procedure,
                *getattr(expression, "params", ()),
            )
            collection = HeapLocation(
                self.heap.allocation_object(
                    procedure,
                    expression,
                    label="type parameters",
                    context=self._current_context,
                )
            )
            if parameters:
                self.state.write(
                    self.heap.dynamic_subscript_location(
                        collection,
                        DYNAMIC_SUBSCRIPT_WILDCARD,
                    ),
                    parameters,
                    UpdatePolicy.WEAK,
                )
            return tuple(dict.fromkeys((collection, *parameters)))
        if isinstance(expression, py_ast.Local):
            declared = self._declared_location(procedure, expression)
            if declared is not None:
                return self.state.read(declared)
            locations = self.heap.locations_for_local(procedure, expression)
            if locations:
                return locations
            if isinstance(procedure, py_ast.ClassDef):
                outer_locations = self._outer_local_locations(expression)
                if outer_locations:
                    return outer_locations
            obj = self.heap.local_object(procedure, expression)
            self.heap.bind_local_to_object(procedure, expression, obj)
            return self.heap.locations_for_local(procedure, expression)
        if isinstance(expression, py_ast.GetGlobal):
            location = self.effect_builder.global_location(procedure, expression.name)
            return self.state.read(location)
        if isinstance(expression, (py_ast.GetCell, py_ast.GetCellDeref)):
            location = self.effect_builder.cell_location(expression.cell, procedure)
            return self.state.read(location)
        if isinstance(expression, (py_ast.GetAttr, py_ast.Load)):
            bases = self.locations_for_expression(procedure, expression.expr)
            self.locations_for_expression(procedure, expression.name)
            attribute = (
                self.effect_builder._path_component(expression.name)
                if isinstance(expression, py_ast.Load)
                else self.effect_builder._constant_string(expression.name) or "*"
            )
            if isinstance(expression, py_ast.Load) and getattr(
                expression, "fieldtype", None
            ) in {"Dictionary", "Array"}:
                locations = self.heap.dynamic_subscript_locations(
                    bases,
                    (f"[{attribute}]",),
                )
            else:
                locations = self.heap.dynamic_attribute_locations(
                    bases,
                    (attribute,),
                )
            values = list(self._read_heap_locations(locations))
            if attribute != "*":
                classes = tuple(
                    dict.fromkeys(
                        class_location
                        for base in bases
                        for class_location in self.state.read(
                            self.heap.dynamic_attribute_location(base, "__class__"),
                            fallback=(),
                        )
                    )
                )
                values.extend(self._class_attribute_values(classes, attribute))
            return tuple(dict.fromkeys(values))
        if isinstance(expression, py_ast.GetSubscript):
            bases = self.locations_for_expression(procedure, expression.expr)
            self.locations_for_expression(procedure, expression.subscript)
            subscript = self.effect_builder._constant_subscript(expression.subscript)
            if subscript is None:
                values: list[HeapLocation] = []
                for base in bases:
                    wildcard = self.heap.dynamic_subscript_location(
                        base,
                        DYNAMIC_SUBSCRIPT_WILDCARD,
                    )
                    values.extend(self.state.read_contained(wildcard))
                if values:
                    return tuple(dict.fromkeys(values))
                return self.heap.dynamic_subscript_locations(
                    bases,
                    (DYNAMIC_SUBSCRIPT_WILDCARD,),
                )
            locations = self.heap.dynamic_subscript_locations(
                bases,
                (subscript, DYNAMIC_SUBSCRIPT_WILDCARD),
            )
            return self._read_heap_locations(locations)
        if isinstance(expression, py_ast.DirectCall) and isinstance(
            expression.code,
            py_ast.Code,
        ):
            return self._evaluate_direct_call_expression(procedure, expression)
        if isinstance(expression, (py_ast.Call, py_ast.DirectCall, py_ast.MethodCall)):
            operand_locations = self._evaluate_call_operands(
                procedure,
                expression,
            )
            kind = self.effect_builder.call_return_kind(expression)
            if kind == CALL_RETURN_NONE:
                return ()
            modeled = self._modeled_call_return_locations(
                procedure,
                expression,
                kind,
                operand_locations,
            )
            if modeled:
                self._attach_known_class(procedure, expression, modeled)
                return modeled
            result = (
                HeapLocation(
                    self.effect_builder.call_return_object(procedure, expression)
                ),
            )
            call_name = resolve_call_name(expression)
            if (
                kind == CALL_RETURN_FRESH
                and call_name is not None
                and (
                    self._module_owner(procedure),
                    call_name.rsplit(".", 1)[-1],
                )
                in self._class_definitions
            ):
                result = tuple(
                    dict.fromkeys(
                        (*result, self._external_value_location(procedure))
                    )
                )
            if kind == CALL_RETURN_COPY:
                self._copy_call_result_contents(
                    procedure,
                    None,
                    expression,
                    result,
                )
            self._attach_known_class(procedure, expression, result)
            return result
        if isinstance(
            expression,
            (
                py_ast.BuildTuple,
                py_ast.BuildList,
                py_ast.BuildSet,
                py_ast.BuildMap,
                py_ast.BuildSlice,
                py_ast.Allocate,
            ),
        ):
            if isinstance(expression, py_ast.BuildSlice):
                for component in (
                    expression.start,
                    expression.stop,
                    expression.step,
                ):
                    self.locations_for_expression(procedure, component)
            elif isinstance(expression, py_ast.Allocate):
                self.locations_for_expression(procedure, expression.expr)
            allocation = HeapLocation(
                self.heap.allocation_object(
                    procedure,
                    expression,
                    label=self.effect_builder._allocation_label(expression),
                    context=self._current_context,
                )
            )
            if isinstance(
                expression,
                (py_ast.BuildTuple, py_ast.BuildList, py_ast.BuildSet, py_ast.BuildMap),
            ):
                self.state.complete_roots.add(allocation.root)
                for argument in getattr(expression, "args", ()):
                    self.locations_for_expression(procedure, argument)
                self._write_collection_literal_elements(
                    procedure,
                    allocation,
                    expression,
                    self._collection_literal_values(expression),
                )
            elif isinstance(expression, py_ast.BuildSlice):
                for slice_field, component in (
                    ("start", expression.start),
                    ("stop", expression.stop),
                    ("step", expression.step),
                ):
                    component_locations = self.locations_for_expression(
                        procedure,
                        component,
                    )
                    if component_locations:
                        self.state.write(
                            self.heap.dynamic_attribute_location(
                                allocation,
                                slice_field,
                            ),
                            component_locations,
                            UpdatePolicy.STRONG,
                        )
            return (allocation,)
        if isinstance(expression, py_ast.MakeFunction):
            function = HeapLocation(
                self.heap.allocation_object(
                    procedure,
                    expression,
                    label="function",
                    context=self._current_context,
                )
            )
            default_locations = self._merge_expression_locations(
                procedure,
                *getattr(expression, "defaults", ()),
            )
            if default_locations:
                self.state.write(
                    self.heap.dynamic_attribute_location(function, "__defaults__"),
                    default_locations,
                    UpdatePolicy.STRONG,
                )
            closure_locations = self._merge_expression_locations(
                procedure,
                *getattr(expression, "cells", ()),
            )
            if closure_locations:
                self.state.write(
                    self.heap.dynamic_attribute_location(function, "__closure__"),
                    closure_locations,
                    UpdatePolicy.STRONG,
                )
            return (function,)
        if isinstance(expression, (py_ast.GetIter, py_ast.AsyncGetIter)):
            sources = self.locations_for_expression(procedure, expression.expr)
            iterator = HeapLocation(
                self.heap.allocation_object(
                    procedure,
                    expression,
                    label="async iterator" if isinstance(expression, py_ast.AsyncGetIter) else "iterator",
                    context=self._current_context,
                )
            )
            self._copy_locations(sources, (iterator,))
            self.state.write(
                self.heap.dynamic_attribute_location(iterator, "__iterable__"),
                sources,
                UpdatePolicy.STRONG,
            )
            return tuple(
                dict.fromkeys(
                    (iterator, *sources, self._external_value_location(procedure))
                )
            )
        if isinstance(expression, py_ast.GetSlice):
            bases = self.locations_for_expression(procedure, expression.expr)
            for component in (
                expression.start,
                expression.stop,
                expression.step,
            ):
                self.locations_for_expression(procedure, component)
            sliced = HeapLocation(
                self.heap.allocation_object(
                    procedure,
                    expression,
                    label="slice result",
                    context=self._current_context,
                )
            )
            self._copy_locations(bases, (sliced,))
            return tuple(
                dict.fromkeys(
                    (*bases, sliced, self._external_value_location(procedure))
                )
            )
        if isinstance(expression, (py_ast.UnaryPrefixOp,)):
            return self._merge_expression_locations(
                procedure,
                expression.expr,
                self._external_value_location(procedure),
            )
        if isinstance(expression, py_ast.BinaryOp):
            return self._merge_expression_locations(
                procedure,
                expression.left,
                expression.right,
                self._external_value_location(procedure),
            )
        if isinstance(expression, (py_ast.ConvertToBool, py_ast.Not)):
            self.locations_for_expression(procedure, expression.expr)
            return ()
        if isinstance(expression, (py_ast.Is, py_ast.Check)):
            self.locations_for_expression(procedure, expression.left if isinstance(expression, py_ast.Is) else expression.expr)
            if isinstance(expression, py_ast.Is):
                self.locations_for_expression(procedure, expression.right)
            else:
                self.locations_for_expression(procedure, expression.name)
            return ()
        if isinstance(expression, py_ast.Await):
            awaitable = self.locations_for_expression(procedure, expression.expr)
            resumed = self._resume_deferred_activations(
                procedure,
                awaitable,
                use_yields=False,
            )
            self.heap.mark_all_escaped(awaitable)
            self.state.mark_escaped(awaitable)
            return tuple(
                dict.fromkeys(
                    (
                        *resumed,
                        *awaitable,
                        self._external_value_location(procedure),
                    )
                )
            )
        if isinstance(expression, (py_ast.Yield, py_ast.AsyncYield)):
            yielded = self.locations_for_expression(procedure, expression.expr)
            self.state.set_yields(procedure, yielded)
            self.heap.mark_all_escaped(yielded)
            self.state.mark_escaped(yielded)
            if self._yield_state_stack:
                self._yield_state_stack[-1].append(
                    (self._capture_flow_state(), yielded)
                )
            if self._resume_input_stack and self._resume_input_stack[-1]:
                return self._resume_input_stack[-1]
            return (self._external_value_location(procedure),)
        if isinstance(expression, py_ast.YieldFrom):
            yielded = self.locations_for_expression(procedure, expression.expr)
            resumed = self._resume_deferred_activations(
                procedure,
                yielded,
                use_yields=True,
            )
            expanded = tuple(
                dict.fromkeys((*resumed, *self._contained_values(yielded)))
            )
            self.state.set_yields(
                procedure,
                expanded or yielded,
            )
            self.heap.mark_all_escaped(yielded)
            self.state.mark_escaped(yielded)
            if self._yield_state_stack:
                self._yield_state_stack[-1].append(
                    (
                        self._capture_flow_state(),
                        expanded or yielded,
                    )
                )
            return tuple(
                dict.fromkeys(
                    (*yielded, self._external_value_location(procedure))
                )
            )
        if isinstance(expression, (py_ast.ShortCircutAnd, py_ast.ShortCircutOr)):
            terms = tuple(getattr(expression, "terms", ()))
            if not terms:
                return ()
            possible_locations: list[HeapLocation] = []
            prefix_states: list[_FlowState] = []
            for term in terms:
                possible_locations.extend(
                    self.locations_for_expression(procedure, term)
                )
                # Evaluation may stop after every term.  Joining all prefixes
                # preserves both skipped and executed side effects from later
                # terms without pretending they execute unconditionally.
                prefix_states.append(self._capture_flow_state())
            self._restore_flow_state(
                self._join_flow_states(tuple(prefix_states))
            )
            return tuple(dict.fromkeys(possible_locations))
        if isinstance(expression, py_ast.ConditionalExpr):
            self.locations_for_expression(procedure, expression.test)
            branch_entry = self._capture_flow_state()
            self._restore_flow_state(branch_entry)
            body_locations = self.locations_for_expression(
                procedure,
                expression.body,
            )
            body_state = self._capture_flow_state()
            self._restore_flow_state(branch_entry)
            else_locations = self.locations_for_expression(
                procedure,
                expression.orelse,
            )
            else_state = self._capture_flow_state()
            self._restore_flow_state(
                self._join_flow_states((body_state, else_state))
            )
            return tuple(dict.fromkeys((*body_locations, *else_locations)))
        if isinstance(expression, py_ast.NamedExpr):
            locations = self.locations_for_expression(procedure, expression.value)
            if locations:
                self._bind_runtime_local(
                    procedure,
                    expression.target,
                    locations,
                )
            else:
                self._clear_runtime_local(procedure, expression.target)
            return locations
        if isinstance(expression, py_ast.Existing):
            value = getattr(expression.object, "pyobj", None)
            if isinstance(
                value,
                (str, bytes, int, float, complex, bool, type(None)),
            ):
                return ()
            return (
                HeapLocation(
                    self.heap.external_object(
                        ("existing", id(expression.object)),
                        label=repr(value),
                    )
                ),
            )
        return ()

    def _class_attribute_values(
        self,
        classes: tuple[HeapLocation, ...],
        attribute: str,
    ) -> tuple[HeapLocation, ...]:
        values: list[HeapLocation] = []
        pending = list(classes)
        seen: set[HeapLocation] = set()
        while pending:
            class_location = pending.pop()
            if class_location in seen:
                continue
            seen.add(class_location)
            values.extend(
                self.state.read(
                    self.heap.dynamic_attribute_location(
                        class_location,
                        attribute,
                    ),
                    fallback=(),
                )
            )
            pending.extend(
                self.state.read(
                    self.heap.dynamic_attribute_location(
                        class_location,
                        "__bases__",
                    ),
                    fallback=(),
                )
            )
        return tuple(dict.fromkeys(values))

    def _external_value_location(self, procedure: object) -> HeapLocation:
        return HeapLocation(
            self.heap.summary_object(
                ("external-value", id(procedure)),
                label="external value",
            )
        )

    def _read_heap_locations(
        self,
        locations: tuple[HeapLocation, ...],
    ) -> tuple[HeapLocation, ...]:
        values: list[HeapLocation] = []
        for location in locations:
            stored = self.state.read(location, fallback=())
            if stored:
                values.extend(stored)
            elif (
                not self.state.definitely_absent(location)
                and location.root not in self.state.complete_roots
            ):
                values.append(location)
        return tuple(dict.fromkeys(values))

    def _outer_local_locations(
        self,
        local: py_ast.Local,
    ) -> tuple[HeapLocation, ...]:
        local_id = id(local)
        local_name = getattr(local, "name", None)
        locations: list[HeapLocation] = []
        keys = set(self.heap.storage_overrides) | set(self.heap.allocation_sites)
        for key in keys:
            if (
                key[1] != local_id
                and (
                    not isinstance(local_name, str)
                    or self.heap._local_names.get(key) != local_name
                )
            ):
                continue
            storage = self.heap.storage_overrides.get(key)
            if storage is None:
                site = self.heap.allocation_sites.get(key)
                storage = (
                    self.heap.site_storage.get(site, ())
                    if site is not None
                    else ()
                )
            locations.extend(
                self.heap.location_for_raw(raw) for raw in storage
            )
        return tuple(dict.fromkeys(locations))

    def _declared_location(
        self,
        procedure: object,
        local: py_ast.Local,
    ) -> HeapLocation | None:
        name = getattr(local, "name", None)
        if not name:
            return None
        if name in self._global_declarations.get(id(procedure), set()):
            return self.effect_builder.global_location(procedure, name)
        if name in self._nonlocal_declarations.get(id(procedure), set()):
            return HeapLocation(
                self.heap.summary_object(
                    ("nonlocal-cell", name),
                    label=f"nonlocal {name}",
                )
            )
        return None

    def _bind_runtime_local(
        self,
        procedure: object,
        local: py_ast.Local,
        locations: tuple[HeapLocation, ...],
        *,
        include_raw_fallback: bool = False,
    ) -> None:
        declared = self._declared_location(procedure, local)
        if declared is not None:
            self.state.write(declared, locations, UpdatePolicy.STRONG)
            return
        self.heap.bind_local_to_locations(
            procedure,
            local,
            locations,
            include_raw_fallback=include_raw_fallback,
        )

    def _clear_runtime_local(
        self,
        procedure: object,
        local: py_ast.Local,
    ) -> None:
        declared = self._declared_location(procedure, local)
        if declared is not None:
            self.state.delete(declared)
            return
        self.heap.clear_local_binding(procedure, local)

    def _merge_expression_locations(self, procedure, *expressions):
        """Return the deduplicated union of heap locations from multiple expressions."""
        locations: list[HeapLocation] = []
        for expr in expressions:
            if expr is not None:
                locations.extend(self.locations_for_expression(procedure, expr))
        return tuple(dict.fromkeys(locations))

    @classmethod
    def iter_code_objects(cls, root: object):
        """Yield code objects reachable from *root* without recursing into bodies."""
        seen: set[int] = set()

        def visit(value: object):
            if value is None or isinstance(value, py_ast.leafTypes):
                return
            if isinstance(value, py_ast.Code):
                key = id(value)
                if key not in seen:
                    seen.add(key)
                    yield value
                return
            if isinstance(value, (list, tuple, set, frozenset)):
                for item in value:
                    yield from visit(item)
                return
            for attr in ("liveCode", "entryPoints", "codes", "procedures", "functions"):
                child = getattr(value, attr, None)
                if child is not None:
                    yield from visit(child)
            code = getattr(value, "code", None)
            if code is not value:
                yield from visit(code)

        yield from visit(root)

    @classmethod
    def iter_operations(cls, node: object):
        """Yield operation nodes inside a code body."""
        if node is None or isinstance(node, py_ast.leafTypes):
            return
        if isinstance(node, py_ast.Code):
            return
        if isinstance(node, py_ast.Suite):
            for block in node.blocks:
                yield from cls.iter_operations(block)
            return
        if isinstance(node, py_ast.PythonASTNode):
            yield node
            if hasattr(node, "visitChildren"):
                children: list[object] = []
                node.visitChildren(children.append)
                for child in children:
                    yield from cls.iter_operations(child)

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

    def _materialize_assignment_result(
        self, procedure: object, operation: object
    ) -> None:
        targets = self._direct_assigned_locals(operation)
        if not targets:
            return
        if isinstance(operation, py_ast.InputBlock):
            external = self._external_value_location(procedure)
            for target in targets:
                self._bind_runtime_local(procedure, target, (external,))
            return
        if isinstance(operation, py_ast.Phi):
            phi_locations = tuple(
                dict.fromkeys(
                    location
                    for argument in getattr(operation, "arguments", ())
                    if argument is not None
                    for location in self.locations_for_expression(procedure, argument)
                )
            )
            if phi_locations:
                self._bind_runtime_local(
                    procedure,
                    operation.target,
                    phi_locations,
                )
            else:
                self._bind_runtime_local(
                    procedure,
                    operation.target,
                    (self._external_value_location(procedure),),
                )
            return
        if isinstance(operation, py_ast.UnpackSequence):
            self._materialize_unpack_targets(procedure, operation)
            return
        expr = self._assigned_expression(operation)
        if isinstance(
            expr,
            (
                py_ast.BuildTuple,
                py_ast.BuildList,
                py_ast.BuildSet,
                py_ast.BuildMap,
                py_ast.BuildSlice,
                py_ast.MakeFunction,
                py_ast.Allocate,
            ),
        ):
            allocations = self.locations_for_expression(procedure, expr)
            for target in targets:
                self._bind_runtime_local(procedure, target, allocations)
            return
        if isinstance(expr, py_ast.Import):
            module = self.effect_builder.import_object(expr, procedure)
            imported = [HeapLocation(module)]
            if not getattr(expr, "fromlist", None) and "." in expr.name:
                imported.append(
                    HeapLocation(
                        self.heap.module_object(
                            expr.name.split(".", 1)[0],
                            label=expr.name.split(".", 1)[0],
                        )
                    )
                )
            if getattr(expr, "fromlist", None):
                imported.append(self._external_value_location(procedure))
            for target in targets:
                self._bind_runtime_local(
                    procedure,
                    target,
                    tuple(imported),
                )
            return
        if isinstance(expr, (py_ast.Call, py_ast.DirectCall, py_ast.MethodCall)):
            if isinstance(expr, py_ast.DirectCall) and isinstance(
                expr.code,
                py_ast.Code,
            ):
                # Resolved calls evaluate/bind their actuals and results in
                # _apply_call_transfer.  Binding a placeholder here would
                # overwrite a target that may also be used as an argument.
                return
            slots = self._bind_call_result_targets(
                procedure,
                targets,
                expr,
                bind=False,
            )
            self._pending_call_results[id(operation)] = (targets, slots)
            return
        if expr is not None and not isinstance(expr, py_ast.Local):
            expr_locations = self.locations_for_expression(procedure, expr)
            if expr_locations:
                for target in targets:
                    self._bind_runtime_local(
                        procedure,
                        target,
                        expr_locations,
                    )
            else:
                for target in targets:
                    self._clear_runtime_local(procedure, target)
            return
        if isinstance(expr, py_ast.Local):
            source_locations = self.locations_for_expression(procedure, expr)
            for target in targets:
                self._bind_runtime_local(procedure, target, source_locations)
            return
        self.heap.update_assignment_aliases(procedure, targets, expr)

    @staticmethod
    def _direct_assigned_locals(operation: object) -> tuple[py_ast.Local, ...]:
        if isinstance(operation, py_ast.Assign):
            return tuple(
                local for local in operation.lcls if isinstance(local, py_ast.Local)
            )
        if isinstance(operation, py_ast.UnpackSequence):
            return tuple(
                local
                for local in operation.targets
                if isinstance(local, py_ast.Local)
            )
        if isinstance(operation, py_ast.AnnAssign):
            if operation.value is not None and isinstance(operation.target, py_ast.Local):
                return (operation.target,)
            return ()
        if isinstance(operation, py_ast.InputBlock):
            return tuple(
                input_.lcl
                for input_ in getattr(operation, "inputs", ())
                if isinstance(getattr(input_, "lcl", None), py_ast.Local)
            )
        if isinstance(operation, py_ast.Phi) and isinstance(
            getattr(operation, "target", None), py_ast.Local
        ):
            return (operation.target,)
        return ()

    def _materialize_unpack_targets(
        self,
        procedure: object,
        operation: py_ast.UnpackSequence,
    ) -> None:
        sources = self.locations_for_expression(procedure, operation.expr)
        for index, target in enumerate(operation.targets):
            if not isinstance(target, py_ast.Local):
                continue
            values: list[HeapLocation] = []
            for source in sources:
                exact = self.heap.dynamic_subscript_location(source, f"[{index}]")
                wildcard = self.heap.dynamic_subscript_location(
                    source,
                    DYNAMIC_SUBSCRIPT_WILDCARD,
                )
                values.extend(self.state.read(exact, fallback=()))
                values.extend(self.state.read(wildcard, fallback=()))
                values.extend(self.state.read_contained(wildcard))
            if not values:
                values.extend(sources)
                values.append(self._external_value_location(procedure))
            self._bind_runtime_local(
                procedure,
                target,
                tuple(dict.fromkeys(values)),
            )

    def _apply_definition_transfer(
        self,
        procedure: object,
        operation: object,
        *,
        related_locations: tuple[HeapLocation, ...] | None = None,
    ) -> HeapLocation | None:
        if isinstance(operation, py_ast.TypeAlias):
            deferred_state = self._capture_flow_state()
            value_locations = self.locations_for_expression(
                procedure,
                operation.value,
            )
            parameter_locations = self._merge_expression_locations(
                procedure,
                *getattr(operation, "params", ()),
            )
            alias = HeapLocation(
                self.heap.allocation_object(
                    procedure,
                    operation,
                    label=f"type alias {operation.name}",
                    context=self._current_context,
                )
            )
            if value_locations:
                self.state.write(
                    self.heap.dynamic_attribute_location(alias, "__value__"),
                    value_locations,
                    UpdatePolicy.STRONG,
                )
            if parameter_locations:
                self.state.write(
                    self.heap.dynamic_attribute_location(alias, "__type_params__"),
                    parameter_locations,
                    UpdatePolicy.STRONG,
                )
            # PEP 695 aliases evaluate their value lazily.  Preserve both the
            # deferred state and the state in which the value has been forced;
            # clients can therefore soundly analyze programs regardless of
            # whether a later operation materializes ``__value__``.
            forced_state = self._capture_flow_state()
            self._restore_flow_state(
                self._join_flow_states((deferred_state, forced_state))
            )
            alias_values = (alias,)
            if self._is_module_scope(procedure):
                target = self.effect_builder.global_location(
                    procedure,
                    operation.name,
                )
                self.state.write(target, alias_values, UpdatePolicy.STRONG)
                self.heap.mark_all_escaped(alias_values)
                self.state.mark_escaped(alias_values)
            self._bind_definition_local(
                procedure,
                operation.name,
                alias_values,
            )
            return alias
        if not isinstance(operation, (py_ast.FunctionDef, py_ast.ClassDef)):
            return None

        label = (
            f"function {operation.name}"
            if isinstance(operation, py_ast.FunctionDef)
            else f"class {operation.name}"
        )
        definition = HeapLocation(
            self.heap.allocation_object(
                procedure,
                operation,
                label=label,
                context=self._current_context,
            )
        )
        default_locations: list[HeapLocation] = []
        if isinstance(operation, py_ast.FunctionDef):
            defaults = tuple(
                getattr(operation.code.codeparameters, "defaults", ())
            )
            for index, default in enumerate(defaults):
                locations = self.locations_for_expression(procedure, default)
                self._definition_default_locations[
                    (id(operation.code), index)
                ] = locations
                default_locations.extend(locations)

        related_expressions = self._definition_header_expressions(operation)
        if related_locations is None:
            related_locations = tuple(
                dict.fromkeys(
                    location
                    for expression in related_expressions
                    for location in self.locations_for_expression(
                        procedure,
                        expression,
                    )
                )
            )
        decorated_or_dynamic = ()
        if getattr(operation, "decorators", ()):
            decorated_or_dynamic = (self._external_value_location(procedure),)
        values = tuple(dict.fromkeys((definition, *decorated_or_dynamic)))
        if isinstance(operation, py_ast.ClassDef):
            self._class_definitions[
                (self._module_owner(procedure), operation.name)
            ] = definition
        if self._is_module_scope(procedure):
            target = self.effect_builder.global_location(
                procedure,
                operation.name,
            )
            self.state.write(target, values, UpdatePolicy.STRONG)
            self.heap.mark_all_escaped(values)
            self.state.mark_escaped(values)
        self._bind_definition_local(procedure, operation.name, values)

        if default_locations:
            self.state.write(
                self.heap.dynamic_attribute_location(
                    definition,
                    "__defaults__",
                ),
                tuple(dict.fromkeys(default_locations)),
                UpdatePolicy.STRONG,
            )
        if isinstance(operation, py_ast.FunctionDef):
            closure_locations = tuple(
                dict.fromkeys(
                    self.effect_builder.cell_location(cell, procedure)
                    for cell in code_closure_cells(operation.code)
                )
            )
            if closure_locations:
                self.state.write(
                    self.heap.dynamic_attribute_location(
                        definition,
                        "__closure__",
                    ),
                    closure_locations,
                    UpdatePolicy.STRONG,
                )
        if isinstance(operation, py_ast.ClassDef):
            base_locations = self._merge_expression_locations(
                procedure,
                *getattr(operation, "bases", ()),
            )
            if base_locations:
                self.state.write(
                    self.heap.dynamic_attribute_location(definition, "__bases__"),
                    base_locations,
                    UpdatePolicy.STRONG,
                )
            implicit_class_cell = class_cell(operation)
            if implicit_class_cell is not None:
                self.state.write(
                    self.effect_builder.cell_location(
                        implicit_class_cell,
                        procedure,
                    ),
                    (definition,),
                    UpdatePolicy.STRONG,
                )
        if related_locations:
            self.state.write(
                self.heap.dynamic_attribute_location(
                    definition,
                    "__definition_inputs__",
                ),
                related_locations,
                UpdatePolicy.STRONG,
            )
        return definition

    def _is_module_scope(self, procedure: object) -> bool:
        return (
            isinstance(procedure, py_ast.Code)
            and id(procedure) not in self._lexical_parents
        )

    def _module_owner(self, procedure: object) -> object:
        explicit = getattr(procedure, "module", None)
        if explicit is not None:
            return explicit
        cached = self._module_owners.get(id(procedure))
        if cached is not None:
            return cached
        parent = self._lexical_parents.get(id(procedure))
        if parent is not None:
            owner = self._module_owner(parent)
            self._module_owners[id(procedure)] = owner
            return owner
        origin = getattr(getattr(procedure, "annotation", None), "origin", ()) or ()
        for item in origin:
            if isinstance(item, str) and item.startswith("source("):
                payload = item[len("source(") :].rstrip(")")
                filename = payload.rsplit(":", 1)[0]
                owner = ("source-module", filename)
                self._module_owners[id(procedure)] = owner
                return owner
        owner = ("code-module", id(procedure))
        self._module_owners[id(procedure)] = owner
        return owner

    def _bind_definition_local(
        self,
        procedure: object,
        name: str,
        locations: tuple[HeapLocation, ...],
    ) -> None:
        key = (id(procedure), name)
        local = self._definition_locals.get(key)
        if local is None:
            local = py_ast.Local(name)
            self._definition_locals[key] = local
        self._bind_runtime_local(procedure, local, locations)

    def _scope_members(
        self,
        procedure: object,
        environment: HeapEnvironment,
    ) -> dict[str, tuple[HeapLocation, ...]]:
        members: dict[str, list[HeapLocation]] = {}
        procedure_id = id(procedure)
        keys = set(environment.storage_overrides) | set(
            environment.allocation_sites
        )
        for key in keys:
            if key[0] != procedure_id:
                continue
            name = environment.local_names.get(key)
            if not name:
                continue
            storage = self.heap._environment_storage(environment, key)
            members.setdefault(name, []).extend(
                self.heap.location_for_raw(raw) for raw in storage
            )
        return {
            name: tuple(dict.fromkeys(locations))
            for name, locations in members.items()
            if locations
        }

    @staticmethod
    def _definition_header_expressions(operation: object) -> tuple[object, ...]:
        expressions: list[object] = []
        if isinstance(operation, py_ast.FunctionDef):
            expressions.extend(
                code_definition_annotations(operation.code)
            )
        if isinstance(operation, py_ast.ClassDef):
            expressions.extend(getattr(operation, "bases", ()))
            expressions.extend(
                keyword[1]
                if isinstance(keyword, tuple) and len(keyword) == 2
                else keyword
                for keyword in getattr(operation, "keywords", ())
            )
        expressions.extend(getattr(operation, "decorators", ()))
        type_params = getattr(operation, "type_params", None)
        if type_params is not None:
            expressions.append(type_params)
        return tuple(expressions)

    def _apply_external_boundary_transfer(
        self,
        procedure: object,
        operation: object,
    ) -> None:
        expressions: list[object] = []
        if isinstance(operation, py_ast.OutputBlock):
            expressions.extend(
                output.expr
                for output in getattr(operation, "outputs", ())
                if getattr(output, "expr", None) is not None
            )
        elif isinstance(operation, py_ast.Output):
            expressions.append(operation.expr)
        elif isinstance(operation, py_ast.Print):
            expressions.extend(
                expression
                for expression in (operation.target, operation.expr)
                if expression is not None
            )
        if not expressions:
            return
        escaped = tuple(
            dict.fromkeys(
                location
                for expression in expressions
                for location in self.locations_for_expression(procedure, expression)
            )
        )
        self.heap.mark_all_escaped(escaped)
        self.state.mark_escaped(escaped)

    def _apply_call_transfer(self, procedure: object, operation: object) -> None:
        call = self._call_expression(operation)
        if call is None:
            return
        if isinstance(call, py_ast.DirectCall) and isinstance(call.code, py_ast.Code):
            self._bind_direct_call(procedure, operation, call)
            return
        call_name = resolve_call_name(call)
        function_model = self.intrinsics.function_model(call_name)
        collection_model = self.intrinsics.collection_mutator(call_name)
        fully_modeled_heap_calls = {
            "setattr",
            "builtins.setattr",
            "delattr",
            "builtins.delattr",
            "interpreter_getitem",
            "interpreter_setitem",
            "interpreter_delitem",
        }
        if (
            function_model is not None
            or collection_model is not None
            or call_name in fully_modeled_heap_calls
        ):
            escaped: list[HeapLocation] = []
            actuals = tuple(actual_argument_expressions(call))
            if collection_model is not None and isinstance(call, py_ast.MethodCall):
                # Name-only method recognition cannot prove a builtin receiver.
                # Retain the collection effect for precision, but conservatively
                # expose receiver and operands as an arbitrary user method may.
                escaped.extend(self.locations_for_expression(procedure, call.expr))
                for actual in actuals:
                    escaped.extend(
                        self.locations_for_expression(procedure, actual)
                    )
            if function_model is not None:
                if function_model.escapes_self and isinstance(call, py_ast.MethodCall):
                    escaped.extend(
                        self.locations_for_expression(procedure, call.expr)
                    )
                for index in function_model.escape_arg_indices:
                    if index < len(actuals):
                        escaped.extend(
                            self.locations_for_expression(
                                procedure,
                                actuals[index],
                            )
                        )
            escaped_locations = tuple(dict.fromkeys(escaped))
            self.heap.mark_all_escaped(escaped_locations)
            self.state.mark_escaped(escaped_locations)
            return
        effect = self.effect_builder.unresolved_call_effect(procedure, call)
        self.heap.mark_all_escaped(effect.escapes)
        self.state.mark_escaped(effect.escapes)

    def _bind_direct_call(
        self,
        caller: object,
        operation: object,
        call: py_ast.DirectCall,
    ) -> None:
        callee = call.code
        if getattr(callee, "module", None) is None:
            self._module_owners.setdefault(id(callee), self._module_owner(caller))
        actual_bindings = self._direct_call_actual_locations(caller, callee, call)
        possible_returns = self._evaluate_direct_call_with_bindings(
            caller,
            call,
            actual_bindings,
        )
        targets = assigned_locals(operation)
        if not targets:
            return
        if len(targets) == 1:
            if possible_returns:
                self._bind_runtime_local(
                    caller,
                    targets[0],
                    possible_returns,
                )
            return
        if id(call) not in self._last_direct_call_summary:
            for target in targets:
                if possible_returns:
                    self._bind_runtime_local(caller, target, possible_returns)
            return
        summary = self._last_direct_call_summary[id(call)]
        for index, target in enumerate(targets):
            if index >= len(summary.returns):
                continue
            target_locations = list(summary.returns[index])
            for param_idx in summary.param_returns.get(index, frozenset()):
                target_locations.extend(actual_bindings.get(param_idx, ()))
            self._bind_runtime_local(
                caller,
                target,
                tuple(dict.fromkeys(target_locations)),
            )

    def _evaluate_direct_call_expression(
        self,
        caller: object,
        call: py_ast.DirectCall,
    ) -> tuple[HeapLocation, ...]:
        actual_bindings = self._direct_call_actual_locations(caller, call.code, call)
        return self._evaluate_direct_call_with_bindings(
            caller,
            call,
            actual_bindings,
        )

    def _evaluate_direct_call_with_bindings(
        self,
        caller: object,
        call: py_ast.DirectCall,
        actual_bindings: dict[int, tuple[HeapLocation, ...]],
    ) -> tuple[HeapLocation, ...]:
        callee = call.code
        cache_key = self._direct_call_cache_key(call, actual_bindings)
        cached = self._direct_call_evaluation_cache.get(cache_key)
        if cached is not None:
            return cached

        deferred_kind = self._deferred_code_kind(callee)
        if deferred_kind is not None:
            deferred = HeapLocation(
                self.heap.allocation_object(
                    caller,
                    (deferred_kind, id(call)),
                    label=deferred_kind,
                    context=self._current_context,
                )
            )
            self._deferred_activations[deferred.root] = _DeferredActivation(
                callee,
                actual_bindings,
            )
            captured = tuple(
                dict.fromkeys(
                    location
                    for locations in actual_bindings.values()
                    for location in locations
                )
            )
            if captured:
                self.state.write(
                    self.heap.dynamic_attribute_location(
                        deferred,
                        "__captured_arguments__",
                    ),
                    captured,
                    UpdatePolicy.STRONG,
                )
            result: tuple[HeapLocation, ...] = (deferred,)
            self._direct_call_evaluation_cache[cache_key] = result
            return result

        previous_context = self._current_context
        self._current_context = (
            *previous_context,
            self._context_token(call),
            self._evaluation_epoch,
        )
        try:
            summary = self._callee_summary(callee, actual_bindings)
        finally:
            self._current_context = previous_context
        self._direct_call_summary_cache[cache_key] = summary
        self._last_direct_call_summary[id(call)] = summary
        if summary.raise_state is not None and self._operation_call_raises:
            raised_state = summary.raise_state.copy()
            if summary.raises:
                raised_state.set_raised(caller, summary.raises)
            self._operation_call_raises[-1].append(
                _FlowState(
                    raised_state,
                    summary.raise_environment
                    or summary.environment
                    or self.heap.snapshot_environment(),
                    dict(self._definition_default_locations),
                )
            )
        if summary.normal_state is None and self._operation_normal_possible:
            self._operation_normal_possible[-1] = False
        self._apply_callee_summary(summary, caller)
        for param_idx in summary.param_escapes:
            actual_locations = actual_bindings.get(param_idx, ())
            if actual_locations:
                self.heap.mark_all_escaped(tuple(actual_locations))

        possible_returns: list[HeapLocation] = []
        for return_index, return_locations in enumerate(summary.returns):
            possible_returns.extend(return_locations)
            for param_idx in summary.param_returns.get(
                return_index,
                frozenset(),
            ):
                possible_returns.extend(actual_bindings.get(param_idx, ()))
        result = tuple(dict.fromkeys(possible_returns))
        self._direct_call_evaluation_cache[cache_key] = result
        return result

    @staticmethod
    def _deferred_code_kind(callee: py_ast.Code) -> str | None:
        origin = getattr(getattr(callee, "annotation", None), "origin", ()) or ()
        if "converted_generator" in origin or "converted_genexpr" in origin:
            return "generator"
        if "converted_async_function" in origin:
            return "coroutine"
        return None

    def _direct_call_cache_key(
        self,
        call: py_ast.DirectCall,
        actual_bindings: dict[int, tuple[HeapLocation, ...]],
    ) -> tuple[object, ...]:
        return (
            "direct-call",
            self._evaluation_epoch,
            id(call),
            self._summary_key(call.code, actual_bindings),
        )

    def _propagate_escapes_transitively(self) -> None:
        """Propagate escape through container/closure values.

        If container location C is marked escaped, and C's heap state
        (values/contaminants) holds location V, then V's root should also
        be marked escaped — the value is reachable from outside the
        procedure via the escaped container.

        This is a fixed-point iteration because nested containers may
        transitively hold further values (e.g. outer -> inner -> value).
        """
        if not self.heap.policy.track_escapes:
            return
        changed = True
        while changed:
            changed = False
            new_escaped: list[HeapLocation] = []
            # Check all known location -> values mappings
            for mapping in (self.state.values, self.state.contaminants):
                for container_loc, value_locs in mapping.items():
                    if not self._location_is_escaped(container_loc):
                        continue
                    for value_loc in value_locs:
                        if not self._location_is_escaped(value_loc):
                            new_escaped.append(value_loc)
            # Also propagate through return values: if a return slot (ret0)
            # contains locations, those are also reachable from outside.
            for ret_locs in self.state.returns.values():
                for ret_loc in ret_locs:
                    if not self._location_is_escaped(ret_loc):
                        new_escaped.append(ret_loc)
            if new_escaped:
                self.heap.mark_all_escaped(tuple(new_escaped))
                self.state.mark_escaped(tuple(new_escaped))
                changed = True

    def _location_is_escaped(self, location: HeapLocation) -> bool:
        from .model import HeapEscapeState

        return (
            location in self.state.escaped
            or location.root in self.heap._escaped_objects
            or location.root.escape
            in {
                HeapEscapeState.ESCAPED,
                HeapEscapeState.EXTERNAL,
                HeapEscapeState.UNKNOWN,
            }
        )

    def _callee_summary(
        self,
        callee: py_ast.Code,
        actual_bindings: dict[int, tuple[HeapLocation, ...]],
    ) -> _CallSummary:
        if callee in self._summary_in_progress:
            return self._conservative_return_summary(callee)

        self._summary_in_progress.add(callee)
        caller_state = self.state
        caller_environment = self.heap.snapshot_environment()
        # Analyze a known callee against the heap that exists at this call
        # site.  Starting from an empty state loses field/global/cell reads and
        # makes summaries stale after caller-side mutations.
        self.state = caller_state.copy()
        self.state.returns.pop(callee, None)
        self.state.return_slots.pop(callee, None)
        self.state.yields.pop(callee, None)
        self.state.raised.pop(callee, None)
        summary_deletes: list[HeapLocation] = []
        yield_events: list[tuple[_FlowState, tuple[HeapLocation, ...]]] = []
        self._summary_delete_stack.append(summary_deletes)
        is_generator = self._deferred_code_kind(callee) == "generator"
        if is_generator:
            self._yield_state_stack.append(yield_events)
        try:
            self._bind_callee_formals(callee, actual_bindings)
            self.bind_parameters(callee)
            initial_formal_locations = self._callee_formal_locations(callee)
            outcome = self.analyze_node(callee, callee.ast)
            normal_candidates = tuple(
                state
                for state in (
                    outcome.normal,
                    outcome.abrupt.get("return"),
                )
                if state is not None
            )
            normal_flow = (
                self._join_flow_states(normal_candidates)
                if normal_candidates
                else None
            )
            raise_flow = outcome.abrupt.get("raise")
            all_exit_states = tuple(
                state
                for state in (
                    normal_flow,
                    raise_flow,
                    *(state for state, _yielded in yield_events),
                    *(
                        state
                        for kind, state in outcome.abrupt.items()
                        if kind not in {"return", "raise"}
                    ),
                )
                if state is not None
            )
            joined = self._join_flow_states(all_exit_states)
            self._restore_flow_state(joined)
            self._propagate_escapes_transitively()
            summary_state = self.state
            return_locations = (
                normal_flow.heap_state.return_slots.get(
                    callee,
                    self._return_locations(callee),
                )
                if normal_flow is not None
                else ()
            )
            param_returns = self._compute_param_returns(
                return_locations,
                initial_formal_locations,
            )
            param_escapes = self._compute_param_escapes(
                summary_state,
                initial_formal_locations,
            )
            callee_environment = self.heap.snapshot_environment()
            # Callee locals/formals cease to be live at return and must not
            # inflate caller reference counts.  Preserve caller bindings plus
            # globally relevant object labels and escape facts only.
            caller_environment.object_labels.update(
                callee_environment.object_labels
            )
            caller_environment.escaped_objects.update(
                callee_environment.escaped_objects
            )
            def cleaned(flow: _FlowState | None) -> HeapState | None:
                if flow is None:
                    return None
                state = flow.heap_state.copy()
                state.raised.pop(callee, None)
                state.yields.pop(callee, None)
                state.returns.pop(callee, None)
                state.return_slots.pop(callee, None)
                state.active_exceptions.pop(callee, None)
                return state

            normal_state = cleaned(normal_flow)
            raise_state = cleaned(raise_flow)
            raised_locations = (
                raise_flow.heap_state.raised.get(callee, ())
                if raise_flow is not None
                else ()
            )
            yielded_locations = summary_state.yields.get(callee, ())
            yield_steps = tuple(
                (
                    cleaned(event_state) or event_state.heap_state.copy(),
                    caller_environment,
                    yielded,
                )
                for event_state, yielded in yield_events
            )
            post_state = normal_state or raise_state or cleaned(joined)
            assert post_state is not None
            result = _CallSummary(
                state=post_state,
                returns=return_locations,
                environment=caller_environment,
                normal_state=normal_state,
                normal_environment=caller_environment,
                raise_state=raise_state,
                raise_environment=caller_environment,
                deletes=tuple(dict.fromkeys(summary_deletes)),
                raises=raised_locations,
                yields=yielded_locations,
                yield_steps=yield_steps,
                param_returns=param_returns,
                param_escapes=param_escapes,
            )
            return result
        finally:
            if is_generator:
                self._yield_state_stack.pop()
            self._summary_delete_stack.pop()
            self.state = caller_state
            self.heap.restore_environment(caller_environment)
            self._summary_in_progress.discard(callee)

    def _apply_callee_summary(
        self,
        summary: _CallSummary,
        caller: object,
    ) -> None:
        self._record_summary_deletes(summary.deletes)
        # The summary starts from this exact call site's state, so it already
        # is the complete post-call state.  Joining it with the pre-call state
        # would resurrect values removed by strong writes and must-deletes.
        selected_state = summary.normal_state or summary.state
        self.state = selected_state.copy()
        selected_environment = summary.normal_environment or summary.environment
        if selected_environment is not None:
            self.heap.restore_environment(selected_environment)
        self.heap.mark_all_escaped(tuple(summary.state.escaped))
        # Propagate transitively after merging summary state: the caller
        # may now have new escaped containers holding values that should
        # also be considered escaped.
        self._propagate_escapes_transitively()

    def _record_summary_deletes(self, deletes: tuple[HeapLocation, ...]) -> None:
        if self._summary_delete_stack and deletes:
            self._summary_delete_stack[-1].extend(deletes)

    def _summary_key(
        self,
        callee: py_ast.Code,
        actual_bindings: dict[int, tuple[HeapLocation, ...]],
    ) -> tuple[object, ...]:
        actual_key = tuple(
            actual_bindings.get(index, ())
            for index, _formal in enumerate(self._callee_formals(callee))
        )
        return callee, actual_key

    def _return_locations(
        self,
        callee: py_ast.Code,
    ) -> tuple[tuple[HeapLocation, ...], ...]:
        code_parameters = getattr(callee, "codeparameters", None)
        if code_parameters is None:
            return ()
        locations: list[tuple[HeapLocation, ...]] = []
        for index, target in enumerate(getattr(code_parameters, "returnparams", ())):
            if isinstance(target, py_ast.Local):
                target_locations = self.heap.locations_for_local(callee, target)
                if target_locations:
                    locations.append(target_locations)
                    continue
            locations.append((HeapLocation(self.heap.return_object(callee, index)),))
        return tuple(locations)

    def _callee_formal_locations(
        self,
        callee: py_ast.Code,
    ) -> dict[int, tuple[HeapLocation, ...]]:
        """Return a dict mapping formal param index -> its heap locations."""
        formal_locations: dict[int, tuple[HeapLocation, ...]] = {}
        for idx, formal in enumerate(self._callee_formals(callee)):
            locs = self.heap.locations_for_local(callee, formal)
            if locs:
                formal_locations[idx] = locs
        return formal_locations

    def _compute_param_returns(
        self,
        return_locations: tuple[tuple[HeapLocation, ...], ...],
        formal_locations: dict[int, tuple[HeapLocation, ...]],
    ) -> dict[int, frozenset[int]]:
        """Return a dict mapping return_index -> formal_param_index when a
        return directly carries a formal parameter's location."""
        if not return_locations:
            return {}
        if not formal_locations:
            return {}
        param_returns: dict[int, frozenset[int]] = {}
        for ret_idx, ret_locs in enumerate(return_locations):
            matches: set[int] = set()
            for formal_idx, formal_locs in formal_locations.items():
                if any(ret_loc in formal_locs for ret_loc in ret_locs):
                    matches.add(formal_idx)
            if matches:
                param_returns[ret_idx] = frozenset(matches)
        return param_returns

    def _compute_param_escapes(
        self,
        summary_state: HeapState,
        formal_locations: dict[int, tuple[HeapLocation, ...]],
    ) -> frozenset[int]:
        """Return the set of formal parameter indices whose locations escape."""
        if not summary_state.escaped:
            return frozenset()
        if not formal_locations:
            return frozenset()
        escaped: set[int] = set()
        for idx, locs in formal_locations.items():
            for loc in locs:
                if loc in summary_state.escaped:
                    escaped.add(idx)
                    break
        return frozenset(escaped)

    def _conservative_return_summary(
        self,
        callee: py_ast.Code,
    ) -> _CallSummary:
        state = self.state.copy()
        returns = self._return_locations(callee)
        if not returns:
            code_parameters = getattr(callee, "codeparameters", None)
            returns = tuple(
                (HeapLocation(self.heap.return_object(callee, index)),)
                for index, _target in enumerate(
                    getattr(code_parameters, "returnparams", ())
                    if code_parameters is not None
                    else ()
                )
            )
        return _CallSummary(
            state=state,
            returns=returns,
            environment=self.heap.snapshot_environment(),
            normal_state=state,
            normal_environment=self.heap.snapshot_environment(),
        )

    def _bind_callee_formals(
        self,
        callee: py_ast.Code,
        actual_bindings: dict[int, tuple[HeapLocation, ...]],
    ) -> None:
        for index, formal in enumerate(self._callee_formals(callee)):
            actual_locations = actual_bindings.get(index, ())
            self.heap.bind_parameter(callee, formal, index, actual_locations)

    @staticmethod
    def _callee_formals(callee: py_ast.Code) -> tuple[py_ast.Local, ...]:
        params = getattr(callee, "codeparameters", None)
        if params is None:
            return ()
        formals: list[py_ast.Local] = []
        for candidate in (
            getattr(params, "selfparam", None),
            *getattr(params, "posonlyparams", ()),
            *getattr(params, "params", ()),
            getattr(params, "vparam", None),
            getattr(params, "kparam", None),
        ):
            if isinstance(candidate, py_ast.Local) and candidate not in formals:
                formals.append(candidate)
        return tuple(formals)

    def _direct_call_actual_locations(
        self,
        caller: object,
        callee: py_ast.Code,
        call: py_ast.DirectCall,
    ) -> dict[int, tuple[HeapLocation, ...]]:
        """Bind a resolved call according to Python's formal parameter layout."""
        params = callee.codeparameters
        formals = self._callee_formals(callee)
        evaluated_operands = self._evaluate_call_operands(caller, call)
        formal_indices = {id(formal): index for index, formal in enumerate(formals)}
        bindings: dict[int, list[HeapLocation]] = {
            index: [] for index in range(len(formals))
        }
        uncertainly_bound: set[int] = set()

        def evaluate(expression_procedure, expression):
            cached = evaluated_operands.get(id(expression))
            if cached is not None:
                return cached
            return self.locations_for_expression(
                expression_procedure,
                expression,
            )

        def bind(formal, locations):
            bindings[formal_indices[id(formal)]].extend(locations)

        selfparam = getattr(params, "selfparam", None)
        selfarg = getattr(call, "selfarg", None)
        if isinstance(selfparam, py_ast.Local) and selfarg is not None:
            bind(selfparam, evaluate(caller, selfarg))

        encoded_params = list(getattr(params, "params", ()))
        encoded_names = list(getattr(params, "paramnames", ()))
        parameter_entries = list(zip(encoded_names, encoded_params))
        regular_params = [
            formal
            for name, formal in parameter_entries
            if not (isinstance(name, str) and name.startswith("kwonly:"))
        ]
        positional_slots = [
            *getattr(params, "posonlyparams", ()),
            *regular_params,
        ]
        positional_items = call_positional_items(call)
        positional_actuals = list(getattr(call, "args", ()))
        extra_positional: list[tuple[HeapLocation, ...]] = []
        positional_index = 0
        if positional_items:
            uncertain_spread = False
            for is_spread, actual in positional_items:
                locations = evaluate(caller, actual)
                expanded = (
                    self._ordered_contained_values(locations)
                    if is_spread
                    else locations
                )
                if is_spread and not expanded:
                    possible = tuple(
                        dict.fromkeys(
                            (*locations, self._external_value_location(caller))
                        )
                    )
                    for formal in positional_slots[positional_index:]:
                        if isinstance(formal, py_ast.Local):
                            bind(formal, possible)
                            uncertainly_bound.add(formal_indices[id(formal)])
                    extra_positional.append(possible)
                    uncertain_spread = True
                    continue
                if uncertain_spread and not is_spread:
                    for formal in positional_slots[positional_index:]:
                        if isinstance(formal, py_ast.Local):
                            bind(formal, expanded)
                            uncertainly_bound.add(formal_indices[id(formal)])
                    extra_positional.append(expanded)
                    continue
                for item_locations in (
                    ((location,) for location in expanded)
                    if is_spread
                    else (expanded,)
                ):
                    if positional_index < len(positional_slots):
                        formal = positional_slots[positional_index]
                        if isinstance(formal, py_ast.Local):
                            bind(formal, item_locations)
                    else:
                        extra_positional.append(item_locations)
                    positional_index += 1
        else:
            for index, actual in enumerate(positional_actuals):
                locations = evaluate(caller, actual)
                if index < len(positional_slots):
                    formal = positional_slots[index]
                    if isinstance(formal, py_ast.Local):
                        bind(formal, locations)
                else:
                    extra_positional.append(locations)

        named_formals = {
            (
                name[len("kwonly:") :]
                if name.startswith("kwonly:")
                else name
            ): formal
            for name, formal in parameter_entries
            if isinstance(name, str) and isinstance(formal, py_ast.Local)
        }
        extra_keywords: list[tuple[str | None, tuple[HeapLocation, ...]]] = []
        for keyword in getattr(call, "kwds", ()):
            if not (isinstance(keyword, tuple) and len(keyword) == 2):
                extra_keywords.append((None, evaluate(caller, keyword)))
                continue
            name, actual = keyword
            locations = evaluate(caller, actual)
            formal = named_formals.get(name)
            if formal is None:
                extra_keywords.append((name if isinstance(name, str) else None, locations))
                continue
            bind(formal, locations)

        vargs_locations: tuple[HeapLocation, ...] = ()
        positional_spreads = call_positional_spreads(call)
        if positional_spreads:
            vargs_locations = tuple(
                dict.fromkeys(
                    location
                    for spread in positional_spreads
                    for location in evaluate(caller, spread)
                )
            )
        elif getattr(call, "vargs", None) is not None:
            vargs_locations = evaluate(caller, call.vargs)

        kargs_locations: tuple[HeapLocation, ...] = ()
        keyword_spreads = call_keyword_spreads(call)
        if keyword_spreads:
            kargs_locations = tuple(
                dict.fromkeys(
                    location
                    for spread in keyword_spreads
                    for location in evaluate(caller, spread)
                )
            )
        elif getattr(call, "kargs", None) is not None:
            kargs_locations = evaluate(caller, call.kargs)

        explicitly_bound = {
            index for index, locations in bindings.items() if locations
        }

        if vargs_locations and not positional_items:
            expanded_vargs = self._contained_values(vargs_locations)
            if not expanded_vargs:
                expanded_vargs = (
                    *vargs_locations,
                    self._external_value_location(caller),
                )
            for formal in positional_slots:
                if not isinstance(formal, py_ast.Local):
                    continue
                index = formal_indices[id(formal)]
                if not bindings[index]:
                    bind(formal, expanded_vargs)

        if kargs_locations:
            for name, formal in named_formals.items():
                index = formal_indices[id(formal)]
                if bindings[index]:
                    continue
                possible: list[HeapLocation] = []
                for root in kargs_locations:
                    exact = self.heap.dynamic_subscript_location(
                        root,
                        f"[{name!r}]",
                    )
                    wildcard = self.heap.dynamic_subscript_location(
                        root,
                        DYNAMIC_SUBSCRIPT_WILDCARD,
                    )
                    possible.extend(self.state.read(exact, fallback=()))
                    possible.extend(self.state.read_contained(wildcard))
                if not possible:
                    possible.extend(kargs_locations)
                    possible.append(self._external_value_location(caller))
                    uncertainly_bound.add(index)
                bind(formal, tuple(dict.fromkeys(possible)))

        defaults = list(getattr(params, "defaults", ()))
        if defaults:
            defaultable_formals = [
                *getattr(params, "posonlyparams", ()),
                *encoded_params,
            ]
            default_formals = defaultable_formals[-len(defaults):]
            for default_index, (formal, default) in enumerate(
                zip(default_formals, defaults)
            ):
                if not isinstance(formal, py_ast.Local):
                    continue
                if (
                    isinstance(default, py_ast.Existing)
                    and getattr(default.object, "pyobj", None) is MISSING_DEFAULT
                ):
                    continue
                index = formal_indices[id(formal)]
                if (
                    not bindings[index]
                    or index in uncertainly_bound
                    or (
                        index not in explicitly_bound
                        and (vargs_locations or kargs_locations)
                    )
                ):
                    locations = self._definition_default_locations.get(
                        (id(callee), default_index)
                    )
                    if locations is None:
                        locations = evaluate(callee, default)
                    bind(formal, locations)

        vparam = getattr(params, "vparam", None)
        if isinstance(vparam, py_ast.Local):
            packed = HeapLocation(
                self.heap.summary_object(
                    ("varargs", id(callee), id(call)),
                    label="*args",
                )
            )
            element_index = 0
            for locations in extra_positional:
                self.state.write(
                    self.heap.dynamic_subscript_location(
                        packed,
                        f"[{element_index}]",
                    ),
                    locations,
                    UpdatePolicy.STRONG,
                )
                element_index += 1
            expanded_vargs = self._expand_contained_locations(vargs_locations)
            if expanded_vargs:
                self.state.write(
                    self.heap.dynamic_subscript_location(
                        packed,
                        DYNAMIC_SUBSCRIPT_WILDCARD,
                    ),
                    expanded_vargs,
                    UpdatePolicy.WEAK,
                )
            bind(vparam, (packed,))

        kparam = getattr(params, "kparam", None)
        if isinstance(kparam, py_ast.Local):
            packed = HeapLocation(
                self.heap.summary_object(
                    ("kwargs", id(callee), id(call)),
                    label="**kwargs",
                )
            )
            for name, locations in extra_keywords:
                self.state.write(
                    self.heap.dynamic_subscript_location(
                        packed,
                        f"[{name!r}]" if name is not None else DYNAMIC_SUBSCRIPT_WILDCARD,
                    ),
                    locations,
                    UpdatePolicy.STRONG if name is not None else UpdatePolicy.WEAK,
                )
            expanded_kargs = self._expand_contained_locations(kargs_locations)
            if expanded_kargs:
                self.state.write(
                    self.heap.dynamic_subscript_location(
                        packed,
                        DYNAMIC_SUBSCRIPT_WILDCARD,
                    ),
                    expanded_kargs,
                    UpdatePolicy.WEAK,
                )
            bind(kparam, (packed,))

        return {
            index: tuple(dict.fromkeys(locations))
            for index, locations in bindings.items()
        }

    def _bind_call_result_targets(
        self,
        procedure: object,
        targets: tuple[py_ast.Local, ...],
        call_expression: object,
        *,
        bind: bool = True,
    ) -> tuple[tuple[HeapLocation, ...], ...]:
        if not self.heap.policy.bind_call_results:
            return ()
        operand_locations = self._evaluate_call_operands(
            procedure,
            call_expression,
        )
        kind = self.effect_builder.call_return_kind(call_expression)
        label = self.effect_builder._call_result_label(call_expression)
        modeled_locations = self._modeled_call_return_locations(
            procedure,
            call_expression,
            kind,
            operand_locations,
        )
        slots: list[tuple[HeapLocation, ...]] = []
        for index, target in enumerate(targets):
            site = self.effect_builder.call_return_site(call_expression, index, kind)
            result_locations: tuple[HeapLocation, ...]
            if kind == CALL_RETURN_NONE:
                result_locations = ()
            elif kind in {CALL_RETURN_SELF, CALL_RETURN_ARG}:
                if modeled_locations:
                    result_locations = modeled_locations
                else:
                    result_locations = (
                        HeapLocation(self.heap.summary_object(site, label=label)),
                    )
            elif modeled_locations:
                result_locations = modeled_locations
            elif kind in {CALL_RETURN_FRESH, CALL_RETURN_COPY}:
                result_location = HeapLocation(
                    self.heap.allocation_object(
                        procedure,
                        site,
                        label=label,
                        context=self._current_context,
                    )
                )
                result_locations = (result_location,)
                if kind == CALL_RETURN_COPY:
                    self._copy_call_result_contents(
                        procedure,
                        None,
                        call_expression,
                        (result_location,),
                    )
            elif kind == CALL_RETURN_SUMMARY:
                result_locations = (
                    HeapLocation(self.heap.summary_object(site, label=label)),
                )
            else:
                result_locations = (
                    HeapLocation(
                        self.heap.call_result_object(
                            procedure,
                            site,
                            label=label,
                            context=self._current_context,
                        )
                    ),
                )
            call_name = resolve_call_name(call_expression)
            if (
                kind == CALL_RETURN_FRESH
                and call_name is not None
                and (
                    self._module_owner(procedure),
                    call_name.rsplit(".", 1)[-1],
                )
                in self._class_definitions
            ):
                # A resolved ``__new__`` may return a pre-existing object or
                # an instance of another class.  Retain the normal fresh
                # allocation while adding an opaque alternative.
                result_locations = tuple(
                    dict.fromkeys(
                        (*result_locations, self._external_value_location(procedure))
                    )
                )
            slots.append(tuple(dict.fromkeys(result_locations)))
            self._attach_known_class(
                procedure,
                call_expression,
                result_locations,
            )
            if bind:
                if result_locations:
                    self._bind_runtime_local(
                        procedure,
                        target,
                        result_locations,
                    )
                else:
                    self._clear_runtime_local(procedure, target)
        return tuple(slots)

    def _attach_known_class(
        self,
        procedure: object,
        call: object,
        instances: tuple[HeapLocation, ...],
    ) -> None:
        call_name = resolve_call_name(call)
        if call_name is None:
            return
        class_location = self._class_definitions.get(
            (self._module_owner(procedure), call_name.rsplit(".", 1)[-1])
        )
        if class_location is None:
            return
        for instance in instances:
            self.state.write(
                self.heap.dynamic_attribute_location(instance, "__class__"),
                (class_location,),
                UpdatePolicy.STRONG,
            )
        initializer = self._class_initializers.get(
            (self._module_owner(procedure), call_name.rsplit(".", 1)[-1])
        )
        if initializer is None or id(call) in self._initialized_class_calls:
            return
        self._initialized_class_calls.add(id(call))
        formals = self._callee_formals(initializer)
        bindings: dict[int, tuple[HeapLocation, ...]] = {}
        if formals:
            bindings[0] = instances
        actuals = tuple(getattr(call, "args", ()))
        evaluated = self._last_call_operands.get(id(call), {})
        for index, actual in enumerate(actuals, start=1):
            if index >= len(formals):
                break
            locations = evaluated.get(id(actual))
            if locations is None:
                locations = self.locations_for_expression(procedure, actual)
            bindings[index] = locations
        params = initializer.codeparameters
        encoded_names = list(getattr(params, "paramnames", ()))
        encoded_formals = list(getattr(params, "params", ()))
        formal_indices = {id(formal): index for index, formal in enumerate(formals)}
        named = {
            (
                name[len("kwonly:") :]
                if name.startswith("kwonly:")
                else name
            ): formal_indices[id(formal)]
            for name, formal in zip(encoded_names, encoded_formals)
            if isinstance(name, str)
            and isinstance(formal, py_ast.Local)
            and id(formal) in formal_indices
        }
        for keyword in getattr(call, "kwds", ()):
            if not (isinstance(keyword, tuple) and len(keyword) == 2):
                continue
            name, actual = keyword
            index = named.get(name)
            if index is None:
                continue
            locations = evaluated.get(id(actual))
            if locations is None:
                locations = self.locations_for_expression(procedure, actual)
            bindings[index] = tuple(
                dict.fromkeys((*bindings.get(index, ()), *locations))
            )
        if getattr(call, "vargs", None) is not None or getattr(call, "kargs", None) is not None:
            unknown = (self._external_value_location(procedure),)
            for index in range(len(formals)):
                bindings.setdefault(index, unknown)
        summary = self._callee_summary(initializer, bindings)
        if summary.raise_state is not None and self._operation_call_raises:
            raised_state = summary.raise_state.copy()
            if summary.raises:
                raised_state.set_raised(procedure, summary.raises)
            self._operation_call_raises[-1].append(
                _FlowState(
                    raised_state,
                    summary.raise_environment
                    or summary.environment
                    or self.heap.snapshot_environment(),
                    dict(self._definition_default_locations),
                )
            )
        if summary.normal_state is None and self._operation_normal_possible:
            self._operation_normal_possible[-1] = False
        self._apply_callee_summary(summary, procedure)

    def _apply_pending_call_result(
        self,
        procedure: object,
        operation: object,
    ) -> None:
        pending = self._pending_call_results.pop(id(operation), None)
        if pending is None:
            return
        targets, slots = pending
        for index, target in enumerate(targets):
            locations = slots[index] if index < len(slots) else ()
            if locations:
                self._bind_runtime_local(procedure, target, locations)
            else:
                self._clear_runtime_local(procedure, target)

    def _evaluate_call_operands(
        self,
        procedure: object,
        call: object,
    ) -> dict[int, tuple[HeapLocation, ...]]:
        """Evaluate a non-resolved call's operands once, in Python order."""
        evaluated: dict[int, tuple[HeapLocation, ...]] = {}

        def evaluate(expression: object) -> None:
            if expression is None:
                return
            evaluated[id(expression)] = self.locations_for_expression(
                procedure,
                expression,
            )

        if isinstance(call, py_ast.Call):
            evaluate(call.expr)
        elif isinstance(call, py_ast.MethodCall):
            evaluate(call.expr)
            evaluate(call.name)
        elif isinstance(call, py_ast.DirectCall):
            evaluate(call.selfarg)
        for actual in actual_argument_expressions(call):
            # DirectCall.selfarg is already the first element returned by the
            # shared helper; do not execute it twice.
            if isinstance(call, py_ast.DirectCall) and actual is call.selfarg:
                continue
            evaluate(actual)
        self._last_call_operands[id(call)] = evaluated
        return evaluated

    def _modeled_call_return_locations(
        self,
        procedure: object,
        call: object,
        kind: str,
        operand_locations: dict[int, tuple[HeapLocation, ...]] | None = None,
    ) -> tuple[HeapLocation, ...]:
        call_name = resolve_call_name(call)
        actuals = tuple(actual_argument_expressions(call))
        receiver = getattr(call, "expr", None) if isinstance(
            call, py_ast.MethodCall
        ) else getattr(call, "selfarg", None)

        def operand_locs(expression: object) -> tuple[HeapLocation, ...]:
            if operand_locations is not None:
                cached = operand_locations.get(id(expression))
                if cached is not None:
                    return cached
            return self.locations_for_expression(procedure, expression)

        if call_name in {"type", "builtins.type"}:
            return (
                HeapLocation(
                    self.heap.summary_object(
                        ("shared-type-result",),
                        label="type result",
                        type_hint="type",
                    )
                ),
            )
        if call_name == "decimal.getcontext":
            return (
                HeapLocation(
                    self.heap.summary_object(
                        ("decimal-context",),
                        label="decimal context",
                    )
                ),
            )
        if call_name == "logging.getLogger":
            logger_name = (
                self.effect_builder._constant_string(actuals[0])
                if actuals
                else "root"
            )
            return (
                HeapLocation(
                    self.heap.summary_object(
                        ("logging.getLogger", logger_name),
                        label=f"logger {logger_name or '<dynamic>'}",
                    )
                ),
            )
        if call_name == "importlib.import_module" and actuals:
            module_name = self.effect_builder._constant_string(actuals[0])
            if module_name is not None:
                return (
                    HeapLocation(
                        self.heap.module_object(module_name, label=module_name)
                    ),
                )

        if call_name in {
            "next",
            "builtins.next",
            "__next__",
            "anext",
            "builtins.anext",
            "__anext__",
            "send",
            "throw",
        }:
            iterable = receiver if receiver is not None else (actuals[0] if actuals else None)
            if iterable is not None:
                roots = operand_locs(iterable)
                values: list[HeapLocation] = list(
                    self._resume_deferred_activations(
                        procedure,
                        roots,
                        use_yields=True,
                        sent_values=(
                            operand_locs(
                                actuals[0]
                                if receiver is not None
                                else actuals[1]
                            )
                            if call_name == "send"
                            and (
                                (receiver is not None and actuals)
                                or (receiver is None and len(actuals) > 1)
                            )
                            else ()
                        ),
                    )
                )
                for root in roots:
                    wildcard = self.heap.dynamic_subscript_location(
                        root,
                        DYNAMIC_SUBSCRIPT_WILDCARD,
                    )
                    values.extend(self.state.read_contained(wildcard))
                if values:
                    if len(actuals) >= 2:
                        values.extend(operand_locs(actuals[1]))
                    return tuple(dict.fromkeys(values))
                if len(actuals) >= 2:
                    default = operand_locs(actuals[1])
                    if default:
                        return default
                return (self._external_value_location(procedure),)
        if call_name == "close" and receiver is not None:
            roots = operand_locs(receiver)
            self._resume_deferred_activations(
                procedure,
                roots,
                use_yields=False,
            )
            return ()
        if call_name in {"max", "builtins.max", "min", "builtins.min"}:
            positional = tuple(getattr(call, "args", ()))
            if len(positional) == 1:
                values = list(
                    self._contained_values(operand_locs(positional[0]))
                )
                for keyword in getattr(call, "kwds", ()):
                    if (
                        isinstance(keyword, tuple)
                        and len(keyword) == 2
                        and keyword[0] == "default"
                    ):
                        values.extend(operand_locs(keyword[1]))
                return tuple(dict.fromkeys(values)) or (
                    self._external_value_location(procedure),
                )
        if call_name in {"random.choice"} and actuals:
            roots = operand_locs(actuals[0])
            choice_values = self._contained_values(roots)
            return choice_values or (self._external_value_location(procedure),)
        if call_name in {"iter", "builtins.iter", "__iter__"}:
            iterable = receiver if receiver is not None else (actuals[0] if actuals else None)
            if iterable is not None:
                roots = operand_locs(iterable)
                iterator = HeapLocation(
                    self.effect_builder.call_return_object(procedure, call)
                )
                self._copy_locations(roots, (iterator,))
                return tuple(
                    dict.fromkeys(
                        (
                            *roots,
                            iterator,
                            self._external_value_location(procedure),
                        )
                    )
                )
        if kind == CALL_RETURN_SELF and receiver is not None:
            return operand_locs(receiver)
        if kind == CALL_RETURN_ARG:
            model = self.intrinsics.function_model(call_name)
            return_index = model.return_arg_index if model is not None else -1
            expressions = (
                actuals
                if return_index is None or return_index < 0
                else actuals[return_index:return_index + 1]
            )
            return tuple(
                dict.fromkeys(
                    location
                    for expression in expressions
                    for location in operand_locs(expression)
                )
            )

        if call_name in {"getattr", "builtins.getattr"} and len(actuals) >= 2:
            attribute = self.effect_builder._constant_string(actuals[1])
            attributes = (attribute,) if attribute is not None else ("*",)
            target_locations = self.heap.dynamic_attribute_locations(
                operand_locs(actuals[0]),
                attributes,
            )
            values = list(self._read_heap_locations(target_locations))
            if len(actuals) >= 3:
                values.extend(operand_locs(actuals[2]))
            return tuple(dict.fromkeys(values))

        property_names = {
            "get",
            "setdefault",
            "pop",
            "dict.get",
            "dict.setdefault",
            "dict.pop",
            "list.pop",
            "set.pop",
            "popleft",
            "popitem",
            "popfirst",
            "get_and_del",
            "interpreter_getitem",
        }
        if call_name in property_names:
            container_expr = receiver
            args = actuals
            if container_expr is None and actuals:
                container_expr = actuals[0]
                args = actuals[1:]
            if container_expr is not None:
                roots = operand_locs(container_expr)
                if args:
                    subscript = self.effect_builder._constant_subscript(args[0])
                    target_locations = self.heap.dynamic_subscript_locations(
                        roots,
                        (
                            (subscript, DYNAMIC_SUBSCRIPT_WILDCARD)
                            if subscript is not None
                            else (DYNAMIC_SUBSCRIPT_WILDCARD,)
                        ),
                    )
                else:
                    target_locations = self.heap.dynamic_subscript_locations(
                        roots,
                        (DYNAMIC_SUBSCRIPT_WILDCARD,),
                    )
                if args and subscript is None:
                    values = [
                        value
                        for root in roots
                        for value in self.state.read_contained(
                            self.heap.dynamic_subscript_location(
                                root,
                                DYNAMIC_SUBSCRIPT_WILDCARD,
                            )
                        )
                    ]
                elif not args:
                    values = [
                        value
                        for root in roots
                        for value in self.state.read_contained(
                            self.heap.dynamic_subscript_location(
                                root,
                                DYNAMIC_SUBSCRIPT_WILDCARD,
                            )
                        )
                    ]
                else:
                    values = list(self._read_heap_locations(target_locations))
                if call_name in {"get", "dict.get", "pop", "dict.pop"} and len(args) >= 2:
                    values.extend(operand_locs(args[1]))
                if call_name in {"setdefault", "dict.setdefault"} and len(args) >= 2:
                    values.extend(operand_locs(args[1]))
                return tuple(dict.fromkeys(values))

        return ()

    def _resume_deferred_activations(
        self,
        caller: object,
        roots: tuple[HeapLocation, ...],
        *,
        use_yields: bool,
        sent_values: tuple[HeapLocation, ...] = (),
    ) -> tuple[HeapLocation, ...]:
        values: list[HeapLocation] = []
        for root in roots:
            activation = self._deferred_activations.get(root.root)
            if activation is None:
                continue
            previous_context = self._current_context
            self._current_context = (
                *previous_context,
                "resume",
                root.root.key,
                self._evaluation_epoch,
            )
            try:
                if activation.summary is None or sent_values:
                    if sent_values:
                        self._resume_input_stack.append(sent_values)
                    try:
                        activation.summary = self._callee_summary(
                            activation.callee,
                            activation.actual_bindings,
                        )
                    finally:
                        if sent_values:
                            self._resume_input_stack.pop()
                summary = activation.summary
            finally:
                self._current_context = previous_context
            if summary.raise_state is not None and self._operation_call_raises:
                raised_state = summary.raise_state.copy()
                if summary.raises:
                    raised_state.set_raised(caller, summary.raises)
                self._operation_call_raises[-1].append(
                    _FlowState(
                        raised_state,
                        summary.raise_environment
                        or summary.environment
                        or self.heap.snapshot_environment(),
                        dict(self._definition_default_locations),
                    )
                )
            if use_yields:
                if activation.resume_index < len(summary.yield_steps):
                    step_state, step_environment, yielded = summary.yield_steps[
                        activation.resume_index
                    ]
                    activation.resume_index += 1
                    caller_environment = self.heap.snapshot_environment()
                    caller_environment.object_labels.update(
                        step_environment.object_labels
                    )
                    caller_environment.escaped_objects.update(
                        step_environment.escaped_objects
                    )
                    self.state = step_state.copy()
                    self.heap.restore_environment(caller_environment)
                    values.extend(yielded)
                else:
                    if summary.normal_state is None and self._operation_normal_possible:
                        self._operation_normal_possible[-1] = False
                    self._apply_callee_summary(summary, caller)
            else:
                if activation.resume_index == 0:
                    activation.resume_index = 1
                    if summary.normal_state is None and self._operation_normal_possible:
                        self._operation_normal_possible[-1] = False
                    self._apply_callee_summary(summary, caller)
                    for slot in summary.returns:
                        values.extend(slot)
                else:
                    # Re-awaiting a consumed coroutine raises at runtime.
                    values.append(self._external_value_location(caller))
        return tuple(dict.fromkeys(values))

    @staticmethod
    def _context_token(node: object) -> object:
        origin = getattr(getattr(node, "annotation", None), "origin", ()) or ()
        if origin:
            return (
                type(node).__name__,
                tuple(repr(item) for item in origin),
                getattr(node, "name", None),
            )
        line = getattr(node, "line", None)
        column = getattr(node, "column", None)
        if line is not None or column is not None:
            return type(node).__name__, line, column
        return type(node).__name__, id(node)

    def _copy_call_result_contents(
        self,
        procedure: object,
        target: py_ast.Local | None,
        call: object,
        target_locations: tuple[HeapLocation, ...] | None = None,
    ) -> None:
        if target_locations is None:
            if target is None:
                return
            target_locations = self.heap.locations_for_local(procedure, target)
        actuals = tuple(actual_argument_expressions(call))
        call_name = resolve_call_name(call)
        source_exprs: tuple[object, ...]
        retain_all_arguments = {
            "functools.partial",
            "functools.lru_cache",
            "functools.cached_property",
            "functools.singledispatch",
            "functools.wraps",
            "collections.ChainMap",
            "collections.defaultdict",
            "collections.Counter",
            "collections.OrderedDict",
            "collections.deque",
            "collections.UserDict",
            "collections.UserList",
            "collections.UserString",
            "itertools.chain",
            "itertools.product",
            "itertools.compress",
            "itertools.starmap",
            "zip",
            "builtins.zip",
            "interpreter_build_map",
            "interpreter_merge_varargs",
            "interpreter_merge_kwargs",
        }
        if isinstance(call, py_ast.MethodCall):
            source_exprs = (call.expr,)
        elif call_name in retain_all_arguments:
            source_exprs = actuals
        elif call_name in {"map", "builtins.map", "filter", "builtins.filter"}:
            source_exprs = actuals[1:]
        else:
            source_exprs = actuals[:1]
        if not source_exprs:
            return
        evaluated = self._last_call_operands.get(id(call), {})
        source_locations = tuple(
            dict.fromkeys(
                location
                for source_expr in source_exprs
                for location in (
                    evaluated.get(id(source_expr))
                    if id(source_expr) in evaluated
                    else self.locations_for_expression(procedure, source_expr)
                )
            )
        )
        self._copy_locations(source_locations, target_locations)
        if source_locations:
            for target_location in target_locations:
                self.state.write(
                    self.heap.dynamic_attribute_location(
                        target_location,
                        "__source__",
                    ),
                    source_locations,
                    UpdatePolicy.WEAK,
                )
        contained = list(self._contained_values(source_locations))
        if call_name in {"keys", "dict.keys"}:
            contained.extend(
                value
                for source in source_locations
                for value in self.state.read(
                    self.heap.dynamic_attribute_location(source, "__keys__"),
                    fallback=(),
                )
            )
        elif call_name in {"items", "dict.items"}:
            contained.extend(
                value
                for source in source_locations
                for value in self.state.read(
                    self.heap.dynamic_attribute_location(source, "__keys__"),
                    fallback=(),
                )
            )
        if call_name in {"map", "builtins.map"}:
            contained.append(self._external_value_location(procedure))
        if contained:
            for target_location in target_locations:
                self.state.write(
                    self.heap.dynamic_subscript_location(
                        target_location,
                        DYNAMIC_SUBSCRIPT_WILDCARD,
                    ),
                    tuple(dict.fromkeys(contained)),
                    UpdatePolicy.WEAK,
                )

    def _copy_locations(
        self,
        source_locations: tuple[HeapLocation, ...],
        target_locations: tuple[HeapLocation, ...],
    ) -> None:
        stored_items = (
            *self.state.values.items(),
            *self.state.contaminants.items(),
        )
        for target_location in target_locations:
            for source_location in source_locations:
                for stored, values in stored_items:
                    if stored.root != source_location.root or not stored.selectors:
                        continue
                    copied = HeapLocation(target_location.root, stored.selectors)
                    self.state.write(copied, values, UpdatePolicy.WEAK)

    def _materialize_return_values(
        self,
        procedure: object,
        operation: py_ast.Return,
        returns: tuple[HeapLocation, ...],
    ) -> None:
        # HeapEffect exposes a flat return set for procedure summaries, but a
        # direct call with multiple result variables needs the values grouped
        # by result position.  Re-evaluate the expressions here and preserve
        # that grouping through branch joins.
        del returns
        code_parameters = getattr(procedure, "codeparameters", None)
        if code_parameters is None:
            return
        returnparams = tuple(getattr(code_parameters, "returnparams", ()))
        expression_locations = tuple(
            self.locations_for_expression(procedure, expression)
            for expression in getattr(operation, "exprs", ())
        )
        return_slots: list[tuple[HeapLocation, ...]] = []
        for index, target in enumerate(returnparams):
            if len(returnparams) == 1 and len(expression_locations) == 1:
                bind_locations = expression_locations[0]
            elif index < len(expression_locations):
                bind_locations = expression_locations[index]
            else:
                bind_locations = ()

            if not bind_locations:
                bind_locations = (
                    HeapLocation(
                        self.heap.return_object(
                            procedure,
                            index,
                            label=getattr(target, "name", None),
                        )
                    ),
                )
            return_slots.append(tuple(dict.fromkeys(bind_locations)))

            if isinstance(target, py_ast.Local):
                self.heap.bind_local_to_locations(
                    procedure,
                    target,
                    bind_locations,
                )
            # Any returned value is visible from outside the procedure,
            # including a slot represented by DoNotCare rather than a local.
            self.heap.mark_all_escaped(bind_locations)

        slots = tuple(return_slots)
        flat_returns = tuple(
            dict.fromkeys(
                location
                for slot in slots
                for location in slot
            )
        )
        self.state.set_return_slots(procedure, slots)
        self.state.set_returns(procedure, flat_returns)

    def _apply_writes(
        self,
        procedure: object,
        operation: object,
        writes: tuple[object, ...],
    ) -> None:
        value = self._stored_value_expression(operation)
        if value is not None:
            value_locations = self.locations_for_expression(procedure, value)
            if isinstance(operation, py_ast.SetSlice):
                value_locations = self._expand_contained_locations(
                    value_locations
                )
            # Don't return early when value_locations is empty: write()
            # handles STRONG+empty (pop to clear the binding) and
            # WEAK+empty (no-op) correctly.
        else:
            # No direct stored-value expression.  Check whether this operation
            # wraps a collection mutator call (e.g. ``list.append(x)``) whose
            # value arguments should be written to the container's wildcard
            # location generated by HeapEffectBuilder.collection_mutation().
            coll_value_locs = self._collection_mutator_value_locations(
                procedure, operation
            )
            if not coll_value_locs:
                return
            value_locations = coll_value_locs
        for write in writes:
            location = getattr(write, "location", None)
            policy = getattr(write, "policy", None)
            if not isinstance(location, HeapLocation):
                continue
            self.state.write(
                location,
                tuple(dict.fromkeys(value_locations)),
                (
                    UpdatePolicy.STRONG
                    if isinstance(operation, (py_ast.SetGlobal, py_ast.SetCellDeref))
                    else policy
                    if isinstance(policy, UpdatePolicy)
                    else UpdatePolicy.WEAK
                ),
            )
        if isinstance(operation, py_ast.SetSubscript):
            key_locations = self.locations_for_expression(
                procedure,
                operation.subscript,
            )
            if key_locations:
                roots = tuple(
                    dict.fromkeys(
                        HeapLocation(write.location.root)
                        for write in writes
                        if isinstance(getattr(write, "location", None), HeapLocation)
                    )
                )
                for root in roots:
                    self.state.write(
                        self.heap.dynamic_attribute_location(root, "__keys__"),
                        key_locations,
                        UpdatePolicy.WEAK,
                    )

    def _collection_mutator_value_locations(
        self,
        procedure: object,
        operation: object,
    ) -> tuple[HeapLocation, ...]:
        """Extract value locations for collection mutator calls.

        When a ``Discard(MethodCall(container, "append", [value]))`` is
        processed, :meth:`HeapEffectBuilder.operation_effect` generates
        wildcard writes to the container but the write values are buried
        in the method-call arguments rather than in a ``value`` attribute.
        This helper extracts those value expressions and resolves them
        to heap locations.
        """
        call = self._call_expression(operation)
        if call is None:
            return ()
        call_name = resolve_call_name(call)
        if call_name is None or call_name not in self.collection_mutator_names:
            return ()
        model = self.intrinsics.collection_mutator(call_name)
        if model is None or not model.writes_value:
            return ()
        actuals = actual_argument_expressions(call)
        if isinstance(call, py_ast.MethodCall):
            value_exprs = model.value_args(actuals)
        else:
            remaining = actuals[1:] if len(actuals) > 1 else ()
            value_exprs = model.value_args(remaining)
        return self._expand_contained_locations(
            tuple(
                loc
                for val_expr in value_exprs
                for loc in self.locations_for_expression(procedure, val_expr)
            )
        )

    def _apply_collection_reorder(
        self,
        procedure: object,
        operation: object,
    ) -> None:
        """Move every currently stored element into the wildcard may-set."""
        call = self._call_expression(operation)
        container = None
        if isinstance(operation, (py_ast.SetSlice, py_ast.DeleteSlice, py_ast.DeleteSubscript)):
            container = operation.expr
        elif call is not None:
            model = self.intrinsics.collection_mutator(resolve_call_name(call))
            if model is None or not model.reorders_values:
                return
            actuals = tuple(actual_argument_expressions(call))
            container = (
                call.expr
                if isinstance(call, py_ast.MethodCall)
                else actuals[0]
                if actuals
                else None
            )
        else:
            return
        if container is None:
            return
        evaluated = self._last_call_operands.get(id(call), {}) if call is not None else {}
        roots = evaluated.get(id(container))
        if roots is None:
            roots = self.locations_for_expression(procedure, container)
        for root in roots:
            wildcard = self.heap.dynamic_subscript_location(
                root,
                DYNAMIC_SUBSCRIPT_WILDCARD,
            )
            values = self.state.read_contained(wildcard)
            if values:
                self.state.write(wildcard, values, UpdatePolicy.WEAK)

    def _expand_contained_locations(
        self,
        roots: tuple[HeapLocation, ...],
    ) -> tuple[HeapLocation, ...]:
        """Include values reachable as elements of possible iterable roots.

        This deliberately retains the roots too: append-like mutators store
        the argument object itself, while extend/update and slice assignment
        store values obtained by iterating it.  Using their union is a sound
        may-approximation for the shared mutator model.
        """
        expanded = list(roots)
        for root in roots:
            wildcard = self.heap.dynamic_subscript_location(
                root,
                DYNAMIC_SUBSCRIPT_WILDCARD,
            )
            expanded.extend(self.state.read_contained(wildcard))
        return tuple(dict.fromkeys(expanded))

    def _contained_values(
        self,
        roots: tuple[HeapLocation, ...],
    ) -> tuple[HeapLocation, ...]:
        values: list[HeapLocation] = []
        for root in roots:
            values.extend(
                self.state.read_contained(
                    self.heap.dynamic_subscript_location(
                        root,
                        DYNAMIC_SUBSCRIPT_WILDCARD,
                    )
                )
            )
        return tuple(dict.fromkeys(values))

    def _ordered_contained_values(
        self,
        roots: tuple[HeapLocation, ...],
    ) -> tuple[HeapLocation, ...]:
        """Return known positional elements before wildcard remainder values."""
        values: list[HeapLocation] = []
        for root in roots:
            for index in range(self.heap.policy.max_index + 1):
                values.extend(
                    self.state.read(
                        self.heap.dynamic_subscript_location(root, f"[{index}]"),
                        fallback=(),
                    )
                )
            values.extend(
                self.state.read(
                    self.heap.dynamic_subscript_location(
                        root,
                        DYNAMIC_SUBSCRIPT_WILDCARD,
                    ),
                    fallback=(),
                )
            )
        return tuple(values)

    def _apply_deletes(self, deletes: tuple[HeapLocation, ...]) -> None:
        for deleted in deletes:
            self.state.delete(deleted)

    def _effective_deletes(
        self,
        operation: object,
        deletes: tuple[HeapLocation, ...],
    ) -> tuple[HeapLocation, ...]:
        return self.effect_builder.definite_delete_locations(operation, deletes)

    def _handle_local_delete(
        self,
        procedure: object,
        operation: object,
    ) -> None:
        """Handle ``del x`` — break aliasing and remove the local's heap state."""
        if not isinstance(operation, py_ast.Delete):
            return
        self._clear_runtime_local(procedure, operation.lcl)

    def _materialize_collection_literal_values(
        self,
        procedure: object,
        operation: object,
    ) -> None:
        expr = self._assigned_expression(operation)
        if not isinstance(
            expr,
            (py_ast.BuildTuple, py_ast.BuildList, py_ast.BuildSet, py_ast.BuildMap),
        ):
            return
        for argument in getattr(expr, "args", ()):
            self.locations_for_expression(procedure, argument)
        targets = assigned_locals(operation)
        target_locations = tuple(
            location
            for target in targets
            for location in self.heap.locations_for_local(procedure, target)
        )
        value_exprs = self._collection_literal_values(expr)
        for location in target_locations:
            if location.root.kind is HeapObjectKind.ALLOCATION:
                # Write literal element values into the container's heap state
                # so subsequent reads and transitive escape propagation can
                # find them when the container itself escapes.
                self._write_collection_literal_elements(
                    procedure, location, expr, value_exprs
                )

    def _materialize_function_default_values(
        self,
        procedure: object,
        operation: object,
    ) -> None:
        expr = self._assigned_expression(operation)
        if not isinstance(expr, py_ast.MakeFunction):
            return
        targets = assigned_locals(operation)
        target_locations = tuple(
            location
            for target in targets
            for location in self.heap.locations_for_local(procedure, target)
        )
        default_locations = tuple(
            location
            for default in getattr(expr, "defaults", ())
            for location in self.locations_for_expression(procedure, default)
        )
        if not default_locations:
            return
        for location in target_locations:
            defaults_location = self.heap.dynamic_attribute_location(
                location,
                "__defaults__",
            )
            self.state.write(
                defaults_location,
                tuple(dict.fromkeys(default_locations)),
                UpdatePolicy.STRONG,
            )

    def _write_collection_literal_elements(
        self,
        procedure: object,
        container: HeapLocation,
        expr: object,
        value_exprs: tuple[object, ...],
    ) -> None:
        if isinstance(expr, py_ast.BuildMap):
            keys = tuple(expr.args[0::2])
            for key_expr, val_expr in zip(keys, value_exprs):
                key_locations = self.locations_for_expression(
                    procedure,
                    key_expr,
                )
                if key_locations:
                    self.state.write(
                        self.heap.dynamic_attribute_location(
                            container,
                            "__keys__",
                        ),
                        key_locations,
                        UpdatePolicy.WEAK,
                    )
                subscript = self.effect_builder._constant_subscript(key_expr)
                key_loc = self.heap.dynamic_subscript_location(
                    container,
                    subscript or DYNAMIC_SUBSCRIPT_WILDCARD,
                )
                val_locs = self.locations_for_expression(procedure, val_expr)
                if val_locs:
                    self.state.write(
                        key_loc,
                        val_locs,
                        (
                            UpdatePolicy.STRONG
                            if subscript
                            else UpdatePolicy.WEAK
                        ),
                    )
        elif isinstance(expr, py_ast.BuildSet):
            set_loc = self.heap.dynamic_subscript_location(
                container, DYNAMIC_SUBSCRIPT_WILDCARD
            )
            all_val_locs: list[HeapLocation] = []
            for val_expr in value_exprs:
                all_val_locs.extend(
                    self.locations_for_expression(procedure, val_expr)
                )
            if all_val_locs:
                self.state.write(
                    set_loc, tuple(dict.fromkeys(all_val_locs)), UpdatePolicy.WEAK
                )
        else:
            for index, val_expr in enumerate(value_exprs):
                index_loc = self.heap.dynamic_subscript_location(
                    container, f"[{index}]"
                )
                val_locs = self.locations_for_expression(procedure, val_expr)
                if index_loc and val_locs:
                    self.state.write(
                        index_loc, val_locs, UpdatePolicy.STRONG
                    )

    @staticmethod
    def _collection_literal_values(expr: object) -> tuple[object, ...]:
        if isinstance(expr, py_ast.BuildMap):
            return tuple(expr.args[1::2])
        return tuple(getattr(expr, "args", ()))

    def _stored_value_expression(self, operation: object) -> object | None:
        values = self.effect_builder._stored_value_expressions(operation)
        if values:
            return values[0]
        collection_value = self.effect_builder.dynamic_subscript_value(operation)
        if collection_value is not None:
            return collection_value
        dynamic_attr_value = self.effect_builder._dynamic_setattr_value(operation)
        if dynamic_attr_value is not None:
            return dynamic_attr_value
        return None

    @staticmethod
    def _assigned_expression(operation: object) -> object | None:
        if isinstance(operation, (py_ast.Assign, py_ast.UnpackSequence)):
            return operation.expr
        if isinstance(operation, py_ast.AnnAssign):
            return operation.value
        return None

    @staticmethod
    def _call_expression(operation: object) -> object | None:
        expr = HeapTransferEngine._assigned_expression(operation)
        if isinstance(expr, (py_ast.Call, py_ast.DirectCall, py_ast.MethodCall)):
            return expr
        wrapped = getattr(operation, "expr", None)
        if isinstance(wrapped, (py_ast.Call, py_ast.DirectCall, py_ast.MethodCall)):
            return wrapped
        if isinstance(operation, (py_ast.Call, py_ast.DirectCall, py_ast.MethodCall)):
            return operation
        return None
