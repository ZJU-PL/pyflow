"""Inter-procedural call transfer methods (mixin for HeapTransferEngine).

This module contains the inter-procedural call methods extracted from
:class:`HeapTransferEngine`. It is used as a mixin and should not be
instantiated directly.
"""

from __future__ import annotations

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

from .abstraction import HeapEnvironment
from .heap_effects import (
    CALL_RETURN_COPY,
    CALL_RETURN_FRESH,
    CALL_RETURN_SUMMARY,
    DYNAMIC_SUBSCRIPT_WILDCARD,
)
from .heap_state import HeapState
from .intrinsics import (
    CALL_RETURN_ARG,
    CALL_RETURN_NONE,
    CALL_RETURN_SELF,
)
from .model import HeapLocation, HeapObjectKind, UpdatePolicy

# Import dataclasses from transfer.py at runtime.
# These are defined BEFORE the class in transfer.py, so importing this module
# after those definitions works without circular import issues when
# transfer.py places the mixin import after the dataclass definitions.
from .transfer import _CallSummary, _DeferredActivation, _FlowState


class _TransferCallsMixin:
    """Mixin providing inter-procedural call transfer methods.

    This class contains only methods; it does not define ``__init__``.
    At runtime ``self`` is the :class:`HeapTransferEngine` instance.
    """

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
        meaningful_origin = tuple(item for item in origin if item is not None)
        if meaningful_origin:
            return (
                type(node).__name__,
                tuple(repr(item) for item in meaningful_origin),
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

