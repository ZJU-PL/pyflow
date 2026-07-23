"""Call binding, summary, and interprocedural transfer methods."""

from __future__ import annotations
from pyflow.analysis.ir_utils import (
    actual_argument_expressions,
    assigned_locals,
    call_keyword_spreads,
    call_positional_items,
    call_positional_spreads,
    resolve_call_name,
)
from pyflow.language.python import ast as py_ast
from pyflow.language.python.default_markers import MISSING_DEFAULT
from ..domain.state import HeapState
from ..domain.summary import HeapSummary, ProcedureHeapSummary
from ..semantics.effects import (
    CALL_RETURN_COPY,
    CALL_RETURN_FRESH,
    CALL_RETURN_OPAQUE,
    CALL_RETURN_SUMMARY,
    DYNAMIC_SUBSCRIPT_WILDCARD,
)
from ..semantics.intrinsics import (
    CALL_RETURN_ARG,
    CALL_RETURN_NONE,
    CALL_RETURN_SELF,
)
from ..model import HeapLocation, UpdatePolicy
from .state import _CallBindingResult, _CallSummary, _DeferredActivation, _FlowState


class _CallTransferMixin:
    """Internal mixin composed by HeapTransferEngine."""

    def _apply_call_transfer(self, procedure: object, operation: object) -> None:
        call = self._call_expression(operation)
        if call is None:
            return
        application_key = self._call_application_key(call)
        if application_key in self._applied_calls:
            return
        self._applied_calls.add(application_key)
        if isinstance(call, py_ast.DirectCall) and isinstance(call.code, py_ast.Code):
            self._bind_direct_call(procedure, operation, call)
            return
        if self._apply_finite_known_call(procedure, operation, call):
            return
        if self._known_class_locations(procedure, call):
            return
        call_name = resolve_call_name(call)
        callback_returns = self._apply_known_callback_calls(
            procedure,
            call,
            call_name,
        )
        if callback_returns:
            self._callback_call_results[application_key] = callback_returns
            pending = self._pending_call_results.get(id(operation))
            if pending is not None:
                _targets, slots = pending
                for roots in slots:
                    for root in roots:
                        self.state.write(
                            self.heap.dynamic_subscript_location(
                                root,
                                DYNAMIC_SUBSCRIPT_WILDCARD,
                            ),
                            callback_returns,
                            UpdatePolicy.WEAK,
                        )
        protocol_returns = self._apply_named_protocol_call(
            procedure,
            operation,
            call,
            call_name,
        )
        if protocol_returns:
            self._protocol_call_results[application_key] = protocol_returns
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
                    escaped.extend(self.locations_for_expression(procedure, actual))
            if function_model is not None:
                if function_model.escapes_self and isinstance(call, py_ast.MethodCall):
                    escaped.extend(self.locations_for_expression(procedure, call.expr))
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
            if function_model is not None and collection_model is None:
                mutated: list[HeapLocation] = []
                if function_model.mutates_self and isinstance(call, py_ast.MethodCall):
                    mutated.extend(self.locations_for_expression(procedure, call.expr))
                for index in function_model.write_arg_indices:
                    if index < len(actuals):
                        mutated.extend(
                            self.locations_for_expression(
                                procedure,
                                actuals[index],
                            )
                        )
                self._contaminate_modeled_mutations(
                    procedure,
                    tuple(dict.fromkeys(mutated)),
                    call_name,
                )
            return
        effect = self.effect_builder.unresolved_call_effect(procedure, call)
        self.heap.mark_all_escaped(effect.escapes)
        self.state.mark_escaped(effect.escapes)

    def _contaminate_modeled_mutations(
        self,
        procedure: object,
        roots: tuple[HeapLocation, ...],
        call_name: str | None,
    ) -> None:
        if not roots:
            return
        unknown = HeapLocation(
            self.heap.unknown_object(
                (
                    "modeled-mutation",
                    call_name,
                    self._evaluation_epoch,
                    self._current_context,
                ),
                label=f"unknown mutation by {call_name or 'known call'}",
            )
        )
        for root in roots:
            self.state.write(
                self.heap.dynamic_attribute_location(root, "*"),
                (unknown,),
                UpdatePolicy.WEAK,
            )
            self.state.write(
                self.heap.dynamic_subscript_location(
                    root,
                    DYNAMIC_SUBSCRIPT_WILDCARD,
                ),
                (unknown,),
                UpdatePolicy.WEAK,
            )

    def _apply_known_callback_calls(
        self,
        procedure: object,
        call: object,
        call_name: str | None,
    ) -> tuple[HeapLocation, ...]:
        short = call_name.rsplit(".", 1)[-1] if call_name else None
        actuals = tuple(actual_argument_expressions(call))
        callback_expression = None
        iterable_expressions: tuple[object, ...] = ()
        if short in {"map", "filter", "reduce"} and actuals:
            callback_expression = actuals[0]
            iterable_expressions = actuals[1:]
        elif short in {"sorted", "sort", "min", "max"}:
            for keyword in getattr(call, "kwds", ()):
                if (
                    isinstance(keyword, tuple)
                    and len(keyword) == 2
                    and keyword[0] == "key"
                ):
                    callback_expression = keyword[1]
                    break
            iterable_expressions = actuals[:1]
        if callback_expression is None:
            return ()
        callbacks = self.locations_for_expression(
            procedure,
            callback_expression,
        )
        arguments: list[HeapLocation] = []
        for iterable_expression in iterable_expressions:
            roots = self.locations_for_expression(
                procedure,
                iterable_expression,
            )
            contained = self._contained_values(roots)
            arguments.extend(contained or roots)
        argument_group = tuple(dict.fromkeys(arguments)) or (
            self._external_value_location(procedure),
        )
        results: list[HeapLocation] = []
        for callback in callbacks:
            code = self._function_codes_by_root.get(callback.root)
            receivers: tuple[HeapLocation, ...] = ()
            if code is None:
                bound = self._bound_methods_by_root.get(callback.root)
                if bound is not None:
                    code, receivers = bound
            if code is None:
                continue
            callback_groups = (
                (argument_group, argument_group)
                if short == "reduce"
                else (argument_group,)
            )
            groups = (receivers, *callback_groups) if receivers else callback_groups
            results.extend(self._evaluate_known_code(procedure, code, groups))
        return tuple(dict.fromkeys(results))

    def _apply_named_protocol_call(
        self,
        procedure: object,
        operation: object,
        call: object,
        call_name: str | None,
    ) -> tuple[HeapLocation, ...]:
        """Model builtins whose semantics include a special-method call."""
        short_name = call_name.rsplit(".", 1)[-1] if call_name else None
        protocol = {
            "len": "__len__",
            "iter": "__iter__",
            "next": "__next__",
            "bool": "__bool__",
            "hash": "__hash__",
            "repr": "__repr__",
            "str": "__str__",
            "bytes": "__bytes__",
            "reversed": "__reversed__",
            "int": "__int__",
            "float": "__float__",
            "complex": "__complex__",
            "round": "__round__",
            "format": "__format__",
            "index": "__index__",
            "getattr": "__getattribute__",
            "setattr": "__setattr__",
            "delattr": "__delattr__",
        }.get(short_name)
        actuals = tuple(actual_argument_expressions(call))
        if protocol is None or not actuals:
            return ()
        operands = self._last_call_operands.get(id(call))
        if operands is None:
            operands = self._evaluate_call_operands(procedure, call)
        receivers = operands.get(id(actuals[0]), ())
        groups = tuple(operands.get(id(actual), ()) for actual in actuals[1:])
        returned = self._evaluate_known_protocol(
            procedure,
            receivers,
            protocol,
            groups,
        )
        if not returned:
            return ()
        pending = self._pending_call_results.get(id(operation))
        if pending is None:
            return returned
        targets, slots = pending
        self._pending_call_results[id(operation)] = (
            targets,
            tuple(tuple(dict.fromkeys((*slot, *returned))) for slot in slots),
        )
        return returned

    def _apply_finite_known_call(
        self,
        caller: object,
        operation: object,
        call: object,
    ) -> bool:
        """Apply a generic/virtual call when its target set is finite and known.

        Resolution is intentionally all-or-nothing.  If any possible function,
        receiver class, or method implementation is unknown, the ordinary
        unresolved-call transfer remains responsible for the whole call.
        """
        candidates = self._finite_known_call_targets(caller, call)
        if not candidates:
            return False
        base = self._capture_flow_state()
        normal_states: list[_FlowState] = []
        possible_returns: list[HeapLocation] = []
        return_slots: list[list[HeapLocation]] = []
        for code, receiver_locations in candidates:
            self._restore_flow_state(base)
            method_call = isinstance(call, py_ast.MethodCall)
            direct = py_ast.DirectCall(
                code,
                None,
                (
                    [call.expr, *getattr(call, "args", ())]
                    if method_call and receiver_locations
                    else list(getattr(call, "args", ()))
                ),
                list(getattr(call, "kwds", ())),
                getattr(call, "vargs", None),
                getattr(call, "kargs", None),
            )
            binding_result = self._direct_call_actual_locations(
                caller,
                code,
                direct,
                receiver_supplied=bool(receiver_locations),
                receiver_consumes_positional=bool(receiver_locations)
                and not method_call,
            )
            bindings = dict(binding_result.bindings)
            if receiver_locations:
                formals = self._callee_formals(code)
                if formals:
                    if not method_call:
                        original = dict(bindings)
                        bindings = {
                            index + 1: locations
                            for index, locations in original.items()
                            if index + 1 < len(formals)
                        }
                    bindings[0] = receiver_locations
            returned = self._evaluate_direct_call_with_bindings(
                caller,
                direct,
                _CallBindingResult(
                    bindings,
                    binding_result.definitely_invalid,
                    binding_result.maybe_invalid,
                    binding_result.reasons,
                ),
            )
            if self._operation_normal_possible[-1]:
                normal_states.append(self._capture_flow_state())
                possible_returns.extend(returned)
                summary = self._last_direct_call_summary.get(id(direct))
                if summary is not None:
                    while len(return_slots) < len(summary.returns):
                        return_slots.append([])
                    for return_index, locations in enumerate(summary.returns):
                        return_slots[return_index].extend(locations)
                        for formal_index in summary.param_returns.get(
                            return_index,
                            frozenset(),
                        ):
                            return_slots[return_index].extend(
                                bindings.get(formal_index, ())
                            )
            # A target that raises exclusively only contributes its abrupt
            # outcome, already recorded by _evaluate_direct_call_with_bindings.
            self._operation_normal_possible[-1] = True
        if normal_states:
            self._restore_flow_state(self._join_flow_states(tuple(normal_states)))
        else:
            self._restore_flow_state(base)
            self._operation_normal_possible[-1] = False
        targets = assigned_locals(operation)
        if targets:
            values = tuple(dict.fromkeys(possible_returns))
            if len(targets) == 1:
                slots = (values,)
            else:
                slots = tuple(
                    (
                        tuple(dict.fromkeys(return_slots[index]))
                        if index < len(return_slots)
                        else ()
                    )
                    for index, _target in enumerate(targets)
                )
            self._pending_call_results[id(operation)] = (
                targets,
                slots,
            )
        self._finite_call_results[self._call_application_key(call)] = tuple(
            dict.fromkeys(possible_returns)
        )
        return True

    def _call_application_key(self, call: object) -> tuple[object, ...]:
        return (
            id(call),
            self._evaluation_epoch,
            self._current_context,
        )

    def _finite_known_call_targets(
        self,
        procedure: object,
        call: object,
    ) -> tuple[tuple[py_ast.Code, tuple[HeapLocation, ...]], ...]:
        operands = self._last_call_operands.get(id(call))
        if operands is None:
            operands = self._evaluate_call_operands(procedure, call)
        if isinstance(call, py_ast.Call):
            functions = operands.get(id(call.expr), ())
            if not functions:
                return ()
            codes: list[tuple[py_ast.Code, tuple[HeapLocation, ...]]] = []
            for function in functions:
                code = self._function_codes_by_root.get(function.root)
                if code is not None:
                    codes.append((code, ()))
                    continue
                bound = self._bound_methods_by_root.get(function.root)
                if bound is not None:
                    codes.append(bound)
                    continue
                classes = self.state.read(
                    self.heap.dynamic_attribute_location(
                        function,
                        "__class__",
                    ),
                    fallback=(),
                )
                if not classes:
                    return ()
                for class_location in classes:
                    callable_code = self._resolve_known_class_method(
                        class_location,
                        "__call__",
                    )
                    if callable_code is None:
                        return ()
                    codes.append((callable_code, (function,)))
            return tuple(dict.fromkeys(codes))
        if not isinstance(call, py_ast.MethodCall):
            return ()
        name = self.effect_builder._constant_string(call.name)
        receivers = operands.get(id(call.expr), ())
        if name is None or not receivers:
            return ()
        candidates: list[tuple[py_ast.Code, tuple[HeapLocation, ...]]] = []
        for receiver in receivers:
            super_classes = self.state.read(
                self.heap.dynamic_attribute_location(
                    receiver,
                    "__super_class__",
                ),
                fallback=(),
            )
            if super_classes:
                super_receivers = self.state.read(
                    self.heap.dynamic_attribute_location(
                        receiver,
                        "__super_self__",
                    ),
                    fallback=(),
                )
                registered = self._super_methods_by_root.get(
                    receiver.root,
                    {},
                ).get(name)
                if registered is not None:
                    candidates.append(registered)
                    continue
                resolved = False
                for current_class in super_classes:
                    for next_class in self._known_class_mro(current_class)[1:]:
                        method = self._class_methods_by_root.get(
                            next_class.root,
                            {},
                        ).get(name)
                        if method is not None:
                            candidates.append((method, super_receivers))
                            resolved = True
                            break
                    if resolved:
                        break
                if not resolved:
                    return ()
                continue
            classes = self.state.read(
                self.heap.dynamic_attribute_location(receiver, "__class__"),
                fallback=(),
            )
            if not classes:
                return ()
            for class_location in classes:
                method = self._resolve_known_class_method(class_location, name)
                if method is None:
                    return ()
                kind = self._resolve_known_class_method_kind(
                    class_location,
                    name,
                )
                if kind == "staticmethod":
                    bound_receiver = ()
                elif kind == "classmethod":
                    bound_receiver = (class_location,)
                else:
                    bound_receiver = (receiver,)
                candidates.append((method, bound_receiver))
        return tuple(dict.fromkeys(candidates))

    def _bind_direct_call(
        self,
        caller: object,
        operation: object,
        call: py_ast.DirectCall,
    ) -> None:
        callee = call.code
        if getattr(callee, "module", None) is None:
            self._module_owners.setdefault(id(callee), self._module_owner(caller))
        binding_result = self._direct_call_actual_locations(caller, callee, call)
        actual_bindings = binding_result.bindings
        possible_returns = self._evaluate_direct_call_with_bindings(
            caller,
            call,
            binding_result,
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
        binding_result = self._direct_call_actual_locations(
            caller,
            call.code,
            call,
        )
        return self._evaluate_direct_call_with_bindings(
            caller,
            call,
            binding_result,
        )

    def _evaluate_direct_call_with_bindings(
        self,
        caller: object,
        call: py_ast.DirectCall,
        binding_result: _CallBindingResult,
    ) -> tuple[HeapLocation, ...]:
        callee = call.code
        actual_bindings = binding_result.bindings
        if binding_result.definitely_invalid:
            raised_state = self.state.copy()
            exception = self._external_value_location(caller)
            raised_state.set_raised(caller, (exception,))
            if self._operation_call_raises:
                self._operation_call_raises[-1].append(
                    _FlowState(
                        raised_state,
                        self.heap.snapshot_environment(),
                        dict(self._definition_default_locations),
                    )
                )
            if self._operation_normal_possible:
                self._operation_normal_possible[-1] = False
            return ()
        if binding_result.maybe_invalid and self._operation_call_raises:
            raised_state = self.state.copy()
            exception = self._external_value_location(caller)
            raised_state.set_raised(caller, (exception,))
            self._operation_call_raises[-1].append(
                _FlowState(
                    raised_state,
                    self.heap.snapshot_environment(),
                    dict(self._definition_default_locations),
                )
            )
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

    def _call_binding_status(
        self,
        callee: py_ast.Code,
        call: py_ast.DirectCall,
        *,
        receiver_supplied: bool = False,
        receiver_consumes_positional: bool = False,
    ) -> tuple[bool, bool, frozenset[str]]:
        """Classify Python argument binding without losing uncertain success.

        Explicit contradictions are definite ``TypeError`` paths.  A dynamic
        ``*args``/``**kwargs`` expansion can instead make the call both
        successful and failing, so callers retain both outcomes.
        """
        params = callee.codeparameters
        reasons: set[str] = set()
        uncertain_reasons: set[str] = set()
        positional_spread = bool(
            call_positional_spreads(call) or getattr(call, "vargs", None) is not None
        )
        keyword_spread = bool(
            call_keyword_spreads(call) or getattr(call, "kargs", None) is not None
        )

        selfparam = getattr(params, "selfparam", None)
        if isinstance(selfparam, py_ast.Local) and not (
            receiver_supplied or getattr(call, "selfarg", None) is not None
        ):
            reasons.add("missing-receiver")
        receiver_consumes_positional = receiver_consumes_positional and not isinstance(
            selfparam, py_ast.Local
        )

        posonly_entries = [
            (name, formal)
            for name, formal in zip(
                getattr(params, "posonlynames", ()),
                getattr(params, "posonlyparams", ()),
            )
            if isinstance(formal, py_ast.Local)
        ]
        regular_entries: list[tuple[str, py_ast.Local]] = []
        keyword_only_entries: list[tuple[str, py_ast.Local]] = []
        for name, formal in zip(
            getattr(params, "paramnames", ()),
            getattr(params, "params", ()),
        ):
            if not isinstance(name, str) or not isinstance(formal, py_ast.Local):
                continue
            if name.startswith("kwonly:"):
                keyword_only_entries.append((name[len("kwonly:") :], formal))
            else:
                regular_entries.append((name, formal))

        positional_entries = [*posonly_entries, *regular_entries]
        explicit_positional_count = len(getattr(call, "args", ()))
        positional_items = call_positional_items(call)
        if positional_items:
            explicit_positional_count = sum(
                1 for is_spread, _actual in positional_items if not is_spread
            )
        if receiver_consumes_positional:
            explicit_positional_count += 1
        if (
            explicit_positional_count > len(positional_entries)
            and getattr(params, "vparam", None) is None
        ):
            reasons.add("too-many-positional")
        elif positional_spread and getattr(params, "vparam", None) is None:
            uncertain_reasons.add("positional-spread-overflow")

        definitely_positional: set[py_ast.Local] = set()
        if positional_items:
            definite_prefix = 0
            for is_spread, _actual in positional_items:
                if is_spread:
                    break
                definite_prefix += 1
        else:
            definite_prefix = len(getattr(call, "args", ()))
        if receiver_consumes_positional:
            definite_prefix += 1
        definitely_positional.update(
            formal for _name, formal in positional_entries[:definite_prefix]
        )

        keyword_bindable = {
            name: formal for name, formal in (*regular_entries, *keyword_only_entries)
        }
        posonly_names = {
            name for name, _formal in posonly_entries if isinstance(name, str)
        }
        keyword_names: list[str] = []
        definitely_keyword: set[py_ast.Local] = set()
        for keyword in getattr(call, "kwds", ()):
            if not (
                isinstance(keyword, tuple)
                and len(keyword) == 2
                and isinstance(keyword[0], str)
            ):
                if getattr(params, "kparam", None) is None:
                    reasons.add("unknown-keyword")
                continue
            name = keyword[0]
            keyword_names.append(name)
            formal = keyword_bindable.get(name)
            if formal is not None:
                if formal in definitely_positional:
                    reasons.add("multiple-values")
                definitely_keyword.add(formal)
            elif name in posonly_names:
                if getattr(params, "kparam", None) is None:
                    reasons.add("positional-only-keyword")
            elif getattr(params, "kparam", None) is None:
                reasons.add("unexpected-keyword")
        if len(keyword_names) != len(set(keyword_names)):
            reasons.add("duplicate-keyword")
        keyword_spread_count = len(call_keyword_spreads(call)) + (
            1 if getattr(call, "kargs", None) is not None else 0
        )
        if keyword_spread and (
            getattr(params, "kparam", None) is None
            or bool(keyword_names)
            or bool(definitely_positional.intersection(keyword_bindable.values()))
            or keyword_spread_count > 1
        ):
            uncertain_reasons.add("keyword-spread-collision")
        if positional_spread and definitely_keyword:
            uncertain_reasons.add("positional-spread-keyword-collision")

        defaultable = [formal for _name, formal in positional_entries]
        defaultable.extend(formal for _name, formal in keyword_only_entries)
        defaults = tuple(getattr(params, "defaults", ()))
        defaulted: set[py_ast.Local] = set()
        if defaults:
            for formal, default in zip(defaultable[-len(defaults) :], defaults):
                if not (
                    isinstance(default, py_ast.Existing)
                    and getattr(default.object, "pyobj", None) is MISSING_DEFAULT
                ):
                    defaulted.add(formal)

        possibly_positional = (
            {formal for _name, formal in positional_entries}
            if positional_spread
            else set()
        )
        possibly_keyword = set(keyword_bindable.values()) if keyword_spread else set()
        for _name, formal in (*positional_entries, *keyword_only_entries):
            if formal in defaulted:
                continue
            if formal in definitely_positional or formal in definitely_keyword:
                continue
            if formal in possibly_positional or formal in possibly_keyword:
                uncertain_reasons.add("missing-required")
            else:
                reasons.add("missing-required")

        definitely_invalid = bool(reasons)
        maybe_invalid = not definitely_invalid and bool(uncertain_reasons)
        return (
            definitely_invalid,
            maybe_invalid,
            frozenset((*reasons, *uncertain_reasons)),
        )

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
        from ..model import HeapEscapeState

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
        summary_effects: list[object] = []
        degradation_start = len(self.precision_degradations)
        yield_events: list[tuple[int, _FlowState, tuple[HeapLocation, ...]]] = []
        self._summary_delete_stack.append(summary_deletes)
        self._summary_effect_stack.append(summary_effects)
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
                self._join_flow_states(normal_candidates) if normal_candidates else None
            )
            raise_flow = outcome.abrupt.get("raise")
            all_exit_states = tuple(
                state
                for state in (
                    normal_flow,
                    raise_flow,
                    *(state for _depth, state, _yielded in yield_events),
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
            caller_environment.object_labels.update(callee_environment.object_labels)
            caller_environment.escaped_objects.update(
                callee_environment.escaped_objects
            )

            def cleaned(flow: _FlowState | None) -> HeapState | None:
                if flow is None:
                    return None
                state = flow.heap_state.copy()
                state.raised.pop(callee, None)
                state.yields.pop(callee, None)
                state.yield_depths.pop(callee, None)
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
            yield_steps_list = []
            for depth in sorted({depth for depth, _state, _value in yield_events}):
                events = tuple(
                    (event_state, yielded)
                    for event_depth, event_state, yielded in yield_events
                    if event_depth == depth
                )
                joined_event = self._join_flow_states(
                    tuple(event_state for event_state, _yielded in events)
                )
                yielded = tuple(
                    dict.fromkeys(
                        location
                        for _event_state, event_values in events
                        for location in event_values
                    )
                )
                yield_steps_list.append(
                    (
                        cleaned(joined_event) or joined_event.heap_state.copy(),
                        joined_event.environment,
                        yielded,
                    )
                )
            yield_steps = tuple(yield_steps_list)
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
            public_summary = ProcedureHeapSummary(
                normal_state=normal_state.copy() if normal_state is not None else None,
                raise_state=raise_state.copy() if raise_state is not None else None,
                returns=return_locations,
                raises=raised_locations,
                yields=yielded_locations,
                deletes=result.deletes,
                param_returns=param_returns,
                param_escapes=param_escapes,
                effects=HeapSummary.from_effects(summary_effects),
                precision_degradations=frozenset(
                    reason
                    for _node, reason in self.precision_degradations[degradation_start:]
                ),
            )
            previous_summary = self.procedure_summaries.get(callee)
            self.procedure_summaries[callee] = (
                public_summary
                if previous_summary is None
                else previous_summary.merge(public_summary)
            )
            return result
        finally:
            if is_generator:
                self._yield_state_stack.pop()
            self._summary_delete_stack.pop()
            completed_effects = self._summary_effect_stack.pop()
            if self._summary_effect_stack:
                self._summary_effect_stack[-1].extend(completed_effects)
            self.state = caller_state
            self.heap.restore_environment(caller_environment)
            self._summary_in_progress.discard(callee)

    def _apply_callee_summary(
        self,
        summary: _CallSummary,
        caller: object,
        *,
        preserve_current: bool = False,
    ) -> None:
        self._record_summary_deletes(summary.deletes)
        # The summary starts from this exact call site's state, so it already
        # is the complete post-call state.  Joining it with the pre-call state
        # would resurrect values removed by strong writes and must-deletes.
        selected_state = summary.normal_state or summary.state
        self.state = (
            self.state.join(selected_state)
            if preserve_current
            else selected_state.copy()
        )
        selected_environment = summary.normal_environment or summary.environment
        if selected_environment is not None and not preserve_current:
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
        *,
        receiver_supplied: bool = False,
        receiver_consumes_positional: bool = False,
    ) -> _CallBindingResult:
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
                    ((location,) for location in expanded) if is_spread else (expanded,)
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
            (name[len("kwonly:") :] if name.startswith("kwonly:") else name): formal
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
                extra_keywords.append(
                    (name if isinstance(name, str) else None, locations)
                )
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

        explicitly_bound = {index for index, locations in bindings.items() if locations}

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
            default_formals = defaultable_formals[-len(defaults) :]
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
                        (
                            f"[{name!r}]"
                            if name is not None
                            else DYNAMIC_SUBSCRIPT_WILDCARD
                        ),
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

        resolved_bindings = {
            index: tuple(dict.fromkeys(locations))
            for index, locations in bindings.items()
        }
        definitely_invalid, maybe_invalid, reasons = self._call_binding_status(
            callee,
            call,
            receiver_supplied=receiver_supplied,
            receiver_consumes_positional=receiver_consumes_positional,
        )
        return _CallBindingResult(
            resolved_bindings,
            definitely_invalid,
            maybe_invalid,
            reasons,
        )

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
        known_classes = self._known_class_locations(
            procedure,
            call_expression,
            operand_locations,
        )
        constructed = self._evaluate_known_class_targets(
            procedure,
            call_expression,
            known_classes,
            operand_locations,
            label,
        )
        slots: list[tuple[HeapLocation, ...]] = []
        for index, target in enumerate(targets):
            site = self.effect_builder.call_return_site(call_expression, index, kind)
            result_locations: tuple[HeapLocation, ...]
            if constructed:
                result_locations = constructed
            elif kind == CALL_RETURN_NONE:
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
                call_name = resolve_call_name(call_expression)
                if (
                    kind == CALL_RETURN_OPAQUE
                    and isinstance(call_expression, py_ast.MethodCall)
                    and isinstance(call_name, str)
                    and "." not in call_name
                ):
                    # A method name alone does not establish a builtin
                    # receiver. Preserve the useful container/property model
                    # while retaining an arbitrary user-method return.
                    result_locations = tuple(
                        dict.fromkeys(
                            (
                                *result_locations,
                                HeapLocation(
                                    self.heap.call_result_object(
                                        procedure,
                                        site,
                                        label=label,
                                        context=self._current_context,
                                    )
                                ),
                            )
                        )
                    )
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
            slots.append(tuple(dict.fromkeys(result_locations)))
            if not constructed:
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
