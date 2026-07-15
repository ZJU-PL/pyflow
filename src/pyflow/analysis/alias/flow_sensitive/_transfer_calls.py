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
    CALL_RETURN_OPAQUE,
    CALL_RETURN_SUMMARY,
    DYNAMIC_SUBSCRIPT_WILDCARD,
)
from .heap_state import HeapState
from .heap_summary import HeapSummary, ProcedureHeapSummary
from .intrinsics import (
    CALL_RETURN_ARG,
    CALL_RETURN_NONE,
    CALL_RETURN_SELF,
)
from .model import HeapLocation, UpdatePolicy

# Import dataclasses from transfer.py at runtime.
# These are defined BEFORE the class in transfer.py, so importing this module
# after those definitions works without circular import issues when
# transfer.py places the mixin import after the dataclass definitions.
from .transfer import (
    _CallBindingResult,
    _CallSummary,
    _DeferredActivation,
    _FlowState,
)


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
        decorator_kind = self._definition_decorator_kind(operation)
        decorated_or_dynamic = ()
        if getattr(operation, "decorators", ()) and decorator_kind == "dynamic":
            decorated_or_dynamic = (self._external_value_location(procedure),)
        values = tuple(dict.fromkeys((definition, *decorated_or_dynamic)))
        if isinstance(operation, py_ast.ClassDef):
            self._class_definitions[
                (self._module_owner(procedure), operation.name)
            ] = definition
            self._class_locations_by_root[definition.root] = definition
            self._class_locations_by_definition[id(operation)] = definition
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
            self._function_codes_by_root[definition.root] = operation.code
            self._function_binding_kinds[definition.root] = decorator_kind
            if getattr(operation, "decorators", ()) and decorator_kind == "dynamic":
                decorated = self._apply_known_definition_decorators(
                    procedure,
                    operation,
                    (definition,),
                )
                self._rebind_definition_value(
                    procedure,
                    operation.name,
                    decorated,
                )
        if isinstance(operation, py_ast.ClassDef):
            base_locations = self._merge_expression_locations(
                procedure,
                *getattr(operation, "bases", ()),
            )
            named_bases = tuple(
                self._class_definitions[
                    (self._module_owner(procedure), base.name)
                ]
                for base in getattr(operation, "bases", ())
                if isinstance(base, py_ast.Local)
                and (self._module_owner(procedure), base.name)
                in self._class_definitions
            )
            base_locations = tuple(
                dict.fromkeys((*base_locations, *named_bases))
            )
            if base_locations:
                self.state.write(
                    self.heap.dynamic_attribute_location(definition, "__bases__"),
                    base_locations,
                    UpdatePolicy.STRONG,
                )
            self._class_bases_by_root[definition.root] = base_locations
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

    def _apply_known_definition_decorators(
        self,
        procedure: object,
        operation: object,
        initial: tuple[HeapLocation, ...],
    ) -> tuple[HeapLocation, ...]:
        current = initial
        for decorator_expression in reversed(
            tuple(getattr(operation, "decorators", ()))
        ):
            decorator_locations = self.locations_for_expression(
                procedure,
                decorator_expression,
            )
            results: list[HeapLocation] = []
            complete = bool(decorator_locations)
            for decorator in decorator_locations:
                code = self._function_codes_by_root.get(decorator.root)
                receivers: tuple[HeapLocation, ...] = ()
                if code is None:
                    bound = self._bound_methods_by_root.get(decorator.root)
                    if bound is not None:
                        code, receivers = bound
                if code is None:
                    complete = False
                    continue
                actual_groups = (
                    (receivers, current)
                    if receivers
                    else (current,)
                )
                results.extend(
                    self._evaluate_known_code(
                        procedure,
                        code,
                        actual_groups,
                    )
                )
            current = (
                tuple(dict.fromkeys(results))
                if complete and results
                else (self._external_value_location(procedure),)
            )
        return current

    def _rebind_definition_value(
        self,
        procedure: object,
        name: str,
        values: tuple[HeapLocation, ...],
    ) -> None:
        if self._is_module_scope(procedure):
            self.state.write(
                self.effect_builder.global_location(procedure, name),
                values,
                UpdatePolicy.STRONG,
            )
        self._bind_definition_local(procedure, name, values)

    def _definition_decorator_kind(self, operation: object) -> str:
        decorators = tuple(getattr(operation, "decorators", ()))
        if not decorators:
            return "instance"
        recognized = None
        for decorator in decorators:
            name = resolve_call_name(decorator)
            if name is None:
                name = self.effect_builder._constant_string(decorator)
            short = name.rsplit(".", 1)[-1] if isinstance(name, str) else None
            if short in {"staticmethod", "classmethod", "property"}:
                recognized = short
            else:
                return "dynamic"
        return recognized or "dynamic"

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
            groups = (
                (receivers, *callback_groups)
                if receivers
                else callback_groups
            )
            results.extend(
                self._evaluate_known_code(procedure, code, groups)
            )
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
        groups = tuple(
            operands.get(id(actual), ())
            for actual in actuals[1:]
        )
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
            tuple(
                tuple(dict.fromkeys((*slot, *returned)))
                for slot in slots
            ),
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
                    tuple(dict.fromkeys(return_slots[index]))
                    if index < len(return_slots)
                    else ()
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
        receiver_consumes_positional = (
            receiver_consumes_positional
            and not isinstance(selfparam, py_ast.Local)
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
        posonly_names = {name for name, _formal in posonly_entries if isinstance(name, str)}
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
        if keyword_spread:
            uncertain_reasons.add("keyword-spread-collision")

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

        possibly_positional = set(positional_entries and (
            formal for _name, formal in positional_entries
        ) if positional_spread else ())
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
        summary_effects: list[object] = []
        degradation_start = len(self.precision_degradations)
        yield_events: list[
            tuple[int, _FlowState, tuple[HeapLocation, ...]]
        ] = []
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
                    for _node, reason in self.precision_degradations[
                        degradation_start:
                    ]
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

    def _known_class_locations(
        self,
        procedure: object,
        call: object,
        operand_locations: dict[int, tuple[HeapLocation, ...]] | None = None,
    ) -> tuple[HeapLocation, ...]:
        if not isinstance(call, py_ast.Call):
            return ()
        operands = operand_locations or self._last_call_operands.get(id(call))
        if operands is None:
            operands = self._evaluate_call_operands(procedure, call)
        return tuple(
            dict.fromkeys(
                self._class_locations_by_root[location.root]
                for location in operands.get(id(call.expr), ())
                if location.root in self._class_locations_by_root
            )
        )

    def _evaluate_known_class_targets(
        self,
        procedure: object,
        call: object,
        classes: tuple[HeapLocation, ...],
        operand_locations: dict[int, tuple[HeapLocation, ...]],
        label: str,
    ) -> tuple[HeapLocation, ...]:
        if not classes:
            return ()
        base = self._capture_flow_state()
        states: list[_FlowState] = []
        results: list[HeapLocation] = []
        for class_location in classes:
            self._restore_flow_state(base)
            allocator = self._resolve_class_method(
                class_location,
                self._class_allocators_by_root,
            )
            allocated = self._evaluate_known_class_allocator(
                procedure,
                call,
                class_location,
                operand_locations,
            ) if allocator is not None else ()
            if allocator is None:
                allocated = (
                    HeapLocation(
                        self.heap.allocation_object(
                            procedure,
                            ("class-instance", id(call), class_location.root),
                            label=label,
                            context=self._current_context,
                        )
                    ),
                )
                self.state.complete_roots.update(
                    location.root for location in allocated
                )
            elif not allocated:
                allocated = (self._external_value_location(procedure),)
            self._attach_known_class(
                procedure,
                call,
                allocated,
                allocator_known=allocator is not None,
                class_location=class_location,
            )
            results.extend(allocated)
            states.append(self._capture_flow_state())
        self._restore_flow_state(self._join_flow_states(tuple(states)))
        return tuple(dict.fromkeys(results))

    def _evaluate_known_class_allocator(
        self,
        procedure: object,
        call: object,
        class_location: HeapLocation,
        operand_locations: dict[int, tuple[HeapLocation, ...]],
    ) -> tuple[HeapLocation, ...]:
        allocator = self._resolve_class_method(
            class_location,
            self._class_allocators_by_root,
        )
        if allocator is None:
            return ()
        formals = self._callee_formals(allocator)
        bindings: dict[int, tuple[HeapLocation, ...]] = {}
        if formals:
            bindings[0] = (class_location,)
        for index, actual in enumerate(getattr(call, "args", ()), start=1):
            if index >= len(formals):
                break
            locations = operand_locations.get(id(actual))
            if locations is None:
                locations = self.locations_for_expression(procedure, actual)
            bindings[index] = locations
        parameter_names = tuple(
            getattr(allocator.codeparameters, "paramnames", ())
        )
        named_indices = {
            name: index
            for index, name in enumerate(parameter_names, start=1)
            if isinstance(name, str) and index < len(formals)
        }
        for keyword in getattr(call, "kwds", ()):
            if not (isinstance(keyword, tuple) and len(keyword) == 2):
                continue
            name, actual = keyword
            index = named_indices.get(name)
            if index is None:
                continue
            locations = operand_locations.get(id(actual))
            if locations is None:
                locations = self.locations_for_expression(procedure, actual)
            bindings[index] = locations
        summary = self._callee_summary(allocator, bindings)
        if summary.raise_state is not None and self._operation_call_raises:
            self._operation_call_raises[-1].append(
                _FlowState(
                    summary.raise_state.copy(),
                    summary.raise_environment
                    or summary.environment
                    or self.heap.snapshot_environment(),
                    dict(self._definition_default_locations),
                )
            )
        if summary.normal_state is None:
            if self._operation_normal_possible:
                self._operation_normal_possible[-1] = False
            return ()
        self._apply_callee_summary(summary, procedure)
        returns: list[HeapLocation] = []
        for index, locations in enumerate(summary.returns):
            returns.extend(locations)
            for formal_index in summary.param_returns.get(index, frozenset()):
                returns.extend(bindings.get(formal_index, ()))
        return tuple(dict.fromkeys(returns))

    def _attach_known_class(
        self,
        procedure: object,
        call: object,
        instances: tuple[HeapLocation, ...],
        *,
        allocator_known: bool = False,
        class_location: HeapLocation | None = None,
    ) -> None:
        if class_location is None:
            classes = self._known_class_locations(procedure, call)
            class_location = classes[0] if len(classes) == 1 else None
        if class_location is None:
            return
        compatible: list[HeapLocation] = []
        for instance in instances:
            class_slot = self.heap.dynamic_attribute_location(
                instance,
                "__class__",
            )
            existing_classes = self.state.read(class_slot, fallback=())
            if not existing_classes:
                # A default allocation is definitely an instance.  A value
                # returned by a known __new__ is only possibly compatible when
                # its concrete class is not otherwise known.
                self.state.write(
                    class_slot,
                    (class_location,),
                    UpdatePolicy.WEAK if allocator_known else UpdatePolicy.STRONG,
                )
                compatible.append(instance)
                continue
            if any(
                class_location in self._known_class_mro(existing_class)
                for existing_class in existing_classes
            ):
                compatible.append(instance)
        initializer = self._resolve_class_initializer(class_location)
        if (
            initializer is None
            or not compatible
            or (id(call), class_location.root) in self._initialized_class_calls
        ):
            return
        self._initialized_class_calls.add((id(call), class_location.root))
        formals = self._callee_formals(initializer)
        bindings: dict[int, tuple[HeapLocation, ...]] = {}
        if formals:
            bindings[0] = tuple(compatible)
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

    def _resolve_class_initializer(
        self,
        class_location: HeapLocation,
    ) -> py_ast.Code | None:
        """Resolve ``__init__`` through the known class base graph."""
        return self._resolve_class_method(
            class_location,
            self._class_initializers_by_root,
        )

    def _apply_known_class_creation_hooks(
        self,
        procedure: object,
        class_node: py_ast.ClassDef,
        class_location: HeapLocation,
        members: dict[str, tuple[HeapLocation, ...]],
    ) -> None:
        """Apply closed-world descriptor and subclass creation hooks."""
        inherited_dispatch: dict[str, py_ast.Code] = {}
        for base in self._known_class_mro(class_location)[1:]:
            for name, method in self._class_methods_by_root.get(
                base.root,
                {},
            ).items():
                inherited_dispatch.setdefault(name, method)
        self._super_dispatch_by_class_root[
            class_location.root
        ] = inherited_dispatch
        for name, descriptors in members.items():
            self._evaluate_known_protocol(
                procedure,
                descriptors,
                "__set_name__",
                (
                    (class_location,),
                    (self._external_value_location(procedure),),
                ),
            )
        bases = self.state.read(
            self.heap.dynamic_attribute_location(class_location, "__bases__"),
            fallback=(),
        )
        for base in bases:
            hook = self._resolve_known_class_method(base, "__init_subclass__")
            if hook is not None:
                self._evaluate_known_code(
                    procedure,
                    hook,
                    ((class_location,),),
                )

        metaclass_expressions = tuple(
            keyword[1]
            for keyword in getattr(class_node, "keywords", ())
            if isinstance(keyword, tuple)
            and len(keyword) == 2
            and keyword[0] == "metaclass"
        )
        metaclasses = self._merge_expression_locations(
            procedure,
            *metaclass_expressions,
        )
        if not metaclasses:
            return
        self.state.write(
            self.heap.dynamic_attribute_location(class_location, "__class__"),
            metaclasses,
            UpdatePolicy.STRONG,
        )
        for metaclass in metaclasses:
            for hook_name in ("__new__", "__init__"):
                hook = self._resolve_known_class_method(metaclass, hook_name)
                if hook is not None:
                    self._evaluate_known_code(
                        procedure,
                        hook,
                        (
                            (metaclass,),
                            (class_location,),
                            bases,
                        ),
                    )

    def _resolve_class_method(
        self,
        class_location: HeapLocation,
        methods: dict[object, py_ast.Code],
    ) -> py_ast.Code | None:
        for current in self._known_class_mro(class_location):
            method = methods.get(current.root)
            if method is not None:
                return method
        return None

    def _known_class_mro(
        self,
        class_location: HeapLocation,
    ) -> tuple[HeapLocation, ...]:
        """Compute a C3 linearization for the statically known base graph."""
        memo: dict[object, tuple[HeapLocation, ...]] = {}
        active: set[object] = set()

        def linearize(current: HeapLocation) -> tuple[HeapLocation, ...]:
            cached = memo.get(current.root)
            if cached is not None:
                return cached
            if current.root in active:
                return (current,)
            active.add(current.root)
            bases = tuple(
                dict.fromkeys(
                    (
                        *self._class_bases_by_root.get(current.root, ()),
                        *self.state.read(
                            self.heap.dynamic_attribute_location(
                                current,
                                "__bases__",
                            ),
                            fallback=(),
                        ),
                    )
                )
            )
            sequences = [list(linearize(base)) for base in bases]
            sequences.append(list(bases))
            merged: list[HeapLocation] = []
            while any(sequences):
                sequences = [sequence for sequence in sequences if sequence]
                candidate = next(
                    (
                        sequence[0]
                        for sequence in sequences
                        if all(
                            sequence[0] not in other[1:]
                            for other in sequences
                        )
                    ),
                    None,
                )
                if candidate is None:
                    # An invalid or partially unknown hierarchy would fail
                    # class creation concretely. Retain every remaining base
                    # as a conservative analysis fallback.
                    merged.extend(
                        item for sequence in sequences for item in sequence
                    )
                    break
                merged.append(candidate)
                for sequence in sequences:
                    if sequence and sequence[0] == candidate:
                        sequence.pop(0)
            active.remove(current.root)
            result = tuple(dict.fromkeys((current, *merged)))
            memo[current.root] = result
            return result

        return linearize(class_location)

    def _resolve_known_class_method(
        self,
        class_location: HeapLocation,
        name: str,
    ) -> py_ast.Code | None:
        for current in self._known_class_mro(class_location):
            method = self._class_methods_by_root.get(current.root, {}).get(name)
            if method is not None:
                return method
        return None

    def _resolve_known_class_method_kind(
        self,
        class_location: HeapLocation,
        name: str,
    ) -> str:
        for current in self._known_class_mro(class_location):
            kinds = self._class_method_kinds_by_root.get(current.root, {})
            if name in kinds:
                return kinds[name]
        return "instance"

    def _evaluate_known_protocol(
        self,
        procedure: object,
        receivers: tuple[HeapLocation, ...],
        name: str,
        actual_groups: tuple[tuple[HeapLocation, ...], ...] = (),
    ) -> tuple[HeapLocation, ...]:
        """Analyze every statically known implementation of a Python protocol."""
        base = self._capture_flow_state()
        normal_states: list[_FlowState] = [base]
        returns: list[HeapLocation] = []
        seen: set[tuple[object, object]] = set()
        for receiver in receivers:
            classes = self.state.read(
                self.heap.dynamic_attribute_location(receiver, "__class__"),
                fallback=(),
            )
            for class_location in classes:
                method = self._resolve_known_class_method(class_location, name)
                if method is None or (receiver.root, method) in seen:
                    continue
                seen.add((receiver.root, method))
                self._restore_flow_state(base)
                formals = self._callee_formals(method)
                bindings: dict[int, tuple[HeapLocation, ...]] = {}
                if formals:
                    bindings[0] = (receiver,)
                for index, locations in enumerate(actual_groups, start=1):
                    if index >= len(formals):
                        break
                    bindings[index] = locations or (
                        self._external_value_location(procedure),
                    )
                summary = self._callee_summary(method, bindings)
                if summary.normal_state is not None:
                    normal_states.append(
                        _FlowState(
                            summary.normal_state.copy(),
                            summary.normal_environment
                            or summary.environment
                            or base.environment,
                            dict(base.definition_defaults),
                        )
                    )
                if summary.raise_state is not None and self._operation_call_raises:
                    self._operation_call_raises[-1].append(
                        _FlowState(
                            summary.raise_state.copy(),
                            summary.raise_environment
                            or summary.environment
                            or base.environment,
                            dict(base.definition_defaults),
                        )
                    )
                for return_index, locations in enumerate(summary.returns):
                    returns.extend(locations)
                    for formal_index in summary.param_returns.get(
                        return_index,
                        frozenset(),
                    ):
                        returns.extend(bindings.get(formal_index, ()))
        self._restore_flow_state(self._join_flow_states(tuple(normal_states)))
        return tuple(dict.fromkeys(returns))

    def _evaluate_known_code(
        self,
        procedure: object,
        code: py_ast.Code,
        actual_groups: tuple[tuple[HeapLocation, ...], ...],
    ) -> tuple[HeapLocation, ...]:
        """Evaluate one already-resolved callable from explicit location groups."""
        formals = self._callee_formals(code)
        bindings = {
            index: locations
            for index, locations in enumerate(actual_groups)
            if index < len(formals)
        }
        summary = self._callee_summary(code, bindings)
        if summary.raise_state is not None and self._operation_call_raises:
            self._operation_call_raises[-1].append(
                _FlowState(
                    summary.raise_state.copy(),
                    summary.raise_environment
                    or summary.environment
                    or self.heap.snapshot_environment(),
                    dict(self._definition_default_locations),
                )
            )
        if summary.normal_state is None:
            if self._operation_normal_possible:
                self._operation_normal_possible[-1] = False
            return ()
        self._apply_callee_summary(summary, procedure)
        returns: list[HeapLocation] = []
        for return_index, locations in enumerate(summary.returns):
            returns.extend(locations)
            for formal_index in summary.param_returns.get(
                return_index,
                frozenset(),
            ):
                returns.extend(bindings.get(formal_index, ()))
        return tuple(dict.fromkeys(returns))

    def _apply_implicit_protocol_transfer(
        self,
        procedure: object,
        operation: object,
    ) -> None:
        protocol = None
        receiver_expression = None
        actual_expressions: tuple[object, ...] = ()
        if isinstance(operation, py_ast.SetAttr):
            protocol = "__setattr__"
            receiver_expression = operation.expr
            actual_expressions = (operation.name, operation.value)
        elif isinstance(operation, py_ast.SetSubscript):
            protocol = "__setitem__"
            receiver_expression = operation.expr
            actual_expressions = (operation.subscript, operation.value)
        elif isinstance(operation, py_ast.SetSlice):
            protocol = "__setitem__"
            receiver_expression = operation.expr
            actual_expressions = (
                operation.start,
                operation.stop,
                operation.step,
                operation.value,
            )
        elif isinstance(operation, py_ast.DeleteAttr):
            protocol = "__delattr__"
            receiver_expression = operation.expr
            actual_expressions = (operation.name,)
        elif isinstance(operation, py_ast.DeleteSubscript):
            protocol = "__delitem__"
            receiver_expression = operation.expr
            actual_expressions = (operation.subscript,)
        elif isinstance(operation, py_ast.DeleteSlice):
            protocol = "__delitem__"
            receiver_expression = operation.expr
            actual_expressions = (
                operation.start,
                operation.stop,
                operation.step,
            )
        if protocol is None or receiver_expression is None:
            return
        receivers = self.locations_for_expression(procedure, receiver_expression)
        actual_groups = tuple(
            self.locations_for_expression(procedure, expression)
            for expression in actual_expressions
        )
        self._evaluate_known_protocol(
            procedure,
            receivers,
            protocol,
            actual_groups,
        )
        if not isinstance(operation, (py_ast.SetAttr, py_ast.DeleteAttr)):
            return
        attribute = self.effect_builder._constant_string(operation.name)
        if attribute is None:
            return
        classes = tuple(
            dict.fromkeys(
                class_location
                for receiver in receivers
                for class_location in self.state.read(
                    self.heap.dynamic_attribute_location(receiver, "__class__"),
                    fallback=(),
                )
            )
        )
        descriptors = self._class_attribute_values(classes, attribute)
        descriptor_protocol = (
            "__set__" if isinstance(operation, py_ast.SetAttr) else "__delete__"
        )
        descriptor_actuals = (
            (receivers, actual_groups[-1])
            if isinstance(operation, py_ast.SetAttr)
            else (receivers,)
        )
        self._evaluate_known_protocol(
            procedure,
            descriptors,
            descriptor_protocol,
            descriptor_actuals,
        )

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

        if isinstance(call, py_ast.MethodCall):
            method_name = self.effect_builder._constant_string(call.name)
            if method_name is not None:
                for receiver_root in operand_locs(call.expr):
                    registered = self._super_methods_by_root.get(
                        receiver_root.root,
                        {},
                    ).get(method_name)
                    if registered is None:
                        continue
                    code, bound_receivers = registered
                    return self._evaluate_known_code(
                        procedure,
                        code,
                        (
                            bound_receivers,
                            *tuple(
                                operand_locs(actual)
                                for actual in getattr(call, "args", ())
                            ),
                        ),
                    )

        if call_name in {"super", "builtins.super"}:
            enclosing = self._lexical_parents.get(id(procedure))
            current_class = self._class_locations_by_definition.get(id(enclosing))
            if actuals:
                explicit_class = operand_locs(actuals[0])
                current_class = explicit_class[0] if explicit_class else current_class
            receiver_locations: tuple[HeapLocation, ...] = ()
            if len(actuals) > 1:
                receiver_locations = operand_locs(actuals[1])
            elif current_class is not None:
                formals = self._callee_formals(procedure)
                if formals:
                    receiver_locations = self.heap.locations_for_local(
                        procedure,
                        formals[0],
                    )
            if current_class is not None:
                proxy = HeapLocation(
                    self.heap.allocation_object(
                        procedure,
                        ("super", id(call), current_class.root),
                        label="super proxy",
                        context=self._current_context,
                    )
                )
                self.state.write(
                    self.heap.dynamic_attribute_location(proxy, "__super_class__"),
                    (current_class,),
                    UpdatePolicy.STRONG,
                )
                self.state.write(
                    self.heap.dynamic_attribute_location(proxy, "__super_self__"),
                    receiver_locations,
                    UpdatePolicy.STRONG,
                )
                inherited: dict[
                    str,
                    tuple[py_ast.Code, tuple[HeapLocation, ...]],
                ] = {}
                for name, method in self._super_dispatch_by_class_root.get(
                    current_class.root,
                    {},
                ).items():
                    inherited[name] = (method, receiver_locations)
                if not inherited and isinstance(enclosing, py_ast.ClassDef):
                    for base_expression in getattr(enclosing, "bases", ()):
                        if not isinstance(base_expression, py_ast.Local):
                            continue
                        base = self._class_definitions.get(
                            (
                                self._module_owner(procedure),
                                base_expression.name,
                            )
                        )
                        if base is None:
                            continue
                        for base_class in self._known_class_mro(base):
                            for name, method in self._class_methods_by_root.get(
                                base_class.root,
                                {},
                            ).items():
                                inherited.setdefault(
                                    name,
                                    (method, receiver_locations),
                                )
                self._super_methods_by_root[proxy.root] = inherited
                return (proxy,)
            return (self._external_value_location(procedure),)
        if call_name in {"type", "builtins.type"}:
            operand_types = tuple(
                dict.fromkeys(
                    class_location
                    for actual in actuals[:1]
                    for location in operand_locs(actual)
                    for class_location in self.state.read(
                        self.heap.dynamic_attribute_location(
                            location,
                            "__class__",
                        ),
                        fallback=(),
                    )
                )
            )
            if operand_types:
                return operand_types
            type_tokens = tuple(
                dict.fromkeys(
                    token
                    for actual in actuals[:1]
                    for location in operand_locs(actual)
                    for token in (self._known_builtin_type_token(location),)
                    if token is not None
                )
            )
            if type_tokens:
                return tuple(
                    HeapLocation(
                        self.heap.external_object(
                            ("builtin-type", token),
                            label=f"type {token}",
                            type_hint="type",
                            stable_identity=True,
                        )
                    )
                    for token in type_tokens
                )
            return (
                HeapLocation(
                    self.heap.unknown_object(
                        ("type-result", id(call), self._evaluation_epoch),
                        label="unknown type result",
                        type_hint="type",
                    )
                ),
            )
        if call_name == "decimal.getcontext":
            return (
                HeapLocation(
                    self.heap.external_object(
                        ("decimal-context",),
                        label="decimal context",
                        stable_identity=True,
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
                    self.heap.external_object(
                        ("logging.getLogger", logger_name),
                        label=f"logger {logger_name or '<dynamic>'}",
                        stable_identity=True,
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

    @staticmethod
    def _known_builtin_type_token(location: HeapLocation) -> str | None:
        if location.root.type_hint:
            return location.root.type_hint
        label = location.root.label
        return {
            "list literal": "list",
            "tuple literal": "tuple",
            "set literal": "set",
            "map literal": "dict",
            "slice": "slice",
        }.get(label)

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
            resume_base = self.state.copy()
            previous_context = self._current_context
            self._current_context = (
                *previous_context,
                "resume",
                root.root.key,
            )
            try:
                if activation.summary is None or sent_values or use_yields:
                    external_environment = self.heap.snapshot_environment()
                    if activation.frame_environment is not None:
                        self.heap.restore_environment(
                            self.heap.join_environments(
                                (
                                    external_environment,
                                    activation.frame_environment,
                                )
                            )
                        )
                    if sent_values:
                        self._resume_input_stack.append(
                            (max(activation.resume_index - 1, 0), sent_values)
                        )
                    try:
                        activation.summary = self._callee_summary(
                            activation.callee,
                            activation.actual_bindings,
                        )
                    finally:
                        if sent_values:
                            self._resume_input_stack.pop()
                        self.heap.restore_environment(external_environment)
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
                    resume_index = activation.resume_index
                    step_state, step_environment, yielded = summary.yield_steps[
                        resume_index
                    ]
                    activation.resume_index += 1
                    activation.frame_environment = step_environment
                    caller_environment = self.heap.snapshot_environment()
                    caller_environment.object_labels.update(
                        step_environment.object_labels
                    )
                    caller_environment.escaped_objects.update(
                        step_environment.escaped_objects
                    )
                    previous_frontier = (
                        resume_base
                        if resume_index == 0
                        else summary.yield_steps[resume_index - 1][0]
                    )
                    self._apply_continuation_frontier(
                        previous_frontier,
                        step_state,
                    )
                    self.heap.restore_environment(caller_environment)
                    values.extend(yielded)
                else:
                    if summary.normal_state is None and self._operation_normal_possible:
                        self._operation_normal_possible[-1] = False
                    self._apply_callee_summary(
                        summary,
                        caller,
                        preserve_current=activation.resume_index > 0,
                    )
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

    def _apply_continuation_frontier(
        self,
        previous: HeapState,
        current: HeapState,
    ) -> None:
        """Rebase the delta between two suspension frontiers onto the caller.

        Summaries are recomputed against the heap visible at each resume.  By
        applying only facts changed after the preceding yield, effects in the
        already-consumed generator prefix are not replayed into the caller.
        """
        rebased = self.state.copy()
        for attribute in ("values", "contaminants", "versions"):
            before_map = getattr(previous, attribute)
            after_map = getattr(current, attribute)
            target_map = getattr(rebased, attribute)
            for location in set(before_map) | set(after_map):
                if before_map.get(location) == after_map.get(location):
                    continue
                if location in after_map:
                    target_map[location] = after_map[location]
                else:
                    target_map.pop(location, None)
        changed_absence = previous.absent ^ current.absent
        for location in changed_absence:
            if location in current.absent:
                rebased.absent.add(location)
            else:
                rebased.absent.discard(location)
        changed_scalars = previous.scalar_present ^ current.scalar_present
        for location in changed_scalars:
            if location in current.scalar_present:
                rebased.scalar_present.add(location)
                rebased.absent.discard(location)
            else:
                rebased.scalar_present.discard(location)
        rebased.complete_roots.update(
            current.complete_roots - previous.complete_roots
        )
        rebased.escaped.update(current.escaped - previous.escaped)
        self.state = rebased

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
