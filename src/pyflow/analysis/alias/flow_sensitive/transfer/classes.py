"""Known-class, descriptor, and protocol transfer methods."""

from __future__ import annotations
from pyflow.language.python.ir_metadata import actual_argument_expressions, resolve_call_name
from pyflow.language.python import ast as py_ast
from ..semantics.effects import DYNAMIC_SUBSCRIPT_WILDCARD
from ..semantics.intrinsics import CALL_RETURN_ARG, CALL_RETURN_SELF
from ..model import HeapLocation, UpdatePolicy
from .state import _FlowState


class _ClassTransferMixin:
    """Internal mixin composed by HeapTransferEngine."""

    def _known_class_locations(
        self,
        procedure: object,
        call: object,
        operand_locations: dict[object, tuple[HeapLocation, ...]] | None = None,
    ) -> tuple[HeapLocation, ...]:
        if not isinstance(call, py_ast.Call):
            return ()
        operands = operand_locations or self._last_call_operands.get(
            self._program_point_identity(procedure, call)
        )
        if operands is None:
            operands = self._evaluate_call_operands(procedure, call)
        return tuple(
            dict.fromkeys(
                self._class_locations_by_root[location.root]
                for location in operands.get(
                    self._program_point_identity(procedure, call.expr), ()
                )
                if location.root in self._class_locations_by_root
            )
        )

    def _evaluate_known_class_targets(
        self,
        procedure: object,
        call: object,
        classes: tuple[HeapLocation, ...],
        operand_locations: dict[object, tuple[HeapLocation, ...]],
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
            allocated = (
                self._evaluate_known_class_allocator(
                    procedure,
                    call,
                    class_location,
                    operand_locations,
                )
                if allocator is not None
                else ()
            )
            if allocator is None:
                allocated = (
                    HeapLocation(
                        self.heap.allocation_object(
                            procedure,
                            (
                                "class-instance",
                                self._program_point_identity(procedure, call),
                                class_location.root,
                            ),
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
        operand_locations: dict[object, tuple[HeapLocation, ...]],
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
            locations = operand_locations.get(
                self._program_point_identity(procedure, actual)
            )
            if locations is None:
                locations = self.locations_for_expression(procedure, actual)
            bindings[index] = locations
        parameter_names = tuple(getattr(allocator.codeparameters, "paramnames", ()))
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
            locations = operand_locations.get(
                self._program_point_identity(procedure, actual)
            )
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
            or (
                self._program_point_identity(procedure, call),
                class_location.root,
            )
            in self._initialized_class_calls
        ):
            return
        self._initialized_class_calls.add(
            (self._program_point_identity(procedure, call), class_location.root)
        )
        formals = self._callee_formals(initializer)
        bindings: dict[int, tuple[HeapLocation, ...]] = {}
        if formals:
            bindings[0] = tuple(compatible)
        actuals = tuple(getattr(call, "args", ()))
        evaluated = self._last_call_operands.get(
            self._program_point_identity(procedure, call), {}
        )
        for index, actual in enumerate(actuals, start=1):
            if index >= len(formals):
                break
            locations = evaluated.get(
                self._program_point_identity(procedure, actual)
            )
            if locations is None:
                locations = self.locations_for_expression(procedure, actual)
            bindings[index] = locations
        params = initializer.codeparameters
        encoded_names = list(getattr(params, "paramnames", ()))
        encoded_formals = list(getattr(params, "params", ()))
        formal_indices = {
            self._reference_identity(initializer, formal): index
            for index, formal in enumerate(formals)
        }
        named = {
            (
                name[len("kwonly:") :] if name.startswith("kwonly:") else name
            ): formal_indices[self._reference_identity(initializer, formal)]
            for name, formal in zip(encoded_names, encoded_formals)
            if isinstance(name, str)
            and isinstance(formal, py_ast.Local)
            and self._reference_identity(initializer, formal) in formal_indices
        }
        for keyword in getattr(call, "kwds", ()):
            if not (isinstance(keyword, tuple) and len(keyword) == 2):
                continue
            name, actual = keyword
            index = named.get(name)
            if index is None:
                continue
            locations = evaluated.get(
                self._program_point_identity(procedure, actual)
            )
            if locations is None:
                locations = self.locations_for_expression(procedure, actual)
            bindings[index] = tuple(
                dict.fromkeys((*bindings.get(index, ()), *locations))
            )
        if (
            getattr(call, "vargs", None) is not None
            or getattr(call, "kargs", None) is not None
        ):
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
        self._super_dispatch_by_class_root[class_location.root] = inherited_dispatch
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
                        if all(sequence[0] not in other[1:] for other in sequences)
                    ),
                    None,
                )
                if candidate is None:
                    # An invalid or partially unknown hierarchy would fail
                    # class creation concretely. Retain every remaining base
                    # as a conservative analysis fallback.
                    merged.extend(item for sequence in sequences for item in sequence)
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
        pending = self._pending_call_results.pop(
            self._program_point_identity(procedure, operation), None
        )
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
    ) -> dict[object, tuple[HeapLocation, ...]]:
        """Evaluate a non-resolved call's operands once, in Python order."""
        evaluated: dict[object, tuple[HeapLocation, ...]] = {}

        def evaluate(expression: object) -> None:
            if expression is None:
                return
            evaluated[self._program_point_identity(procedure, expression)] = (
                self.locations_for_expression(
                procedure,
                expression,
            )
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
        self._last_call_operands[
            self._program_point_identity(procedure, call)
        ] = evaluated
        return evaluated

    def _modeled_call_return_locations(
        self,
        procedure: object,
        call: object,
        kind: str,
        operand_locations: dict[object, tuple[HeapLocation, ...]] | None = None,
    ) -> tuple[HeapLocation, ...]:
        call_name = resolve_call_name(call)
        actuals = tuple(actual_argument_expressions(call))
        receiver = (
            getattr(call, "expr", None)
            if isinstance(call, py_ast.MethodCall)
            else getattr(call, "selfarg", None)
        )

        def operand_locs(expression: object) -> tuple[HeapLocation, ...]:
            if operand_locations is not None:
                cached = operand_locations.get(
                    self._program_point_identity(procedure, expression)
                )
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
            enclosing = self._lexical_parents.get(procedure)
            current_class = self._class_locations_by_definition.get(enclosing)
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
                        (
                            "super",
                            self._program_point_identity(procedure, call),
                            current_class.root,
                        ),
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
                        (
                            "type-result",
                            self._program_point_identity(procedure, call),
                            self._evaluation_epoch,
                        ),
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
                self.effect_builder._constant_string(actuals[0]) if actuals else "root"
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
            iterable = (
                receiver if receiver is not None else (actuals[0] if actuals else None)
            )
            if iterable is not None:
                roots = operand_locs(iterable)
                values: list[HeapLocation] = list(
                    self._resume_deferred_activations(
                        procedure,
                        roots,
                        use_yields=True,
                        sent_values=(
                            operand_locs(
                                actuals[0] if receiver is not None else actuals[1]
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
                values = list(self._contained_values(operand_locs(positional[0])))
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
            iterable = (
                receiver if receiver is not None else (actuals[0] if actuals else None)
            )
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
                else actuals[return_index : return_index + 1]
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
                if (
                    call_name in {"get", "dict.get", "pop", "dict.pop"}
                    and len(args) >= 2
                ):
                    values.extend(operand_locs(args[1]))
                if call_name in {"setdefault", "dict.setdefault"} and len(args) >= 2:
                    values.extend(operand_locs(args[1]))
                return tuple(dict.fromkeys(values))

        return ()
