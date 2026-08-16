"""Name, attribute, and subscript expression resolution."""

from __future__ import annotations

from pyflow.language.python import ast as py_ast

from ..model import HeapLocation, UpdatePolicy
from ..semantics.effects import DYNAMIC_SUBSCRIPT_WILDCARD
from .state import ExpressionValue


class _ExpressionAccessMixin:
    def _resolve_type_parameter(
        self,
        procedure: object,
        expression: object,
    ) -> tuple[HeapLocation, ...]:
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

    def _resolve_type_parameters(
        self,
        procedure: object,
        expression: object,
    ) -> tuple[HeapLocation, ...]:
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

    def _resolve_local(
        self,
        procedure: object,
        expression: object,
    ) -> tuple[HeapLocation, ...]:
        declared = self._declared_location(procedure, expression)
        if declared is not None:
            return self._read_heap_locations((declared,))
        local_value = self.heap.local_value_for_local(procedure, expression)
        if local_value is not None:
            if local_value.may_unbound:
                self._record_unbound_local_read(procedure, expression)
            if (
                not local_value.refs
                and not local_value.may_non_reference
                and local_value.may_unbound
                and self._operation_normal_possible
            ):
                self._operation_normal_possible[-1] = False
            storage_order = self.heap.locations_for_local(procedure, expression)
            return tuple(
                dict.fromkeys(
                    (
                        *(location for location in storage_order if location in local_value.refs),
                        *sorted(
                            local_value.refs.difference(storage_order),
                            key=repr,
                        ),
                    )
                )
            )
        definition_local = self._definition_locals.get(
            (self._procedure_identity(procedure), expression.name)
        )
        if definition_local is not None:
            locations = self.heap.locations_for_local(
                procedure,
                definition_local,
            )
            if locations:
                return locations
        if isinstance(procedure, py_ast.ClassDef):
            outer_locations = self._outer_local_locations(expression)
            if outer_locations:
                return outer_locations
        for index, formal in enumerate(self._callee_formals(procedure)):
            if getattr(formal, "name", None) != expression.name:
                continue
            self.heap.bind_parameter(procedure, expression, index, ())
            return self.heap.locations_for_local(procedure, expression)
        if self._scope_defines_name(procedure, expression.name):
            self.heap.clear_local_binding(procedure, expression, unbound=True)
            self._record_unbound_local_read(procedure, expression)
            if self._operation_normal_possible:
                self._operation_normal_possible[-1] = False
            return ()
        obj = self.heap.local_object(procedure, expression)
        self.heap.bind_local_to_object(procedure, expression, obj)
        return self.heap.locations_for_local(procedure, expression)

    def _record_unbound_local_read(
        self,
        procedure: object,
        expression: object,
    ) -> None:
        if not self._operation_call_raises:
            return
        raised_state = self.state.copy()
        exception = HeapLocation(
            self.heap.external_object(
                (
                    "unbound-local",
                    self._procedure_identity(procedure),
                    expression.name,
                ),
                label="UnboundLocalError",
                type_hint="UnboundLocalError",
            )
        )
        raised_state.set_raised(procedure, (exception,))
        from .state import _FlowState

        self._operation_call_raises[-1].append(
            _FlowState(
                raised_state,
                self.heap.snapshot_environment(),
                dict(self._definition_default_locations),
            )
        )

    def _resolve_global(
        self,
        procedure: object,
        expression: object,
    ) -> tuple[HeapLocation, ...]:
        return self._resolve_global_value(procedure, expression).refs

    def _resolve_global_value(
        self,
        procedure: object,
        expression: object,
    ) -> ExpressionValue:
        location = self.effect_builder.global_location(procedure, expression.name)
        return self._read_heap_value((location,))

    def _resolve_cell(
        self,
        procedure: object,
        expression: object,
    ) -> tuple[HeapLocation, ...]:
        return self._resolve_cell_value(procedure, expression).refs

    def _resolve_cell_value(
        self,
        procedure: object,
        expression: object,
    ) -> ExpressionValue:
        location = self.effect_builder.cell_location(expression.cell, procedure)
        return self._read_heap_value((location,))

    def _resolve_attribute(
        self,
        procedure: object,
        expression: object,
    ) -> tuple[HeapLocation, ...]:
        return self._resolve_attribute_value(procedure, expression).refs

    def _resolve_attribute_value(
        self,
        procedure: object,
        expression: object,
    ) -> ExpressionValue:
        bases = self.locations_for_expression(procedure, expression.expr)
        name_locations = self.locations_for_expression(
            procedure,
            expression.name,
        )
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
        heap_value = self._read_heap_value(locations)
        values = list(heap_value.refs)
        super_members: list[HeapLocation] = []
        super_receivers: list[HeapLocation] = []
        for base in bases:
            current_classes = self.state.read(
                self.heap.dynamic_attribute_location(
                    base,
                    "__super_class__",
                ),
                fallback=(),
            )
            receivers = self.state.read(
                self.heap.dynamic_attribute_location(base, "__super_self__"),
                fallback=(),
            )
            for current_class in current_classes:
                mro = self._known_class_mro(current_class)
                for next_class in mro[1:]:
                    stored = self.state.read(
                        self.heap.dynamic_attribute_location(
                            next_class,
                            attribute,
                        ),
                        fallback=(),
                    )
                    if stored:
                        super_members.extend(stored)
                        super_receivers.extend(receivers)
                        break
        values.extend(super_members)
        for member in super_members:
            code = self._function_codes_by_root.get(member.root)
            if code is None:
                continue
            bound = HeapLocation(
                self.heap.allocation_object(
                    procedure,
                    ("super-bound-method", expression, member),
                    label=f"bound super method {attribute}",
                    context=self._current_context,
                )
            )
            self._bound_methods_by_root[bound.root] = (
                code,
                tuple(dict.fromkeys(super_receivers)),
            )
            values.append(bound)
        values.extend(
            self._evaluate_known_protocol(
                procedure,
                bases,
                "__getattribute__",
                (name_locations,),
            )
        )
        values.extend(
            self._evaluate_known_protocol(
                procedure,
                bases,
                "__getattr__",
                (name_locations,),
            )
        )
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
            class_values = self._class_attribute_values(classes, attribute)
            bound_values: list[HeapLocation] = []
            ordinary_class_values: list[HeapLocation] = []
            for member in class_values:
                code = self._function_codes_by_root.get(member.root)
                if code is None:
                    ordinary_class_values.append(member)
                    continue
                kind = self._function_binding_kinds.get(
                    member.root,
                    "instance",
                )
                if kind == "property":
                    values.extend(
                        self._evaluate_known_code(
                            procedure,
                            code,
                            (bases,),
                        )
                    )
                    continue
                if kind == "staticmethod":
                    ordinary_class_values.append(member)
                    continue
                receivers = classes if kind == "classmethod" else bases
                bound = HeapLocation(
                    self.heap.allocation_object(
                        procedure,
                        ("bound-method", expression, member, receivers),
                        label=f"bound method {attribute}",
                        context=self._current_context,
                    )
                )
                self._bound_methods_by_root[bound.root] = (code, receivers)
                self.state.write(
                    self.heap.dynamic_attribute_location(bound, "__func__"),
                    (member,),
                    UpdatePolicy.STRONG,
                )
                self.state.write(
                    self.heap.dynamic_attribute_location(bound, "__self__"),
                    receivers,
                    UpdatePolicy.STRONG,
                )
                bound_values.append(bound)
            values.extend(ordinary_class_values)
            values.extend(bound_values)
            values.extend(
                self._evaluate_known_protocol(
                    procedure,
                    tuple(ordinary_class_values),
                    "__get__",
                    (bases, classes),
                )
            )
        return ExpressionValue(
            refs=tuple(dict.fromkeys(values)),
            may_non_reference=heap_value.may_non_reference,
        )

    def _resolve_subscript(
        self,
        procedure: object,
        expression: object,
    ) -> tuple[HeapLocation, ...]:
        return self._resolve_subscript_value(procedure, expression).refs

    def _resolve_subscript_value(
        self,
        procedure: object,
        expression: object,
    ) -> ExpressionValue:
        bases = self.locations_for_expression(procedure, expression.expr)
        subscript_locations = self.locations_for_expression(
            procedure,
            expression.subscript,
        )
        protocol_values = self._evaluate_known_protocol(
            procedure,
            bases,
            "__getitem__",
            (subscript_locations,),
        )
        subscript = self.effect_builder._constant_subscript(expression.subscript)
        if subscript is None:
            values: list[HeapLocation] = []
            wildcard_locations = self.heap.dynamic_subscript_locations(
                bases,
                (DYNAMIC_SUBSCRIPT_WILDCARD,),
            )
            for base in bases:
                wildcard = self.heap.dynamic_subscript_location(
                    base,
                    DYNAMIC_SUBSCRIPT_WILDCARD,
                )
                values.extend(self.state.read_contained(wildcard))
            if values:
                return ExpressionValue(
                    tuple(dict.fromkeys((*values, *protocol_values))),
                    may_non_reference=any(
                        self.state.locations_may_overlap(stored, wildcard)
                        for wildcard in wildcard_locations
                        for stored in self.state.scalar_present
                    ),
                )
            if protocol_values:
                return ExpressionValue(protocol_values)
            return ExpressionValue(wildcard_locations)
        locations = self.heap.dynamic_subscript_locations(
            bases,
            (subscript, DYNAMIC_SUBSCRIPT_WILDCARD),
        )
        heap_value = self._read_heap_value(locations)
        return ExpressionValue(
            refs=tuple(dict.fromkeys((*heap_value.refs, *protocol_values))),
            may_non_reference=heap_value.may_non_reference,
        )
