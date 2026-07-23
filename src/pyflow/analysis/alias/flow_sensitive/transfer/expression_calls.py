"""Call, allocation, and function expression resolution."""

from __future__ import annotations

from pyflow.language.python.ir_metadata import resolve_call_name
from pyflow.language.python import ast as py_ast

from ..model import HeapLocation, UpdatePolicy
from ..semantics.effects import (
    CALL_RETURN_COPY,
    CALL_RETURN_FRESH,
)
from ..semantics.intrinsics import CALL_RETURN_NONE


class _ExpressionCallMixin:
    def _resolve_direct_call(
        self,
        procedure: object,
        expression: object,
    ) -> tuple[HeapLocation, ...]:
        return self._evaluate_direct_call_expression(procedure, expression)

    def _resolve_call(
        self,
        procedure: object,
        expression: object,
    ) -> tuple[HeapLocation, ...]:
        # Calls are expressions in Python, so their control-flow and heap
        # effects must be applied even when nested inside another
        # expression rather than materialized by an Assign/Discard node.
        self._apply_call_transfer(procedure, expression)
        application_key = self._call_application_key(expression)
        finite_values = self._finite_call_results.get(application_key)
        if finite_values is not None:
            return finite_values
        operand_locations = self._evaluate_call_operands(
            procedure,
            expression,
        )
        known_classes = self._known_class_locations(
            procedure,
            expression,
            operand_locations,
        )
        if known_classes:
            return self._evaluate_known_class_targets(
                procedure,
                expression,
                known_classes,
                operand_locations,
                self.effect_builder._call_result_label(expression),
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
            return tuple(
                dict.fromkeys(
                    (
                        *modeled,
                        *self._protocol_call_results.get(application_key, ()),
                    )
                )
            )
        result = (
            HeapLocation(self.effect_builder.call_return_object(procedure, expression)),
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
                dict.fromkeys((*result, self._external_value_location(procedure)))
            )
        if kind == CALL_RETURN_COPY:
            self._copy_call_result_contents(
                procedure,
                None,
                expression,
                result,
            )
        self._attach_known_class(procedure, expression, result)
        return tuple(
            dict.fromkeys(
                (
                    *result,
                    *self._protocol_call_results.get(application_key, ()),
                )
            )
        )

    def _resolve_allocation(
        self,
        procedure: object,
        expression: object,
    ) -> tuple[HeapLocation, ...]:
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

    def _resolve_function(
        self,
        procedure: object,
        expression: object,
    ) -> tuple[HeapLocation, ...]:
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
        if isinstance(expression.code, py_ast.Code):
            self._function_codes_by_root[function.root] = expression.code
            self._function_binding_kinds[function.root] = "instance"
            self._lexical_parents.setdefault(id(expression.code), procedure)
            self._module_owners.setdefault(
                id(expression.code),
                self._module_owner(procedure),
            )
        return (function,)
