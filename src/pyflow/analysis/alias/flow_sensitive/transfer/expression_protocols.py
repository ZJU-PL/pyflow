"""Protocol-driven expression resolution for operators and iteration."""

from __future__ import annotations

from pyflow.language.python import ast as py_ast

from ..model import HeapLocation, UpdatePolicy


class _ExpressionProtocolMixin:
    def _resolve_iterator(
        self,
        procedure: object,
        expression: object,
    ) -> tuple[HeapLocation, ...]:
        sources = self.locations_for_expression(procedure, expression.expr)
        protocol_values = self._evaluate_known_protocol(
            procedure,
            sources,
            (
                "__aiter__"
                if isinstance(expression, py_ast.AsyncGetIter)
                else "__iter__"
            ),
        )
        if not protocol_values and isinstance(expression, py_ast.GetIter):
            protocol_values = self._evaluate_known_protocol(
                procedure,
                sources,
                "__getitem__",
                ((self._external_value_location(procedure),),),
            )
        iterator = HeapLocation(
            self.heap.allocation_object(
                procedure,
                expression,
                label=(
                    "async iterator"
                    if isinstance(expression, py_ast.AsyncGetIter)
                    else "iterator"
                ),
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
                if not protocol_values
                else (iterator, *sources, *protocol_values)
            )
        )

    def _resolve_slice(
        self,
        procedure: object,
        expression: object,
    ) -> tuple[HeapLocation, ...]:
        bases = self.locations_for_expression(procedure, expression.expr)
        components: list[HeapLocation] = []
        for component in (
            expression.start,
            expression.stop,
            expression.step,
        ):
            components.extend(self.locations_for_expression(procedure, component))
        protocol_values = self._evaluate_known_protocol(
            procedure,
            bases,
            "__getitem__",
            (tuple(dict.fromkeys(components)),),
        )
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
                (
                    *bases,
                    sliced,
                    *protocol_values,
                    self._external_value_location(procedure),
                )
            )
        )

    def _resolve_unary(
        self,
        procedure: object,
        expression: object,
    ) -> tuple[HeapLocation, ...]:
        operand = self.locations_for_expression(procedure, expression.expr)
        protocol = {
            "+": "__pos__",
            "-": "__neg__",
            "~": "__invert__",
        }.get(expression.op)
        protocol_values = (
            self._evaluate_known_protocol(procedure, operand, protocol)
            if protocol is not None
            else ()
        )
        return tuple(
            dict.fromkeys(
                (
                    *operand,
                    *protocol_values,
                    self._external_value_location(procedure),
                )
            )
        )

    def _resolve_binary(
        self,
        procedure: object,
        expression: object,
    ) -> tuple[HeapLocation, ...]:
        left = self.locations_for_expression(procedure, expression.left)
        right = self.locations_for_expression(procedure, expression.right)
        if expression.op in {"in", "not in"}:
            protocol_values = self._evaluate_known_protocol(
                procedure,
                right,
                "__contains__",
                (left,),
            )
        else:
            protocol = self._binary_protocol_name(expression.op)
            reflected = self._reflected_binary_protocol_name(expression.op)
            if reflected is None:
                reflected = self._reflected_comparison_protocol_name(expression.op)
            protocol_values = tuple(
                dict.fromkeys(
                    (
                        *(
                            self._evaluate_known_protocol(
                                procedure, left, protocol, (right,)
                            )
                            if protocol is not None
                            else ()
                        ),
                        *(
                            self._evaluate_known_protocol(
                                procedure, right, reflected, (left,)
                            )
                            if reflected is not None
                            else ()
                        ),
                    )
                )
            )
        return tuple(
            dict.fromkeys(
                (
                    *left,
                    *right,
                    *protocol_values,
                    self._external_value_location(procedure),
                )
            )
        )

    def _resolve_boolean_conversion(
        self,
        procedure: object,
        expression: object,
    ) -> tuple[HeapLocation, ...]:
        operand = self.locations_for_expression(procedure, expression.expr)
        bool_values = self._evaluate_known_protocol(
            procedure,
            operand,
            "__bool__",
        )
        if not bool_values:
            self._evaluate_known_protocol(
                procedure,
                operand,
                "__len__",
            )
        return ()

    def _resolve_identity_or_check(
        self,
        procedure: object,
        expression: object,
    ) -> tuple[HeapLocation, ...]:
        self.locations_for_expression(
            procedure,
            (expression.left if isinstance(expression, py_ast.Is) else expression.expr),
        )
        if isinstance(expression, py_ast.Is):
            self.locations_for_expression(procedure, expression.right)
        else:
            self.locations_for_expression(procedure, expression.name)
        return ()
