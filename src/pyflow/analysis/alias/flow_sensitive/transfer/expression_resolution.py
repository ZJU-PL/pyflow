"""Expression-to-heap-location resolution for the transfer engine."""

from __future__ import annotations

from pyflow.language.python import ast as py_ast

from ..model import HeapLocation, HeapObjectIdentity


from .expression_access import _ExpressionAccessMixin
from .expression_calls import _ExpressionCallMixin
from .expression_control import _ExpressionControlMixin
from .expression_protocols import _ExpressionProtocolMixin


class _ExpressionResolverMixin(
    _ExpressionAccessMixin,
    _ExpressionCallMixin,
    _ExpressionProtocolMixin,
    _ExpressionControlMixin,
):
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
        cache_key = self._program_point_identity(procedure, expression)
        if cache is not None and cacheable:
            cached = cache.get(cache_key)
            if cached is not None:
                return cached
        self._record_exception_prefix()
        result = self._locations_for_expression_impl(procedure, expression)
        self._record_exception_prefix()
        if cache is not None and cacheable:
            cache[cache_key] = result
        return result

    def _locations_for_expression_impl(
        self,
        procedure: object,
        expression: object,
    ) -> tuple[HeapLocation, ...]:
        """Conservative locations read by an expression."""
        if expression is None:
            return ()
        if isinstance(expression, HeapLocation):
            return (expression,)
        if isinstance(expression, py_ast.DoNotCare):
            return ()
        if isinstance(expression, py_ast.Input):
            return self.locations_for_expression(procedure, expression.lcl)
        if isinstance(expression, py_ast.Cell):
            return (self.effect_builder.cell_location(expression, procedure),)
        if isinstance(expression, py_ast.TypeParam):
            return self._resolve_type_parameter(procedure, expression)
        if isinstance(expression, py_ast.TypeParams):
            return self._resolve_type_parameters(procedure, expression)
        if isinstance(expression, py_ast.Local):
            return self._resolve_local(procedure, expression)
        if isinstance(expression, py_ast.GetGlobal):
            return self._resolve_global(procedure, expression)
        if isinstance(expression, (py_ast.GetCell, py_ast.GetCellDeref)):
            return self._resolve_cell(procedure, expression)
        if isinstance(expression, (py_ast.GetAttr, py_ast.Load)):
            return self._resolve_attribute(procedure, expression)
        if isinstance(expression, py_ast.GetSubscript):
            return self._resolve_subscript(procedure, expression)
        if isinstance(expression, py_ast.DirectCall) and isinstance(
            expression.code, py_ast.Code
        ):
            return self._resolve_direct_call(procedure, expression)
        if isinstance(expression, (py_ast.Call, py_ast.DirectCall, py_ast.MethodCall)):
            return self._resolve_call(procedure, expression)
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
            return self._resolve_allocation(procedure, expression)
        if isinstance(expression, py_ast.MakeFunction):
            return self._resolve_function(procedure, expression)
        if isinstance(expression, (py_ast.GetIter, py_ast.AsyncGetIter)):
            return self._resolve_iterator(procedure, expression)
        if isinstance(expression, py_ast.GetSlice):
            return self._resolve_slice(procedure, expression)
        if isinstance(expression, (py_ast.UnaryPrefixOp,)):
            return self._resolve_unary(procedure, expression)
        if isinstance(expression, py_ast.BinaryOp):
            return self._resolve_binary(procedure, expression)
        if isinstance(expression, (py_ast.ConvertToBool, py_ast.Not)):
            return self._resolve_boolean_conversion(procedure, expression)
        if isinstance(expression, (py_ast.Is, py_ast.Check)):
            return self._resolve_identity_or_check(procedure, expression)
        if isinstance(expression, py_ast.Await):
            return self._resolve_await(procedure, expression)
        if isinstance(expression, (py_ast.Yield, py_ast.AsyncYield)):
            return self._resolve_yield(procedure, expression)
        if isinstance(expression, py_ast.YieldFrom):
            return self._resolve_yield_from(procedure, expression)
        if isinstance(expression, (py_ast.ShortCircutAnd, py_ast.ShortCircutOr)):
            return self._resolve_short_circuit(procedure, expression)
        if isinstance(expression, py_ast.ConditionalExpr):
            return self._resolve_conditional(procedure, expression)
        if isinstance(expression, py_ast.NamedExpr):
            return self._resolve_named_expression(procedure, expression)
        if isinstance(expression, py_ast.Existing):
            return self._resolve_existing(procedure, expression)
        if isinstance(expression, py_ast.Expression):
            return self._resolve_unsupported_expression(procedure, expression)
        return ()

    def _class_attribute_values(
        self,
        classes: tuple[HeapLocation, ...],
        attribute: str,
    ) -> tuple[HeapLocation, ...]:
        values: list[HeapLocation] = []
        for root_class in classes:
            for class_location in self._known_class_mro(root_class):
                stored = self.state.read(
                    self.heap.dynamic_attribute_location(
                        class_location,
                        attribute,
                    ),
                    fallback=(),
                )
                if stored:
                    values.extend(stored)
                    # Python attribute resolution stops at the first class in
                    # the MRO defining the attribute.
                    break
        return tuple(dict.fromkeys(values))

    def _external_value_location(self, procedure: object) -> HeapLocation:
        return HeapLocation(
            self.heap.unknown_object(
                ("external-value", self._procedure_identity(procedure)),
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
                values.append(
                    HeapLocation(
                        self.heap.unknown_object(
                            (
                                "read",
                                location,
                                tuple(sorted(self.state.version_for(location))),
                            ),
                            label=f"unknown value at {location!r}",
                            identity=(
                                HeapObjectIdentity.SYMBOLIC
                                if not location.is_nested()
                                else HeapObjectIdentity.SUMMARY
                            ),
                        )
                    )
                )
        return tuple(dict.fromkeys(values))

    def _merge_expression_locations(self, procedure, *expressions):
        """Return the deduplicated union of heap locations from multiple expressions."""
        locations: list[HeapLocation] = []
        for expr in expressions:
            if expr is not None:
                locations.extend(self.locations_for_expression(procedure, expr))
        return tuple(dict.fromkeys(locations))

    @staticmethod
    def _binary_protocol_name(operator: str) -> str | None:
        return {
            "+": "__add__",
            "-": "__sub__",
            "*": "__mul__",
            "@": "__matmul__",
            "/": "__truediv__",
            "//": "__floordiv__",
            "%": "__mod__",
            "**": "__pow__",
            "<<": "__lshift__",
            ">>": "__rshift__",
            "&": "__and__",
            "|": "__or__",
            "^": "__xor__",
            "<": "__lt__",
            "<=": "__le__",
            ">": "__gt__",
            ">=": "__ge__",
            "==": "__eq__",
            "!=": "__ne__",
        }.get(operator)

    @staticmethod
    def _reflected_binary_protocol_name(operator: str) -> str | None:
        return {
            "+": "__radd__",
            "-": "__rsub__",
            "*": "__rmul__",
            "@": "__rmatmul__",
            "/": "__rtruediv__",
            "//": "__rfloordiv__",
            "%": "__rmod__",
            "**": "__rpow__",
            "<<": "__rlshift__",
            ">>": "__rrshift__",
            "&": "__rand__",
            "|": "__ror__",
            "^": "__rxor__",
        }.get(operator)

    @staticmethod
    def _reflected_comparison_protocol_name(operator: str) -> str | None:
        return {
            "<": "__gt__",
            "<=": "__ge__",
            ">": "__lt__",
            ">=": "__le__",
            "==": "__eq__",
            "!=": "__ne__",
        }.get(operator)

    @staticmethod
    def _assigned_expression(operation: object) -> object | None:
        if isinstance(operation, (py_ast.Assign, py_ast.UnpackSequence)):
            return operation.expr
        if isinstance(operation, py_ast.AnnAssign):
            return operation.value
        return None

    @staticmethod
    def _call_expression(operation: object) -> object | None:
        expr = _ExpressionResolverMixin._assigned_expression(operation)
        if isinstance(expr, (py_ast.Call, py_ast.DirectCall, py_ast.MethodCall)):
            return expr
        wrapped = getattr(operation, "expr", None)
        if isinstance(wrapped, (py_ast.Call, py_ast.DirectCall, py_ast.MethodCall)):
            return wrapped
        if isinstance(operation, (py_ast.Call, py_ast.DirectCall, py_ast.MethodCall)):
            return operation
        return None
