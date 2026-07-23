"""Collection mutation and contained-value transfer helpers."""

from __future__ import annotations

from pyflow.analysis.ir_utils import (
    actual_argument_expressions,
    resolve_call_name,
)
from pyflow.language.python import ast as py_ast

from ..model import HeapLocation, UpdatePolicy
from ..semantics.effects import DYNAMIC_SUBSCRIPT_WILDCARD


class _CollectionMutationMixin:
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
        if isinstance(
            operation, (py_ast.SetSlice, py_ast.DeleteSlice, py_ast.DeleteSubscript)
        ):
            container = operation.expr
        elif call is not None:
            model = self.intrinsics.collection_mutator(resolve_call_name(call))
            if model is None or not model.reorders_values:
                return
            actuals = tuple(actual_argument_expressions(call))
            container = (
                call.expr
                if isinstance(call, py_ast.MethodCall)
                else actuals[0] if actuals else None
            )
        else:
            return
        if container is None:
            return
        evaluated = (
            self._last_call_operands.get(id(call), {}) if call is not None else {}
        )
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
