"""Heap-effect extraction for IFDS clients.

This module translates Python IR operations into analysis-neutral heap effects:
reads, writes, deletes, escapes, returns, and allocation roots.  Concrete IFDS
clients consume these effects to decide how their own facts should flow.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable

from pyflow.language.python import ast as py_ast

from ..ifds.cfg_adapter import assigned_locals
from .heap import HeapAbstraction, HeapLocation, HeapObject, HeapWrite, UpdatePolicy
from ..ifds.transfers import actual_argument_expressions, resolve_call_name


DYNAMIC_ATTRIBUTE_WILDCARD = "*"
DYNAMIC_SUBSCRIPT_WILDCARD = "[*]"
LocationReader = Callable[[object, object], tuple[object, ...]]
CALL_RETURN_FRESH = "fresh"
CALL_RETURN_COPY = "copy"
CALL_RETURN_SUMMARY = "summary"
CALL_RETURN_OPAQUE = "opaque"


@dataclass(frozen=True)
class HeapEffect:
    """Operation-level heap behavior independent of any IFDS fact domain."""

    reads: tuple[HeapLocation, ...] = ()
    writes: tuple[HeapWrite, ...] = ()
    deletes: tuple[HeapLocation, ...] = ()
    escapes: tuple[HeapLocation, ...] = ()
    returns: tuple[HeapLocation, ...] = ()
    allocations: tuple[HeapObject, ...] = ()

    def strong_write_locations(self) -> tuple[HeapLocation, ...]:
        return tuple(
            dict.fromkeys(
                write.location
                for write in self.writes
                if write.policy is UpdatePolicy.STRONG
            )
        )


class HeapEffectBuilder:
    """Build heap effects for Python IR operations."""

    def __init__(
        self,
        heap: HeapAbstraction,
        read_locations: LocationReader,
    ) -> None:
        self.heap = heap
        self.read_locations = read_locations

    def operation_effect(
        self,
        procedure: object,
        operation: object,
        *,
        collection_mutator_names: frozenset[str] = frozenset(),
    ) -> HeapEffect:
        if operation is None:
            return HeapEffect()

        reads = [
            *self.static_attribute_read_locations(procedure, operation),
            *self.dynamic_getattr_locations(procedure, operation),
            *self.dynamic_subscript_read_locations(procedure, operation),
            *self.getiter_read_locations(procedure, operation),
        ]
        writes = [
            self.heap.write_for_location(location)
            for location in (
                *self.static_attribute_write_locations(procedure, operation),
                *self.dynamic_setattr_locations(procedure, operation),
                *self.dynamic_subscript_write_locations(procedure, operation),
                *self.dynamic_slice_write_locations(procedure, operation),
            )
        ]
        deletes = [
            *self.dynamic_subscript_delete_locations(procedure, operation),
            *self.dynamic_attribute_delete_locations(procedure, operation),
            *self.dynamic_slice_delete_locations(procedure, operation),
        ]

        collection_locations, collection_values = self.collection_mutation(
            procedure,
            operation,
            collection_mutator_names,
        )
        writes.extend(
            self.heap.write_for_location(location) for location in collection_locations
        )

        escape_exprs = list(self._stored_value_expressions(operation))
        if collection_locations:
            escape_exprs.extend(collection_values)

        return_exprs: tuple[object, ...] = ()
        if isinstance(operation, py_ast.Return):
            return_exprs = tuple(operation.exprs)
            if self.heap.policy.escape_on_return:
                escape_exprs.extend(return_exprs)

        if isinstance(operation, (py_ast.Yield, py_ast.YieldFrom)):
            yield_exprs = (
                (operation.expr,) if operation.expr is not None else ()
            )
            escape_exprs.extend(yield_exprs)

        return HeapEffect(
            reads=tuple(dict.fromkeys(reads)),
            writes=tuple(dict.fromkeys(writes)),
            deletes=tuple(dict.fromkeys(deletes)),
            escapes=self._locations_for_expressions(procedure, tuple(escape_exprs)),
            returns=self._locations_for_expressions(procedure, return_exprs),
            allocations=self._allocation_objects_for_operation(procedure, operation),
        )

    def unresolved_call_effect(
        self,
        procedure: object,
        call_expression: py_ast.PythonASTNode | None,
    ) -> HeapEffect:
        """Return conservative heap effects for a call with no resolved body."""
        if call_expression is None or not self.heap.policy.escape_on_unresolved_call:
            return HeapEffect()
        escaped_exprs = list(actual_argument_expressions(call_expression))
        if isinstance(call_expression, py_ast.MethodCall):
            escaped_exprs.append(call_expression.expr)
        return HeapEffect(
            reads=self._locations_for_expressions(procedure, tuple(escaped_exprs)),
            escapes=self._locations_for_expressions(procedure, tuple(escaped_exprs)),
        )

    def call_return_kind(self, call_expression: object) -> str:
        """Classify a call return according to the fixed heap policy."""
        call_name = resolve_call_name(call_expression)
        if call_name is None:
            return CALL_RETURN_OPAQUE
        policy = self.heap.policy
        if call_name in policy.summary_return_names:
            return CALL_RETURN_SUMMARY
        if call_name in policy.copy_return_names:
            return CALL_RETURN_COPY
        if call_name in policy.fresh_return_names:
            return CALL_RETURN_FRESH
        if policy.treat_capitalized_calls_as_fresh and self._is_capitalized_call_name(
            call_name
        ):
            return CALL_RETURN_FRESH
        return CALL_RETURN_OPAQUE

    def call_return_object(
        self,
        procedure: object,
        call_expression: object,
        return_index: int = 0,
        *,
        label: str | None = None,
    ) -> HeapObject:
        """Return the abstract object root for a modeled call return."""
        kind = self.call_return_kind(call_expression)
        site = self.call_return_site(call_expression, return_index, kind)
        call_label = label or self._call_result_label(call_expression)
        if kind in {CALL_RETURN_FRESH, CALL_RETURN_COPY}:
            return self.heap.allocation_object(procedure, site, label=call_label)
        if kind == CALL_RETURN_SUMMARY:
            return self.heap.summary_object(site, label=call_label)
        return self.heap.call_result_object(procedure, site, label=call_label)

    def call_return_site(
        self,
        call_expression: object,
        return_index: int = 0,
        kind: str | None = None,
    ) -> tuple[object, ...]:
        """Stable allocation-site key for a call return."""
        return (
            "call_return",
            id(call_expression),
            return_index,
            kind or self.call_return_kind(call_expression),
        )

    def dynamic_getattr_locations(
        self,
        procedure: object,
        expr: object,
    ) -> tuple[HeapLocation, ...]:
        call = self._dynamic_attribute_call(expr, {"getattr", "builtins.getattr"})
        if call is None:
            return ()
        actuals = actual_argument_expressions(call)
        if len(actuals) < 2:
            return ()
        attribute = self._constant_string(actuals[1])
        attributes = (DYNAMIC_ATTRIBUTE_WILDCARD,)
        if attribute is not None:
            attributes = (attribute, DYNAMIC_ATTRIBUTE_WILDCARD)
        return self.dynamic_attribute_locations(procedure, actuals[0], attributes)

    def static_attribute_read_locations(
        self,
        procedure: object,
        expr: object,
    ) -> tuple[HeapLocation, ...]:
        if not isinstance(expr, (py_ast.GetAttr, py_ast.Load)):
            return ()
        return self.dynamic_attribute_locations(
            procedure,
            expr.expr,
            (self._path_component(expr.name),),
        )

    def static_attribute_write_locations(
        self,
        procedure: object,
        operation: object,
    ) -> tuple[HeapLocation, ...]:
        if not isinstance(operation, (py_ast.SetAttr, py_ast.Store)):
            return ()
        return self.dynamic_attribute_locations(
            procedure,
            operation.expr,
            (self._path_component(operation.name),),
        )

    def dynamic_setattr_locations(
        self,
        procedure: object,
        operation: object,
    ) -> tuple[HeapLocation, ...]:
        call = self._dynamic_attribute_call(operation, {"setattr", "builtins.setattr"})
        if call is None:
            return ()
        actuals = actual_argument_expressions(call)
        if len(actuals) < 2:
            return ()
        attribute = self._constant_string(actuals[1]) or DYNAMIC_ATTRIBUTE_WILDCARD
        attributes = (attribute,)
        if attribute != DYNAMIC_ATTRIBUTE_WILDCARD:
            attributes = (attribute, DYNAMIC_ATTRIBUTE_WILDCARD)
        return self.dynamic_attribute_locations(procedure, actuals[0], attributes)

    def dynamic_attribute_locations(
        self,
        procedure: object,
        base_expr: object,
        attributes: tuple[str, ...],
    ) -> tuple[HeapLocation, ...]:
        return self.heap.dynamic_attribute_locations(
            self.read_locations(procedure, base_expr),
            attributes,
        )

    def dynamic_subscript_read_locations(
        self,
        procedure: object,
        expr: object,
    ) -> tuple[HeapLocation, ...]:
        if isinstance(expr, py_ast.GetSubscript):
            container = expr.expr
            key = expr.subscript
        else:
            call = self._call_from_expression_or_statement(expr)
            if call is None or resolve_call_name(call) != "interpreter_getitem":
                return ()
            actuals = actual_argument_expressions(call)
            if len(actuals) < 2:
                return ()
            container = actuals[0]
            key = actuals[1]
        return self.dynamic_subscript_locations_for_key(procedure, container, key)

    def dynamic_subscript_write_locations(
        self,
        procedure: object,
        operation: object,
    ) -> tuple[HeapLocation, ...]:
        target = self.dynamic_subscript_write_target(operation)
        if target is None:
            return ()
        container, key, _value = target
        return self.dynamic_subscript_locations_for_key(procedure, container, key)

    def dynamic_subscript_locations_for_key(
        self,
        procedure: object,
        container: object,
        key: object,
    ) -> tuple[HeapLocation, ...]:
        subscript = self._constant_subscript(key)
        subscripts = (DYNAMIC_SUBSCRIPT_WILDCARD,)
        if subscript is not None:
            subscripts = (subscript, DYNAMIC_SUBSCRIPT_WILDCARD)
        return self.dynamic_subscript_locations(procedure, container, subscripts)

    def dynamic_subscript_value(self, operation: object) -> object | None:
        target = self.dynamic_subscript_write_target(operation)
        if target is None:
            return None
        return target[2]

    def dynamic_subscript_delete_locations(
        self,
        procedure: object,
        operation: object,
    ) -> tuple[HeapLocation, ...]:
        if isinstance(operation, py_ast.DeleteSubscript):
            return self.dynamic_subscript_locations_for_key(
                procedure,
                operation.expr,
                operation.subscript,
            )
        call = self._call_from_expression_or_statement(operation)
        if call is None or resolve_call_name(call) != "interpreter_delitem":
            return ()
        actuals = actual_argument_expressions(call)
        if len(actuals) < 2:
            return ()
        return self.dynamic_subscript_locations_for_key(procedure, actuals[0], actuals[1])

    def dynamic_attribute_delete_locations(
        self,
        procedure: object,
        operation: object,
    ) -> tuple[HeapLocation, ...]:
        if not isinstance(operation, py_ast.DeleteAttr):
            return ()
        attribute = self._constant_string(operation.name) or DYNAMIC_ATTRIBUTE_WILDCARD
        attributes = (attribute,)
        if attribute != DYNAMIC_ATTRIBUTE_WILDCARD:
            attributes = (attribute, DYNAMIC_ATTRIBUTE_WILDCARD)
        return self.dynamic_attribute_locations(procedure, operation.expr, attributes)

    def dynamic_subscript_write_target(
        self,
        operation: object,
    ) -> tuple[object, object, object] | None:
        if isinstance(operation, py_ast.SetSubscript):
            return operation.expr, operation.subscript, operation.value
        call = self._call_from_expression_or_statement(operation)
        if call is None or resolve_call_name(call) != "interpreter_setitem":
            return None
        actuals = actual_argument_expressions(call)
        if len(actuals) < 3:
            return None
        return actuals[0], actuals[1], actuals[2]

    def dynamic_subscript_locations(
        self,
        procedure: object,
        base_expr: object,
        subscripts: tuple[str, ...],
    ) -> tuple[HeapLocation, ...]:
        return self.heap.dynamic_subscript_locations(
            self.read_locations(procedure, base_expr),
            subscripts,
        )

    def collection_mutation(
        self,
        procedure: object,
        operation: object,
        mutator_names: frozenset[str],
    ) -> tuple[tuple[HeapLocation, ...], tuple[object, ...]]:
        call = self._call_from_expression_or_statement(operation)
        if call is None or resolve_call_name(call) not in mutator_names:
            return (), ()

        actuals = actual_argument_expressions(call)
        if isinstance(call, py_ast.MethodCall):
            container = call.expr
            values = actuals
        else:
            if len(actuals) < 2:
                return (), ()
            container = actuals[0]
            values = actuals[1:]

        locations = self.dynamic_subscript_locations(
            procedure,
            container,
            (DYNAMIC_SUBSCRIPT_WILDCARD,),
        )
        return locations, tuple(values)

    def _locations_for_expressions(
        self,
        procedure: object,
        expressions: tuple[object, ...],
    ) -> tuple[HeapLocation, ...]:
        return tuple(
            dict.fromkeys(
                self.heap.location_for_raw(location)
                for expr in expressions
                for location in self.read_locations(procedure, expr)
            )
        )

    def _stored_value_expressions(self, operation: object) -> tuple[object, ...]:
        if isinstance(
            operation,
            (
                py_ast.SetAttr,
                py_ast.SetSubscript,
                py_ast.SetSlice,
                py_ast.SetGlobal,
                py_ast.SetCellDeref,
                py_ast.Store,
            ),
        ):
            value = getattr(operation, "value", None)
            return (value,) if value is not None else ()
        dynamic_value = self.dynamic_subscript_value(operation)
        if dynamic_value is not None:
            return (dynamic_value,)
        dynamic_attr_value = self._dynamic_setattr_value(operation)
        if dynamic_attr_value is not None:
            return (dynamic_attr_value,)
        return ()

    def _allocation_objects_for_operation(
        self,
        procedure: object,
        operation: object,
    ) -> tuple[HeapObject, ...]:
        expr = None
        if isinstance(operation, (py_ast.Assign, py_ast.UnpackSequence)):
            expr = operation.expr
        elif isinstance(operation, py_ast.AnnAssign):
            expr = operation.value
        if isinstance(expr, (py_ast.DirectCall, py_ast.Call, py_ast.MethodCall)):
            kind = self.call_return_kind(expr)
            if kind not in {CALL_RETURN_FRESH, CALL_RETURN_COPY}:
                return ()
            return (self.call_return_object(procedure, expr),)
        if not isinstance(
            expr,
            (
                py_ast.BuildTuple,
                py_ast.BuildList,
                py_ast.BuildSet,
                py_ast.BuildMap,
            ),
        ):
            return ()
        label = self._allocation_label(expr)
        return tuple(
            dict.fromkeys(
                self.heap.allocation_object(procedure, expr, label=label)
                for target in assigned_locals(operation)
                if getattr(target, "name", None) is not None
            )
        )

    def _dynamic_setattr_value(self, operation: object) -> object | None:
        call = self._dynamic_attribute_call(operation, {"setattr", "builtins.setattr"})
        if call is None:
            return None
        actuals = actual_argument_expressions(call)
        if len(actuals) < 3:
            return None
        return actuals[2]

    def _dynamic_attribute_call(
        self,
        expr: object,
        names: set[str],
    ) -> py_ast.PythonASTNode | None:
        candidate = self._call_from_expression_or_statement(expr)
        if candidate is None:
            return None
        if resolve_call_name(candidate) not in names:
            return None
        return candidate

    def _call_from_expression_or_statement(
        self,
        expr: object,
    ) -> py_ast.PythonASTNode | None:
        candidate = expr
        if not isinstance(candidate, (py_ast.DirectCall, py_ast.Call, py_ast.MethodCall)):
            wrapped = getattr(expr, "expr", None)
            if isinstance(wrapped, (py_ast.DirectCall, py_ast.Call, py_ast.MethodCall)):
                candidate = wrapped
        if not isinstance(candidate, (py_ast.DirectCall, py_ast.Call, py_ast.MethodCall)):
            return None
        return candidate

    def _constant_string(self, expr: object) -> str | None:
        if not isinstance(expr, py_ast.Existing):
            return None
        value = getattr(expr.object, "pyobj", None)
        return value if isinstance(value, str) else None

    def _path_component(self, expr: object) -> str:
        if isinstance(expr, py_ast.Local) and expr.name:
            return expr.name
        if isinstance(expr, py_ast.Existing):
            value = getattr(expr.object, "pyobj", None)
            if value is not None:
                return str(value)
        return "*"

    def _constant_subscript(self, expr: object) -> str | None:
        if not isinstance(expr, py_ast.Existing):
            return None
        value = getattr(expr.object, "pyobj", None)
        return f"[{value!r}]"

    def _allocation_label(self, expr: object) -> str:
        if isinstance(expr, py_ast.BuildTuple):
            return "tuple literal"
        if isinstance(expr, py_ast.BuildList):
            return "list literal"
        if isinstance(expr, py_ast.BuildSet):
            return "set literal"
        if isinstance(expr, py_ast.BuildMap):
            return "dict literal"
        return type(expr).__name__

    def _call_result_label(self, expr: object) -> str:
        call_name = resolve_call_name(expr)
        if call_name is not None:
            return f"{call_name}()"
        return type(expr).__name__

    def dynamic_slice_write_locations(
        self,
        procedure: object,
        operation: object,
    ) -> tuple[HeapLocation, ...]:
        if not isinstance(operation, py_ast.SetSlice):
            return ()
        return self.dynamic_subscript_locations(
            procedure,
            operation.expr,
            (DYNAMIC_SUBSCRIPT_WILDCARD,),
        )

    def dynamic_slice_delete_locations(
        self,
        procedure: object,
        operation: object,
    ) -> tuple[HeapLocation, ...]:
        if not isinstance(operation, py_ast.DeleteSlice):
            return ()
        return self.dynamic_subscript_locations(
            procedure,
            operation.expr,
            (DYNAMIC_SUBSCRIPT_WILDCARD,),
        )

    def getiter_read_locations(
        self,
        procedure: object,
        operation: object,
    ) -> tuple[HeapLocation, ...]:
        if not isinstance(operation, py_ast.GetIter):
            return ()
        if operation.expr is None:
            return ()
        return self._locations_for_expressions(procedure, (operation.expr,))

    def _is_capitalized_call_name(self, call_name: str) -> bool:
        short_name = call_name.rsplit(".", 1)[-1]
        return bool(short_name) and short_name[0].isupper()
