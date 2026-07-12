"""Heap-effect extraction for IFDS clients.

This module translates Python IR operations into analysis-neutral heap effects:
reads, writes, deletes, escapes, returns, and allocation roots.  Concrete IFDS
clients consume these effects to decide how their own facts should flow.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable

from pyflow.language.python import ast as py_ast

from pyflow.analysis.ir_utils import (
    actual_argument_expressions,
    assigned_locals,
    resolve_call_name,
)

from .abstraction import HeapAbstraction
from .intrinsics import (
    CALL_RETURN_COPY,
    CALL_RETURN_FRESH,
    CALL_RETURN_OPAQUE,
    CALL_RETURN_SUMMARY,
    COLLECTION_DELETE_MUTATOR_NAMES,
    COLLECTION_VALUE_MUTATOR_NAMES,
    DEFAULT_COLLECTION_MUTATOR_NAMES,
    DEFAULT_HEAP_INTRINSICS,
)
from .model import HeapLocation, HeapObject, HeapWrite, UpdatePolicy


DYNAMIC_ATTRIBUTE_WILDCARD = "*"
DYNAMIC_SUBSCRIPT_WILDCARD = "[*]"
LocationReader = Callable[[object, object], tuple[object, ...]]


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

    def __repr__(self) -> str:
        nz = {
            k: len(v) for k, v in (
                ("r", self.reads), ("w", self.writes),
                ("d", self.deletes), ("e", self.escapes),
            ) if v
        }
        detail = " ".join(f"{k}={c}" for k, c in sorted(nz.items()))
        n_alloc = len(self.allocations)
        if n_alloc:
            detail = f"{detail} alloc={n_alloc}" if detail else f"alloc={n_alloc}"
        return f"HeapEffect({detail or 'empty'})"

    def to_dict(self) -> dict:
        return {
            "reads": [loc.to_dict() for loc in self.reads],
            "writes": [w.to_dict() for w in self.writes],
            "deletes": [loc.to_dict() for loc in self.deletes],
            "escapes": [loc.to_dict() for loc in self.escapes],
            "returns": [loc.to_dict() for loc in self.returns],
            "allocations": [obj.to_dict() for obj in self.allocations],
        }

    def __bool__(self) -> bool:
        return bool(
            self.reads
            or self.writes
            or self.deletes
            or self.escapes
            or self.returns
            or self.allocations
        )

    @property
    def is_empty(self) -> bool:
        return not bool(self)

    def merge(self, other: "HeapEffect") -> "HeapEffect":
        """Return a new effect combining both effects (union with dedup)."""
        return HeapEffect(
            reads=tuple(dict.fromkeys((*self.reads, *other.reads))),
            writes=tuple(dict.fromkeys((*self.writes, *other.writes))),
            deletes=tuple(dict.fromkeys((*self.deletes, *other.deletes))),
            escapes=tuple(dict.fromkeys((*self.escapes, *other.escapes))),
            returns=tuple(dict.fromkeys((*self.returns, *other.returns))),
            allocations=tuple(
                dict.fromkeys((*self.allocations, *other.allocations))
            ),
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
            *self.global_read_locations(procedure, operation),
            *self.cell_read_locations(procedure, operation),
            *self.static_attribute_read_locations(procedure, operation),
            *self.dynamic_getattr_locations(procedure, operation),
            *self.dynamic_subscript_read_locations(procedure, operation),
            *self.getiter_read_locations(procedure, operation),
        ]
        writes = [
            self.heap.write_for_location(location)
            for location in (
                *self.global_write_locations(procedure, operation),
                *self.cell_write_locations(procedure, operation),
                *self.static_attribute_write_locations(procedure, operation),
                *self.dynamic_setattr_locations(procedure, operation),
                *self.dynamic_subscript_write_locations(procedure, operation),
                *self.dynamic_slice_write_locations(procedure, operation),
            )
        ]
        deletes = [
            *self.global_delete_locations(procedure, operation),
            *self.dynamic_subscript_delete_locations(procedure, operation),
            *self.dynamic_attribute_delete_locations(procedure, operation),
            *self.dynamic_slice_delete_locations(procedure, operation),
            *self.collection_delete_locations(
                procedure,
                operation,
                collection_mutator_names,
            ),
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
        intrinsic_kind = DEFAULT_HEAP_INTRINSICS.return_kind(call_name)
        if intrinsic_kind is not None:
            return intrinsic_kind
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

    def global_read_locations(
        self,
        procedure: object,
        expr: object,
    ) -> tuple[HeapLocation, ...]:
        if not isinstance(expr, py_ast.GetGlobal):
            return ()
        return (self.global_location(procedure, expr.name),)

    def global_write_locations(
        self,
        procedure: object,
        operation: object,
    ) -> tuple[HeapLocation, ...]:
        if not isinstance(operation, py_ast.SetGlobal):
            return ()
        return (self.global_location(procedure, operation.name),)

    def global_delete_locations(
        self,
        procedure: object,
        operation: object,
    ) -> tuple[HeapLocation, ...]:
        if not isinstance(operation, py_ast.DeleteGlobal):
            return ()
        return (self.global_location(procedure, operation.name),)

    def global_location(
        self,
        procedure: object,
        name: object,
    ) -> HeapLocation:
        module = getattr(procedure, "module", None)
        return self.heap.location_for_raw(
            self.heap.global_object(
                self._path_component(name),
                module=module,
            )
        )

    def cell_read_locations(
        self,
        procedure: object,
        expr: object,
    ) -> tuple[HeapLocation, ...]:
        if not isinstance(expr, (py_ast.GetCell, py_ast.GetCellDeref)):
            return ()
        return (self.cell_location(expr.cell),)

    def cell_write_locations(
        self,
        procedure: object,
        operation: object,
    ) -> tuple[HeapLocation, ...]:
        if not isinstance(operation, py_ast.SetCellDeref):
            return ()
        return (self.cell_location(operation.cell),)

    def cell_location(self, cell: object) -> HeapLocation:
        return self.heap.location_for_raw(
            self.heap.cell_object(getattr(cell, "name", cell))
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
        call_name = resolve_call_name(call) if call is not None else None
        model = DEFAULT_HEAP_INTRINSICS.collection_mutator(call_name)
        if call is None or call_name not in mutator_names:
            return (), ()
        if model is not None and not model.writes_value:
            return (), ()

        actuals = actual_argument_expressions(call)
        if isinstance(call, py_ast.MethodCall):
            container = call.expr
            values = (
                model.value_args(actuals)
                if model is not None
                else self._collection_mutation_values(call_name, actuals)
            )
        else:
            if len(actuals) < 2:
                return (), ()
            container = actuals[0]
            remaining = actuals[1:]
            values = (
                model.value_args(remaining)
                if model is not None
                else self._collection_mutation_values(call_name, remaining)
            )

        locations = self.dynamic_subscript_locations(
            procedure,
            container,
            (DYNAMIC_SUBSCRIPT_WILDCARD,),
        )
        return locations, tuple(values)

    def collection_delete_locations(
        self,
        procedure: object,
        operation: object,
        mutator_names: frozenset[str],
    ) -> tuple[HeapLocation, ...]:
        call = self._call_from_expression_or_statement(operation)
        call_name = resolve_call_name(call) if call is not None else None
        model = DEFAULT_HEAP_INTRINSICS.collection_mutator(call_name)
        if call is None or call_name not in mutator_names:
            return ()
        if model is None or not model.deletes_value:
            return ()

        actuals = actual_argument_expressions(call)
        if isinstance(call, py_ast.MethodCall):
            container = call.expr
            args = actuals
        else:
            if len(actuals) < 1:
                return ()
            container = actuals[0]
            args = actuals[1:]

        if model.key_arg_index is not None and model.key_arg_index < len(args):
            return self.dynamic_subscript_locations_for_key(
                procedure,
                container,
                args[model.key_arg_index],
            )
        return self.dynamic_subscript_locations(
            procedure,
            container,
            (DYNAMIC_SUBSCRIPT_WILDCARD,),
        )

    @staticmethod
    def _collection_mutation_values(
        call_name: str | None,
        actuals: tuple[object, ...],
    ) -> tuple[object, ...]:
        if call_name == "insert":
            return actuals[1:2]
        if call_name == "setdefault":
            return actuals[1:2]
        return actuals

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
