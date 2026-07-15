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
from .intrinsics import (  # noqa: F401 - selected names are public re-exports
    CALL_RETURN_COPY,
    CALL_RETURN_FRESH,
    CALL_RETURN_OPAQUE,
    CALL_RETURN_SUMMARY,
    COLLECTION_DELETE_MUTATOR_NAMES,  # noqa: F401 - public re-export
    COLLECTION_VALUE_MUTATOR_NAMES,  # noqa: F401 - public re-export
    DEFAULT_COLLECTION_MUTATOR_NAMES,  # noqa: F401 - public re-export
    DEFAULT_HEAP_INTRINSICS,
    HeapIntrinsicModels,
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


@dataclass(frozen=True)
class HeapOperationSemantics:
    """Shared operation description for transfer, summaries, and IFDS."""

    effect: HeapEffect
    stored_value: object | None = None
    call_expression: object | None = None


class HeapEffectBuilder:
    """Build heap effects for Python IR operations."""

    def __init__(
        self,
        heap: HeapAbstraction,
        read_locations: LocationReader,
        *,
        intrinsics: HeapIntrinsicModels = DEFAULT_HEAP_INTRINSICS,
        module_owner: Callable[[object], object | None] | None = None,
    ) -> None:
        self.heap = heap
        self.read_locations = read_locations
        self.intrinsics = intrinsics
        self.module_owner = module_owner

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
            *self.getslice_read_locations(procedure, operation),
            *self.getiter_read_locations(procedure, operation),
            *self.assert_read_locations(procedure, operation),
            *self.make_function_read_locations(procedure, operation),
            *self.delete_read_locations(procedure, operation),
            *self.misc_read_locations(procedure, operation),
        ]
        write_locations = (
            *self.global_write_locations(procedure, operation),
            *self.cell_write_locations(procedure, operation),
            *self.static_attribute_write_locations(procedure, operation),
            *self.dynamic_setattr_locations(procedure, operation),
            *self.dynamic_subscript_write_locations(procedure, operation),
            *self.dynamic_slice_write_locations(procedure, operation),
        )
        ambiguous_write_roots = len(
            {location.root for location in write_locations if location.is_nested()}
        ) > 1
        writes = [
            self.heap.write_for_location(
                location,
                policy=(
                    UpdatePolicy.WEAK
                    if ambiguous_write_roots and location.is_nested()
                    else None
                ),
            )
            for location in write_locations
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
            *self.delete_locations(procedure, operation),
        ]

        collection_locations, collection_values = self.collection_mutation(
            procedure,
            operation,
            collection_mutator_names,
        )
        writes.extend(
            self.heap.write_for_location(location) for location in collection_locations
        )

        model_escape_exprs: list[object] = []
        call = self._call_from_expression_or_statement(operation)
        call_name = resolve_call_name(call) if call is not None else None
        function_model = self.intrinsics.function_model(call_name)
        collection_model = self.intrinsics.collection_mutator(call_name)
        if call is not None and function_model is not None:
            actuals = actual_argument_expressions(call)
            if isinstance(call, py_ast.MethodCall):
                if function_model.reads_self:
                    reads.extend(
                        self._locations_for_expressions(procedure, (call.expr,))
                    )
                if function_model.escapes_self:
                    model_escape_exprs.append(call.expr)
            reads.extend(
                self._locations_for_expressions(
                    procedure,
                    tuple(
                        actuals[index]
                        for index in function_model.read_arg_indices
                        if index < len(actuals)
                    ),
                )
            )
            model_escape_exprs.extend(
                actuals[index]
                for index in function_model.escape_arg_indices
                if index < len(actuals)
            )
            # Collection mutators already expose their precise element/key
            # writes.  Other known stateful APIs expose bounded wildcard
            # writes so IFDS and standalone summaries agree on mutation.
            if collection_model is None:
                mutated_roots: list[HeapLocation] = []
                if function_model.mutates_self and isinstance(call, py_ast.MethodCall):
                    mutated_roots.extend(
                        self._locations_for_expressions(procedure, (call.expr,))
                    )
                mutated_roots.extend(
                    self._locations_for_expressions(
                        procedure,
                        tuple(
                            actuals[index]
                            for index in function_model.write_arg_indices
                            if index < len(actuals)
                        ),
                    )
                )
                for root in dict.fromkeys(mutated_roots):
                    writes.append(
                        self.heap.write_for_location(
                            self.heap.dynamic_attribute_location(
                                root,
                                DYNAMIC_ATTRIBUTE_WILDCARD,
                            ),
                            policy=UpdatePolicy.WEAK,
                        )
                    )
                    writes.append(
                        self.heap.write_for_location(
                            self.heap.dynamic_subscript_location(
                                root,
                                DYNAMIC_SUBSCRIPT_WILDCARD,
                            ),
                            policy=UpdatePolicy.WEAK,
                        )
                    )

        escape_exprs = [
            *model_escape_exprs,
            *self._stored_value_expressions(operation),
        ]
        if collection_locations:
            escape_exprs.extend(collection_values)

        return_exprs: tuple[object, ...] = ()
        if isinstance(operation, py_ast.Return):
            return_exprs = tuple(operation.exprs)
            if self.heap.policy.escape_on_return:
                escape_exprs.extend(return_exprs)

        yield_expr = self._yield_expression(operation)
        if yield_expr is not None:
            escape_exprs.append(yield_expr)

        if isinstance(operation, py_ast.Await) and operation.expr is not None:
            reads.extend(
                self._locations_for_expressions(procedure, (operation.expr,))
            )
            escape_exprs.append(operation.expr)

        if isinstance(operation, py_ast.Raise):
            escape_exprs.extend(self.raise_escape_expressions(operation))

        if isinstance(operation, py_ast.Assert) and operation.message is not None:
            escape_exprs.append(operation.message)

        if isinstance(operation, py_ast.OutputBlock):
            escape_exprs.extend(
                output.expr
                for output in getattr(operation, "outputs", ())
                if getattr(output, "expr", None) is not None
            )
        elif isinstance(operation, py_ast.Output):
            escape_exprs.append(operation.expr)
        elif isinstance(operation, py_ast.Print):
            escape_exprs.extend(
                expression
                for expression in (operation.target, operation.expr)
                if expression is not None
            )
        elif isinstance(operation, py_ast.TypeAlias):
            escape_exprs.append(operation.value)
        elif isinstance(operation, (py_ast.FunctionDef, py_ast.ClassDef)):
            escape_exprs.extend(getattr(operation, "decorators", ()))
            if isinstance(operation, py_ast.ClassDef):
                escape_exprs.extend(getattr(operation, "bases", ()))

        return HeapEffect(
            reads=tuple(dict.fromkeys(reads)),
            writes=tuple(dict.fromkeys(writes)),
            deletes=tuple(dict.fromkeys(deletes)),
            escapes=tuple(dict.fromkeys(
                self._locations_for_expressions(procedure, tuple(escape_exprs))
            )),
            returns=self._locations_for_expressions(procedure, return_exprs),
            allocations=self._allocation_objects_for_operation(procedure, operation),
        )

    def operation_semantics(
        self,
        procedure: object,
        operation: object,
        *,
        collection_mutator_names: frozenset[str] = frozenset(),
    ) -> HeapOperationSemantics:
        """Return the canonical semantic descriptor for one operation."""
        stored_values = self._stored_value_expressions(operation)
        stored_value = stored_values[0] if stored_values else None
        if stored_value is None:
            stored_value = self.dynamic_subscript_value(operation)
        if stored_value is None:
            stored_value = self._dynamic_setattr_value(operation)
        return HeapOperationSemantics(
            effect=self.operation_effect(
                procedure,
                operation,
                collection_mutator_names=collection_mutator_names,
            ),
            stored_value=stored_value,
            call_expression=self._call_from_expression_or_statement(operation),
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

    @staticmethod
    def _yield_expression(operation: object) -> object | None:
        """Return the yielded value for a yield operation or discarded yield expression."""
        candidate = operation
        if isinstance(operation, py_ast.Discard):
            candidate = operation.expr
        elif isinstance(operation, py_ast.Assign):
            candidate = operation.expr
        elif isinstance(operation, py_ast.AnnAssign):
            candidate = operation.value
        if isinstance(candidate, (py_ast.Yield, py_ast.YieldFrom, py_ast.AsyncYield)):
            return candidate.expr
        return None

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
        if (
            isinstance(call_expression, py_ast.MethodCall)
            and "." not in call_name
            and self.intrinsics.collection_mutator(call_name) is not None
        ):
            # A bare method name does not prove the receiver is the builtin
            # collection whose convention says the method returns None.
            return CALL_RETURN_OPAQUE
        intrinsic_kind = self.intrinsics.return_kind(call_name)
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
            self.heap._site_identity(call_expression),
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
        if isinstance(expr, py_ast.Load) and getattr(expr, "fieldtype", None) in {
            "Dictionary",
            "Array",
        }:
            return self.dynamic_subscript_locations(
                procedure,
                expr.expr,
                (f"[{self._path_component(expr.name)}]",),
            )
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
        if isinstance(operation, py_ast.Store) and getattr(
            operation, "fieldtype", None
        ) in {"Dictionary", "Array"}:
            return self.dynamic_subscript_locations(
                procedure,
                operation.expr,
                (f"[{self._path_component(operation.name)}]",),
            )
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
        module = (
            self.module_owner(procedure)
            if self.module_owner is not None
            else getattr(procedure, "module", None)
        )
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

    def cell_location(self, cell: object, procedure: object = None) -> HeapLocation:
        name = getattr(cell, "name", cell)
        return self.heap.location_for_raw(
            self.heap.cell_object(
                cell,
                label=str(name),
            )
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

    def getslice_read_locations(
        self,
        procedure: object,
        operation: object,
    ) -> tuple[HeapLocation, ...]:
        """Return read locations for a slice-read expression."""
        expr: object | None = None
        if isinstance(operation, py_ast.GetSlice):
            expr = operation
        else:
            wrapped = getattr(operation, "expr", None)
            if isinstance(wrapped, py_ast.GetSlice):
                expr = wrapped
        if expr is None:
            return ()
        expressions: list[object] = [expr.expr]
        if expr.start is not None:
            expressions.append(expr.start)
        if expr.stop is not None:
            expressions.append(expr.stop)
        if expr.step is not None:
            expressions.append(expr.step)
        return self._locations_for_expressions(procedure, tuple(expressions))

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

    def delete_read_locations(
        self,
        procedure: object,
        operation: object,
    ) -> tuple[HeapLocation, ...]:
        """Return read locations for a local variable delete operation."""
        if not isinstance(operation, py_ast.Delete):
            return ()
        return self._locations_for_expressions(procedure, (operation.lcl,))

    def delete_locations(
        self,
        procedure: object,
        operation: object,
    ) -> tuple[HeapLocation, ...]:
        """Return the root heap location(s) invalidated by a local variable delete."""
        if not isinstance(operation, py_ast.Delete):
            return ()
        return self._locations_for_expressions(procedure, (operation.lcl,))

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
        model = self.intrinsics.collection_mutator(call_name)
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
        model = self.intrinsics.collection_mutator(call_name)
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
        if isinstance(expr, py_ast.Import):
            return (self.import_object(expr, procedure),)
        if not isinstance(
            expr,
            (
                py_ast.BuildTuple,
                py_ast.BuildList,
                py_ast.BuildSet,
                py_ast.BuildMap,
                py_ast.BuildSlice,
                py_ast.MakeFunction,
                py_ast.Allocate,
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
        if isinstance(expr, str):
            return expr
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
        # Negative indices are sequence-relative.  Without a proven concrete
        # length, treating them as exact keys loses aliases such as ``xs[-1]``
        # -> ``xs[len(xs)-1]``.  Widening is also safe for mappings.
        if isinstance(value, int) and not isinstance(value, bool) and value < 0:
            return None
        # Python mappings coalesce equal numeric keys (True, 1 and 1.0).
        # Preserve the traditional integer spelling so existing paths remain
        # stable while canonicalising the common cross-type equalities.
        if isinstance(value, bool):
            value = int(value)
        elif isinstance(value, float) and value.is_integer():
            value = int(value)
        elif isinstance(value, complex) and value.imag == 0 and value.real.is_integer():
            value = int(value.real)
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
        if isinstance(expr, py_ast.MakeFunction):
            return "function"
        if isinstance(expr, py_ast.BuildSlice):
            return "slice literal"
        if isinstance(expr, py_ast.Allocate):
            return "allocate"
        return type(expr).__name__

    def import_object(
        self,
        expr: py_ast.Import,
        procedure: object | None = None,
    ) -> HeapObject:
        module_name = expr.name
        if getattr(expr, "level", 0):
            owner = (
                self.module_owner(procedure)
                if self.module_owner is not None and procedure is not None
                else None
            )
            module_name = ("relative", owner, expr.level, module_name)
        return self.heap.module_object(module_name, label=expr.name)

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

    def definite_delete_locations(
        self,
        operation: object,
        deletes: tuple[HeapLocation, ...],
    ) -> tuple[HeapLocation, ...]:
        """Filter deletion effects to locations definitely absent afterward."""
        if len({location.root for location in deletes}) > 1:
            # A runtime receiver denotes only one of these abstract roots, so
            # no individual root is definitely deleted on every path.
            return ()
        if isinstance(operation, (py_ast.Delete, py_ast.DeleteGlobal)):
            return deletes
        if isinstance(operation, py_ast.DeleteAttr):
            if self._constant_string(operation.name) is None:
                return ()
            return tuple(location for location in deletes if location.is_precise())
        if isinstance(operation, py_ast.DeleteSubscript):
            if self._constant_subscript(operation.subscript) is None:
                return ()
            return tuple(location for location in deletes if location.is_precise())
        if isinstance(operation, py_ast.DeleteSlice):
            return ()

        call = self._call_from_expression_or_statement(operation)
        call_name = resolve_call_name(call) if call is not None else None
        if (
            isinstance(call, py_ast.MethodCall)
            and isinstance(call_name, str)
            and "." not in call_name
        ):
            return ()
        if call_name in {"clear", "dict.clear", "list.clear", "set.clear"}:
            return deletes
        if call_name in {"pop", "dict.pop", "get_and_del"} and call is not None:
            actuals = actual_argument_expressions(call)
            args = actuals if isinstance(call, py_ast.MethodCall) else actuals[1:]
            if args and self._constant_subscript(args[0]) is not None:
                return tuple(location for location in deletes if location.is_precise())
        if call_name == "interpreter_delitem" and call is not None:
            actuals = actual_argument_expressions(call)
            if len(actuals) >= 2 and self._constant_subscript(actuals[1]) is not None:
                return tuple(location for location in deletes if location.is_precise())
        return ()

    def getiter_read_locations(
        self,
        procedure: object,
        operation: object,
    ) -> tuple[HeapLocation, ...]:
        if not isinstance(operation, (py_ast.GetIter, py_ast.AsyncGetIter)):
            return ()
        if operation.expr is None:
            return ()
        return self._locations_for_expressions(procedure, (operation.expr,))

    def assert_read_locations(
        self,
        procedure: object,
        operation: object,
    ) -> tuple[HeapLocation, ...]:
        if not isinstance(operation, py_ast.Assert):
            return ()
        expressions = [operation.test]
        if operation.message is not None:
            expressions.append(operation.message)
        return self._locations_for_expressions(procedure, tuple(expressions))

    def misc_read_locations(
        self,
        procedure: object,
        operation: object,
    ) -> tuple[HeapLocation, ...]:
        expressions: list[object] = []
        if isinstance(operation, py_ast.Phi):
            expressions.extend(
                argument
                for argument in getattr(operation, "arguments", ())
                if argument is not None
            )
        elif isinstance(operation, py_ast.AnnAssign):
            expressions.append(operation.annotation_expr)
        elif isinstance(operation, py_ast.Print):
            expressions.extend(
                expression
                for expression in (operation.target, operation.expr)
                if expression is not None
            )
        elif isinstance(operation, py_ast.OutputBlock):
            expressions.extend(
                output.expr
                for output in getattr(operation, "outputs", ())
                if getattr(output, "expr", None) is not None
            )
        elif isinstance(operation, py_ast.Output):
            expressions.append(operation.expr)
        elif isinstance(operation, py_ast.TypeAlias):
            expressions.append(operation.value)
            expressions.extend(getattr(operation, "params", ()))
        elif isinstance(operation, (py_ast.FunctionDef, py_ast.ClassDef)):
            expressions.extend(getattr(operation, "decorators", ()))
            type_params = getattr(operation, "type_params", None)
            if type_params is not None:
                expressions.append(type_params)
            if isinstance(operation, py_ast.FunctionDef):
                expressions.extend(
                    getattr(operation.code.codeparameters, "defaults", ())
                )
            else:
                expressions.extend(getattr(operation, "bases", ()))
                expressions.extend(
                    keyword[1]
                    if isinstance(keyword, tuple) and len(keyword) == 2
                    else keyword
                    for keyword in getattr(operation, "keywords", ())
                )
        return self._locations_for_expressions(procedure, tuple(expressions))

    @staticmethod
    def raise_escape_expressions(operation: py_ast.Raise) -> tuple[object, ...]:
        return tuple(
            expr
            for expr in (
                operation.exception,
                operation.parameter,
                operation.traceback,
            )
            if expr is not None
        )

    def make_function_read_locations(
        self,
        procedure: object,
        operation: object,
    ) -> tuple[HeapLocation, ...]:
        expr = self._assigned_expression(operation)
        if not isinstance(expr, py_ast.MakeFunction):
            return ()
        locations: list[HeapLocation] = []
        for default in getattr(expr, "defaults", ()):
            locations.extend(
                self.heap.location_for_raw(raw)
                for raw in self.read_locations(procedure, default)
            )
        for cell in getattr(expr, "cells", ()):
            locations.append(self.cell_location(cell, procedure))
        return tuple(dict.fromkeys(locations))

    @staticmethod
    def _assigned_expression(operation: object) -> object | None:
        if isinstance(operation, (py_ast.Assign, py_ast.UnpackSequence)):
            return operation.expr
        if isinstance(operation, py_ast.AnnAssign):
            return operation.value
        return operation

    def _is_capitalized_call_name(self, call_name: str) -> bool:
        short_name = call_name.rsplit(".", 1)[-1]
        return bool(short_name) and short_name[0].isupper()
