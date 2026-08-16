"""Heap write/delete planning and application."""

from __future__ import annotations

from pyflow.language.python import ast as py_ast

from ..model import HeapLocation, UpdatePolicy
from ..semantics.effects import DYNAMIC_SUBSCRIPT_WILDCARD


class _WriteTransferMixin:
    def _prepared_target_writes(
        self,
        procedure: object,
        operation: object,
    ) -> tuple[object, ...] | None:
        bases: tuple[HeapLocation, ...]
        locations: tuple[HeapLocation, ...]
        if isinstance(operation, (py_ast.SetAttr, py_ast.Store)):
            bases = self.locations_for_expression(procedure, operation.expr)
            self.locations_for_expression(procedure, operation.name)
            if isinstance(operation, py_ast.Store) and getattr(
                operation,
                "fieldtype",
                None,
            ) in {"Dictionary", "Array"}:
                locations = self.heap.dynamic_subscript_locations(
                    bases,
                    (f"[{self.effect_builder._path_component(operation.name)}]",),
                )
                self.locations_for_expression(procedure, operation.value)
            else:
                attribute = (
                    self.effect_builder._path_component(operation.name)
                    if isinstance(operation, py_ast.Store)
                    else self.effect_builder._constant_string(operation.name) or "*"
                )
                locations = self.heap.dynamic_attribute_locations(
                    bases,
                    (attribute,),
                )
                if isinstance(operation, py_ast.Store):
                    self.locations_for_expression(procedure, operation.value)
            return self._prepared_writes_for_bases(locations, bases)
        if isinstance(operation, py_ast.SetSubscript):
            bases = self.locations_for_expression(procedure, operation.expr)
            self.locations_for_expression(procedure, operation.subscript)
            subscript = self.effect_builder._constant_subscript(operation.subscript)
            locations = self.heap.dynamic_subscript_locations(
                bases,
                (subscript or DYNAMIC_SUBSCRIPT_WILDCARD,),
            )
            return self._prepared_writes_for_bases(locations, bases)
        if isinstance(operation, py_ast.SetSlice):
            bases = self.locations_for_expression(procedure, operation.expr)
            for component in (operation.start, operation.stop, operation.step):
                self.locations_for_expression(procedure, component)
            locations = self.heap.dynamic_subscript_locations(
                bases,
                (DYNAMIC_SUBSCRIPT_WILDCARD,),
            )
            return self._prepared_writes_for_bases(locations, bases)
        return None

    def _prepared_writes_for_bases(
        self,
        locations: tuple[HeapLocation, ...],
        bases: tuple[HeapLocation, ...],
    ) -> tuple[object, ...]:
        ambiguous = len({base.root for base in bases}) > 1
        return tuple(
            self.heap.write_for_location(
                location,
                policy=UpdatePolicy.WEAK if ambiguous else None,
            )
            for location in locations
        )

    def _prepared_delete_locations(
        self,
        procedure: object,
        operation: object,
    ) -> tuple[HeapLocation, ...] | None:
        if isinstance(operation, py_ast.DeleteAttr):
            bases = self.locations_for_expression(procedure, operation.expr)
            self.locations_for_expression(procedure, operation.name)
            attribute = self.effect_builder._constant_string(operation.name) or "*"
            return self.heap.dynamic_attribute_locations(bases, (attribute,))
        if isinstance(operation, py_ast.DeleteSubscript):
            bases = self.locations_for_expression(procedure, operation.expr)
            self.locations_for_expression(procedure, operation.subscript)
            subscript = self.effect_builder._constant_subscript(operation.subscript)
            return self.heap.dynamic_subscript_locations(
                bases,
                (subscript or DYNAMIC_SUBSCRIPT_WILDCARD,),
            )
        if isinstance(operation, py_ast.DeleteSlice):
            bases = self.locations_for_expression(procedure, operation.expr)
            for component in (operation.start, operation.stop, operation.step):
                self.locations_for_expression(procedure, component)
            return self.heap.dynamic_subscript_locations(
                bases,
                (DYNAMIC_SUBSCRIPT_WILDCARD,),
            )
        return None

    def _immediate_escape_locations(
        self,
        operation: object,
        effect: object,
    ) -> tuple[HeapLocation, ...]:
        """Return effect escapes that are externally reachable immediately.

        Stores into fields, subscripts, cells, or collection mutators create
        heap reachability edges. The stored values escape only if the
        destination root is, or later becomes, escaped; the fixed-point escape
        propagation handles that through ``HeapState``.
        """
        escapes = getattr(effect, "escapes", ())
        writes = getattr(effect, "writes", ())
        if not writes or not escapes:
            return escapes
        if isinstance(operation, py_ast.SetGlobal):
            return escapes
        if isinstance(
            operation,
            (
                py_ast.SetAttr,
                py_ast.SetSubscript,
                py_ast.SetSlice,
                py_ast.SetCellDeref,
                py_ast.Store,
            ),
        ):
            return ()
        call = self._call_expression(operation)
        if call is not None:
            return ()
        return escapes

    def _apply_writes(
        self,
        procedure: object,
        operation: object,
        writes: tuple[object, ...],
        *,
        stored_value: object | None = None,
    ) -> None:
        value = stored_value
        if value is not None:
            value_locations = self.locations_for_expression(procedure, value)
            if isinstance(operation, py_ast.SetSlice):
                value_locations = self._expand_contained_locations(value_locations)
            # Don't return early when value_locations is empty: write()
            # handles STRONG+empty (pop to clear the binding) and
            # WEAK+empty (no-op) correctly.
        else:
            # No direct stored-value expression.  Check whether this operation
            # wraps a collection mutator call (e.g. ``list.append(x)``) whose
            # value arguments should be written to the container's wildcard
            # location generated by HeapEffectBuilder.collection_mutation().
            coll_value_locs = self._collection_mutator_value_locations(
                procedure, operation
            )
            if not coll_value_locs:
                return
            value_locations = coll_value_locs
        for write in writes:
            location = getattr(write, "location", None)
            policy = getattr(write, "policy", None)
            if not isinstance(location, HeapLocation):
                continue
            self.state.write(
                location,
                tuple(dict.fromkeys(value_locations)),
                (
                    UpdatePolicy.STRONG
                    if isinstance(operation, (py_ast.SetGlobal, py_ast.SetCellDeref))
                    else (
                        policy
                        if isinstance(policy, UpdatePolicy)
                        else UpdatePolicy.WEAK
                    )
                ),
                has_non_reference=value is not None and not value_locations,
            )
            if isinstance(operation, py_ast.SetGlobal):
                module = self._module_locations_by_owner.get(
                    self._module_owner(procedure)
                )
                if module is not None:
                    self.state.write(
                        self.heap.dynamic_attribute_location(
                            module,
                            self.effect_builder._constant_string(operation.name)
                            or self.effect_builder._path_component(operation.name),
                        ),
                        tuple(dict.fromkeys(value_locations)),
                        UpdatePolicy.STRONG,
                        has_non_reference=(value is not None and not value_locations),
                    )
        if isinstance(operation, py_ast.SetSubscript):
            key_locations = self.locations_for_expression(
                procedure,
                operation.subscript,
            )
            if key_locations:
                roots = tuple(
                    dict.fromkeys(
                        HeapLocation(write.location.root)
                        for write in writes
                        if isinstance(getattr(write, "location", None), HeapLocation)
                    )
                )
                for root in roots:
                    self.state.write(
                        self.heap.dynamic_attribute_location(root, "__keys__"),
                        key_locations,
                        UpdatePolicy.WEAK,
                    )

    def _apply_deletes(self, deletes: tuple[HeapLocation, ...]) -> None:
        for deleted in deletes:
            self.state.delete(deleted)

    def _effective_deletes(
        self,
        operation: object,
        deletes: tuple[HeapLocation, ...],
    ) -> tuple[HeapLocation, ...]:
        return self.effect_builder.definite_delete_locations(operation, deletes)

    def _handle_local_delete(
        self,
        procedure: object,
        operation: object,
    ) -> None:
        """Handle ``del x`` — break aliasing and remove the local's heap state."""
        if not isinstance(operation, py_ast.Delete):
            return
        self._clear_runtime_local(procedure, operation.lcl, unbound=True)
