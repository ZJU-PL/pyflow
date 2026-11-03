"""Model container allocation and element flow for pointer analysis."""

import ast
from abc import ABC, abstractmethod
from typing import TYPE_CHECKING, Any, Optional
from .processor import Processor
from ..object import ListObject, TupleObject, DictObject, SetObject, ConstantObject, AllocKind
from ..heap_model import dict_keys, elem, elem_only, key
from ..points_to_set import PointsToSet
from ..constraints import (
    LoadSubscrConstraint,
    StoreSubscrConstraint,
    LoadConstraint,
    StoreConstraint,
)

if TYPE_CHECKING:
    from pyflow.analysis.alias.kcfa._pythonstan.ir.ir_statements import IRStatement
    from ..pointer_flow_graph import NormalNode
    from ..solver import PointerSolver
    from ..context import Ctx, Scope, AbstractContext
    from ..constraints import AllocConstraint, Constraint


class ContainerProcessor(Processor):
    """Handle container allocations and subscript load/store constraints.

    With index sensitivity enabled, constant keys receive precise synthetic
    fields while a generic element field preserves sound flow for unknown keys.
    """

    def __init__(self, index_sensitive: bool = True):
        """Initialize the processor and optionally retain constant indices."""
        self.index_sensitive = index_sensitive

    def handle_allocation(
        self,
        solver: "PointerSolver",
        target: "Ctx[Any]",
        scope: "Scope",
        context: "AbstractContext",
        c: "AllocConstraint",
    ) -> bool:
        state = solver.state

        obj = None

        if c.alloc_site.kind == AllocKind.LIST and self.index_sensitive:
            obj = self._alloc_list(scope, context, c)

        elif c.alloc_site.kind == AllocKind.TUPLE and self.index_sensitive:
            obj = self._alloc_tuple(scope, context, c)

        elif c.alloc_site.kind == AllocKind.DICT and self.index_sensitive:
            obj = self._alloc_dict(scope, context, c)

        elif c.alloc_site.kind == AllocKind.SET and self.index_sensitive:
            obj = self._alloc_set(scope, context, c)

        if obj is not None:
            state._heap.set_obj(scope, context, c.alloc_site, obj)
            state.obj_scope[obj] = scope
            if self._literal_positions_are_complete(c.alloc_site):
                state._precise_container_objects.add(obj)
            solver.handle_new_points_to(target, scope, PointsToSet.singleton(obj))
            return True

        return False

    def _alloc_list(
        self, scope: "Scope", context: "AbstractContext", c: "AllocConstraint"
    ) -> "ListObject":
        """Allocate list object."""
        obj = ListObject(context, c.alloc_site)
        return obj

    def _alloc_tuple(
        self, scope: "Scope", context: "AbstractContext", c: "AllocConstraint"
    ) -> "TupleObject":
        """Allocate tuple object."""
        obj = TupleObject(context, c.alloc_site)
        return obj

    def _alloc_dict(
        self, scope: "Scope", context: "AbstractContext", c: "AllocConstraint"
    ) -> "DictObject":
        """Allocate dict object."""
        obj = DictObject(context, c.alloc_site)
        return obj

    def _alloc_set(
        self, scope: "Scope", context: "AbstractContext", c: "AllocConstraint"
    ) -> "SetObject":
        """Allocate set object."""
        obj = SetObject(context, c.alloc_site)
        return obj

    @staticmethod
    def _literal_positions_are_complete(alloc_site) -> bool:
        """Whether a literal has a key cell for every element."""
        stmt = getattr(alloc_site, "stmt", None)
        rval = stmt.get_rval() if hasattr(stmt, "get_rval") else None
        if isinstance(rval, ast.List) or isinstance(rval, ast.Tuple):
            return all(isinstance(element, ast.Name) for element in rval.elts)
        if isinstance(rval, ast.Dict):
            return all(
                isinstance(value, ast.Name) and (isinstance(key_expr, (ast.Constant, ast.Name)))
                for key_expr, value in zip(rval.keys, rval.values)
            )
        return False

    def handle_constraint(
        self,
        solver: "PointerSolver",
        target: "Ctx[Any]",
        scope: "Scope",
        constraint: "Constraint",
        pts: "PointsToSet",
    ) -> bool:
        if isinstance(constraint, LoadSubscrConstraint):
            return self._apply_load_subscr(solver, scope, target, constraint, pts)
        elif isinstance(constraint, StoreSubscrConstraint):
            return self._apply_store_subscr(solver, scope, target, constraint, pts)
        return False

    @staticmethod
    def _literal_sequence_length(obj: Any) -> Optional[int]:
        """Return the statically known length of a literal sequence object.

        ``None`` means the length cannot be determined (non-literal container,
        starred element, or an unsupported literal form).
        """
        stmt = getattr(getattr(obj, "alloc_site", None), "stmt", None)
        rval = stmt.get_rval() if hasattr(stmt, "get_rval") else None
        if not isinstance(rval, (ast.List, ast.Tuple)):
            return None
        if any(isinstance(element, ast.Starred) for element in rval.elts):
            return None
        return len(rval.elts)

    def _add_negative_index_loads(
        self,
        solver: "PointerSolver",
        scope: "Scope",
        c: "LoadSubscrConstraint",
        index_value: Any,
        base_objects: PointsToSet,
    ) -> None:
        """Resolve ``seq[-n]`` against a literal sequence's known length."""
        if not isinstance(index_value, int) or isinstance(index_value, bool) or index_value >= 0:
            return
        for base_obj in base_objects:
            if not isinstance(base_obj, (ListObject, TupleObject)):
                continue
            length = self._literal_sequence_length(base_obj)
            if length is None or index_value < -length:
                continue
            solver.add_constraint(
                scope,
                scope.context,
                LoadConstraint(c.base, key(length + index_value), c.target),
            )

    def _apply_load_subscr(
        self,
        solver: "PointerSolver",
        scope: "Scope",
        variable: "Ctx",
        c: "LoadSubscrConstraint",
        pts: "PointsToSet",
    ):
        """Apply load constraint: target = base[index].

        Soundness rules:

        * A statically known index yields a precise ``key(...)`` load.  For
          sequences, negative indices are normalised against the literal
          length (``seq[-1]`` becomes the last element).
        * ``elem_only()`` may only replace the generic fallback when *every*
          index value is a known constant addressing a precise literal
          container.  Otherwise an unknown index (for example a loop counter)
          must fall back to ``elem()``; ``elem_only()`` holds only positions
          that could not be determined statically and therefore cannot stand
          in for an arbitrary index.
        """
        state = solver.state
        base_ctx = state.get_variable(scope, scope.context, c.base)
        base_objects = state.get_points_to(base_ctx)
        if base_objects.is_empty():
            # The index constants may be available before the container is
            # allocated.  Wait for the base points-to set instead of adding an
            # imprecise elem() fallback that can never be retracted.
            state.dependencies.subscribe(
                ("load-subscr-base", scope, scope.context, c),
                (base_ctx,),
                lambda: self._apply_load_subscr(
                    solver, scope, base_ctx, c, state.get_points_to(variable)
                ),
            )
            return True

        constant_indices = [obj for obj in pts if isinstance(obj, ConstantObject)]
        for index_obj in constant_indices:
            field = key(index_obj.value)
            solver.add_constraint(scope, scope.context, LoadConstraint(c.base, field, c.target))
            self._add_negative_index_loads(solver, scope, c, index_obj.value, base_objects)

        precise = (
            bool(pts)
            and len(constant_indices) == len(pts)
            and all(obj in state._precise_container_objects for obj in base_objects)
        )
        if precise:
            # Literal containers mirror key(i) and elem(); only values added
            # through an unknown position need the generic fallback.
            solver.add_constraint(
                scope,
                scope.context,
                LoadConstraint(c.base, elem_only(), c.target),
            )
        else:
            # Always include elem() for containers whose key cells may not be
            # complete (append/update/starred unpacking, custom containers) and
            # for any index that is not a known constant.
            solver.add_constraint(
                scope,
                scope.context,
                LoadConstraint(c.base, elem(), c.target),
            )
        return True

    def _apply_store_subscr(
        self,
        solver: "PointerSolver",
        scope: "Scope",
        variable: "Ctx",
        c: "StoreSubscrConstraint",
        pts: "PointsToSet",
    ):
        """Apply store constraint: base[index] = source."""

        state = solver.state
        # An empty index set means "the index is not known", not "no store
        # happens": keep the write visible through the generic element cell.
        unknown_index = len(pts) == 0
        stored_elem = False
        for index_obj in pts:
            if isinstance(index_obj, ConstantObject):
                field = key(index_obj.value)
                solver.add_constraint(
                    scope, scope.context, StoreConstraint(c.base, field, c.source)
                )
                stored_elem = True
            else:
                unknown_index = True
        if unknown_index or stored_elem:
            solver.add_constraint(scope, scope.context, StoreConstraint(c.base, elem(), c.source))
        if unknown_index:
            solver.add_constraint(
                scope, scope.context, StoreConstraint(c.base, elem_only(), c.source)
            )
        # Remember the key objects so ``keys()``/``items()``/iteration can
        # enumerate them (``key(name)`` cells are not enumerable).
        solver.add_constraint(scope, scope.context, StoreConstraint(c.base, dict_keys(), c.index))
        return True

    def handle_new_constraint(
        self, solver: "PointerSolver", scope: "Scope", constraint: "Constraint"
    ) -> bool:
        state = solver.state
        if isinstance(constraint, LoadSubscrConstraint):
            index = state.get_variable(scope, scope.context, constraint.index)
            state.constraints.add(scope, index, constraint)
            index_pts = state.get_points_to(index)
            if len(index_pts) > 0:
                self._apply_load_subscr(solver, scope, index, constraint, index_pts)
            return True
        elif isinstance(constraint, StoreSubscrConstraint):
            index = state.get_variable(scope, scope.context, constraint.index)
            state.constraints.add(scope, index, constraint)
            index_pts = state.get_points_to(index)
            if len(index_pts) > 0:
                self._apply_store_subscr(solver, scope, index, constraint, index_pts)
            return True
        return False
