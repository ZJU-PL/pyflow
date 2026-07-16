from abc import ABC, abstractmethod
from typing import TYPE_CHECKING, Any
from .processor import Processor
from ..object import ListObject, TupleObject, DictObject, SetObject, ConstantObject, AllocKind
from ..heap_model import elem, key
from ..points_to_set import PointsToSet
from ..constraints import LoadSubscrConstraint, StoreSubscrConstraint, LoadConstraint, StoreConstraint

if TYPE_CHECKING:
    from pyflow.analysis.alias.kcfa._pythonstan.ir.ir_statements import IRStatement
    from ..pointer_flow_graph import NormalNode
    from ..solver import PointerSolver
    from ..context import Ctx, Scope, AbstractContext
    from ..constraints import AllocConstraint, Constraint


class ContainerProcessor(Processor):
    """
    Handle container allocations and load/store of container elements.
    """
    
    def __init__(self, index_sensitive: bool = True):
        """
        Initialize container processor.
        """
        self.index_sensitive = index_sensitive
        
    def handle_allocation(self, solver: 'PointerSolver', target: 'Ctx[Any]', scope: 'Scope', context: 'AbstractContext', c: 'AllocConstraint') -> bool:                
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
            solver.handle_new_points_to(target, scope, PointsToSet.singleton(obj))
            return True

        return False
        
    def _alloc_list(self, scope: 'Scope', context: 'AbstractContext', c: 'AllocConstraint') -> 'ListObject':
        """Allocate list object."""
        obj = ListObject(context, c.alloc_site)
        return obj
    
    def _alloc_tuple(self, scope: 'Scope', context: 'AbstractContext', c: 'AllocConstraint') -> 'TupleObject':
        """Allocate tuple object."""
        obj = TupleObject(context, c.alloc_site)
        return obj
    
    def _alloc_dict(self, scope: 'Scope', context: 'AbstractContext', c: 'AllocConstraint') -> 'DictObject':
        """Allocate dict object."""
        obj = DictObject(context, c.alloc_site)
        return obj
    
    def _alloc_set(self, scope: 'Scope', context: 'AbstractContext', c: 'AllocConstraint') -> 'SetObject':
        """Allocate set object."""
        obj = SetObject(context, c.alloc_site)
        return obj
    
    def handle_constraint(self, solver: 'PointerSolver', target: 'Ctx[Any]', scope: 'Scope', constraint: 'Constraint', pts: 'PointsToSet') -> bool:
        if isinstance(constraint, LoadSubscrConstraint):
            return self._apply_load_subscr(solver, scope, target, constraint, pts)
        elif isinstance(constraint, StoreSubscrConstraint):
            return self._apply_store_subscr(solver, scope, target, constraint, pts)
        return False
    
    def _apply_load_subscr(self, solver: 'PointerSolver', scope: 'Scope', variable: 'Ctx', c: 'LoadSubscrConstraint', pts: 'PointsToSet'):
        """Apply load constraint: target = base[index].
        
        For any index (constant or not), we add LoadConstraint with elem() to ensure
        all container values are visible through the generic element field (soundness).
        We also add key-specific constraints for constant indices (precision).
        """
        for index_obj in pts:
            if isinstance(index_obj, ConstantObject):
                field = key(index_obj.value)
                solver.add_constraint(scope, scope.context, LoadConstraint(c.base, field, c.target))
        # Always include elem() for soundness (dict/list append/update, etc.)
        solver.add_constraint(scope, scope.context, LoadConstraint(c.base, elem(), c.target))
        return True
    
    def _apply_store_subscr(self, solver: 'PointerSolver', scope: 'Scope', variable: 'Ctx', c: 'StoreSubscrConstraint', pts: 'PointsToSet'):
        """Apply store constraint: base[index] = source."""
        
        state = solver.state
        unknown_index = False
        stored_elem = False
        for index_obj in pts:
            if isinstance(index_obj, ConstantObject):
                field = key(index_obj.value)
                solver.add_constraint(scope, scope.context, StoreConstraint(c.base, field, c.source))
                stored_elem = True
            else:
                unknown_index = True
        if unknown_index or stored_elem:
            solver.add_constraint(scope, scope.context, StoreConstraint(c.base, elem(), c.source))
        return True
    
    def handle_new_constraint(self, solver: 'PointerSolver', scope: 'Scope', constraint: 'Constraint') -> bool:
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
