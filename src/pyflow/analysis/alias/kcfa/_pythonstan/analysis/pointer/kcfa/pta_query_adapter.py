"""PtaQuery adapter for AI to query kcfa pointer analysis state.

This module provides an adapter that implements the AI's PtaQuery protocol
over the kcfa PointerAnalysisState, enabling AI to query points-to information,
field values, and class hierarchy (MRO).

Extended to support closure/scope queries:
- get_function_cell_vars: Get captured cell variable bindings
- get_function_global_vars: Get accessible global variable bindings
"""

import ast
from typing import Dict, FrozenSet, List, TYPE_CHECKING, Optional, Tuple

from pyflow.analysis.alias.kcfa._pythonstan.ir.ir_statements import IRCall
from .context import CallSite

if TYPE_CHECKING:
    from .state import PointerAnalysisState
    from .object import AbstractObject
    from .heap_model import Field
    from .variable import Variable
    from .context import AbstractContext, Scope
    from .class_hierarchy import ClassHierarchyManager
    from .points_to_set import PointsToSet
    from .context_selector import ContextSelector

__all__ = ["PtaQueryAdapter"]


class PtaQueryAdapter:
    """Adapter implementing AI's PtaQuery protocol over kcfa state.
    
    This allows the AI engine to query the kcfa pointer analysis state
    for points-to information without depending on the full solver.
    """

    def __init__(
        self,
        state: 'PointerAnalysisState',
        class_hierarchy: Optional['ClassHierarchyManager'] = None,
        context_selector: Optional['ContextSelector'] = None,
    ):
        """Initialize the adapter.
        
        Args:
            state: The kcfa pointer analysis state
            class_hierarchy: Optional class hierarchy manager for MRO queries
        """
        self._state = state
        self._class_hierarchy = class_hierarchy
        self._context_selector = context_selector
        self._callsite_cache: Dict[str, CallSite] = {}

    def _get_call_site(self, callsite_id: str) -> CallSite:
        if callsite_id in self._callsite_cache:
            return self._callsite_cache[callsite_id]
        call_stmt = IRCall(ast.parse("callsite()").body[0].value)
        call_site = CallSite(statement=call_stmt, scope_name=callsite_id)
        self._callsite_cache[callsite_id] = call_site
        return call_site

    def points_to(
        self,
        var: 'Variable',
        scope: 'Scope',
        context: 'AbstractContext',
    ) -> 'PointsToSet':
        """Get points-to set for a variable in given scope/context.
        
        Args:
            var: Variable to query
            scope: Scope containing the variable
            context: Analysis context
            
        Returns:
            PointsToSet of abstract objects the variable may point to
        """
        from .points_to_set import PointsToSet
        
        ctx_var = self._state.get_variable(scope, context, var)
        return self._state.get_points_to(ctx_var)

    def field_points_to(
        self,
        obj: 'AbstractObject',
        field: 'Field',
        scope: 'Scope',
        context: 'AbstractContext',
    ) -> 'PointsToSet':
        """Get points-to set for an object's field.
        
        Args:
            obj: Abstract object
            field: Field key (attr/key/elem)
            scope: Current scope
            context: Analysis context
            
        Returns:
            PointsToSet of objects the field may point to
        """
        from .points_to_set import PointsToSet
        from .object import summarize_object, is_summary_object
        
        # Summary objects: union over all concrete objects that map to this summary
        if is_summary_object(obj):
            summary_rep = summarize_object(obj)
            pts_acc = PointsToSet.empty()
            for concrete in self._state._heap.objects.values():
                if summarize_object(concrete) == summary_rep:
                    field_var = self._state.get_field(scope, context, concrete, field)
                    pts_acc = pts_acc.union(self._state.get_points_to(field_var))
            return pts_acc
        
        # Get field access variable for concrete object
        field_var = self._state.get_field(scope, context, obj, field)
        return self._state.get_points_to(field_var)

    def get_class_mro(self, cls_obj: 'AbstractObject') -> List['AbstractObject']:
        """Get MRO (method resolution order) for a class object.
        
        Args:
            cls_obj: Class object
            
        Returns:
            List of class objects in MRO order (most specific first)
        """
        if self._class_hierarchy is not None:
            try:
                return self._class_hierarchy.get_mro(cls_obj)
            except Exception:
                # Fall back to just the class itself if MRO fails
                pass
        return [cls_obj]

    def may_have_attr(
        self,
        obj: 'AbstractObject',
        attr_name: str,
        scope: 'Scope',
        context: 'AbstractContext',
    ) -> bool:
        """Check if an object may have an attribute (for descriptor checks).
        
        Conservative implementation: returns True unless we can prove
        the attribute definitely doesn't exist.
        
        Args:
            obj: Object to check
            attr_name: Attribute name (e.g., "__get__", "__set__")
            scope: Current scope
            context: Analysis context
            
        Returns:
            True if the object may have the attribute
        """
        from .heap_model import attr
        
        # Check if field exists in state
        field_access = self._state.has_field(scope, context, obj, attr(attr_name))
        if field_access is not None:
            # Field exists, check if it has any points-to
            pts = self._state.get_points_to(field_access)
            if not pts.is_empty():
                return True
        
        # Conservative: assume it may have the attribute
        return True

    def select_call_context(
        self,
        callsite_id: str,
        argc: int,
        caller_ctx: 'AbstractContext',
        receiver_obj: Optional['AbstractObject'],
        params: Optional[Tuple['AbstractObject', ...]] = None,
    ) -> Optional['AbstractContext']:
        """Delegate call context selection to kcfa ContextSelector when available."""
        if self._context_selector is None:
            return None
        call_site = self._get_call_site(callsite_id)
        return self._context_selector.select_call_context(
            call_site,
            caller_ctx,
            receiver_obj,
            params=params,
        )

    def get_function_cell_vars(
        self,
        func_obj: 'AbstractObject',
    ) -> Dict[str, FrozenSet['AbstractObject']]:
        """Get cell variable bindings captured by a function object.
        
        Cell variables are variables from enclosing scopes that are captured
        by the function for use in its body (closure variables).
        
        This method queries the KCFA heap model to find captured bindings
        stored in the function object's closure representation.
        
        Args:
            func_obj: Function object to query
            
        Returns:
            Dict mapping cell variable names to their captured points-to sets
        """
        from .variable import VariableKind
        from .heap_model import attr
        
        result: Dict[str, FrozenSet['AbstractObject']] = {}
        
        # Get the function's internal scope to access cell_vars metadata
        scope = self._state.get_internal_scope(func_obj)
        if scope is None:
            return result
        
        # Try to get the IRFunc from the scope
        ir_func = None
        if hasattr(scope, 'stmt'):
            ir_stmt = scope.stmt
            from pyflow.analysis.alias.kcfa._pythonstan.ir.ir_statements import IRFunc
            if isinstance(ir_stmt, IRFunc):
                ir_func = ir_stmt
        
        if ir_func is None:
            return result
        
        # Get cell_vars from the IRFunc
        cell_var_names = ir_func.cell_vars
        
        # For each cell var, try to find its binding in the function's closure
        # The closure is typically stored as a special field on the function object
        for var_name in cell_var_names:
            # Try to read from closure field (named __closure__ or similar)
            closure_field = attr(f"__cell_{var_name}__")
            try:
                pts = self.field_points_to(func_obj, closure_field, scope, None)
                if pts:
                    result[var_name] = frozenset(pts)
            except Exception:
                pass
            
            # Fallback: try to read from nonlocal tracking in state
            # This uses the KCFA variable tracking for cell/nonlocal vars
            from .variable import Variable
            cell_var = Variable(name=var_name, kind=VariableKind.CELL)
            try:
                ctx_var = self._state.get_variable(scope, None, cell_var)
                pts = self._state.get_points_to(ctx_var)
                if pts and not pts.is_empty():
                    result[var_name] = frozenset(pts) | result.get(var_name, frozenset())
            except Exception:
                pass
        
        return result

    def get_function_global_vars(
        self,
        func_obj: 'AbstractObject',
    ) -> Dict[str, FrozenSet['AbstractObject']]:
        """Get global variable bindings accessible by a function object.
        
        Global variables are module-level names that the function may read/write.
        This method queries the KCFA state to find global variable bindings
        in the module namespace.
        
        Args:
            func_obj: Function object to query
            
        Returns:
            Dict mapping global variable names to their points-to sets
        """
        from .variable import Variable, VariableKind
        from .heap_model import attr
        
        result: Dict[str, FrozenSet['AbstractObject']] = {}
        
        # Get the function's internal scope
        scope = self._state.get_internal_scope(func_obj)
        if scope is None:
            return result
        
        # Try to get the IRFunc from the scope
        ir_func = None
        if hasattr(scope, 'stmt'):
            ir_stmt = scope.stmt
            from pyflow.analysis.alias.kcfa._pythonstan.ir.ir_statements import IRFunc
            if isinstance(ir_stmt, IRFunc):
                ir_func = ir_stmt
        
        if ir_func is None:
            return result
        
        # Get global_vars from the IRFunc
        global_var_names = ir_func.global_vars
        
        # Try to find the module object containing this function
        # This is a heuristic - look for MODULE kind objects
        from .object import AllocKind
        module_obj = None
        for obj in self._state._heap.objects.values():
            if hasattr(obj, 'kind') and obj.kind == AllocKind.MODULE:
                # Check if this module contains our function
                # This is a simplified check
                module_obj = obj
                break
        
        for var_name in global_var_names:
            # Try to read from module attribute
            if module_obj is not None:
                field = attr(var_name)
                try:
                    pts = self.field_points_to(module_obj, field, scope, None)
                    if pts:
                        result[var_name] = frozenset(pts)
                except Exception:
                    pass
            
            # Fallback: read from global variable tracking
            global_var = Variable(name=var_name, kind=VariableKind.GLOBAL)
            try:
                ctx_var = self._state.get_variable(scope, None, global_var)
                pts = self._state.get_points_to(ctx_var)
                if pts and not pts.is_empty():
                    result[var_name] = frozenset(pts) | result.get(var_name, frozenset())
            except Exception:
                pass
        
        return result
