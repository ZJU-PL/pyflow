"""IR to constraint translation.

This module translates IR events to pointer constraints for analysis.
"""

from typing import List, TYPE_CHECKING, Optional, Tuple, Dict, Set, Union
import logging, ast
from collections import defaultdict
from dataclasses import replace

from .constraints import *
from .config import Config
from .context import CallSite
from .variable import Variable, VariableFactory, VariableKind
from .heap_model import elem, attr, key
from pyflow.analysis.alias.kcfa._pythonstan.ir.ir_statements import *
from .object import AllocSite, AllocKind

logger = logging.getLogger(__name__)

__all__ = ["IRTranslator"]

BINOP_TABLE = {
    ast.Add: "__add__",       # +  
    ast.Sub: "__sub__",       # -  
    ast.Mult: "__mul__",      # *  
    ast.Div: "__truediv__",   # /  
    ast.FloorDiv: "__floordiv__",  # //  
    ast.Mod: "__mod__",       # %  
    ast.Pow: "__pow__",       # **  
    ast.LShift: "__lshift__", # <<  
    ast.RShift: "__rshift__", # >>  
    ast.BitOr: "__or__",      # |  
    ast.BitXor: "__xor__",    # ^  
    ast.BitAnd: "__and__",    # &  
    ast.MatMult: "__matmul__", # @ (矩阵乘法)  
    ast.Eq: "__eq__",         # ==  
    ast.NotEq: "__ne__",      # !=  
    ast.Lt: "__lt__",         # <  
    ast.LtE: "__le__",        # <=  
    ast.Gt: "__gt__",         # >  
    ast.GtE: "__ge__",        # >=  
    ast.In: "__contains__",    # in  
}

UNARYOP_TABLE = {  
    ast.UAdd: "__pos__",      # +x  
    ast.USub: "__neg__",      # -x  
    ast.Not: "__bool__",      # not x
    ast.Invert: "__invert__", # ~x  
}


class IRTranslator:
    """Translates IR to pointer constraints."""
    def __init__(self, config: 'Config'):    
        self.config = config
        self._var_factory = VariableFactory()
        self._current_scope: Optional['IRScope'] = None
        self._current_module: Optional['IRModule'] = None
        self._scope_constraints: Dict[IRScope, List['Constraint']] = {}
        self._import_depth = 0  # Track import depth for recursion limit
        self._local_vars: Dict[IRScope, Set[str]] = defaultdict(set)
        self._class_used_variables: Dict[IRClass, List['Variable']] = {}
        self._class_base_variables: Dict[IRClass, Tuple['Variable', ...]] = {}
        self._class_metaclass_variables: Dict[IRClass, Tuple['Variable', ...]] = {}
        
        from pyflow.analysis.alias.kcfa._pythonstan.world import World
        if not hasattr(World, "scope_manager"):
            World.setup()
        self.world = World()
        self.scope_manager = self.world.scope_manager
        self.namespace_manager = self.world.namespace_manager
    
    def translate_function(self, func: IRFunc) -> List['Constraint']:        
        constraints = []
        
        # avoid infinite recursion
        if func in self._scope_constraints:
            return self._scope_constraints[func]
        
        self._current_scope = func
        locals_set = self._local_vars.setdefault(func, set())
        locals_set.update(func.get_arg_names())
        stmts = self.scope_manager.get_ir(func, 'ir')
        if stmts is not None:
            binders = set()
            for stmt in stmts:
                binders.update(stmt.get_stores())
            binders.difference_update(func.get_global_vars())
            binders.difference_update(func.get_nonlocal_vars())
            locals_set.update(
                name for name in binders
                if name and name.isidentifier()
            )
            for stmt in stmts:
                constraints.extend(self._process_stmt(stmt))
        
        self._scope_constraints[func] = constraints
        return constraints
    
    def translate_module(self, module: IRModule, import_stmt: Optional['IRImport'] = None
                         ) -> List['Constraint']:
        assert isinstance(module, IRModule), f"Module is not an IRModule: {type(module)}"

        # avoid infinite recursion
        if module in self._scope_constraints:
            return self._scope_constraints[module]
        
        constraints = []
        ir = self.scope_manager.get_ir(module, 'ir')

        if ir is not None:
            self._current_scope = module
            self._current_module = module
            for stmt in ir:
                constraints.extend(self._process_stmt(stmt))

            self._scope_constraints[module] = constraints
        
        return constraints
    
        
    def translate_class(self, cls_stmt: IRClass) -> Tuple[Variable, List['Constraint']]:
        """Translate class definition: allocate class object and bind methods."""
        assert isinstance(cls_stmt, IRClass), f"Class is not an IRClass: {type(cls_stmt)}"

        if cls_stmt in self._scope_constraints:
            return self._scope_constraints[cls_stmt]
        
        constraints = []
        old_used_variables = getattr(self, "used_variables", [])
        self.used_variables = []
        irs = self.scope_manager.get_ir(cls_stmt, "ir")

        if irs is not None:
            old_scope = self._current_scope
            self._current_scope = cls_stmt
            for stmt in irs:
                constraints.extend(self._process_stmt(stmt))
            self._current_scope = old_scope

            self._class_used_variables[cls_stmt] = list(self.used_variables)
            self.used_variables = old_used_variables
            self._scope_constraints[cls_stmt] = constraints
        
        return constraints

    def get_class_used_variables(self, cls_stmt: IRClass) -> List['Variable']:
        return self._class_used_variables.get(cls_stmt, [])

    def get_class_base_variables(self, cls_stmt: IRClass) -> Tuple['Variable', ...]:
        return self._class_base_variables.get(cls_stmt, ())

    def get_class_metaclass_variables(self, cls_stmt: IRClass) -> Tuple['Variable', ...]:
        return self._class_metaclass_variables.get(cls_stmt, ())
    
    def _make_variable(self, name: str) -> 'Variable':
        if self._current_scope is None:
            raise RuntimeError("No active scope for variable creation")
        
        # Check for temporary variables first (applies to all scopes)
        if name.startswith("$"):
            kind = VariableKind.TEMPORARY
        elif isinstance(self._current_scope, IRModule):
            kind = VariableKind.GLOBAL
        elif isinstance(self._current_scope, IRFunc):
            locals_in_scope = self._local_vars.get(self._current_scope, set())
            if name in self._current_scope.get_nonlocal_vars():
                kind = VariableKind.NONLOCAL
            elif name in self._current_scope.get_global_vars():
                kind = VariableKind.GLOBAL
            elif name in locals_in_scope or name in self._current_scope.arg_names:
                kind = VariableKind.LOCAL
            else:
                enclosing_kind = self._resolve_enclosing_variable_kind(name)
                if enclosing_kind is not None:
                    kind = enclosing_kind
                elif name in self._current_scope.get_cell_vars():
                    kind = VariableKind.CELL
                else:
                    # Treat unresolved names as globals (module-level)
                    kind = VariableKind.GLOBAL
        elif isinstance(self._current_scope, IRClass):
            locals_in_scope = self._local_vars.get(self._current_scope, set())
            if name in locals_in_scope:
                kind = VariableKind.LOCAL
            else:
                enclosing_kind = self._resolve_enclosing_variable_kind(name)
                if enclosing_kind is not None:
                    kind = enclosing_kind
                else:
                    kind = VariableKind.GLOBAL
        elif name in self._current_scope.get_nonlocal_vars():
            kind = VariableKind.NONLOCAL
        elif name in self._current_scope.get_global_vars():
            kind = VariableKind.GLOBAL
        else:
            kind = VariableKind.LOCAL

        '''
        if name.startswith('$'):
            kind = VariableKind.TEMPORARY
        elif name in self._current_scope.get_nonlocal_vars():
            kind = VariableKind.NONLOCAL
        elif name in self._current_scope.get_cell_vars():
            kind = VariableKind.CELL
        elif name in self._current_scope.get_global_vars():
            kind = VariableKind.GLOBAL
        else:
            kind = VariableKind.LOCAL
        '''
            
        return self._var_factory.make_variable(
            name=name,
            kind=kind
        )
    
    def _register_local_var(self, name_or_var: Optional[Union[str, 'Variable']]) -> None:
        if not name_or_var:
            return
        if not isinstance(self._current_scope, (IRFunc, IRClass)):
            return
        if isinstance(name_or_var, str):
            name = name_or_var
            is_temporary = not name.isidentifier()
        else:
            name = name_or_var.name
            is_temporary = name_or_var.is_temporary
        if not name:
            return
        if is_temporary:
            return
        locals_set = self._local_vars.setdefault(self._current_scope, set())
        locals_set.add(name)
    
    def _process_stmt(self, stmt: IRStatement) -> List['Constraint']:
        ret = []
        
        if isinstance(stmt, IRCopy):
            ret = self._translate_copy(stmt)
        elif isinstance(stmt, IRAssign):
            ret = self._translate_assign(stmt)
        elif isinstance(stmt, IRLoadAttr):
            ret = self._translate_load_attr(stmt)
        elif isinstance(stmt, IRStoreAttr):
            ret = self._translate_store_attr(stmt)
        elif isinstance(stmt, IRCall):
            ret = self._translate_call(stmt)
        elif isinstance(stmt, IRReturn):
            ret = self._translate_return(stmt)
        elif isinstance(stmt, IRRaise):
            ret = self._translate_raise(stmt)
        elif isinstance(stmt, IRLoadSubscr):
            ret = self._translate_load_subscr(stmt)
        elif isinstance(stmt, IRStoreSubscr):
            ret = self._translate_store_subscr(stmt)
        elif isinstance(stmt, IRFunc):
            _, ret = self._translate_function_def(stmt)
        elif isinstance(stmt, IRClass):
            _, ret = self._translate_class_def(stmt)
        elif isinstance(stmt, IRImport):
            ret = self._translate_import(stmt)
        elif isinstance(stmt, IRYield):
            ret = self._translate_yield(stmt)
        elif isinstance(stmt, IRAwait):
            ret = self._translate_await(stmt)
        
        for c in ret:
            assert isinstance(c, Constraint), f"Constraint is not a constraint: {type(c)}, stmt: {stmt}"

        # Calls and descriptor-aware attribute operations already retain a
        # CallSite.  The simpler Andersen constraints historically discarded
        # their originating IR instruction, which made precise security
        # diagnostics impossible.  Attach it centrally so constraints created
        # by helpers and protocol lowering receive the same provenance.
        ret = [
            replace(c, site=stmt)
            if hasattr(c, "site") and getattr(c, "site") is None
            else c
            for c in ret
        ]

        return ret
    
    def _translate_copy(self, stmt: IRCopy) -> List['Constraint']:
        """Translate IRCopy: target = source"""
        constraints = []
        
        lval = stmt.get_lval().id
        rval = stmt.get_rval().id
        self._register_local_var(lval)
        target_var = self._make_variable(lval)
        source_var = self._make_variable(rval)
        constraints.append(CopyConstraint(source=source_var, target=target_var))
        
        # for fields of class, we need to store the value to the class
        if (isinstance(self._current_scope, IRClass) and 
            not target_var.is_temporary): # only store the field to the class if it is not a temporary variable
            self.used_variables.append(target_var)
        
        return constraints

    def _translate_yield(self, stmt: IRYield) -> List['Constraint']:
        """Translate IRYield: [target =] yield value.
        
        Yields store values to the generator object's elem() field, enabling
        iteration via next()/for-loops. If a target is present (target = yield value),
        the sent value flows into the target from the generator's $sent field.
        
        Design:
        - Yielded values -> generator.$elem via StoreConstraint
        - Sent values -> target via LoadConstraint from generator.$sent (future)
        - Generator object tracked via special $generator variable in scope
        """
        constraints = []
        
        # Get or create the generator variable for this scope
        generator_var = self._make_variable("$generator")
        
        # If there's a value being yielded, store it to generator.elem()
        if stmt.value is not None:
            value_var = self._make_variable(stmt.value.id)
            constraints.append(StoreConstraint(
                base=generator_var,
                field=elem(),
                source=value_var
            ))
        
        # If there's a target (target = yield value), it receives sent values
        # For now, we model send() conservatively by loading from a $sent field
        if stmt.target is not None and isinstance(stmt.target, ast.Name):
            target_name = stmt.target.id
            self._register_local_var(target_name)
            target_var = self._make_variable(target_name)
            # Load from generator.$sent field (populated by generator.send())
            constraints.append(LoadConstraint(
                base=generator_var,
                field=attr("$sent"),
                target=target_var
            ))

        constraints.append(
            YieldConstraint(
                value=(
                    self._make_variable(stmt.value.id)
                    if isinstance(stmt.value, ast.Name)
                    else None
                ),
                target=(
                    self._make_variable(stmt.target.id)
                    if isinstance(stmt.target, ast.Name)
                    else None
                ),
                generator_var=generator_var,
            )
        )
        
        return constraints
    
    def _translate_await(self, stmt: IRAwait) -> List['Constraint']:
        """Translate IRAwait: [target =] await value.
        
        Awaiting loads the result from the awaitable's $await_result field.
        The async function's return statement stores to this field.
        
        Design:
        - await coro -> Load coro.$await_result into target
        - For soundness, also copy the awaitable directly (handles non-coroutine awaitables)
        """
        constraints = []
        
        # Get the awaitable variable
        awaitable_expr = stmt.get_value()
        if not isinstance(awaitable_expr, ast.Name):
            return constraints
        
        awaitable_var = self._make_variable(awaitable_expr.id)
        
        # If there's a target, load the await result into it
        target = stmt.get_target()
        if target is not None and isinstance(target, ast.Name):
            target_name = target.id
            self._register_local_var(target_name)
            target_var = self._make_variable(target_name)
            
            # Load from awaitable.$await_result (set by async function return)
            constraints.append(LoadConstraint(
                base=awaitable_var,
                field=attr("$await_result"),
                target=target_var
            ))
            
            # For soundness: also load from elem() to handle generators-as-coroutines
            constraints.append(LoadConstraint(
                base=awaitable_var,
                field=elem(),
                target=target_var
            ))
        
        return constraints
    
    def _translate_assign(self, stmt: IRAssign) -> List['Constraint']:
        """Translate IRAssign: may allocate objects"""
        constraints = []
        lval = stmt.get_lval()
        rval = stmt.get_rval()
        
        self._register_local_var(lval.id)
        target_var = self._make_variable(lval.id)
        
        if isinstance(rval, ast.List):
            alloc_site = AllocSite.from_ir_node(stmt, AllocKind.LIST)
            constraints.append(AllocConstraint(target=target_var, alloc_site=alloc_site))
            if hasattr(rval, 'elts'):
                for i, elt_expr in enumerate(rval.elts):
                    if isinstance(elt_expr, ast.Name):
                        elem_var = self._make_variable(elt_expr.id)
                        if self.config.index_sensitive:
                            # Store at specific position field                            
                            constraints.append(StoreConstraint(
                                base=target_var,
                                field=key(i),
                                source=elem_var
                            ))
                        # Also store at generic elem() for soundness
                        constraints.append(StoreConstraint(
                            base=target_var,
                            field=elem(),
                            source=elem_var
                        ))

        elif isinstance(rval, ast.Name):
            source_var = self._make_variable(rval.id)
            constraints.append(CopyConstraint(source=source_var, target=target_var))
                        
        elif isinstance(rval, ast.BinOp):
            lvar = self._make_variable(rval.left.id)
            rvar = self._make_variable(rval.right.id)
            target = self._make_variable(lval.id)
            self._translate_binary_op(lvar, rvar, target, rval.op)
        
        elif isinstance(rval, ast.UnaryOp):
            operand = self._make_variable(rval.operand.id)
            target = self._make_variable(lval.id)
            self._translate_unary_op(operand, target, rval.op)
            
        elif isinstance(rval, ast.Dict):
            alloc_site = AllocSite.from_ir_node(stmt, AllocKind.DICT)
            constraints.append(AllocConstraint(target=target_var, alloc_site=alloc_site))
            if hasattr(rval, 'keys') and hasattr(rval, 'values'):
                for i, (key_expr, val_expr) in enumerate(zip(rval.keys, rval.values)):
                    if isinstance(val_expr, ast.Name):
                        val_var = self._make_variable(val_expr.id)
                        # Handle both constant keys and name keys (from TAC transformation)
                        if isinstance(key_expr, ast.Constant) and self.config.index_sensitive:
                            # Direct constant key
                            field = key(key_expr.value)
                            constraints.append(StoreConstraint(
                                base=target_var,
                                field=field,
                                source=val_var
                            ))
                        elif isinstance(key_expr, ast.Name) and self.config.index_sensitive:
                            # Key is a name (e.g., from TAC: $const_1 = "a"; d = {$const_1: v})
                            # Use StoreSubscrConstraint for dynamic resolution
                            key_var = self._make_variable(key_expr.id)
                            constraints.append(StoreSubscrConstraint(
                                base=target_var,
                                index=key_var,
                                source=val_var
                            ))
                        # Always add elem() constraint for soundness
                        constraints.append(StoreConstraint(
                            base=target_var,
                            field=elem(),
                            source=val_var
                        ))
                        
        # Tuple uses position-based fields for precise tracking
        elif isinstance(rval, ast.Tuple):
            alloc_site = AllocSite.from_ir_node(stmt, AllocKind.TUPLE)
            constraints.append(AllocConstraint(target=target_var, alloc_site=alloc_site))
            if hasattr(rval, 'elts'):
                for i, elt_expr in enumerate(rval.elts):
                    if isinstance(elt_expr, ast.Name):
                        elem_var = self._make_variable(elt_expr.id)                        
                        if self.config.index_sensitive:
                            # Store at specific position field
                            constraints.append(StoreConstraint(
                                base=target_var,
                                field=key(i),
                                source=elem_var
                            ))
                        # Also store at generic elem() for soundness
                        constraints.append(StoreConstraint(
                            base=target_var,
                            field=elem(),
                            source=elem_var
                        ))
            
        elif isinstance(rval, ast.Set):
            alloc_site = AllocSite.from_ir_node(stmt, AllocKind.SET)
            constraints.append(AllocConstraint(target=target_var, alloc_site=alloc_site))
            if hasattr(rval, 'elts'):
                for elt_expr in rval.elts:
                    if isinstance(elt_expr, ast.Name):
                        elem_var = self._make_variable(elt_expr.id)
                        constraints.append(StoreConstraint(
                            base=target_var,
                            field=elem(),
                            source=elem_var
                        ))
        
        elif isinstance(rval, ast.Constant):
            alloc_site = AllocSite.from_ir_node(stmt, AllocKind.CONSTANT)
            constraints.append(AllocConstraint(target=target_var, alloc_site=alloc_site))
        
        else:
            alloc_site = AllocSite.from_ir_node(stmt, AllocKind.UNKNOWN)
            constraints.append(AllocConstraint(target=target_var, alloc_site=alloc_site))
            
        
        # for fields of class, we need to store the value to the class
        if (isinstance(self._current_scope, IRClass) and 
            not target_var.is_temporary): # only store the field to the class if it is not a temporary variable
            self.used_variables.append(target_var)
        
        return constraints
    
    def _translate_load_attr(self, stmt: IRLoadAttr) -> List['Constraint']:
        """Translate IRLoadAttr: target = base.attr"""       
        lval = stmt.get_lval().id
        obj_name = stmt.get_obj().id
        attr_name = stmt.get_attr()
        
        self._register_local_var(lval)
        base_var = self._make_variable(obj_name)
        target_var = self._make_variable(lval)
        attr_value = attr_name if attr_name else "<unknown>"
        call_site = CallSite(statement=stmt, scope_name=self._get_current_scope_label())

        if (isinstance(self._current_scope, IRClass) and 
            not target_var.is_temporary): # only store the field to the class if it is not a temporary variable
            self.used_variables.append(target_var)
        
        return [AttrReadConstraint(base=base_var, attr=attr_value, target=target_var, call_site=call_site)]
    
    def _translate_store_attr(self, stmt: IRStoreAttr) -> List['Constraint']:
        """Translate IRStoreAttr: base.attr = source"""
        obj_name = stmt.get_obj().id
        attr_name = stmt.get_attr()
        value_name = stmt.get_rval().id
        
        base_var = self._make_variable(obj_name)
        source_var = self._make_variable(value_name)
        attr_value = attr_name if attr_name else "<unknown>"
        call_site = CallSite(statement=stmt, scope_name=self._get_current_scope_label())
        
        return [AttrWriteConstraint(base=base_var, attr=attr_value, source=source_var, call_site=call_site)]
    
    def _translate_call(self, stmt: IRCall) -> List['Constraint']:
        """Translate IRCall: target = callee(args...)"""
        # TODO all conditions of arguments should be translated to constraints
        constraints = []
        
        lval = stmt.get_target()
        callee_expr = stmt.get_func_name()
        args = stmt.get_args()
        
        callee_var = self._make_variable(callee_expr)
        arg_vars = []
        starred = []
        for idx, (arg, is_starred) in enumerate(args):
            if arg.startswith("<Constant: ") and arg.endswith(">"):
                value_str = arg[len("<Constant: "):-1]
                try:
                    const_value = ast.literal_eval(value_str)
                except Exception:
                    const_value = value_str
                const_name = f"$const_{id(stmt)}_{idx}"
                const_var = self._make_variable(const_name)
                const_assign = IRAssign(
                    ast.Assign(
                        targets=[ast.Name(id=const_name, ctx=ast.Store())],
                        value=ast.Constant(value=const_value),
                    )
                )
                const_alloc = AllocSite.from_ir_node(const_assign, AllocKind.CONSTANT)
                constraints.append(AllocConstraint(target=const_var, alloc_site=const_alloc))
                arg_vars.append(const_var)
            else:
                arg_vars.append(self._make_variable(arg))
            starred.append(is_starred)
        arg_vars = tuple(arg_vars)
        
        target_var = None
        if lval:
            self._register_local_var(lval)
            target_var = self._make_variable(lval)
        
        call_site_scope = self._get_current_scope_label()
        call_site = CallSite(statement=stmt, scope_name=call_site_scope)
        keyword_vars = tuple(
            (kw_name, self._make_variable(kw_val))
            for kw_name, kw_val in stmt.get_keywords()
        )
        constraints.append(CallConstraint(
            callee=callee_var,
            args=arg_vars,
            kwargs=keyword_vars,
            target=target_var,
            call_site=call_site,
            starred=tuple(starred),
        ))
        
        # for fields of class, we need to store the value to the class
        if (isinstance(self._current_scope, IRClass) and 
            target_var is not None and
            not target_var.is_temporary): # only store the field to the class if it is not a temporary variable
            self.used_variables.append(target_var)
        
        return constraints

    def _get_current_scope_label(self) -> str:
        """Return a stable string label for the current scope.
        
        Ensures that the entry module is always labeled '__main__' so tests
        expecting module-level calls from __main__ succeed, while other modules
        retain their qualified names.
        """
        if self._current_scope is None:
            return "<unknown>"
        
        try:
            entry_module = getattr(self.world, "entry_module", None)
        # except AttributeError:
        #     entry_module = None
        finally:
            ...
        
        if isinstance(self._current_scope, IRModule):
            if entry_module is None or self._current_scope is entry_module:
                return "__main__"
            return self._current_scope.get_qualname()
        
        if hasattr(self._current_scope, "get_qualname"):
            return self._current_scope.get_qualname()
        
        if hasattr(self._current_scope, "name"):
            return self._current_scope.name
        
        return str(self._current_scope)

    def _resolve_enclosing_variable_kind(self, name: str) -> Optional[VariableKind]:
        """Infer variable kind from enclosing scopes when closure metadata is missing."""
        if self._current_scope is None:
            return None
        
        father_map = getattr(self.scope_manager, "father", {})
        parent = father_map.get(self._current_scope)
        
        while parent is not None:
            locals_in_parent = self._local_vars.get(parent, set())
            if isinstance(parent, IRFunc):
                arg_names = getattr(parent, "arg_names", set())
                if name in parent.get_global_vars():
                    return VariableKind.GLOBAL
                if name in parent.get_nonlocal_vars():
                    return VariableKind.NONLOCAL
                if (name in parent.get_cell_vars() or
                        name in locals_in_parent or
                        name in arg_names):
                    return VariableKind.CELL
            elif isinstance(parent, IRClass):
                if (
                    not isinstance(self._current_scope, IRFunc)
                    and name in locals_in_parent
                ):
                    return VariableKind.NONLOCAL
            elif isinstance(parent, IRModule):
                return VariableKind.GLOBAL
            parent = father_map.get(parent)
        
        return None
    
    def _translate_return(self, stmt: IRReturn) -> List['Constraint']:
        """Translate IRReturn: return value.
        
        For regular functions: stores to $return variable.
        For async functions: stores to $coroutine.$await_result field.
        For generator functions: yield handles the values, return just exits.
        """
        rval = stmt.get_value()
        
        if not rval:
            return []
        
        source_var = self._make_variable(rval)
        constraints = []
        
        # Check if we're in an async function
        is_async = (isinstance(self._current_scope, IRFunc) and 
                    self._current_scope.is_async)
        
        if is_async:
            # For async functions, store to coroutine's $await_result field
            coroutine_var = self._make_variable("$coroutine")
            constraints.append(StoreConstraint(
                base=coroutine_var,
                field=attr("$await_result"),
                source=source_var
            ))
        
        # Always copy to $return for normal call handling
        return_var = self._make_variable("$return")
        constraints.append(CopyConstraint(source=source_var, target=return_var))
        
        return constraints

    def _translate_raise(self, stmt: IRRaise) -> List['Constraint']:
        """Retain exception and cause values as explicit boundary constraints."""
        exception = (
            self._make_variable(stmt.exc.id)
            if isinstance(stmt.exc, ast.Name)
            else None
        )
        cause = (
            self._make_variable(stmt.cause.id)
            if isinstance(stmt.cause, ast.Name)
            else None
        )
        return [RaiseConstraint(exception=exception, cause=cause)]
    
    def _translate_load_subscr(self, stmt: IRLoadSubscr) -> List['Constraint']:        
        """Translate IRLoadSubscr: target = container[index]"""
        lval = stmt.get_lval().id
        container_name = stmt.get_obj().id
        
        subslice = stmt.get_slice()
        self._register_local_var(lval)
        container_var = self._make_variable(container_name)
        target_var = self._make_variable(lval)
        
        constraints = []
        
        # Extract index variable for dynamic field resolution
        if hasattr(subslice, 'id'):
            index_var = self._make_variable(subslice.id)
        else:
            # For non-name indexes (constants, etc.), create a temporary
            index_name = f"$index_{id(stmt)}"
            index_var = self._make_variable(index_name)
            if isinstance(subslice, ast.Constant):
                const_assign = IRAssign(
                    ast.Assign(
                        targets=[ast.Name(id=index_name, ctx=ast.Store())],
                        value=subslice,
                    )
                )
                const_alloc = AllocSite.from_ir_node(const_assign, AllocKind.CONSTANT)
                constraints.append(AllocConstraint(target=index_var, alloc_site=const_alloc))
        
        # Generate LoadSubscrConstraint with index variable for dynamic resolution
        if self.config.index_sensitive:
            constraints.append(LoadSubscrConstraint(
                base=container_var,
                index=index_var,
                target=target_var
            ))
        else:
            constraints.append(LoadConstraint(
                base=container_var,
                field=elem(),
                target=target_var
            ))
        
        # Also generate __getitem__ call for custom container types
        getitem_method_var = self._make_variable(f"$getitem_{id(stmt)}")
        constraints.append(LoadConstraint(
            base=container_var,
            field=attr("__getitem__"),
            target=getitem_method_var,
            index=None
        ))
        
        try:
            call_site = CallSite(statement=stmt, scope_name=self._get_current_scope_label())
            constraints.append(CallConstraint(
                callee=getitem_method_var,
                args=(index_var,),
                kwargs=(),
                target=target_var,
                call_site=call_site
            ))
        finally:
            pass
        # except Exception as e:
        #     logger.debug(f"Error generating __getitem__ call: {e}")
        
        # for fields of class, we need to store the value to the class
        if (isinstance(self._current_scope, IRClass) and 
            not target_var.is_temporary): # only store the field to the class if it is not a temporary variable
            self.used_variables.append(target_var)
        
        return constraints
    
    def _translate_store_subscr(self, stmt: IRStoreSubscr) -> List['Constraint']:
        """Translate IRStoreSubscr: container[index] = value"""
        container_name = stmt.get_obj().id
        value_name = stmt.get_rval().id
        
        container_var = self._make_variable(container_name)
        value_var = self._make_variable(value_name)
        
        constraints = []
        
        # Extract index variable for dynamic field resolution
        index_expr = stmt.get_slice()
        if hasattr(index_expr, 'id'):
            index_var = self._make_variable(index_expr.id)
        else:
            # For non-name indexes (constants, etc.), create a temporary
            index_name = f"$index_{id(stmt)}"
            index_var = self._make_variable(index_name)
            if isinstance(index_expr, ast.Constant):
                const_assign = IRAssign(
                    ast.Assign(
                        targets=[ast.Name(id=index_name, ctx=ast.Store())],
                        value=index_expr,
                    )
                )
                const_alloc = AllocSite.from_ir_node(const_assign, AllocKind.CONSTANT)
                constraints.append(AllocConstraint(target=index_var, alloc_site=const_alloc))
        
        # Generate StoreSubscrConstraint with index variable for dynamic resolution
        constraints.append(StoreSubscrConstraint(
            base=container_var,
            index=index_var,
            source=value_var
        ))
        if self.config.index_sensitive:
            constraints.append(StoreSubscrConstraint(
                base=container_var,
                index=index_var,
                source=value_var
            ))
        else:
            constraints.append(StoreConstraint(
                base=container_var,
                field=elem(),
                source=value_var
            ))
        
        # Also generate __setitem__ call for custom container types
        setitem_method_var = self._make_variable(f"$setitem_{id(stmt)}")
        constraints.append(LoadConstraint(
            base=container_var,
            field=attr("__setitem__"),
            target=setitem_method_var,
            index=None
        ))
        
        try:
            call_site = CallSite(statement=stmt, scope_name=self._get_current_scope_label())
            
            constraints.append(CallConstraint(
                callee=setitem_method_var,
                args=(index_var, value_var),
                kwargs=(),
                target=None,
                call_site=call_site
            ))
        finally:
            ...
        # except Exception as e:
        #     logger.debug(f"Error generating __setitem__ call: {e}")
        
        return constraints
    
    def _translate_function_def(self, stmt: IRFunc) -> Tuple[Variable, List['Constraint']]:
        """Translate function definition: allocate function object."""
        constraints = []
        self._local_vars.setdefault(stmt, set()).update(stmt.get_arg_names())
        if isinstance(self._current_scope, IRClass):
            self._local_vars.setdefault(self._current_scope, set()).add(stmt.name)
        
        if isinstance(self._current_scope, IRClass) and (not stmt.is_static_method):
            func_alloc = AllocSite.from_ir_node(stmt, AllocKind.METHOD)
        else:
            func_alloc = AllocSite.from_ir_node(stmt, AllocKind.FUNCTION)
        func_var = self._make_variable(stmt.name)
        constraints.append(AllocConstraint(target=func_var, alloc_site=func_alloc))
        
        if hasattr(stmt, 'decorator_list') and stmt.decorator_list:
            current_var = func_var
            for idx, decorator_expr in enumerate(reversed(stmt.decorator_list)):
                try:
                    # Extract decorator variable/name
                    if isinstance(decorator_expr, ast.Name):
                        decorator_var = self._make_variable(decorator_expr.id)
                    elif isinstance(decorator_expr, ast.Attribute):
                        # e.g., @obj.decorator
                        # Create temporary and load decorator from object
                        decorator_var = self._make_variable(f"$decorator_{stmt.name}_{idx}")
                        if isinstance(decorator_expr.value, ast.Name):
                            obj_var = self._make_variable(decorator_expr.value.id)
                            constraints.append(LoadConstraint(
                                base=obj_var,
                                field=attr(decorator_expr.attr),
                                target=decorator_var
                            ))
                    elif isinstance(decorator_expr, ast.Call):
                        # e.g., @decorator(args) - decorator factory pattern
                        # This is critical for Flask's @app.route() pattern
                        
                        # Get the decorator factory (the callable being called)
                        factory_callable = decorator_expr.func
                        
                        # Create variable for the factory
                        if isinstance(factory_callable, ast.Name):
                            factory_var = self._make_variable(factory_callable.id)
                        elif isinstance(factory_callable, ast.Attribute):
                            # e.g., @app.route() - need to load app.route
                            factory_var = self._make_variable(f"$decorator_factory_{stmt.name}_{idx}")
                            if isinstance(factory_callable.value, ast.Name):
                                obj_var = self._make_variable(factory_callable.value.id)
                                constraints.append(LoadConstraint(
                                    base=obj_var,
                                    field=attr(factory_callable.attr),
                                    target=factory_var
                                ))
                        else:
                            # Complex factory expression
                            factory_var = self._make_variable(f"$decorator_factory_{stmt.name}_{idx}")
                            logger.debug(f"Complex decorator factory expression for {stmt.name}")
                        
                        # Extract arguments to the factory call
                        factory_args = []
                        for arg in decorator_expr.args:
                            if isinstance(arg, ast.Name):
                                factory_args.append(self._make_variable(arg.id))
                            else:
                                # Constant or complex expression - create temp
                                arg_name = f"$decorator_arg_{stmt.name}_{idx}_{len(factory_args)}"
                                arg_var = self._make_variable(arg_name)
                                factory_args.append(arg_var)
                                if isinstance(arg, ast.Constant):
                                    const_assign = IRAssign(
                                        ast.Assign(
                                            targets=[ast.Name(id=arg_name, ctx=ast.Store())],
                                            value=arg,
                                        )
                                    )
                                    const_alloc = AllocSite.from_ir_node(const_assign, AllocKind.CONSTANT)
                                    constraints.append(AllocConstraint(target=arg_var, alloc_site=const_alloc))
                        
                        # Create temporary for the decorator returned by the factory
                        decorator_var = self._make_variable(f"$decorator_{stmt.name}_{idx}")
                        
                        # Create call to the decorator factory
                        factory_call_site = CallSite(
                            statement=stmt,
                            scope_name=self._get_current_scope_label(),
                            index=idx * 2
                        )
                        constraints.append(CallConstraint(
                            callee=factory_var,
                            args=tuple(factory_args),
                            kwargs=(),
                            target=decorator_var,
                            call_site=factory_call_site
                        ))
                    else:
                        # Complex decorator expression - create temporary
                        decorator_var = self._make_variable(f"$decorator_{stmt.name}_{idx}")
                        logger.debug(f"Complex decorator expression for {stmt.name}")
                    
                    # result = decorator(current)
                    result_var = self._make_variable(f"{stmt.name}_decorated_{idx}")
                    call_site = CallSite(
                        statement=stmt,
                        scope_name=self._get_current_scope_label(),
                        index=idx * 2 + 1
                    )
                    
                    constraints.append(CallConstraint(
                        callee=decorator_var,
                        args=(current_var,),
                        kwargs=(),
                        target=result_var,
                        call_site=call_site
                    ))
                    
                    current_var = result_var
                finally:
                    pass
                # except Exception as e:
                #     logger.debug(f"Error handling decorator {idx} for {stmt.name}: {e}")
            
            # Rebind function name to final decorated result
            if len(stmt.decorator_list) > 0:
                constraints.append(CopyConstraint(source=current_var, target=func_var))
                
        # for fields of class, we need to store the value to the class
        if (isinstance(self._current_scope, IRClass) and 
            not func_var.is_temporary): # only store the field if it is not a temporary variable
            self.used_variables.append(func_var)
        
        return func_var, constraints
    
    def _translate_class_def(self, ir_cls: IRClass) -> Tuple[Variable, List['Constraint']]:
        """Translate class definition: allocate class object and bind methods."""
        constraints = []

        # A class statement binds its name in the surrounding lexical scope.
        # Register it before resolving the class variable so nested classes use
        # local/cell bindings rather than being forced into module globals.
        self._register_local_var(ir_cls.name)

        base_variables = []
        for base in ir_cls.get_bases():
            if isinstance(base, ast.Name):
                base_variables.append(self._make_variable(base.id))
        self._class_base_variables[ir_cls] = tuple(base_variables)

        metaclass_variables = []
        for keyword in ir_cls.keywords:
            if keyword.arg == "metaclass" and isinstance(keyword.value, ast.Name):
                metaclass_variables.append(self._make_variable(keyword.value.id))
        self._class_metaclass_variables[ir_cls] = tuple(metaclass_variables)
        
        class_alloc = AllocSite.from_ir_node(ir_cls, AllocKind.CLASS)
        class_var = self._make_variable(ir_cls.name)
        constraints.append(AllocConstraint(target=class_var, alloc_site=class_alloc))

        
        # TODO [CRITICAL] the method of treating inheritances is totally wrong, we should use the class hierarchy manager to handle this.
        '''
        for base_name in ir_cls.get_bases():
            if not isinstance(base_name, ast.Name):
                continue # TODO resolve the base name in detail
            
            base_var = self._make_variable(base_name.id)
            constraints.append(StoreConstraint(
                base=class_var,
                field=attr("__bases__"),
                source=base_var
            ))
        '''
        
        # for fields of class, we need to store the value to the class
        if (isinstance(self._current_scope, IRClass) and 
            not class_var.is_temporary): # only store the field if it is not a temporary variable
            self.used_variables.append(class_var)
        
        return class_var, constraints
    
    def _translate_import(self, stmt: IRImport) -> List['Constraint']:
        """Translate import statement with transitive analysis. """
        constraints = []

        # translate the IRs in the imported module
        module_ir = self.scope_manager.get_module_graph().get_succ_module(self._current_scope, stmt)
        if module_ir is None:
            # Preserve the import's canonical identity even when source is not
            # available. Anonymous UNKNOWN objects make external APIs vanish
            # after aliases and field loads.
            alloc_site = AllocSite.from_ir_node(stmt, AllocKind.NATIVE)
        else:
            alloc_site = AllocSite.from_ir_node(stmt, AllocKind.MODULE)

        # allocate the module variable
        if stmt.module is None:
            if stmt.asname is None:
                local_var = self._make_variable(stmt.name)
            else:
                local_var = self._make_variable(stmt.asname)
            constraints.append(AllocConstraint(target=local_var, alloc_site=alloc_site))
        elif stmt.asname is None:
            module_var = self._make_variable(stmt.module)
            constraints.append(AllocConstraint(target=module_var, alloc_site=alloc_site))
            local_var = self._make_variable(stmt.name)
            constraints.append(LoadConstraint(base=module_var, field=attr(stmt.name), target=local_var))
        else:
            module_var = self._make_variable(stmt.module)
            constraints.append(AllocConstraint(target=module_var, alloc_site=alloc_site))
            local_var = self._make_variable(stmt.asname)
            constraints.append(LoadConstraint(base=module_var, field=attr(stmt.name), target=local_var))
        
        # for fields of class, we need to store the value to the class
        if (isinstance(self._current_scope, IRClass) and 
            not local_var.is_temporary): # only store the field to the class if it is not a temporary variable
            self.used_variables.append(local_var)

        return constraints
    
    def _translate_with_enter(self, context_manager_var: 'Variable', target_var: 'Variable') -> List['Constraint']:
        """Generate constraints for context manager __enter__.        
        Used for: with obj as target: ... 
        Generates: temp = obj.__enter__; target = temp()        
        """
        constraints = []
        
        enter_method_var = self._make_variable(f"$enter_{id(context_manager_var)}")
        constraints.append(LoadConstraint(
            base=context_manager_var,
            field=attr("__enter__"),
            target=enter_method_var
        ))
        
        call_stmt = IRCall(ast.parse(f"[{target_var}] = {context_manager_var}.__enter__()").body[0])
        call_site = CallSite(statement=call_stmt, scope_name=self._get_current_scope_label())
        constraints.append(CallConstraint(
            callee=enter_method_var,
            args=(),
            kwargs=(),
            target=target_var,
            call_site=call_site
        ))
        
        return constraints
    
    def _translate_with_exit(self, context_manager_var: 'Variable') -> List['Constraint']:
        """Generate constraints for context manager __exit__.        
        Used for: with obj: ... (at exit)
        Generates: temp = obj.__exit__; temp(None, None, None)
        """
        constraints = []
        
        exit_method_var = self._make_variable(f"$exit_{id(context_manager_var)}")
        constraints.append(LoadConstraint(
            base=context_manager_var,
            field=attr("__exit__"),
            target=exit_method_var
        ))
        
        call_stmt = IRCall(ast.parse(f"{context_manager_var}.__exit__(None, None, None)").body[0].value)
        call_site = CallSite(statement=call_stmt, scope_name=self._get_current_scope_label())
        constraints.append(CallConstraint(
            callee=exit_method_var,
            args=(),
            kwargs=(),
            target=None,
            call_site=call_site
        ))
        
        return constraints
    
    def _translate_iter(self, iterable_var: 'Variable', target_var: 'Variable') -> List['Constraint']:
        """Generate constraints for iterator creation.
        Used for: for item in obj: ...
        Generates: iter_temp = obj.__iter__; target = iter_temp()
        """
        constraints = []
        
        iter_method_var = self._make_variable(f"$iter_{id(iterable_var)}")
        constraints.append(LoadConstraint(
            base=iterable_var,
            field=attr("__iter__"),
            target=iter_method_var
        ))
        
        call_stmt = IRCall(ast.parse(f"[{target_var}] = {iterable_var}.__iter__()").body[0])
        call_site = CallSite(statement=call_stmt, scope_name=self._get_current_scope_label())
        constraints.append(CallConstraint(
            callee=iter_method_var,
            args=(),
            kwargs=(),
            target=target_var,
            call_site=call_site
        ))
        
        return constraints
    
    def _translate_next(self, iterator_var: 'Variable', target_var: 'Variable') -> List['Constraint']:
        """Generate constraints for iterator next."""
        constraints = []
        
        next_method_var = self._make_variable(f"$next_{id(iterator_var)}")
        constraints.append(LoadConstraint(
            base=iterator_var,
            field=attr("__next__"),
            target=next_method_var
        ))
        
        call_stmt = IRCall(ast.parse(f"[{target_var}] = {iterator_var}.__next__()").body[0])
        call_site = CallSite(statement=call_stmt, scope_name=self._get_current_scope_label())
        constraints.append(CallConstraint(
            callee=next_method_var,
            args=(),
            kwargs=(),
            target=target_var,
            call_site=call_site
        ))
        
        return constraints
    
    def _translate_binary_op(
        self, 
        left_var: 'Variable', 
        right_var: 'Variable', 
        target_var: 'Variable',
        op: ast.operator
    ) -> List['Constraint']:
        constraints = []

        op_name = BINOP_TABLE.get(op, None)
        if not op_name:
            return constraints
        
        method_var = self._make_variable(f"${op_name}_{id(left_var)}")
        constraints.append(LoadConstraint(
            base=left_var,
            field=attr(op_name),
            target=method_var
        ))
        
        call_stmt = IRCall(ast.parse(f"[{target_var}] = {left_var}.{op_name}({right_var})").body[0])
        call_site = CallSite(statement=call_stmt, scope_name=self._get_current_scope_label())
        constraints.append(CallConstraint(
            callee=method_var,
            args=(right_var,),
            kwargs=(),
            target=target_var,
            call_site=call_site
        ))

        if (isinstance(self._current_scope, IRClass) and 
            not target_var.is_temporary): # only store the field to the class if it is not a temporary variable
            self.used_variables.append(target_var)
        
        return constraints

    def _translate_unary_op(
        self, 
        operand_var: 'Variable', 
        target_var: 'Variable',
        op: ast.unaryop
    ) -> List['Constraint']:
        constraints = []

        op_name = UNARYOP_TABLE.get(op, None)
        if not op_name:
            return constraints
        
        method_var = self._make_variable(f"${op_name}_{id(operand_var)}")
        constraints.append(LoadConstraint(
            base=operand_var,
            field=attr(op_name),
            target=method_var
        ))
        call_stmt = IRCall(ast.parse(f"[{target_var}] = {operand_var}.{op_name}()").body[0])
        call_site = CallSite(statement=call_stmt, scope_name=self._get_current_scope_label())
        constraints.append(CallConstraint(
            callee=method_var,
            args=(),
            kwargs=(),
            target=target_var,
            call_site=call_site
        ))

        if (isinstance(self._current_scope, IRClass) and 
            not target_var.is_temporary): # only store the field to the class if it is not a temporary variable
            self.used_variables.append(target_var)
        
        return constraints
