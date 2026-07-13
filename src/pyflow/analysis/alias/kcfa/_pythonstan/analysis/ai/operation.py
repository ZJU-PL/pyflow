from typing import Dict, Set, List, Optional, Tuple, Any, Union, DefaultDict
import ast

from pyflow.analysis.alias.kcfa._pythonstan.ir.ir_statements import (
    IRStatement, IRScope, IRFunc, IRClass, IRModule, Label, 
    AbstractIRAssign, IRAssign, IRStoreAttr, IRLoadAttr, IRCall,
    IRStoreSubscr, IRLoadSubscr, IRReturn, IRYield, IRAwait,
    IRDel, IRImport, IRAnno, IRRaise, IRPass, JumpIfTrue, JumpIfFalse,
    Goto, IRCatchException, IRPhi
)
from pyflow.analysis.alias.kcfa._pythonstan.ir.ir_visitor import IRVisitor
from pyflow.analysis.alias.kcfa._pythonstan.analysis.ai.value import (
    Value, Object, ObjectType, 
    ConstantObject, BuiltinObject, ClassObject, FunctionObject, InstanceObject,
    NumericProperty, StringProperty, ContainerProperty,
    create_int_value, create_float_value, create_str_value, create_bool_value,
    create_none_value, create_list_value, create_dict_value, create_set_value,
    create_tuple_value, create_function_value, create_class_value, create_instance_value,
    create_unknown_value
)
from pyflow.analysis.alias.kcfa._pythonstan.analysis.ai.state import (
    AbstractState, Context, ContextType, FlowSensitivity,
    Scope, MemoryModel, ClassHierarchy, CallGraph, ControlFlowState
)
from pyflow.analysis.alias.kcfa._pythonstan.analysis.ai.pointer_adapter import (
    PointerResults, FunctionSymbol, CallSite, AbstractObject, FieldKey,
    AttrFieldKey, ElemFieldKey, ValueFieldKey, UnknownFieldKey,
    MockCallSite
)
from pyflow.analysis.alias.kcfa._pythonstan.graph.call_graph.call_graph import AbstractCallGraph

class AbstractInterpreter(IRVisitor):
    """
    Interpreter for abstract interpretation of IR statements.
    This class implements the operations for each IR statement type.
    """
    
    def __init__(self, state: AbstractState, 
                 pointer: Optional[PointerResults] = None,
                 call_graph: Optional[AbstractCallGraph] = None,
                 solver = None):
        self.state = state
        self.pointer = pointer
        self.solver = solver
        self.external_call_graph = call_graph
        self.current_return_value: Optional[Value] = None
        self.raised_exception: Optional[Value] = None
        self.current_stmt_idx: Optional[int] = None
    
    def visit(self, ir: IRStatement, stmt_idx: int = None):
        """Visit an IR statement and perform the corresponding operation"""
        # Set current statement for control flow tracking
        self.current_stmt_idx = stmt_idx
        if stmt_idx is not None and self.state.control_flow.current_function:
            self.state.control_flow.set_current_stmt(stmt_idx)
        
        # Dispatch to specific visitor method based on statement type
        return IRVisitor.visit(self, ir)
    
    def visit_default(self, ir: IRStatement):
        """Default visitor method for statements without specific implementation"""
        # By default, add successors to worklist in flow-sensitive mode
        if self.current_stmt_idx is not None and self.state.flow_sensitivity == FlowSensitivity.SENSITIVE:
            fn_name = self.state.control_flow.current_function
            if fn_name:
                # Add next statement to worklist (sequential flow)
                next_stmt_idx = self.current_stmt_idx + 1
                self.state.control_flow.add_to_worklist(fn_name, next_stmt_idx)
        return None
    
    def visit_IRAssign(self, ir: IRAssign):
        """
        Perform abstract interpretation for variable assignment: lval = rval
        """
        # Get rvalue
        rval = None
        rval_name = None
        
        # Try to get rval using get_rval() method
        if hasattr(ir, 'get_rval'):
            rval_obj = ir.get_rval()
            if hasattr(rval_obj, 'id'):
                rval_name = rval_obj.id
        # Try to get rval directly from attribute
        elif hasattr(ir, 'rval'):
            rval_obj = ir.rval
            if hasattr(rval_obj, 'id'):
                rval_name = rval_obj.id
        
        # Get the value of rval
        if rval_name:
            rval = self.state.get_variable(rval_name)
        
        if rval is None:
            # Variable not found or not a simple name, use unknown value
            rval = create_unknown_value()
        
        # Get lvalue
        lval_name = None
        
        # Try to get lval using get_lval() method
        if hasattr(ir, 'get_lval'):
            lval_obj = ir.get_lval()
            if hasattr(lval_obj, 'id'):
                lval_name = lval_obj.id
        # Try to get lval directly from attribute
        elif hasattr(ir, 'lval'):
            lval_obj = ir.lval
            if hasattr(lval_obj, 'id'):
                lval_name = lval_obj.id
        
        if lval_name:
            # Check if we're in a flow-sensitive analysis where we might need merging
            fn_name = self.state.control_flow.current_function
            should_merge = False
            
            # First check: statement has been visited before (worklist-based analysis)
            if fn_name and self.state.control_flow.visit_count:
                key = (fn_name, self.current_stmt_idx)
                visit_count = self.state.control_flow.visit_count.get(key, 0)
                if visit_count > 0:
                    should_merge = True
            
            # Second check: for direct visit() calls (not worklist-based)
            # These typically represent manual test execution of different branches
            if not should_merge and self.state.flow_sensitivity.value > 0:
                existing = self.state.get_variable(lval_name)
                if existing is not None:
                    # Variable already has a value
                    # Check if we're in worklist-based analysis or direct visit calls
                    if hasattr(self, '_in_worklist_analysis') and self._in_worklist_analysis:
                        # In worklist analysis, be more conservative about merging
                        # Only merge at actual control flow merge points
                        current_stmt = self.current_stmt_idx
                        if current_stmt is not None and fn_name:
                            predecessors = self.state.control_flow.get_predecessors(fn_name, current_stmt)
                            should_merge = len(predecessors) > 1
                    else:
                        # For direct visit() calls, check if this is likely a post-merge strong update
                        # Strong update is appropriate if:
                        # 1. This statement has multiple predecessors (merge point), OR
                        # 2. This is an unconditional assignment after branching
                        current_stmt = self.current_stmt_idx
                        if current_stmt is not None and fn_name:
                            predecessors = self.state.control_flow.get_predecessors(fn_name, current_stmt)
                            # If statement has multiple predecessors, it's a merge point
                            # In this case, the assignment should dominate and use strong update
                            if len(predecessors) > 1:
                                should_merge = False  # Use strong update at merge points
                            else:
                                # Single predecessor: use weak update to preserve branch values
                                should_merge = True
                        else:
                            # Default to weak update when control flow info is unavailable
                            should_merge = True
            
            if should_merge:
                # Use weak update (merge with existing value) for flow sensitivity
                existing = self.state.get_variable(lval_name)
                if existing:
                    merged = existing.merge(rval)
                    self.state.set_variable(lval_name, merged)
                else:
                    self.state.set_variable(lval_name, rval)
            else:
                # Use pointer analysis for strong/weak update decision
                update_type = self._should_use_strong_update(lval_name)
                
                if update_type:
                    # Strong update: overwrite existing value
                    self.state.set_variable(lval_name, rval)
                else:
                    # Weak update: merge with existing value
                    existing = self.state.get_variable(lval_name)
                    if existing:
                        merged = existing.merge(rval)
                        self.state.set_variable(lval_name, merged)
                    else:
                        self.state.set_variable(lval_name, rval)
        
        # Continue with normal control flow
        return self.visit_default(ir)
    
    def visit_IRStoreAttr(self, ir: IRStoreAttr):
        """
        Perform abstract interpretation for attribute store: obj.attr = rval
        """
        # Get object
        obj_name = ir.get_obj().id
        obj_value = self.state.get_variable(obj_name)
        
        if obj_value is None:
            # Object not found, nothing to do
            return self.visit_default(ir)
        
        # Get rvalue
        rval_name = ir.get_rval().id
        rval = self.state.get_variable(rval_name)
        
        if rval is None:
            # Variable not found, use unknown value
            rval = create_unknown_value()
        
        # Set attribute on all objects in the value
        attr_name = ir.get_attr()
        
        # TODO: Use pointer analysis for precise attribute setting
        # For each object in obj_value, check if it's a singleton
        # If singleton, use strong update; otherwise weak update
        for obj in obj_value.objects:
            field_key = AttrFieldKey(attr_name)
            should_strong_update = self._should_use_strong_update_for_field(obj, field_key)
            
            if should_strong_update:
                # Strong update: overwrite attribute
                obj.set_attr(attr_name, rval)
            else:
                # Weak update: merge with existing attribute value
                existing_attr = obj.get_attr(attr_name)
                if existing_attr and existing_attr.objects:
                    merged = existing_attr.merge(rval)
                    obj.set_attr(attr_name, merged)
                else:
                    obj.set_attr(attr_name, rval)
        
        # Continue with normal control flow
        return self.visit_default(ir)
    
    def visit_IRLoadAttr(self, ir: IRLoadAttr):
        """
        Perform abstract interpretation for attribute load: lval = obj.attr
        """
        # Get object
        obj_name = ir.get_obj().id
        obj_value = self.state.get_variable(obj_name)
        
        if obj_value is None:
            # Object not found, use unknown value for result
            result = create_unknown_value()
        else:
            # Get attribute from object
            attr_name = ir.get_attr()
            
            # TODO: Use pointer analysis for precise attribute resolution
            # For each object, query field_points_to(obj, AttrFieldKey(attr_name))
            result = self._resolve_attribute_with_pointer(obj_value, attr_name)
            
            # If attribute not found, use unknown value
            if not result or not result.objects:
                result = create_unknown_value()
        
        # Set lvalue
        lval_name = ir.get_lval().id
        self.state.set_variable(lval_name, result)
        
        # Continue with normal control flow
        return self.visit_default(ir)
    
    def visit_IRStoreSubscr(self, ir: IRStoreSubscr):
        """
        Perform abstract interpretation for subscript store: obj[slice] = rval
        """
        # Get object
        obj_name = ir.get_obj().id
        obj_value = self.state.get_variable(obj_name)
        
        if obj_value is None:
            # Object not found, nothing to do
            return self.visit_default(ir)
        
        # Get rvalue
        rval_name = ir.get_rval().id
        rval = self.state.get_variable(rval_name)
        
        if rval is None:
            # Variable not found, use unknown value
            rval = create_unknown_value()
        
        # Update container properties for all container objects
        for obj in obj_value.objects:
            if isinstance(obj, BuiltinObject) and obj.builtin_type in (list, dict, set):
                # Add element type information
                for robj in rval.objects:
                    obj.container_property.element_types.add(robj.obj_type)
                
                # Update element values by merging
                obj.container_property.element_values = obj.container_property.element_values.merge(rval)
                
                # Container size may have increased if it's not a reassignment
                # Conservatively assume it might grow
                obj.container_property.min_size = max(1, obj.container_property.min_size)
                if obj.container_property.max_size is not None:
                    obj.container_property.max_size += 1
        
        # Continue with normal control flow
        return self.visit_default(ir)
    
    def visit_IRLoadSubscr(self, ir: IRLoadSubscr):
        """
        Perform abstract interpretation for subscript load: lval = obj[slice]
        """
        # Get object
        obj_name = ir.get_obj().id
        obj_value = self.state.get_variable(obj_name)
        
        if obj_value is None:
            # Object not found, use unknown value for result
            result = create_unknown_value()
        else:
            # Get element values from containers
            result = create_unknown_value()
            
            for obj in obj_value.objects:
                if isinstance(obj, BuiltinObject):
                    # Use the container's element values as result
                    result = result.merge(obj.container_property.element_values)
            
            # If no container elements found, use unknown value
            if not result.objects:
                result = create_unknown_value()
        
        # Set lvalue
        lval_name = ir.get_lval().id
        self.state.set_variable(lval_name, result)
        
        # Continue with normal control flow
        return self.visit_default(ir)
    
    def visit_IRCall(self, ir: IRCall):
        """
        Perform abstract interpretation for function call: [target =] func_name(args, keywords)
        """
        # Get function
        func_name = ir.get_func_name()
        target = ir.get_target() if hasattr(ir, 'get_target') else None

        func_value = self.state.get_variable(func_name)
        
        # Get arguments
        args = []
        for arg_name, is_starred in ir.get_args():
            if arg_name.startswith("<Constant:"):
                # Handle constant arguments
                const_str = arg_name[len("<Constant: "):-1]
                try:
                    # Try to parse as int, float, or string
                    if const_str.isdigit():
                        arg_value = create_int_value(int(const_str))
                    elif const_str.replace('.', '', 1).isdigit():
                        arg_value = create_float_value(float(const_str))
                    else:
                        # Remove quotes if it's a string
                        if (const_str.startswith('"') and const_str.endswith('"')) or \
                           (const_str.startswith("'") and const_str.endswith("'")):
                            const_str = const_str[1:-1]
                        arg_value = create_str_value(const_str)
                except:
                    arg_value = create_unknown_value()
            else:
                # Regular variable
                arg_value = self.state.get_variable(arg_name)
                if arg_value is None:
                    arg_value = create_unknown_value()
            
            args.append(arg_value)
        
        # Get keywords
        keywords = {}
        for kw_name, kw_value_name in ir.get_keywords():
            kw_value = self.state.get_variable(kw_value_name)
            if kw_value is None:
                kw_value = create_unknown_value()
            
            if kw_name is not None:
                keywords[kw_name] = kw_value
            else:
                # **kwargs expansion - not precisely modeled in abstract interpretation
                pass
        
        # Determine result value based on function type
        result = create_unknown_value()
        
        if func_name == 'len' and len(args) == 1:
            result = self._handle_len_function(args[0])
        elif func_name == 'isinstance' and len(args) == 2:
            result = create_bool_value()  # Could be True or False
        elif func_name == 'int' and len(args) >= 1:
            result = self._handle_int_function(args[0])
        elif func_name == 'str' and len(args) >= 1:
            result = create_str_value()
        elif func_name == 'list' and len(args) <= 1:
            result = self._handle_list_function(args[0] if args else None)
        elif func_name == 'dict' and len(args) <= 1:
            result = create_dict_value()
        elif func_name == 'set' and len(args) <= 1:
            result = create_set_value()
        elif func_name == 'tuple' and len(args) <= 1:
            result = create_tuple_value()
        elif func_name == 'bool' and len(args) >= 1:
            result = create_bool_value()
        elif func_name == 'sum' and len(args) >= 1:
            result = create_int_value() # Could be int or float depending on input
        elif func_value and func_value.objects:
            # We have information about the function
            for obj in func_value.objects:
                if isinstance(obj, FunctionObject):
                    # Register the call in the call graph
                    fn_qualname = self.state.control_flow.current_function
                    if fn_qualname:
                        self.state.register_call(
                            fn_qualname, 
                            obj.qualname, 
                            ir, 
                            self.current_stmt_idx,
                            self.state.current_context
                        )
                    
                    # For simple cases, try to get the return value immediately
                    # This is a simplified approach for direct function calls
                    if hasattr(self, 'solver') and self.solver is not None:
                        # Try both short name and full qualified name
                        func_qualname = None
                        if obj.qualname in self.solver.func_statements:
                            func_qualname = obj.qualname
                        else:
                            # Try to find by partial match (function name might not include module prefix)
                            for key in self.solver.func_statements.keys():
                                if key.endswith('.' + obj.qualname) or key == obj.qualname:
                                    func_qualname = key
                                    break
                        
                        if func_qualname:
                            print(f"[DEBUG] Executing simple call: {func_qualname} with args: {args}")
                            result = self._perform_simple_function_call_by_qualname(func_qualname, args, keywords)
                            print(f"[DEBUG] Call result: {result}")
                            break
                        else:
                            print(f"[DEBUG] No matching function found for {obj.qualname} in {list(self.solver.func_statements.keys())}")
        
        # TODO: Use pointer analysis for indirect call resolution
        if func_name and self.pointer:
            # Create call site for pointer analysis
            call_site = self._create_call_site_for_ir(ir)
            possible_callees = self._lookup_callees_with_pointer(call_site, self.state.current_context)
            
            # Filter callees based on AI type constraints and update result
            if possible_callees:
                # Use pointer analysis results to refine call targets
                result = self._handle_indirect_call_with_pointer(possible_callees, args, keywords)
            else:
                # Fallback to conservative approximation
                pass
        
        # Set target if there is one
        target = ir.get_target()
        if target:
            self.state.set_variable(target, result)
        
        # Continue with normal control flow
        return self.visit_default(ir)
    
    def _perform_simple_function_call_by_qualname(self, func_qualname: str, args: List[Value], keywords: Dict[str, Value]) -> Value:
        """
        Perform a simple function call immediately (for direct calls without complex control flow).
        This is a simplified approach that doesn't use full interprocedural analysis.
        """
        try:
            # Get function statements
            if not hasattr(self, 'solver') or self.solver is None or func_qualname not in self.solver.func_statements:
                return create_unknown_value()
            
            func_statements = self.solver.func_statements[func_qualname]
            
            # Save current state
            old_context = self.state.current_context
            old_return_value = self.current_return_value
            old_stmt_idx = self.current_stmt_idx
            old_function = self.state.control_flow.current_function
            
            # Save current variable state that might be overwritten
            old_variables = {}
            
            # Get function object to extract parameters
            func_obj = None
            func_value = self.state.get_variable(func_qualname.split('.')[-1])  # Get function from state
            if func_value:
                for obj in func_value.objects:
                    if isinstance(obj, FunctionObject):
                        func_obj = obj
                        break
            
            # Map arguments to parameters
            func_params = []
            if func_obj and func_obj.ir_func:
                # Parse stmt.args directly - this seems to be the most reliable way
                if hasattr(func_obj.ir_func, 'stmt'):
                    func_ast = func_obj.ir_func.stmt
                    if hasattr(func_ast, 'args') and hasattr(func_ast.args, 'args'):
                        func_params = [arg.arg for arg in func_ast.args.args]
                # Alternative: use args attribute directly
                elif hasattr(func_obj.ir_func, 'args'):
                    if hasattr(func_obj.ir_func.args, 'args'):
                        func_params = [arg.arg for arg in func_obj.ir_func.args.args]
            
            # Save old values of parameters that might be overwritten
            for param_name in func_params:
                old_variables[param_name] = self.state.get_variable(param_name)
            
            # Create new context for function call
            new_context = self.state.create_context(self.current_stmt_idx)
            self.state.set_current_context(new_context)
            
            # Set up function context for the called function
            self.state.control_flow.set_current_function(func_qualname)
            
            # Set parameter values in the new context
            for i, param_name in enumerate(func_params):
                if i < len(args):
                    self.state.set_variable(param_name, args[i])
                else:
                    self.state.set_variable(param_name, create_none_value())
            
            # Execute function body
            self.current_return_value = None
            for i, stmt in enumerate(func_statements):
                # Set the correct statement index and function context
                self.current_stmt_idx = i
                self.state.control_flow.set_current_stmt(i)
                # Visit without calling visit() which might set current_stmt_idx
                IRVisitor.visit(self, stmt)
                
                # If we hit a return statement, break
                if self.current_return_value is not None:
                    break
            
            # Get return value
            result = self.current_return_value if self.current_return_value is not None else create_none_value()
            
            # Restore state
            self.state.set_current_context(old_context)
            self.current_return_value = old_return_value
            self.current_stmt_idx = old_stmt_idx
            self.state.control_flow.set_current_function(old_function)
            if old_stmt_idx is not None:
                self.state.control_flow.set_current_stmt(old_stmt_idx)
            
            # Restore old variable values
            for param_name, old_value in old_variables.items():
                if old_value is not None:
                    self.state.set_variable(param_name, old_value)
                # If old_value was None, we might want to remove the variable
                # but for simplicity, we'll leave it as is
            
            return result
            
        except Exception as e:
            # If anything goes wrong, return unknown value
            return create_unknown_value()
    
    def _handle_len_function(self, arg: Value) -> Value:
        """Special handling for len() function"""
        result_obj = ConstantObject(int)
        
        # Update numeric property based on container properties
        min_len = 0
        max_len = None
        
        for obj in arg.objects:
            if isinstance(obj, BuiltinObject):
                # Get container property
                container_prop = obj.container_property
                min_len = max(min_len, container_prop.min_size)
                
                if max_len is not None and container_prop.max_size is not None:
                    max_len = max(max_len, container_prop.max_size)
                elif container_prop.max_size is not None:
                    max_len = container_prop.max_size
            elif isinstance(obj, ConstantObject) and obj.const_type == str:
                # Handle string length
                string_prop = obj.string_property
                min_len = max(min_len, string_prop.min_length)
                
                if max_len is not None and string_prop.max_length is not None:
                    max_len = max(max_len, string_prop.max_length)
                elif string_prop.max_length is not None:
                    max_len = string_prop.max_length
        
        # Update numeric property
        result_obj.numeric_property.lower_bound = min_len
        if max_len is not None:
            result_obj.numeric_property.upper_bound = max_len
        
        # Length can't be negative
        result_obj.numeric_property.may_be_negative = False
        
        # Length can be zero only if min_len is 0
        result_obj.numeric_property.may_be_zero = (min_len == 0)
        
        # Length is always positive unless it's zero
        result_obj.numeric_property.may_be_positive = True
        
        return Value({result_obj})
    
    def _handle_int_function(self, arg: Value) -> Value:
        """Special handling for int() function"""
        result_obj = ConstantObject(int)
        
        # Check if we can determine more precise bounds
        for obj in arg.objects:
            if isinstance(obj, ConstantObject):
                if obj.const_type == int:
                    # int(integer) returns the same integer
                    result_obj.numeric_property = obj.numeric_property
                elif obj.const_type == float:
                    # int(float) truncates towards zero
                    if obj.numeric_property.lower_bound > 0:
                        result_obj.numeric_property.lower_bound = int(obj.numeric_property.lower_bound)
                        result_obj.numeric_property.upper_bound = int(obj.numeric_property.upper_bound)
                    elif obj.numeric_property.upper_bound < 0:
                        result_obj.numeric_property.lower_bound = int(obj.numeric_property.lower_bound)
                        result_obj.numeric_property.upper_bound = int(obj.numeric_property.upper_bound)
                    else:
                        # Could truncate to 0 if the float is between -1 and 1
                        result_obj.numeric_property.may_be_zero = True
                elif obj.const_type == str:
                    # int(string) is hard to determine statically
                    # If we have exact string values, we could try to parse them
                    if obj.string_property.exact_values:
                        exact_ints = set()
                        for s in obj.string_property.exact_values:
                            try:
                                exact_ints.add(int(s))
                            except:
                                pass
                        if exact_ints:
                            result_obj.numeric_property.exact_values = exact_ints
                    
                    # Otherwise, just use default int properties
        
        return Value({result_obj})
    
    def _handle_list_function(self, arg: Optional[Value]) -> Value:
        """Special handling for list() function"""
        result_obj = BuiltinObject(list)
        
        if arg:
            # list(iterable) - copy elements from iterable
            for obj in arg.objects:
                if isinstance(obj, BuiltinObject):
                    # Copy container properties
                    result_obj.container_property = obj.container_property
                    break
        
        return Value({result_obj})
    
    def visit_IRReturn(self, ir: IRReturn):
        """
        Perform abstract interpretation for return statement: return [value]
        """
        # Get return value if any
        value = None
        if hasattr(ir, 'get_value'):
            value = ir.get_value()
        elif hasattr(ir, 'value'):
            value = ir.value
            
        if value:
            # If value is a Name, get the variable value
            if isinstance(value, ast.Name):
                value_name = value.id
                value_obj = self.state.get_variable(value_name)
                if value_obj:
                    self.current_return_value = value_obj
                else:
                    self.current_return_value = create_unknown_value()
            # If value is a constant, create a constant value
            elif isinstance(value, ast.Constant):
                const_val = value.value
                if isinstance(const_val, int):
                    self.current_return_value = create_int_value(const_val)
                elif isinstance(const_val, float):
                    self.current_return_value = create_float_value(const_val)
                elif isinstance(const_val, str):
                    self.current_return_value = create_str_value(const_val)
                elif isinstance(const_val, bool):
                    self.current_return_value = create_bool_value(const_val)
                elif const_val is None:
                    self.current_return_value = create_none_value()
                else:
                    self.current_return_value = create_unknown_value()
            else:
                # For other expressions, use unknown value
                self.current_return_value = create_unknown_value()
        else:
            # Return None
            self.current_return_value = create_none_value()
        
        # In a flow-sensitive analysis, we would not continue to successor statements
        # But for now, we'll just continue with normal control flow
        return self.visit_default(ir)
    
    def visit_IRRaise(self, ir: IRRaise):
        """
        Perform abstract interpretation for raise statement: raise exc [from cause]
        """
        # Get exception
        exc = ir.exc
        if exc and isinstance(exc, ast.Name):
            exc_name = exc.id
            exc_value = self.state.get_variable(exc_name)
            if exc_value:
                self.raised_exception = exc_value
            else:
                self.raised_exception = create_unknown_value()
        else:
            self.raised_exception = create_unknown_value()
        
        # In a flow-sensitive analysis, we would transfer control to exception handler
        # But for now, we'll just continue with normal control flow
        return self.visit_default(ir)
    
    def visit_IRCatchException(self, ir: IRCatchException):
        """
        Perform abstract interpretation for exception handler: catch exp from L1 to L2 goto L3
        """
        # Get labels
        from_label = ir.from_label
        to_label = ir.to_label
        goto_label = ir.goto_label
        
        # In a flow-sensitive analysis, we would:
        # 1. If an exception was raised in the try block, transfer control to the handler
        # 2. If no exception was raised, continue with normal control flow
        # But for now, we'll just continue with normal control flow
        return self.visit_default(ir)
    
    def visit_JumpIfTrue(self, ir: JumpIfTrue):
        """
        Perform abstract interpretation for conditional jump: if test goto label
        """
        # Get test expression
        test = ir.test
        
        # Evaluate test expression (simplified)
        test_result = None
        if isinstance(test, ast.Name):
            test_name = test.id
            test_value = self.state.get_variable(test_name)
            if test_value:
                # Check if test is definitely True or False
                test_result = self._evaluate_boolean_value(test_value)
        
        # Get label
        label = ir.label
        
        # In a flow-sensitive analysis:
        fn_name = self.state.control_flow.current_function
        if fn_name:
            # Save current state before branching
            self._save_current_state(fn_name, self.current_stmt_idx)
            
            # Add both branches to worklist (we don't know which will be taken)
            
            # Add target of jump (taken branch)
            label_idx = self.state.control_flow.get_label_idx(fn_name, label.idx)
            if label_idx is not None:
                self.state.control_flow.add_to_worklist(fn_name, label_idx)
            
            # Add next statement (not taken branch)
            self.state.control_flow.add_to_worklist(fn_name, self.current_stmt_idx + 1)
        
        # No return value needed
        return None
    
    def visit_JumpIfFalse(self, ir: JumpIfFalse):
        """
        Perform abstract interpretation for conditional jump: if not test goto label
        """
        # Get test expression
        test = ir.test
        
        # Evaluate test expression
        test_result = None
        if isinstance(test, ast.Name):
            test_name = test.id
            test_value = self.state.get_variable(test_name)
            if test_value:
                # Check if test is definitely True or False
                test_result = self._evaluate_boolean_value(test_value)
        elif isinstance(test, ast.Compare):
            # Handle comparison expressions like a > 10
            test_result = self._evaluate_comparison(test)
        
        # Get label
        label = ir.label
        
        # In a flow-sensitive analysis:
        fn_name = self.state.control_flow.current_function
        if fn_name:
            # Determine which branches to follow based on test result
            if test_result is True:
                # Test is definitely True, so JumpIfFalse will NOT jump
                # Continue to next statement only
                self.state.control_flow.add_to_worklist(fn_name, self.current_stmt_idx + 1)
            elif test_result is False:
                # Test is definitely False, so JumpIfFalse WILL jump
                # Jump to target label only
                label_idx = self.state.control_flow.get_label_idx(fn_name, label.idx)
                if label_idx is not None:
                    self.state.control_flow.add_to_worklist(fn_name, label_idx)
            else:
                # Test result is unknown, must consider both branches
                # Save current state before branching - this will be used at merge points
                self._save_state_for_branch(fn_name, self.current_stmt_idx)
                
                # Add target of jump (taken branch)
                label_idx = self.state.control_flow.get_label_idx(fn_name, label.idx)
                if label_idx is not None:
                    self.state.control_flow.add_to_worklist(fn_name, label_idx)
                
                # Add next statement (not taken branch)
                self.state.control_flow.add_to_worklist(fn_name, self.current_stmt_idx + 1)
        
        # No return value needed
        return None
    
    def visit_Goto(self, ir: Goto):
        """
        Perform abstract interpretation for unconditional jump: goto label
        """
        # Get label
        label = ir.label
        
        # In a flow-sensitive analysis:
        fn_name = self.state.control_flow.current_function
        if fn_name and label:
            # Add target of jump to worklist
            label_idx = self.state.control_flow.get_label_idx(fn_name, label.idx)
            if label_idx is not None:
                self.state.control_flow.add_to_worklist(fn_name, label_idx)
        
        # No return value needed
        return None
    
    def visit_Label(self, ir: Label):
        """
        Perform abstract interpretation for label: label_idx:
        """
        # Register label in control flow state
        fn_name = self.state.control_flow.current_function
        if fn_name:
            self.state.control_flow.register_label(fn_name, ir, self.current_stmt_idx)
            
            # Check if this is a merge point (multiple predecessors)
            predecessors = self.state.control_flow.get_predecessors(fn_name, self.current_stmt_idx)
            if len(predecessors) > 1:
                # This is a merge point - need to merge states from different branches
                self._handle_merge_point(fn_name, self.current_stmt_idx)
        
        # Continue with normal control flow
        return self.visit_default(ir)
    
    def visit_IRDel(self, ir: IRDel):
        """
        Perform abstract interpretation for delete statement: del value
        """
        # In abstract interpretation, we don't actually delete variables
        # We just mark them as potentially undefined
        
        # Get variable name
        value = ir.value
        if isinstance(value, ast.Name):
            var_name = value.id
            # We could set the variable to a special "undefined" value
            # But for now, we'll just leave it as is
        
        # Continue with normal control flow
        return self.visit_default(ir)
    
    def visit_IRImport(self, ir: IRImport):
        """
        Perform abstract interpretation for import statement: import [module.]name as [asname]
        """
        # Get import information
        module = ir.module
        name = ir.name
        asname = ir.asname if ir.asname else name
        
        # In abstract interpretation, we create an unknown value for imports
        # A more precise analysis would resolve imports and use actual types
        import_value = create_unknown_value()
        
        # Set imported name in current scope
        self.state.set_variable(asname, import_value)
        
        # Continue with normal control flow
        return self.visit_default(ir)
    
    def visit_IRAnno(self, ir: IRAnno):
        """
        Perform abstract interpretation for type annotation: target: anno
        """
        # Type annotations don't affect runtime behavior
        # So we don't need to do anything in abstract interpretation
        
        # Continue with normal control flow
        return self.visit_default(ir)
    
    def visit_IRYield(self, ir: IRYield):
        """
        Perform abstract interpretation for yield statement: [target =] yield value
        """
        # Get yield value if any
        result = create_unknown_value()
        if ir.value:
            value_name = ir.value.id
            value_obj = self.state.get_variable(value_name)
            if value_obj:
                # For yield, the result depends on what's sent to the generator
                # For yield from, the result is whatever the sub-generator yields
                if ir.is_yield_from():
                    # For yield from, the result can be any value yielded from the sub-generator
                    # For simplicity, we use an unknown value
                    result = create_unknown_value()
                else:
                    # For regular yield, the result is whatever is sent back to the generator
                    # For simplicity, we use an unknown value
                    result = create_unknown_value()
            else:
                result = create_unknown_value()
        
        # Set target if there is one
        target = ir.target
        if target and isinstance(target, ast.Name):
            target_name = target.id
            self.state.set_variable(target_name, result)
        
        # Continue with normal control flow
        return self.visit_default(ir)
    
    def visit_IRAwait(self, ir: IRAwait):
        """
        Perform abstract interpretation for await statement: [target =] await value
        """
        # Get await value
        result = create_unknown_value()
        value = ir.get_value()
        if isinstance(value, ast.Name):
            value_name = value.id
            value_obj = self.state.get_variable(value_name)
            if value_obj:
                # For await, the result is the resolved value of the awaitable
                # For simplicity, we use an unknown value
                result = create_unknown_value()
            else:
                result = create_unknown_value()
        
        # Set target if there is one
        target = ir.get_target()
        if target:
            target_name = target.id
            self.state.set_variable(target_name, result)
        
        # Continue with normal control flow
        return self.visit_default(ir)
    
    def visit_IRPass(self, ir: IRPass):
        """
        Perform abstract interpretation for pass statement: pass
        """
        # Pass does nothing
        # Continue with normal control flow
        return self.visit_default(ir)
    
    def visit_IRPhi(self, ir: IRPhi):
        """
        Perform abstract interpretation for phi node: lval = Phi(items)
        """
        # Get phi items
        items = ir.get_items()
        
        # Merge values from all items
        result = create_unknown_value()
        for item in items:
            if item:
                item_name = item.id
                item_value = self.state.get_variable(item_name)
                if item_value:
                    result = result.merge(item_value)
        
        # Set lvalue
        lval_name = ir.get_lval().id
        self.state.set_variable(lval_name, result)
        
        # Continue with normal control flow
        return self.visit_default(ir)
    
    def visit_IRFunc(self, ir: IRFunc):
        """
        Perform abstract interpretation for function definition: def name(...): ...
        """
        # Create function object
        func_obj = FunctionObject(ir)
        func_value = create_function_value(ir)
        
        # Set function in current scope
        self.state.set_variable(ir.name, func_value)
        
        # Continue with normal control flow
        return self.visit_default(ir)
    
    def visit_IRClass(self, ir: IRClass):
        """
        Perform abstract interpretation for class definition: class name(...): ...
        """
        # Register class in class hierarchy
        class_obj = self.state.register_class(ir)
        class_value = create_class_value(ir)
        
        # Set class in current scope
        self.state.set_variable(ir.name, class_value)
        
        # Continue with normal control flow
        return self.visit_default(ir)
    
    def visit_IRModule(self, ir: IRModule):
        """
        Perform abstract interpretation for module: module name
        """
        # Initialize state for module
        self.state.initialize_for_module(ir)
        
        # Continue with normal control flow
        return self.visit_default(ir)
    
    def _evaluate_boolean_value(self, value: Value) -> Optional[bool]:
        """
        Evaluate if a value is definitely True or definitely False.
        Returns True if definitely True, False if definitely False, None if unknown.
        """
        # Check for definite True/False values
        definitely_true = False
        definitely_false = False
        
        for obj in value.objects:
            if isinstance(obj, ConstantObject):
                if obj.const_type == bool:
                    if hasattr(obj, 'bool_value'):
                        if obj.bool_value is True:
                            definitely_true = True
                        elif obj.bool_value is False:
                            definitely_false = True
                elif obj.const_type == int:
                    # Check if number is definitely zero or definitely non-zero
                    if not obj.numeric_property.may_be_zero and (
                        obj.numeric_property.may_be_positive or obj.numeric_property.may_be_negative):
                        definitely_true = True
                    elif (not obj.numeric_property.may_be_positive and 
                          not obj.numeric_property.may_be_negative and 
                          obj.numeric_property.may_be_zero):
                        definitely_false = True
                elif obj.const_type == str:
                    # Check if string is definitely empty or definitely non-empty
                    if obj.string_property.min_length > 0:
                        definitely_true = True
                    elif obj.string_property.max_length == 0:
                        definitely_false = True
                elif obj.const_type == type(None):
                    # None is always False
                    definitely_false = True
            elif isinstance(obj, BuiltinObject):
                # Check if container is definitely empty or definitely non-empty
                if obj.container_property.min_size > 0:
                    definitely_true = True
                elif obj.container_property.max_size == 0:
                    definitely_false = True
        
        # If we have conflicting information, return None (unknown)
        if definitely_true and definitely_false:
            return None
        elif definitely_true:
            return True
        elif definitely_false:
            return False
        else:
            return None
    
    def _evaluate_comparison(self, compare: ast.Compare) -> Optional[bool]:
        """
        Evaluate a comparison expression like a > 10.
        Returns True if definitely True, False if definitely False, None if unknown.
        """
        # Simplify: only handle single comparison for now (not chained comparisons)
        if len(compare.ops) != 1 or len(compare.comparators) != 1:
            return None
        
        left = compare.left
        op = compare.ops[0]
        right = compare.comparators[0]
        
        # Get left value
        left_value = None
        if isinstance(left, ast.Name):
            left_value = self.state.get_variable(left.id)
        
        # Get right value  
        right_value = None
        if isinstance(right, ast.Name):
            right_value = self.state.get_variable(right.id)
        elif isinstance(right, ast.Num):
            # Create a constant value for the number
            right_value = create_int_value(right.n)
        
        # If we can't get both values, return unknown
        if not left_value or not right_value:
            return None
        
        # Try to get numeric values from both sides
        left_num = self._get_definite_numeric_value(left_value)
        right_num = self._get_definite_numeric_value(right_value)
        
        # If we can't get definite numeric values, return unknown
        if left_num is None or right_num is None:
            return None
        
        # Perform the comparison
        if isinstance(op, ast.Gt):
            return left_num > right_num
        elif isinstance(op, ast.GtE):
            return left_num >= right_num
        elif isinstance(op, ast.Lt):
            return left_num < right_num
        elif isinstance(op, ast.LtE):
            return left_num <= right_num
        elif isinstance(op, ast.Eq):
            return left_num == right_num
        elif isinstance(op, ast.NotEq):
            return left_num != right_num
        else:
            return None
    
    def _get_definite_numeric_value(self, value: Value) -> Optional[float]:
        """
        Get a definite numeric value from a Value, or None if not definite.
        """
        for obj in value.objects:
            if isinstance(obj, ConstantObject) and obj.const_type in (int, float):
                # Check if this is a definite constant value
                if (obj.numeric_property.lower_bound == obj.numeric_property.upper_bound and
                    obj.numeric_property.lower_bound is not None):
                    return obj.numeric_property.lower_bound
        return None
    
    # TODO: Pointer analysis integration hooks
    # These methods will be implemented in Session AI-3/AI-4 with actual pointer analysis logic
    
    def _should_use_strong_update(self, var_name: str) -> bool:
        """
        Determine if a strong update should be used for a variable assignment.
        
        Strong update is safe when the target variable points to exactly one abstract object.
        This gives better precision by overwriting rather than merging values.
        
        Args:
            var_name: Variable name being assigned
            
        Returns:
            True if strong update should be used, False for weak update
        """
        if self.pointer and self.state.current_context:
            # Use pointer analysis to check if variable is singleton
            try:
                context = self._get_current_context_for_pointer()
                return self.pointer.is_singleton(var_name, context)
            except Exception:
                # If pointer analysis fails, fall back to conservative choice
                pass
        
        # Conservative fallback: use strong updates for local variables, weak for globals/fields
        # For local variables in the current scope, strong updates are safe and provide better precision
        # For global variables or complex aliases, use weak updates for soundness
        
        # Check if this is a local variable in the current scope
        current_scope = self.state.memory.current_scope
        current_scope_name = current_scope.get_qualname() if current_scope else None
        
        if current_scope_name and self.state.memory.is_local_variable(var_name, current_scope_name):
            # Local variables can safely use strong updates
            return True
        
        # For global variables or when scope is unclear, use weak updates for soundness
        return False
    
    def _should_use_strong_update_for_field(self, obj: Object, field: FieldKey) -> bool:
        """
        Determine if a strong update should be used for a field assignment.
        
        Strong update is safe when:
        1. The object is a singleton (points-to set has size 1)
        2. The field is uniquely identified
        
        Args:
            obj: Object containing the field
            field: Field being assigned
            
        Returns:
            True if strong update should be used, False for weak update
        """
        if self.pointer and hasattr(obj, 'alloc_id'):
            try:
                # Convert to MockAbstractObject if needed for compatibility
                abstract_obj = self._convert_to_abstract_object(obj)
                if abstract_obj:
                    # Check if this object is singleton in its points-to set
                    # This is conservative - we could also check field uniqueness
                    context = self._get_current_context_for_pointer()
                    return self.pointer.is_singleton(abstract_obj, context)
            except Exception:
                # If pointer analysis fails, fall back to conservative choice
                pass
        
        # Conservative fallback: always use weak updates for soundness
        return False
    
    def _resolve_attribute_with_pointer(self, obj_value: Value, attr_name: str) -> Value:
        """
        Resolve attribute access using pointer analysis results.
        
        For each object in obj_value, queries the pointer analysis for field_points_to
        to get precise attribute values, then aggregates the results.
        
        Args:
            obj_value: Value containing objects to get attribute from
            attr_name: Name of attribute to resolve
            
        Returns:
            Value representing possible attribute values
        """
        if self.pointer:
            try:
                # Collect all possible attribute values from pointer analysis
                attr_objects = []
                field_key = AttrFieldKey(attr_name)
                
                for obj in obj_value.objects:
                    abstract_obj = self._convert_to_abstract_object(obj)
                    if abstract_obj:
                        # Query pointer analysis for field values
                        field_pts = self.pointer.field_points_to(abstract_obj, field_key)
                        if field_pts and len(field_pts) > 0:
                            # Convert back to AI objects
                            for pts_obj in field_pts:
                                ai_obj = self._convert_from_abstract_object(pts_obj)
                                if ai_obj:
                                    attr_objects.append(ai_obj)
                
                if attr_objects:
                    # Create combined value from all attribute objects
                    from pyflow.analysis.alias.kcfa._pythonstan.analysis.ai.value import Value
                    return Value(attr_objects)
            except Exception:
                # If pointer analysis fails, fall back to standard resolution
                pass
        
        # Fallback to standard attribute resolution
        return obj_value.get_attribute(attr_name)
    
    def _create_call_site_for_ir(self, ir: IRCall) -> CallSite:
        """
        Create a CallSite object from an IR call statement.
        
        Args:
            ir: IR call statement
            
        Returns:
            CallSite object for pointer analysis queries
        """
        # TODO: Extract actual source location from IR
        # For now, create a mock call site
        site_id = f"call_{self.current_stmt_idx}_{id(ir)}"
        filename = "unknown.py"
        line = self.current_stmt_idx or 0
        col = 0
        
        return MockCallSite(site_id, filename, line, col)
    
    # Helper methods for pointer analysis integration
    
    def _get_current_context_for_pointer(self) -> Optional[Context]:
        """
        Get current AI context in format compatible with pointer analysis.
        
        Returns:
            Context object for pointer analysis, or None if not available
        """
        if self.state.current_context:
            # Convert AI context to pointer analysis context format
            from pyflow.analysis.alias.kcfa._pythonstan.analysis.ai.pointer_adapter import MockContext
            return MockContext(call_string=())  # Simplified for now
        return None
    
    def _convert_to_abstract_object(self, obj: Object) -> Optional[AbstractObject]:
        """
        Convert AI Object to AbstractObject for pointer analysis queries.
        
        Args:
            obj: AI Object instance
            
        Returns:
            AbstractObject compatible with pointer analysis, or None
        """
        if hasattr(obj, 'alloc_id'):
            from pyflow.analysis.alias.kcfa._pythonstan.analysis.ai.pointer_adapter import MockAbstractObject
            return MockAbstractObject(obj.alloc_id)
        elif hasattr(obj, 'obj_type'):
            # Create synthetic alloc_id based on object type and properties
            alloc_id = f"{obj.obj_type.name}_{id(obj)}"
            from pyflow.analysis.alias.kcfa._pythonstan.analysis.ai.pointer_adapter import MockAbstractObject
            return MockAbstractObject(alloc_id)
        return None
    
    def _convert_from_abstract_object(self, abstract_obj: AbstractObject) -> Optional[Object]:
        """
        Convert AbstractObject back to AI Object.
        
        Args:
            abstract_obj: AbstractObject from pointer analysis
            
        Returns:
            AI Object instance, or None if conversion fails
        """
        # For now, create unknown object
        # In real implementation, this would use object registry
        from pyflow.analysis.alias.kcfa._pythonstan.analysis.ai.value import UnknownObject
        return UnknownObject()
    
    def _lookup_callees_with_pointer(self, call_site: CallSite, ctx: Optional[Context]) -> Set[FunctionSymbol]:
        """
        Lookup possible callees for an indirect call using pointer analysis.
        
        Args:
            call_site: Call site to analyze
            ctx: Analysis context
            
        Returns:
            Set of possible function targets
        """
        if self.pointer:
            try:
                # Convert AI context to pointer analysis context
                pointer_ctx = self._get_current_context_for_pointer()
                return self.pointer.possible_callees(call_site, pointer_ctx)
            except Exception:
                # If pointer analysis fails, return empty set
                pass
        
        # Conservative fallback: empty set (no precision)
        return set()
    
    def _handle_indirect_call_with_pointer(self, callees: Set[FunctionSymbol], 
                                          args: List[Value], keywords: Dict[str, Value]) -> Value:
        """
        Handle indirect call using pointer analysis results.
        
        Intersects pointer analysis callees with AI type constraints,
        models each possible call, and merges return values.
        
        Args:
            callees: Possible function targets from pointer analysis
            args: Argument values
            keywords: Keyword argument values
            
        Returns:
            Possible return values from the call
        """
        if not callees:
            return create_unknown_value()
        
        return_values = []
        
        for callee in callees:
            try:
                # Check if callee matches AI type constraints
                if self._callee_matches_ai_constraints(callee, args, keywords):
                    # Model the call and get return value
                    ret_val = self._model_function_call(callee, args, keywords)
                    if ret_val:
                        return_values.append(ret_val)
            except Exception:
                # If modeling fails, add unknown value
                return_values.append(create_unknown_value())
        
        if not return_values:
            return create_unknown_value()
        
        # Merge all possible return values
        result = return_values[0]
        for ret_val in return_values[1:]:
            result = result.merge(ret_val)
        
        return result
    
    def _callee_matches_ai_constraints(self, callee: FunctionSymbol, 
                                     args: List[Value], keywords: Dict[str, Value]) -> bool:
        """
        Check if a callee from pointer analysis matches AI type constraints.
        
        Args:
            callee: Function symbol from pointer analysis
            args: Argument values
            keywords: Keyword argument values
            
        Returns:
            True if callee is compatible with AI constraints
        """
        # For now, accept all callees (conservative)
        # Real implementation would check:
        # - Function signatures
        # - Type compatibility of arguments
        # - Available function definitions
        return True
    
    def _model_function_call(self, callee: FunctionSymbol, 
                           args: List[Value], keywords: Dict[str, Value]) -> Value:
        """
        Model a function call and return the abstract return value.
        
        Args:
            callee: Function to call
            args: Argument values
            keywords: Keyword argument values
            
        Returns:
            Abstract return value
        """
        # For builtin functions, use specific models
        if hasattr(callee, 'name'):
            func_name = callee.name
            
            # Handle common builtin functions
            if func_name == 'len' and len(args) == 1:
                return self._handle_len_function(args[0])
            elif func_name == 'int' and len(args) >= 1:
                return self._handle_int_function(args[0])
            elif func_name == 'str':
                return create_str_value()
            elif func_name == 'list':
                return self._handle_list_function(args[0] if args else None)
            elif func_name == 'dict':
                return create_dict_value()
            elif func_name == 'set':
                return create_set_value()
            elif func_name == 'tuple':
                return create_tuple_value()
            elif func_name == 'bool':
                return create_bool_value()
        
        # For user-defined functions, return unknown (conservative)
        # Real implementation would:
        # - Look up function definition
        # - Create call context
        # - Analyze function body with given arguments
        # - Return computed return value
        return create_unknown_value()
    
    def _should_prune_path_with_pointer(self, condition_var: str, branch_taken: bool) -> bool:
        """
        Determine if a path should be pruned based on pointer analysis.
        
        Uses may_alias information to determine if certain conditions are impossible.
        
        Args:
            condition_var: Variable used in conditional
            branch_taken: Whether true or false branch was taken
            
        Returns:
            True if path should be pruned (unreachable), False otherwise
        """
        if not self.pointer:
            return False
        
        try:
            # Example: if we know two variables cannot alias,
            # we can prune paths that assume they do
            # This is a simplified example - real implementation would be more sophisticated
            context = self._get_current_context_for_pointer()
            
            # For now, be conservative and don't prune any paths
            # Real implementation would analyze the condition and use may_alias
            return False
        except Exception:
            # If analysis fails, don't prune (conservative)
            return False
    
    def _save_current_state(self, function_qualname: str, stmt_idx: int):
        """Save current variable state as a snapshot"""
        # Get all variables in current scope
        current_vars = {}
        scope = self.state.memory.current_scope
        if scope:
            # Save all local variables
            for var_name in scope.get_all_variable_names():
                value = self.state.get_variable(var_name)
                if value:
                    current_vars[var_name] = value
        
        self.state.control_flow.save_state_snapshot(function_qualname, stmt_idx, current_vars)
    
    def _handle_merge_point(self, function_qualname: str, stmt_idx: int):
        """Handle state merging at a control flow merge point"""
        # Get all state snapshots for this merge point
        snapshots = self.state.control_flow.get_state_snapshots(function_qualname, stmt_idx)
        
        if not snapshots:
            # First time reaching this merge point, save current state
            self._save_current_state(function_qualname, stmt_idx)
            return
        
        # Get current state
        current_vars = {}
        scope = self.state.memory.current_scope
        if scope:
            for var_name in scope.get_all_variable_names():
                value = self.state.get_variable(var_name)
                if value:
                    current_vars[var_name] = value
        
        # Merge current state with all previous snapshots
        merged_vars = {}
        all_snapshots = snapshots + [current_vars]
        
        # Collect all variable names from all snapshots
        all_var_names = set()
        for snapshot in all_snapshots:
            all_var_names.update(snapshot.keys())
        
        # Merge each variable across all snapshots
        for var_name in all_var_names:
            values_to_merge = []
            for snapshot in all_snapshots:
                if var_name in snapshot:
                    values_to_merge.append(snapshot[var_name])
            
            if values_to_merge:
                # Start with first value
                merged_value = values_to_merge[0]
                # Merge with remaining values
                for value in values_to_merge[1:]:
                    merged_value = merged_value.merge(value)
                merged_vars[var_name] = merged_value
        
        # Update current state with merged values
        for var_name, merged_value in merged_vars.items():
            self.state.set_variable(var_name, merged_value)
        
        # Save this merged state as a new snapshot
        self._save_current_state(function_qualname, stmt_idx)
    
    def _save_state_for_branch(self, function_qualname: str, stmt_idx: int):
        """Save state at branch point for all reachable merge points"""
        # Find all merge points reachable from this branch point
        merge_points = self._find_reachable_merge_points(function_qualname, stmt_idx)
        
        # Save current state for each merge point
        current_vars = {}
        scope = self.state.memory.current_scope
        if scope:
            for var_name in scope.get_all_variable_names():
                value = self.state.get_variable(var_name)
                if value:
                    current_vars[var_name] = value
        
        for merge_point in merge_points:
            self.state.control_flow.save_state_snapshot(function_qualname, merge_point, current_vars)
    
    def _find_reachable_merge_points(self, function_qualname: str, from_stmt: int) -> Set[int]:
        """Find all merge points (statements with multiple predecessors) reachable from given statement"""
        merge_points = set()
        visited = set()
        
        def dfs(stmt_idx):
            if stmt_idx in visited:
                return
            visited.add(stmt_idx)
            
            # Check if this statement is a merge point
            predecessors = self.state.control_flow.get_predecessors(function_qualname, stmt_idx)
            if len(predecessors) > 1:
                merge_points.add(stmt_idx)
            
            # Continue to successors
            successors = self.state.control_flow.get_successors(function_qualname, stmt_idx)
            for succ in successors:
                dfs(succ)
        
        # Start DFS from the statement after the branch
        successors = self.state.control_flow.get_successors(function_qualname, from_stmt)
        for succ in successors:
            dfs(succ)
        
        return merge_points 