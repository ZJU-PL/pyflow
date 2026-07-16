from abc import ABC, abstractmethod
from enum import Enum
from typing import Dict, Set, List, Optional, Tuple, Any, DefaultDict, Union, FrozenSet
from collections import defaultdict
import ast
import sys
from dataclasses import dataclass, field

from pyflow.analysis.alias.kcfa._pythonstan.ir.ir_statements import (
    IRStatement, IRScope, IRFunc, IRClass, IRModule, Label, 
    AbstractIRAssign, IRAssign, IRStoreAttr, IRLoadAttr, IRCall
)
from pyflow.analysis.alias.kcfa._pythonstan.analysis.ai.value import (
    Value, Object, ObjectType, 
    ConstantObject, BuiltinObject, ClassObject, FunctionObject,
    create_unknown_value
)


class ContextType(Enum):
    """Types of analysis context sensitivity"""
    INSENSITIVE = 0       # No context sensitivity
    CALL_SITE = 1         # Context is the call site
    OBJECT_SENSITIVE = 2  # Context is the receiver object
    HYBRID = 3            # Combination of call site and object sensitivity
    K_CFA = 4             # k-CFA (Control Flow Analysis)


@dataclass(frozen=True)
class Context:
    """Represents a context for context-sensitive analysis"""
    context_id: Tuple[Any, ...] = field(default_factory=tuple)  # Uniquely identifies the context
    
    @staticmethod
    def create_insensitive_context() -> 'Context':
        """Create a context for context-insensitive analysis (singleton)"""
        return Context()
    
    @staticmethod
    def create_call_site_context(call_site_id: Any, depth: int = 1, prev_context: Optional['Context'] = None) -> 'Context':
        """Create a context sensitive to the call site"""
        if prev_context is None or not prev_context.context_id:
            return Context((call_site_id,))
        
        # Add call site to existing context ID, maintaining limited depth (k-CFA)
        ctx_id = prev_context.context_id
        if len(ctx_id) >= depth:
            ctx_id = ctx_id[-(depth-1):] + (call_site_id,)
        else:
            ctx_id = ctx_id + (call_site_id,)
        
        return Context(ctx_id)
    
    @staticmethod
    def create_object_sensitive_context(receiver_obj: Any, depth: int = 1, prev_context: Optional['Context'] = None) -> 'Context':
        """Create a context sensitive to the receiver object"""
        if prev_context is None or not prev_context.context_id:
            return Context((receiver_obj,))
        
        # Add receiver to existing context ID, maintaining limited depth
        ctx_id = prev_context.context_id
        if len(ctx_id) >= depth:
            ctx_id = ctx_id[-(depth-1):] + (receiver_obj,)
        else:
            ctx_id = ctx_id + (receiver_obj,)
        
        return Context(ctx_id)


class FlowSensitivity(Enum):
    """Types of flow sensitivity for analysis"""
    INSENSITIVE = 0   # No flow sensitivity
    SENSITIVE = 1     # Full flow sensitivity


class Scope:
    """Represents a variable scope (function, class, or module)"""
    
    def __init__(self, ir_scope: IRScope, parent_scope: Optional['Scope'] = None):
        self.ir_scope = ir_scope
        self.parent_scope = parent_scope
        self.qualname = ir_scope.get_qualname()
        self.locals: Dict[str, Value] = {}
        
    def get_local(self, name: str) -> Optional[Value]:
        """Get a local variable from this scope"""
        return self.locals.get(name)
    
    def set_local(self, name: str, value: Value):
        """Set a local variable in this scope"""
        self.locals[name] = value
    
    def has_local(self, name: str) -> bool:
        """Check if this scope has a local variable"""
        return name in self.locals
    
    def lookup(self, name: str) -> Optional[Value]:
        """Look up a variable in this scope or parent scopes"""
        # Check locals first
        local_val = self.get_local(name)
        if local_val:
            return local_val
            
        # Check parent scope if available
        if self.parent_scope:
            return self.parent_scope.lookup(name)
            
        return None

    def get_qualname(self) -> str:
        """Get the qualified name of this scope"""
        return self.qualname
    
    def get_all_variable_names(self) -> Set[str]:
        """Get all variable names in this scope (local only)"""
        return set(self.locals.keys())


class MemoryModel:
    """Manages variable storage for the abstract interpreter"""
    
    def __init__(self):
        self.global_scope: Optional[Scope] = None
        self.scopes: Dict[str, Scope] = {}  # qualname -> Scope
        self.current_scope: Optional[Scope] = None
        
        # Context-sensitive storage
        self.ctx_locals: Dict[Tuple[Context, str, str], Value] = {}  # (context, scope_qualname, var_name) -> Value
        
    def create_global_scope(self, ir_module: IRModule):
        """Create and set the global scope"""
        self.global_scope = Scope(ir_module)
        self.scopes[ir_module.get_qualname()] = self.global_scope
        self.current_scope = self.global_scope
    
    def create_function_scope(self, ir_func: IRFunc, parent_scope_name: Optional[str] = None):
        """Create a function scope"""
        parent_scope = self.get_scope(parent_scope_name) if parent_scope_name else self.global_scope
        scope = Scope(ir_func, parent_scope)
        self.scopes[ir_func.get_qualname()] = scope
        return scope
    
    def create_class_scope(self, ir_class: IRClass, parent_scope_name: Optional[str] = None):
        """Create a class scope"""
        parent_scope = self.get_scope(parent_scope_name) if parent_scope_name else self.global_scope
        scope = Scope(ir_class, parent_scope)
        self.scopes[ir_class.get_qualname()] = scope
        return scope
    
    def get_scope(self, qualname: str) -> Optional[Scope]:
        """Get a scope by qualname"""
        return self.scopes.get(qualname)
    
    def set_current_scope(self, qualname: str):
        """Set the current scope by qualname"""
        scope = self.get_scope(qualname)
        if scope:
            self.current_scope = scope
        else:
            raise ValueError(f"Scope {qualname} not found")
    
    def get_variable(self, name: str, context: Optional[Context] = None, scope_name: Optional[str] = None) -> Optional[Value]:
        """Get a variable value with context and flow sensitivity"""
        scope = self.get_scope(scope_name) if scope_name else self.current_scope
        if not scope:
            return None
        
        # If context-sensitive, try to get from context-specific storage
        if context and context.context_id:
            ctx_key = (context, scope.get_qualname(), name)
            if ctx_key in self.ctx_locals:
                return self.ctx_locals[ctx_key]
        
        # Fall back to normal scope lookup
        result = scope.lookup(name)
        return result
    
    def set_variable(self, name: str, value: Value, context: Optional[Context] = None, scope_name: Optional[str] = None):
        """Set a variable value with context and flow sensitivity"""
        scope = self.get_scope(scope_name) if scope_name else self.current_scope
        if not scope:
            if self.global_scope:
                scope = self.global_scope
            else:
                raise ValueError("No scope available to set variable")
        
        # If context-sensitive, store in context-specific storage
        if context and context.context_id:
            ctx_key = (context, scope.get_qualname(), name)
            self.ctx_locals[ctx_key] = value
        else:
            # Otherwise store in normal scope
            scope.set_local(name, value)
    
    def merge_variable(self, name: str, value: Value, context: Optional[Context] = None, scope_name: Optional[str] = None):
        """Merge a new value with the existing value of a variable"""
        existing_value = self.get_variable(name, context, scope_name)
        
        if existing_value:
            merged_value = existing_value.merge(value)
        else:
            merged_value = value
            
        self.set_variable(name, merged_value, context, scope_name)
        return merged_value
    
    def is_local_variable(self, name: str, scope_name: str) -> bool:
        """Check if a variable is local to the given scope"""
        if not scope_name:
            return False
        
        scope = self.get_scope(scope_name)
        if not scope:
            return False
        
        # A variable is considered local if it exists in the current scope
        # (as opposed to being inherited from parent scopes)
        return scope.has_local(name)


class ClassHierarchy:
    """Maintains the class hierarchy relationships"""
    
    def __init__(self):
        self.classes: Dict[str, ClassObject] = {}  # qualname -> ClassObject
        self.subclasses: DefaultDict[str, Set[str]] = defaultdict(set)  # parent_qualname -> {child_qualname}
        self.superclasses: DefaultDict[str, Set[str]] = defaultdict(set)  # child_qualname -> {parent_qualname}
        self.methods: DefaultDict[str, Dict[str, Any]] = defaultdict(dict)  # class_name -> {method_name -> method_value}
    
    def register_class(self, class_obj: ClassObject):
        """Register a class in the hierarchy"""
        self.classes[class_obj.qualname] = class_obj
        
        # Register inheritance relationships
        for base_name in class_obj.bases:
            self.subclasses[base_name].add(class_obj.qualname)
            self.superclasses[class_obj.qualname].add(base_name)
    
    def get_class(self, qualname: str) -> Optional[ClassObject]:
        """Get a class by its qualname"""
        return self.classes.get(qualname)
    
    def get_subclasses(self, qualname: str) -> Set[str]:
        """Get all direct subclasses of a class"""
        return self.subclasses.get(qualname, set())
    
    def get_all_subclasses(self, qualname: str) -> Set[str]:
        """Get all subclasses (direct and indirect) of a class"""
        result = set()
        to_process = list(self.get_subclasses(qualname))
        
        while to_process:
            sub_qualname = to_process.pop()
            if sub_qualname not in result:
                result.add(sub_qualname)
                to_process.extend(self.get_subclasses(sub_qualname))
                
        return result
    
    def get_superclasses(self, qualname: str) -> Set[str]:
        """Get all direct superclasses of a class"""
        return self.superclasses.get(qualname, set())
    
    def get_all_superclasses(self, qualname: str) -> Set[str]:
        """Get all superclasses (direct and indirect) of a class"""
        result = set()
        to_process = list(self.get_superclasses(qualname))
        
        while to_process:
            super_qualname = to_process.pop()
            if super_qualname not in result:
                result.add(super_qualname)
                to_process.extend(self.get_superclasses(super_qualname))
                
        return result
    
    def add_class(self, class_name: str, ir_class):
        """Add a class to the hierarchy (for compatibility with tests)"""
        # Create a simple ClassObject from IRClass for testing
        # In a real implementation, this would be more sophisticated
        from pyflow.analysis.alias.kcfa._pythonstan.analysis.ai.value import ClassObject
        class_obj = ClassObject(ir_class)
        self.register_class(class_obj)
    
    def add_inheritance(self, subclass_name: str, base_class_name: str):
        """Add inheritance relationship between classes (for compatibility with tests)"""
        # This is a simplified implementation for testing
        if subclass_name not in self.superclasses:
            self.superclasses[subclass_name] = set()
        if base_class_name not in self.subclasses:
            self.subclasses[base_class_name] = set()
        
        self.superclasses[subclass_name].add(base_class_name)
        self.subclasses[base_class_name].add(subclass_name)
    
    def add_method(self, class_name: str, method_name: str, method_value):
        """Add a method to a class"""
        self.methods[class_name][method_name] = method_value
    
    def is_subclass(self, subclass_name: str, base_class_name: str) -> bool:
        """Check if subclass_name is a subclass of base_class_name"""
        return base_class_name in self.superclasses.get(subclass_name, set())
    
    def get_method(self, class_name: str, method_name: str):
        """Get a method from a class, searching up the inheritance hierarchy"""
        # First check if the class has the method directly
        if class_name in self.methods and method_name in self.methods[class_name]:
            return self.methods[class_name][method_name]
        
        # If not found, search in superclasses
        for super_class in self.superclasses.get(class_name, set()):
            method = self.get_method(super_class, method_name)
            if method is not None:
                return method
        
        # Method not found in this class or any superclasses
        return None


@dataclass
class CallSite:
    """Represents a call site in the call graph"""
    caller_qualname: str
    call_stmt: IRCall
    stmt_index: int
    context: Optional[Context] = None
    

class CallGraph:
    """Maintains the call graph relationships"""
    
    def __init__(self):
        # Map from callee to all call sites that can reach it
        self.callers: DefaultDict[str, List[CallSite]] = defaultdict(list)
        
        # Map from caller to all functions it can call
        self.callees: DefaultDict[str, Set[str]] = defaultdict(set)
        
        # Context-sensitive call edges
        self.ctx_edges: DefaultDict[Tuple[Context, str], Set[Tuple[Context, str]]] = defaultdict(set)
        
        # Reference to CallSite class for external access
        self.CallSite = CallSite
    
    def add_call_edge(self, caller_qualname: str, callee_qualname: str, 
                    call_stmt: IRCall, stmt_index: int,
                    caller_context: Optional[Context] = None, 
                    callee_context: Optional[Context] = None):
        """Add a call edge to the graph"""
        call_site = CallSite(caller_qualname, call_stmt, stmt_index, caller_context)
        self.callers[callee_qualname].append(call_site)
        self.callees[caller_qualname].add(callee_qualname)
        
        # Add context-sensitive edge if contexts are provided
        if caller_context and callee_context:
            self.ctx_edges[(caller_context, caller_qualname)].add((callee_context, callee_qualname))
    
    def add_call(self, caller_qualname: str, callee_qualname: str, call_site: CallSite):
        """Add a call relationship using an existing CallSite object"""
        # Store the call site
        self.callers[callee_qualname].append(call_site)
        self.callees[caller_qualname].add(callee_qualname)
        
        # Add context-sensitive edge if context is available
        if call_site.context:
            # Create a context for the callee (simplified for now)
            callee_context = call_site.context  # Use same context for simplicity
            self.ctx_edges[(call_site.context, caller_qualname)].add((callee_context, callee_qualname))
    
    def get_callers(self, callee_qualname: str) -> List[CallSite]:
        """Get all call sites that can reach a function"""
        return self.callers.get(callee_qualname, [])
    
    def get_callees(self, caller_qualname: str) -> Set[str]:
        """Get all functions that can be called from a function"""
        return self.callees.get(caller_qualname, set())
    
    def get_context_sensitive_callees(self, caller_context: Context, caller_qualname: str) -> Set[Tuple[Context, str]]:
        """Get all functions that can be called from a function in a specific context"""
        return self.ctx_edges.get((caller_context, caller_qualname), set())


class ControlFlowState:
    """Tracks the control flow state during abstract interpretation"""
    
    def __init__(self, flow_sensitivity: FlowSensitivity = FlowSensitivity.SENSITIVE):
        self.flow_sensitivity = flow_sensitivity
        self.cfg: DefaultDict[str, Dict[int, Set[int]]] = defaultdict(dict)  # qualname -> {stmt_idx -> {next_idx}}
        self.reverse_cfg: DefaultDict[str, Dict[int, Set[int]]] = defaultdict(dict)  # qualname -> {stmt_idx -> {prev_idx}}
        self.current_function: Optional[str] = None
        self.current_stmt_idx: Optional[int] = None
        self.next_stmt_idx: Optional[int] = None
        self.labels: Dict[Tuple[str, str], int] = {}  # (function_qualname, label_name) -> stmt_idx
        
        # Maps from label to the statement index
        self.label_to_idx: Dict[Tuple[str, int], int] = {}  # (function_qualname, label_idx) -> stmt_idx
        
        # Flow-sensitive state
        self.visited_stmts: Set[Tuple[str, int]] = set()  # (function_qualname, stmt_idx)
        self.visit_count: Dict[Tuple[str, int], int] = {}  # (function_qualname, stmt_idx) -> count
        self.worklist: List[Tuple[str, int]] = []  # (function_qualname, stmt_idx)
        self.max_visits_per_stmt = 5  # Limit to prevent infinite loops
        
        # State snapshots for merge points
        self.state_snapshots: Dict[Tuple[str, int], List[Dict[str, 'Value']]] = {}  # (func, stmt) -> [variable_states]
    
    def add_edge(self, function_qualname: str, from_idx: int, to_idx: int):
        """Add a control flow edge"""
        if function_qualname not in self.cfg:
            self.cfg[function_qualname] = {}
            self.reverse_cfg[function_qualname] = {}
        
        if from_idx not in self.cfg[function_qualname]:
            self.cfg[function_qualname][from_idx] = set()
        self.cfg[function_qualname][from_idx].add(to_idx)
        
        if to_idx not in self.reverse_cfg[function_qualname]:
            self.reverse_cfg[function_qualname][to_idx] = set()
        self.reverse_cfg[function_qualname][to_idx].add(from_idx)
    
    def register_label(self, function_qualname: str, label: Label, stmt_idx: int):
        """Register a label in the control flow graph"""
        self.label_to_idx[(function_qualname, label.idx)] = stmt_idx
    
    def get_label_idx(self, function_qualname: str, label_idx: int) -> Optional[int]:
        """Get the statement index for a label"""
        return self.label_to_idx.get((function_qualname, label_idx))
    
    def get_successors(self, function_qualname: str, stmt_idx: int) -> Set[int]:
        """Get all successor statements"""
        if function_qualname in self.cfg and stmt_idx in self.cfg[function_qualname]:
            return self.cfg[function_qualname][stmt_idx]
        return set()
    
    def get_edges(self, function_qualname: str) -> List[Tuple[int, int]]:
        """Get all edges for a function"""
        return [(from_idx, to_idx) for from_idx, to_set in self.cfg.get(function_qualname, {}).items() for to_idx in to_set]
    
    def get_predecessors(self, function_qualname: str, stmt_idx: int) -> Set[int]:
        """Get all predecessor statements"""
        if function_qualname in self.reverse_cfg and stmt_idx in self.reverse_cfg[function_qualname]:
            return self.reverse_cfg[function_qualname][stmt_idx]
        return set()
    
    def set_current_function(self, function_qualname: str):
        """Set the current function being analyzed"""
        self.current_function = function_qualname
        self.current_stmt_idx = None
        self.next_stmt_idx = None
    
    def set_current_stmt(self, stmt_idx: int):
        """Set the current statement being analyzed"""
        self.current_stmt_idx = stmt_idx
        
    def get_current_stmt(self) -> Tuple[Optional[str], Optional[int]]:
        """Get the current function and statement index"""
        return self.current_function, self.current_stmt_idx
    
    def add_to_worklist(self, function_qualname: str, stmt_idx: int):
        """Add a statement to the worklist for flow-sensitive analysis"""
        key = (function_qualname, stmt_idx)
        
        # Check visit count to prevent infinite loops
        current_count = self.visit_count.get(key, 0)
        if current_count < self.max_visits_per_stmt:
            self.worklist.append(key)
            # Don't mark as visited here - we'll count visits during processing
    
    def get_next_from_worklist(self) -> Optional[Tuple[str, int]]:
        """Get the next statement from the worklist"""
        if self.worklist:
            return self.worklist.pop(0)
        return None
    
    def save_state_snapshot(self, function_qualname: str, stmt_idx: int, variable_state: Dict[str, 'Value']):
        """Save a snapshot of variable state at a program point"""
        key = (function_qualname, stmt_idx)
        if key not in self.state_snapshots:
            self.state_snapshots[key] = []
        self.state_snapshots[key].append(variable_state.copy())
    
    def get_state_snapshots(self, function_qualname: str, stmt_idx: int) -> List[Dict[str, 'Value']]:
        """Get all state snapshots for a program point"""
        key = (function_qualname, stmt_idx)
        return self.state_snapshots.get(key, [])


class AbstractState:
    """State for abstract interpretation, including variables, object attributes, control flow"""
    
    def __init__(self, 
                context_type: ContextType = ContextType.CALL_SITE,
                flow_sensitivity: FlowSensitivity = FlowSensitivity.SENSITIVE,
                context_depth: int = 1):
        # Context sensitivity settings
        self.context_type = context_type
        self.context_depth = context_depth
        self.current_context: Context = Context()
        
        # Flow sensitivity settings
        self.flow_sensitivity = flow_sensitivity
        
        # Memory model for storing variables
        self.memory = MemoryModel()
        
        # Create a default global scope for early testing
        # Using a simple module node as required by IRModule constructor
        module_node = ast.Module(body=[], type_ignores=[])
        dummy_module = IRModule("dummy_module", module_node)
        self.memory.create_global_scope(dummy_module)
        
        # Class hierarchy
        self.class_hierarchy = ClassHierarchy()
        
        # Call graph
        self.call_graph = CallGraph()
        
        # Control flow state
        self.control_flow = ControlFlowState(flow_sensitivity)
        
        # Call stack for interprocedural analysis
        self.call_stack: List[Tuple[str, int, Context]] = []
        
        # Initialize builtin objects
        self._init_builtins()
    
    def _init_builtins(self):
        """Initialize built-in types and values"""
        # TODO: Add built-in class objects, functions, etc.
        pass
    
    def create_context(self, 
                      call_site_id: Any = None, 
                      receiver_obj: Any = None) -> Context:
        """Create a context based on the configured sensitivity type"""
        if self.context_type == ContextType.INSENSITIVE:
            return Context.create_insensitive_context()
        elif self.context_type == ContextType.CALL_SITE:
            return Context.create_call_site_context(call_site_id, self.context_depth, self.current_context)
        elif self.context_type == ContextType.OBJECT_SENSITIVE:
            return Context.create_object_sensitive_context(receiver_obj, self.context_depth, self.current_context)
        elif self.context_type == ContextType.HYBRID:
            # Combine call site and object sensitivity
            if receiver_obj:
                return Context.create_object_sensitive_context(receiver_obj, self.context_depth, self.current_context)
            else:
                return Context.create_call_site_context(call_site_id, self.context_depth, self.current_context)
        else:  # K_CFA
            return Context.create_call_site_context(call_site_id, self.context_depth, self.current_context)
    
    def set_current_context(self, context: Context):
        """Set the current analysis context"""
        self.current_context = context
    
    def push_call_stack(self, function_qualname: str, return_stmt_idx: int, context: Optional[Context] = None):
        """Push a new frame onto the call stack"""
        ctx = context if context else self.current_context
        self.call_stack.append((function_qualname, return_stmt_idx, ctx))
    
    def pop_call_stack(self) -> Optional[Tuple[str, int, Context]]:
        """Pop a frame from the call stack"""
        if self.call_stack:
            return self.call_stack.pop()
        return None
    
    def get_variable(self, name: str) -> Optional[Value]:
        """Get a variable's value in the current context"""
        # Only pass context if we're using context sensitivity
        ctx = self.current_context if self.context_type != ContextType.INSENSITIVE else None
        return self.memory.get_variable(name, ctx)
    
    def set_variable(self, name: str, value: Value):
        """Set a variable's value in the current context"""
        # Only pass context if we're using context sensitivity
        ctx = self.current_context if self.context_type != ContextType.INSENSITIVE else None
        self.memory.set_variable(name, value, ctx)
        
        # Verify the variable was set
        check = self.get_variable(name)
        assert check == value, f"Variable {name} set to {value}, but get_variable() returned {check}"
    
    def merge_variable(self, name: str, value: Value) -> Value:
        """Merge a new value with the existing value of a variable"""
        # Only pass context if we're using context sensitivity
        ctx = self.current_context if self.context_type != ContextType.INSENSITIVE else None
        return self.memory.merge_variable(name, value, ctx)
        
    def initialize_for_module(self, ir_module: IRModule):
        """Initialize the state for analyzing a module"""
        # Create global scope
        self.memory.create_global_scope(ir_module)
        self.control_flow.set_current_function(ir_module.get_qualname())
    
    def enter_function(self, ir_func: IRFunc, args: List[Value], 
                      call_site_id: Any = None, 
                      receiver: Optional[Value] = None) -> Context:
        """Enter a function for analysis"""
        # Create appropriate context
        context = self.create_context(call_site_id, receiver)
        self.set_current_context(context)
        
        # Set current function for control flow
        self.control_flow.set_current_function(ir_func.get_qualname())
        
        # Create function scope if needed
        if not self.memory.get_scope(ir_func.get_qualname()):
            parent_scope_qualname = None
            # TODO: Determine parent scope based on lexical scope
            self.memory.create_function_scope(ir_func, parent_scope_qualname)
        
        # Set as current scope
        self.memory.set_current_scope(ir_func.get_qualname())
        
        # Set up parameters
        # Get parameter names from function
        param_names = []
        if hasattr(ir_func, 'get_arg_names'):
            arg_names = ir_func.get_arg_names()
            if hasattr(arg_names, 'args'):
                param_names = [arg.arg for arg in arg_names.args]
        elif hasattr(ir_func, 'args'):
            if isinstance(ir_func.args, list):
                param_names = ir_func.args
            elif hasattr(ir_func.args, 'args'):
                param_names = [arg.arg for arg in ir_func.args.args]
        
        # Bind positional args
        for i, (param_name, arg_value) in enumerate(zip(param_names, args)):
            self.set_variable(param_name, arg_value)
        
        # If this is an instance method, bind 'self'
        if receiver and hasattr(ir_func, 'is_instance_method') and ir_func.is_instance_method and param_names:
            self.set_variable(param_names[0], receiver)
            
        return context
    
    def exit_function(self, return_value: Optional[Value] = None) -> Tuple[Optional[str], Optional[int], Optional[Context]]:
        """Exit the current function and return to caller"""
        frame = self.pop_call_stack()
        
        if frame:
            caller_qualname, return_stmt_idx, caller_context = frame
            self.control_flow.set_current_function(caller_qualname)
            self.control_flow.set_current_stmt(return_stmt_idx)
            self.set_current_context(caller_context)
            
            # Set up the scope
            self.memory.set_current_scope(caller_qualname)
            
            return caller_qualname, return_stmt_idx, caller_context
        
        return None, None, None
    
    def register_call(self, caller_qualname: str, callee_qualname: str, 
                     call_stmt: IRCall, stmt_idx: int,
                     caller_context: Optional[Context] = None,
                     callee_context: Optional[Context] = None):
        """Register a function call in the call graph"""
        ctx_caller = caller_context if caller_context else self.current_context
        ctx_callee = callee_context if callee_context else self.create_context(stmt_idx)
        
        self.call_graph.add_call_edge(
            caller_qualname, callee_qualname, 
            call_stmt, stmt_idx, 
            ctx_caller, ctx_callee
        )
    
    def register_class(self, ir_class: IRClass) -> ClassObject:
        """Register a class in the class hierarchy"""
        # Create class scope if needed
        if not self.memory.get_scope(ir_class.get_qualname()):
            parent_scope_qualname = None
            # TODO: Determine parent scope based on lexical scope
            self.memory.create_class_scope(ir_class, parent_scope_qualname)
        
        # Create ClassObject
        class_obj = ClassObject(ir_class)
        
        # Register in class hierarchy
        self.class_hierarchy.register_class(class_obj)
        
        return class_obj
        
    def get_next_statement(self) -> Tuple[Optional[str], Optional[int]]:
        """Get the next statement to analyze based on flow sensitivity"""
        if self.flow_sensitivity == FlowSensitivity.INSENSITIVE:
            # In flow-insensitive analysis, just continue with the next statement
            return self.control_flow.current_function, self.control_flow.next_stmt_idx
        else:
            # In flow-sensitive analysis, get the next statement from the worklist
            return self.control_flow.get_next_from_worklist()
            

# Factory function to create a new abstract state
def create_abstract_state(
    context_type: ContextType = ContextType.CALL_SITE,
    flow_sensitivity: FlowSensitivity = FlowSensitivity.SENSITIVE,
    context_depth: int = 1
) -> AbstractState:
    """Create a new abstract interpretation state"""
    return AbstractState(context_type, flow_sensitivity, context_depth) 