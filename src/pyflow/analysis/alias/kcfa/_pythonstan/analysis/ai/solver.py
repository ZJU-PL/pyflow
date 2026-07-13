from typing import Dict, Set, List, Optional, Tuple, Any, Union, DefaultDict
import ast
from collections import deque, defaultdict

from pyflow.analysis.alias.kcfa._pythonstan.ir.ir_statements import (
    IRStatement, IRScope, IRFunc, IRClass, IRModule, Label,
    AbstractIRAssign, IRAssign, IRStoreAttr, IRLoadAttr, IRCall,
    IRReturn, IRYield, IRAwait, JumpIfTrue, JumpIfFalse, Goto
)
from pyflow.analysis.alias.kcfa._pythonstan.analysis.ai.value import (
    Value, Object, ObjectType,
    ConstantObject, BuiltinObject, ClassObject, FunctionObject, InstanceObject,
    create_unknown_value, create_none_value, create_function_value
)
from pyflow.analysis.alias.kcfa._pythonstan.analysis.ai.state import (
    AbstractState, Context, ContextType, FlowSensitivity,
    Scope, MemoryModel, ClassHierarchy, CallGraph, ControlFlowState,
    create_abstract_state
)
from pyflow.analysis.alias.kcfa._pythonstan.analysis.ai.operation import AbstractInterpreter
from pyflow.analysis.alias.kcfa._pythonstan.analysis.ai.pointer_adapter import PointerResults
from pyflow.analysis.alias.kcfa._pythonstan.graph.call_graph.call_graph import AbstractCallGraph


class AbstractInterpretationSolver:
    """
    Solver for abstract interpretation of Python programs.
    
    This class orchestrates the abstract interpretation process, including:
    - Building the CFG (Control Flow Graph)
    - Performing intraprocedural analysis
    - Performing interprocedural analysis
    - Handling context sensitivity and flow sensitivity
    """
    
    def __init__(self, 
                context_type: ContextType = ContextType.CALL_SITE,
                flow_sensitivity: FlowSensitivity = FlowSensitivity.SENSITIVE,
                context_depth: int = 1,
                max_iterations: int = 100,
                max_recursion_depth: int = 3,
                pointer: Optional[PointerResults] = None,
                call_graph: Optional[AbstractCallGraph] = None):
        """
        Initialize the abstract interpretation solver.
        
        Args:
            context_type: Type of context sensitivity to use
            flow_sensitivity: Type of flow sensitivity to use
            context_depth: Depth of context to maintain (for call-site sensitivity)
            max_iterations: Maximum number of iterations for fixed point computation
            max_recursion_depth: Maximum recursion depth for interprocedural analysis
            pointer: Optional pointer analysis results for precision
            call_graph: Optional call graph for interprocedural analysis
        """
        self.state = create_abstract_state(context_type, flow_sensitivity, context_depth)
        self.interpreter = AbstractInterpreter(self.state, pointer, call_graph, solver=self)
        self.max_iterations = max_iterations
        self.max_recursion_depth = max_recursion_depth
        self.pointer = pointer
        self.external_call_graph = call_graph
        
        # Mapping from function qualname to its IR statements
        self.func_statements: Dict[str, List[IRStatement]] = {}
        
        # Keep track of analyzed functions to prevent reanalysis
        self.analyzed_functions: Set[str] = set()
        
        # Keep track of function calls being analyzed to detect recursion
        self.callstack: List[str] = []
        
        # Keep track of visited contexts for each function
        self.function_contexts: Dict[str, Set[Context]] = defaultdict(set)
        
        # Performance improvements
        self._transfer_cache: Dict[Tuple[int, str, str], Value] = {}  # (stmt_id, state_fingerprint, pointer_digest) -> result
        self._state_cache: Dict[Tuple[str, str], AbstractState] = {}  # (function, context) -> state
        self._cache_hits = 0
        self._cache_misses = 0
        self._total_iterations = 0
        self._max_state_size = 0
        
    def analyze_module(self, module: IRModule, statements: List[IRStatement]) -> AbstractState:
        """
        Perform abstract interpretation on a module.
        
        Args:
            module: IR module to analyze
            statements: List of IR statements in the module
            
        Returns:
            The final abstract state after analysis
        """
        print(f"Starting analysis of module: {module.get_qualname()}")
        
        # Initialize state for module
        self.state.initialize_for_module(module)
        
        # Store module statements
        self.func_statements[module.get_qualname()] = statements
        
        # First pass: identify and register all classes and functions
        self._register_classes_and_functions(statements, module.get_qualname())
        
        # Second pass: perform intraprocedural analysis on each function
        self._perform_intraprocedural_analysis(module.get_qualname())
        
        # Third pass: perform interprocedural analysis with SCC ordering
        self._perform_interprocedural_analysis_with_scc()
        
        # Log performance statistics
        self._log_performance_stats()
        
        return self.state
    
    def _register_classes_and_functions(self, statements: List[IRStatement], scope_qualname: str):
        """
        Register all classes and functions in the scope.
        
        Args:
            statements: List of IR statements in the scope
            scope_qualname: Qualified name of the current scope
        """
        for stmt in statements:
            if isinstance(stmt, IRClass):
                # Register class in class hierarchy
                class_obj = self.state.register_class(stmt)
                
                # Get class statements (will be analyzed later)
                # This would require additional information not present in the current model
                
            elif isinstance(stmt, IRFunc):
                # Create function object
                func_value = create_function_value(stmt)
                
                # Set function in current scope
                self.state.set_variable(stmt.name, func_value)
                
                # Store function qualname for later analysis
                self.func_statements[stmt.get_qualname()] = []  # Placeholder for statements
    
    def _perform_intraprocedural_analysis(self, scope_qualname: str):
        """
        Perform intraprocedural analysis on all functions in the scope.
        
        Args:
            scope_qualname: Qualified name of the scope to analyze
        """
        statements = self.func_statements.get(scope_qualname, [])
        
        # Build control flow graph for this scope
        self._build_cfg(scope_qualname, statements)
        
        # Analyze statements in this scope
        self._analyze_scope(scope_qualname, statements)
        
        # Mark scope as analyzed
        self.analyzed_functions.add(scope_qualname)
    
    def _build_cfg(self, scope_qualname: str, statements: List[IRStatement]):
        """
        Build control flow graph for a scope.
        
        Args:
            scope_qualname: Qualified name of the scope
            statements: List of IR statements in the scope
        """
        # Set current function for control flow
        self.state.control_flow.set_current_function(scope_qualname)
        
        # Add sequential edges
        for i in range(len(statements) - 1):
            stmt = statements[i]
            if not (isinstance(stmt, IRReturn) or
                   isinstance(stmt, Goto) or 
                   isinstance(stmt, JumpIfTrue) or 
                   isinstance(stmt, JumpIfFalse)):
                # Add edge to next statement
                self.state.control_flow.add_edge(scope_qualname, i, i + 1)
        
        # Register labels
        for i, stmt in enumerate(statements):
            if isinstance(stmt, Label):
                self.state.control_flow.register_label(scope_qualname, stmt, i)
        
        # Add edges for jumps
        for i, stmt in enumerate(statements):
            if isinstance(stmt, Goto) and stmt.label:
                # Get target label index
                label_idx = self.state.control_flow.get_label_idx(scope_qualname, stmt.label.idx)
                if label_idx is not None:
                    # Add edge to label target
                    self.state.control_flow.add_edge(scope_qualname, i, label_idx)
            elif isinstance(stmt, JumpIfTrue) or isinstance(stmt, JumpIfFalse):
                # Add edge for taken branch
                label_idx = self.state.control_flow.get_label_idx(scope_qualname, stmt.label.idx)
                if label_idx is not None:
                    # Add edge to label target
                    self.state.control_flow.add_edge(scope_qualname, i, label_idx)
                
                # Add edge for not taken branch
                if i + 1 < len(statements):
                    self.state.control_flow.add_edge(scope_qualname, i, i + 1)
    
    def _analyze_scope(self, scope_qualname: str, statements: List[IRStatement]):
        """
        Perform flow-sensitive analysis on a scope.
        
        Args:
            scope_qualname: Qualified name of the scope
            statements: List of IR statements in the scope
        """
        # Set current function for control flow
        self.state.control_flow.set_current_function(scope_qualname)
        
        # For flow-sensitive analysis, use worklist algorithm
        if self.state.flow_sensitivity == FlowSensitivity.SENSITIVE:
            # Mark that we're in worklist-based analysis
            self.interpreter._in_worklist_analysis = True
            
            # Initialize worklist with entry point (statement 0)
            self.state.control_flow.add_to_worklist(scope_qualname, 0)
            
            # Process worklist until empty
            iter_count = 0
            while iter_count < self.max_iterations:
                # Get next statement from worklist
                next_item = self.state.control_flow.get_next_from_worklist()
                if next_item is None:
                    # Worklist is empty, analysis is complete
                    break
                
                function_name, stmt_idx = next_item
                
                # Make sure we're still in the right scope
                if function_name != scope_qualname:
                    continue
                
                # Check if statement index is valid
                if stmt_idx < 0 or stmt_idx >= len(statements):
                    continue
                
                # Set current statement
                self.state.control_flow.set_current_stmt(stmt_idx)
                
                # Update visit count for this statement
                key = (function_name, stmt_idx)
                current_count = self.state.control_flow.visit_count.get(key, 0)
                self.state.control_flow.visit_count[key] = current_count + 1
                
                # Interpret statement
                stmt = statements[stmt_idx]
                self.interpreter.visit(stmt, stmt_idx)
                
                iter_count += 1
            
            # Clear the worklist analysis flag
            self.interpreter._in_worklist_analysis = False
        else:
            # For flow-insensitive analysis, just interpret each statement once
            # This is not worklist-based
            self.interpreter._in_worklist_analysis = False
            for i, stmt in enumerate(statements):
                self.interpreter.visit(stmt, i)
    
    def _perform_interprocedural_analysis(self):
        """
        Perform interprocedural analysis on the program.
        
        This involves analyzing function calls and propagating return values.
        """
        # Get initial list of call edges
        worklist = []
        for callee_qualname, call_sites in self.state.call_graph.callers.items():
            for call_site in call_sites:
                worklist.append((call_site, callee_qualname))
        
        # Process worklist until empty or max iterations reached
        iter_count = 0
        while worklist and iter_count < self.max_iterations:
            # Get next call edge
            call_site, callee_qualname = worklist.pop(0)
            
            # Check if we already analyzed this function with this context
            caller_context = call_site.context
            if caller_context in self.function_contexts[callee_qualname]:
                continue
            
            # Create context for callee
            callee_context = self.state.create_context(call_site.stmt_index)
            
            # Add to visited contexts
            self.function_contexts[callee_qualname].add(callee_context)
            
            # Check if function exists
            if callee_qualname not in self.func_statements:
                continue
            
            # Check recursion depth
            if self._check_recursion_limit(callee_qualname):
                continue
            
            # Push call stack
            self.callstack.append(callee_qualname)
            
            # Save current context
            old_context = self.state.current_context
            
            # Set up context for callee
            self.state.set_current_context(callee_context)
            
            # Collect arguments
            args = self._collect_arguments_for_call(call_site)
            
            # Get function object
            func_value = self.state.get_variable(callee_qualname.split('.')[-1])
            func_obj = None
            if func_value:
                for obj in func_value.objects:
                    if isinstance(obj, FunctionObject) and obj.qualname == callee_qualname:
                        func_obj = obj
                        break
            
            if func_obj:
                # Enter function
                self.state.enter_function(
                    func_obj.ir_func, 
                    args,
                    call_site.stmt_index, 
                    None  # No receiver for non-method calls
                )
                
                # Reset the return value before analyzing the function
                self.interpreter.current_return_value = None
                
                # Analyze function if not already analyzed
                if callee_qualname not in self.analyzed_functions:
                    self._perform_intraprocedural_analysis(callee_qualname)
                else:
                    # Just reanalyze with new context
                    self._analyze_scope(callee_qualname, self.func_statements[callee_qualname])
                
                # Get return value
                return_value = self.interpreter.current_return_value
                if return_value is None:
                    return_value = create_none_value()
                
                # Set return value in caller
                target = None
                if hasattr(call_site.call_stmt, 'get_target'):
                    target = call_site.call_stmt.get_target()
                elif hasattr(call_site.call_stmt, 'target'):
                    target = call_site.call_stmt.target
                
                if target:
                    # Restore caller context
                    self.state.set_current_context(old_context)
                    
                    # Set variable in caller context
                    self.state.set_variable(target, return_value)
                    
                    # Check if value changed and if we need to reanalyze caller
                    # This is a simplified check - a real implementation would be more sophisticated
                    worklist.append((call_site, callee_qualname))
            
            # Pop call stack
            self.callstack.pop()
            
            # Restore old context
            self.state.set_current_context(old_context)
            
            iter_count += 1
    
    def _perform_interprocedural_analysis_with_scc(self):
        """
        Perform interprocedural analysis using SCC-based topological ordering.
        
        Analyzes strongly connected components in bottom-up order for better
        convergence and reuses summaries until they change.
        """
        if not self.external_call_graph:
            # Fallback to regular interprocedural analysis
            self._perform_interprocedural_analysis()
            return
        
        # TODO: Implement SCC computation from call graph
        # For now, use simple worklist algorithm with improved caching
        self._perform_interprocedural_analysis()
    
    def _get_state_fingerprint(self, state: AbstractState) -> str:
        """
        Compute a fingerprint for an abstract state for caching.
        
        Args:
            state: Abstract state to fingerprint
            
        Returns:
            String fingerprint of the state
        """
        # Simplified fingerprint - real implementation would be more sophisticated
        var_count = len(state.variables) if hasattr(state, 'variables') else 0
        context_str = str(state.current_context) if state.current_context else "none"
        return f"vars:{var_count},ctx:{hash(context_str)}"
    
    def _should_use_cache(self, stmt_id: int, state: AbstractState) -> Optional[Value]:
        """
        Check if we can use a cached result for this statement and state.
        
        Args:
            stmt_id: Statement identifier
            state: Current abstract state
            
        Returns:
            Cached result if available, None otherwise
        """
        if not self.pointer:
            return None
        
        state_fp = self._get_state_fingerprint(state)
        pointer_digest = self.pointer.pointer_digest_version()
        cache_key = (stmt_id, state_fp, pointer_digest)
        
        if cache_key in self._transfer_cache:
            self._cache_hits += 1
            return self._transfer_cache[cache_key]
        
        self._cache_misses += 1
        return None
    
    def _cache_result(self, stmt_id: int, state: AbstractState, result: Value):
        """
        Cache the result of a transfer function.
        
        Args:
            stmt_id: Statement identifier
            state: Abstract state
            result: Transfer function result
        """
        if not self.pointer:
            return
        
        state_fp = self._get_state_fingerprint(state)
        pointer_digest = self.pointer.pointer_digest_version()
        cache_key = (stmt_id, state_fp, pointer_digest)
        
        self._transfer_cache[cache_key] = result
        
        # Limit cache size to prevent memory explosion
        if len(self._transfer_cache) > 10000:
            # Remove oldest 20% of entries
            keys_to_remove = list(self._transfer_cache.keys())[:2000]
            for key in keys_to_remove:
                del self._transfer_cache[key]
    
    def _log_performance_stats(self):
        """
        Log performance statistics for this analysis run.
        """
        cache_hit_ratio = self._cache_hits / max(1, self._cache_hits + self._cache_misses)
        
        print(f"AI Analysis Performance Stats:")
        print(f"  Total iterations: {self._total_iterations}")
        print(f"  Max state size: {self._max_state_size}")
        print(f"  Cache hits: {self._cache_hits}")
        print(f"  Cache misses: {self._cache_misses}")
        print(f"  Cache hit ratio: {cache_hit_ratio:.2%}")
        print(f"  Transfer cache size: {len(self._transfer_cache)}")
    
    def _check_recursion_limit(self, function_qualname: str) -> bool:
        """
        Check if we've hit the recursion limit for a function.
        
        Args:
            function_qualname: Qualified name of the function
            
        Returns:
            True if recursion limit reached, False otherwise
        """
        # Count occurrences of function in call stack
        count = 0
        for f in self.callstack:
            if f == function_qualname:
                count += 1
                if count >= self.max_recursion_depth:
                    return True
        return False
    
    def _collect_arguments_for_call(self, call_site) -> List[Value]:
        """
        Collect argument values for a function call.
        
        Args:
            call_site: CallSite object representing the call
            
        Returns:
            List of argument values
        """
        args = []
        
        # Save current context and restore caller's context
        old_context = self.state.current_context
        self.state.set_current_context(call_site.context)
        
        # Get args from call site
        if hasattr(call_site.call_stmt, 'get_args'):
            arg_pairs = call_site.call_stmt.get_args()
        else:
            # If get_args() is not available, try to access args directly
            arg_pairs = getattr(call_site.call_stmt, 'args', [])
        
        for arg_info in arg_pairs:
            # Handle different formats of arg_info
            arg_name = None
            is_starred = False
            
            if isinstance(arg_info, tuple):
                arg_name, is_starred = arg_info
            elif isinstance(arg_info, str):
                arg_name = arg_info
            
            if arg_name:
                if arg_name.startswith("<Constant:"):
                    # Handle constant arguments (simplified)
                    const_str = arg_name[len("<Constant: "):-1]
                    # A real implementation would parse the constant value
                    args.append(create_unknown_value())
                else:
                    # Regular variable
                    arg_value = self.state.get_variable(arg_name)
                    if arg_value is None:
                        arg_value = create_unknown_value()
                    args.append(arg_value)
        
        # Restore old context
        self.state.set_current_context(old_context)
        
        return args


# Helper function to create a solver with specified parameters
def create_solver(
    context_type: ContextType = ContextType.CALL_SITE,
    flow_sensitivity: FlowSensitivity = FlowSensitivity.SENSITIVE,
    context_depth: int = 1,
    max_iterations: int = 100,
    max_recursion_depth: int = 3,
    pointer: Optional[PointerResults] = None,
    call_graph: Optional[AbstractCallGraph] = None
) -> AbstractInterpretationSolver:
    """Create a new abstract interpretation solver"""
    return AbstractInterpretationSolver(
        context_type, 
        flow_sensitivity,
        context_depth,
        max_iterations,
        max_recursion_depth,
        pointer,
        call_graph
    ) 