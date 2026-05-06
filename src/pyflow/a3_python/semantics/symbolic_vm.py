"""
Symbolic bytecode executor using Z3.

Implements symbolic semantics over Z3 expressions sufficient for reachability queries.
Target: Python 3.11+ bytecode as abstract machine (symbolic version).
"""

import dis
import types
from dataclasses import dataclass, field
from typing import Any, Optional, List
import z3

from .state import Frame, MachineState
from .oracles import ExecutionOracle, CallObservation
from ..z3model.values import (
    SymbolicValue, ValueTag,
    binary_op_add, binary_op_sub, binary_op_mul,
    binary_op_truediv, binary_op_floordiv, binary_op_mod,
    binary_op_pow,
    binary_op_lshift, binary_op_rshift,
    binary_op_and, binary_op_or, binary_op_xor,
    binary_op_subscript,
    unary_op_negative, unary_op_positive, unary_op_invert, unary_op_not,
    compare_op_lt, compare_op_le, compare_op_eq,
    compare_op_ne, compare_op_gt, compare_op_ge,
    contains_op,
    is_true
)
from ..z3model.heap import SymbolicHeap, SequenceObject, DictObject
from ..contracts.schema import get_contract, Contract
from ..contracts.stdlib_stubs import get_module_exports, is_known_stdlib_module, get_special_attribute
from ..contracts.relations import (
    get_relational_summary, has_relational_summary,
    RelationalSummary, PostCondition
)
# Import stdlib_module_relations to trigger registration of math.sqrt, log, asin, etc.
from ..contracts import stdlib_module_relations  # noqa: F401 - imported for side effect (registration)
# Security taint tracking (barrier-certificate-theory.md §11, leak_theory.md)
# Use the new lattice-based tracker with full (τ, κ, σ) product lattice
from .security_tracker_lattice import (
    LatticeSecurityTracker as SecurityTracker,
    handle_call_pre, handle_call_post,
    handle_binop, handle_unop, handle_subscript,
    ensure_security_contracts_initialized,
    update_state_security_flags,
    infer_sensitivity_from_name
)


def get_stable_value_id(value: SymbolicValue) -> Optional[int]:
    """
    Get a stable ID for a SymbolicValue that persists across LOAD_FAST operations.
    
    CRITICAL FIX (Iteration 490): The Python id() of a SymbolicValue changes every
    time it's loaded from locals, but the Z3 payload (ObjId for OBJ types) is stable.
    This function extracts a stable ID that can be used as a dictionary key for
    tracking variable names and function names across operations.
    
    For OBJ, STR, LIST, TUPLE, DICT types: returns the numeric payload (ObjId)
    For other types: returns None (we only track names for object references)
    
    Args:
        value: The SymbolicValue to get an ID for
    
    Returns:
        A stable integer ID, or None if not applicable
    """
    # Only track object references (things with heap identity)
    if not hasattr(value, 'tag') or not hasattr(value, 'payload'):
        return None
    
    tag_val = value.tag
    if isinstance(tag_val, z3.IntNumRef):
        tag_val = tag_val.as_long()
    elif isinstance(tag_val, int):
        pass
    else:
        return None
    
    # Object types that have stable heap IDs
    object_tags = {
        ValueTag.OBJ.value,
        ValueTag.STR.value,
        ValueTag.LIST.value,
        ValueTag.TUPLE.value,
        ValueTag.DICT.value
    }
    
    if tag_val not in object_tags:
        return None
    
    # Extract the numeric payload (ObjId)
    payload = value.payload
    if isinstance(payload, z3.IntNumRef):
        return payload.as_long()
    elif isinstance(payload, int):
        return payload
    elif isinstance(payload, z3.ExprRef):
        # Try to extract if it's a concrete integer
        try:
            if z3.is_int_value(payload):
                return payload.as_long()
        except:
            pass
    
    return None


@dataclass
class SymbolicFrame:
    """
    Symbolic execution frame.
    
    Similar to Frame but holds SymbolicValue instances.
    """
    code: types.CodeType
    instruction_offset: int = 0
    locals: dict[str, SymbolicValue] = field(default_factory=dict)
    globals: dict[str, SymbolicValue] = field(default_factory=dict)
    builtins: dict[str, SymbolicValue] = field(default_factory=dict)
    operand_stack: list[SymbolicValue] = field(default_factory=list)
    # Cells: for closure variables (cellvars)
    # Maps index to cell value (or None if not yet initialized)
    cells: dict[int, Optional[SymbolicValue]] = field(default_factory=dict)
    # Freevars: closure variables from outer scope
    # Maps index to cell value (shared with outer frame's cells)
    freevars: dict[int, Optional[SymbolicValue]] = field(default_factory=dict)
    # Call context: for inlined user functions, track call info for handle_call_post
    # Contains: {'func_name': str, 'args': List[SymbolicValue], 'func_ref': SymbolicValue}
    call_context: Optional[dict] = None
    
    def copy(self) -> 'SymbolicFrame':
        """Deep copy for path branching."""
        return SymbolicFrame(
            code=self.code,
            instruction_offset=self.instruction_offset,
            locals=self.locals.copy(),
            globals=self.globals.copy(),
            builtins=self.builtins.copy(),
            operand_stack=self.operand_stack.copy(),
            cells=self.cells.copy(),
            freevars=self.freevars.copy(),
            call_context=self.call_context
        )


@dataclass
class SymbolicMachineState:
    """
    Symbolic machine state for path exploration.
    
    State space S in the transition system model.
    """
    frame_stack: list[SymbolicFrame] = field(default_factory=list)
    heap: SymbolicHeap = field(default_factory=SymbolicHeap)
    path_condition: z3.ExprRef = z3.BoolVal(True)
    exception: Optional[str] = None  # Exception type name (for now)
    exception_value: Optional[SymbolicValue] = None  # Exception instance
    halted: bool = False
    return_value: Optional[SymbolicValue] = None
    
    # Function name tracking for contract lookup
    func_names: dict[int, str] = field(default_factory=dict)
    
    # Module tracking for import handling
    module_names: dict[int, str] = field(default_factory=dict)
    
    # Z3 variable tracking for barrier certificate extraction
    # Maps variable names (e.g., "x", "n") to their Z3 symbolic expressions
    # This allows extracting concrete values from Z3 models during counterexample analysis
    z3_variable_map: dict[str, z3.ExprRef] = field(default_factory=dict)
    
    # Generator/coroutine tracking
    # Maps generator object IDs to their execution state (frame snapshot, yield position)
    generator_states: dict[int, dict] = field(default_factory=dict)
    # Track if current execution is inside a generator/coroutine
    is_generator_frame: bool = False
    # Track code objects for function creation (to check generator/coroutine flags)
    code_objects: dict[int, types.CodeType] = field(default_factory=dict)
    
    # User-defined function tracking (for intra-procedural analysis)
    # Maps function object ID to metadata: {code: CodeType, name: str, module: str, defined_in: str}
    user_functions: dict[int, dict] = field(default_factory=dict)
    # Track all user function calls encountered during analysis
    user_function_calls: list = field(default_factory=list)

    # Step counter for k-step reachability provenance (monotone along a path).
    # Incremented once per executed bytecode instruction in SymbolicVM.step().
    step_count: int = 0
    
    # Unsafe region markers (will be populated by unsafe/* modules)
    div_by_zero_reached: bool = False
    fp_domain_error_reached: bool = False
    index_out_of_bounds: bool = False
    none_misuse_reached: bool = False
    type_confusion_reached: bool = False
    heap_size_unbounded: bool = False
    resource_leak_detected: bool = False
    iterator_invalidation_reached: bool = False
    
    # Track exception fork nesting depth to prevent cascading exception forks.
    # Incremented each time an exception path is forked from a CALL contract.
    # When this exceeds MAX_EXCEPTION_FORK_DEPTH, no more exception forks are
    # created (the success path still runs).  This prevents exponential path
    # explosion from handler bodies that make more CALL instructions.
    exception_fork_depth: int = 0
    
    # ========================================================================
    # INTRAPROCEDURAL ANALYSIS INTEGRATION
    # Guard tracking per barrier-certificate-theory.tex §7
    # ========================================================================
    
    # Guard bits for path-sensitive barrier analysis
    # Each guard is a boolean indicating whether a safety check has been established
    # Format: "guard_type:variable[:extra]" -> True if established
    established_guards: dict[str, bool] = field(default_factory=dict)
    
    # Cached intraprocedural analysis results per code object
    # Maps code object id -> IntraprocAnalysisResult
    intraproc_cache: dict[int, 'IntraprocAnalysisResult'] = field(default_factory=dict)
    
    # Context tracking for bug reports (semantic information)
    div_by_zero_context: Optional[dict] = None  # Contains: operation, offset, function_name, left_val, right_val
    # Domain error context (for FP_DOMAIN)
    domain_error_context: Optional[str] = None
    
    # Iterator tracking for ITERATOR_INVALID detection
    active_iterators: list = field(default_factory=list)  # List of (collection_id, iterator_id) tuples
    last_collection_mutation: Optional[str] = None  # Description of last mutation
    
    # INFO_LEAK taint tracking
    tainted_value_at_sink: bool = False
    taint_violations: list = field(default_factory=list)  # List of (value, sink_location, taint_labels)
    exception_tainted: bool = False
    pc_taint: set = field(default_factory=set)  # Program counter taint (control flow taint)
    at_sink_operation: bool = False
    output_tainted: bool = False
    taint_sources: list = field(default_factory=list)  # List of taint source descriptions
    sink_location: Optional[str] = None
    leaked_taint_labels: set = field(default_factory=set)
    implicit_flow_leak: Optional[dict] = None
    
    # ========================================================================
    # SECURITY BUG DETECTION (barrier-certificate-theory.md §11)
    # Taint tracking for 47 CodeQL security query types
    # ========================================================================
    
    # Security tracker instance (see security_tracker.py)
    security_tracker: Optional['SecurityTracker'] = None
    
    # Security violation detection flags
    sql_injection_detected: bool = False
    command_injection_detected: bool = False
    code_injection_detected: bool = False
    path_injection_detected: bool = False
    xss_detected: bool = False
    ssrf_detected: bool = False
    deserialization_detected: bool = False
    xxe_detected: bool = False
    cleartext_logging_detected: bool = False
    cleartext_storage_detected: bool = False
    
    # Security violations list for detailed reporting
    security_violations: list = field(default_factory=list)
    
    # Module-init phase detection (for import-heavy traces)
    # True if execution appears to be in module initialization (early RESUME + many IMPORT_NAME)
    module_init_phase: bool = False
    import_count: int = 0  # Number of IMPORT_NAME opcodes seen
    
    @property
    def current_frame(self) -> Optional[SymbolicFrame]:
        return self.frame_stack[-1] if self.frame_stack else None
    
    # ========================================================================
    # GUARD MANAGEMENT (barrier-certificate-theory.tex §7)
    # ========================================================================
    
    def set_guard(self, guard_type: str, variable: str, extra: str = None):
        """
        Establish a guard fact.
        
        Called when a safety check is performed (e.g., 'if x is not None').
        
        Args:
            guard_type: "nonnull", "type", "div", "bounds", "catch"
            variable: Variable name being checked
            extra: Additional info (type name for g_type, etc.)
        """
        key = f"{guard_type}:{variable}"
        if extra:
            key += f":{extra}"
        self.established_guards[key] = True
    
    def has_guard(self, guard_type: str, variable: str, extra: str = None) -> bool:
        """
        Check if a guard is established.
        
        Returns True if the guard has been established on all paths
        leading to the current program point.
        """
        key = f"{guard_type}:{variable}"
        if extra:
            key += f":{extra}"
        return self.established_guards.get(key, False)
    
    def has_nonnull_guard(self, variable: str) -> bool:
        """Check if g_nonnull(variable) is established."""
        return self.has_guard("nonnull", variable)
    
    def has_type_guard(self, variable: str, type_name: str) -> bool:
        """Check if g_type(variable, type_name) is established."""
        return self.has_guard("type", variable, type_name)
    
    def has_div_guard(self, variable: str) -> bool:
        """Check if g_div(variable) is established (divisor != 0)."""
        return self.has_guard("div", variable)
    
    def has_bounds_guard(self, container: str, index: str) -> bool:
        """Check if g_bounds(container, index) is established."""
        return self.has_guard("bounds", f"{container}[{index}]")
    
    def has_catch_guard(self, exception_type: str) -> bool:
        """Check if g_catch(exception_type) is established."""
        return self.has_guard("catch", exception_type)
    
    def get_intraproc_analysis(self, code: 'types.CodeType') -> Optional['IntraprocAnalysisResult']:
        """
        Get cached intraprocedural analysis for a code object.
        
        Lazily computes the analysis if not cached.
        """
        code_id = id(code)
        if code_id not in self.intraproc_cache:
            try:
                from ..cfg.dataflow import run_intraprocedural_analysis
                self.intraproc_cache[code_id] = run_intraprocedural_analysis(code)
            except Exception:
                return None
        return self.intraproc_cache.get(code_id)
    
    def update_guards_from_analysis(self, code: 'types.CodeType', offset: int):
        """
        Update established_guards based on intraprocedural analysis.
        
        Called at each instruction to propagate guard facts from
        the dataflow analysis.
        """
        analysis = self.get_intraproc_analysis(code)
        if analysis is None:
            return
        
        # Get guards valid at this offset from dataflow
        guard_state = analysis.get_guards_at_offset(offset)
        
        # Merge into established_guards
        for key in guard_state.established:
            self.established_guards[key] = True
    
    def register_z3_variable(self, var_name: str, z3_expr: z3.ExprRef):
        """
        Register a Z3 expression for a program variable.
        
        This allows extracting concrete values from Z3 models during
        counterexample analysis and barrier certificate synthesis.
        
        Args:
            var_name: Program variable name (e.g., "x", "n", "result")
            z3_expr: The Z3 expression representing this variable
        """
        self.z3_variable_map[var_name] = z3_expr
    
    def get_z3_variable(self, var_name: str) -> Optional[z3.ExprRef]:
        """
        Get the Z3 expression for a tracked program variable.
        
        Args:
            var_name: Program variable name
        
        Returns:
            Z3 expression if tracked, None otherwise
        """
        return self.z3_variable_map.get(var_name)
    
    def copy(self) -> 'SymbolicMachineState':
        """Deep copy for path branching."""
        # Create new instance with explicit fields
        new_state = SymbolicMachineState(
            frame_stack=[f.copy() for f in self.frame_stack],
            heap=self.heap.copy(),
            path_condition=self.path_condition,
            exception=self.exception,
            exception_value=self.exception_value,
            halted=self.halted,
            return_value=self.return_value,
            func_names=self.func_names.copy(),
            module_names=self.module_names.copy(),
            z3_variable_map=self.z3_variable_map.copy(),
            code_objects=self.code_objects.copy(),
            generator_states=self.generator_states.copy(),
            is_generator_frame=self.is_generator_frame,
            user_functions=self.user_functions.copy(),
            user_function_calls=self.user_function_calls.copy(),
            step_count=self.step_count,
            established_guards=self.established_guards.copy(),
            intraproc_cache=self.intraproc_cache,  # Shared cache (not copied)
            div_by_zero_reached=self.div_by_zero_reached,
            div_by_zero_context=self.div_by_zero_context.copy() if self.div_by_zero_context else None,
            fp_domain_error_reached=self.fp_domain_error_reached,
            domain_error_context=self.domain_error_context,
            index_out_of_bounds=self.index_out_of_bounds,
            none_misuse_reached=self.none_misuse_reached,
            type_confusion_reached=self.type_confusion_reached,
            heap_size_unbounded=self.heap_size_unbounded,
            resource_leak_detected=self.resource_leak_detected,
            iterator_invalidation_reached=self.iterator_invalidation_reached,
            active_iterators=self.active_iterators.copy(),
            last_collection_mutation=self.last_collection_mutation,
            tainted_value_at_sink=self.tainted_value_at_sink,
            taint_violations=self.taint_violations.copy(),
            exception_tainted=self.exception_tainted,
            pc_taint=self.pc_taint.copy(),
            at_sink_operation=self.at_sink_operation,
            output_tainted=self.output_tainted,
            taint_sources=self.taint_sources.copy(),
            sink_location=self.sink_location,
            leaked_taint_labels=self.leaked_taint_labels.copy(),
            implicit_flow_leak=self.implicit_flow_leak,
            security_tracker=self.security_tracker,  # Shared reference (not copied)
            sql_injection_detected=self.sql_injection_detected,
            command_injection_detected=self.command_injection_detected,
            code_injection_detected=self.code_injection_detected,
            path_injection_detected=self.path_injection_detected,
            xss_detected=self.xss_detected,
            ssrf_detected=self.ssrf_detected,
            deserialization_detected=self.deserialization_detected,
            xxe_detected=self.xxe_detected,
            cleartext_logging_detected=self.cleartext_logging_detected,
            cleartext_storage_detected=self.cleartext_storage_detected,
            security_violations=self.security_violations.copy(),
            module_init_phase=self.module_init_phase,
            import_count=self.import_count
        )
        
        # Copy all dynamically added attributes
        # These are attributes not in the dataclass definition but added with hasattr checks
        for attr_name in dir(self):
            if attr_name.startswith('_') and not attr_name.startswith('__'):
                # Private attributes like _relational_call_counter, _pending_class_decorator
                if hasattr(self, attr_name):
                    value = getattr(self, attr_name)
                    # Try to copy if it's a dict or list
                    if isinstance(value, dict):
                        setattr(new_state, attr_name, value.copy())
                    elif isinstance(value, list):
                        setattr(new_state, attr_name, value.copy())
                    elif isinstance(value, set):
                        setattr(new_state, attr_name, value.copy())
                    else:
                        setattr(new_state, attr_name, value)
            elif not attr_name.startswith('_'):
                # Public dynamically added attributes
                if (hasattr(self, attr_name) and 
                    attr_name not in {'frame_stack', 'heap', 'current_frame'} and  # Skip already copied
                    not callable(getattr(self, attr_name))):  # Skip methods
                    value = getattr(self, attr_name)
                    # Only copy if not already handled in dataclass fields
                    if attr_name not in new_state.__dict__:
                        if isinstance(value, dict):
                            setattr(new_state, attr_name, value.copy())
                        elif isinstance(value, list):
                            setattr(new_state, attr_name, value.copy())
                        elif isinstance(value, set):
                            setattr(new_state, attr_name, value.copy())
                        else:
                            setattr(new_state, attr_name, value)
        
        return new_state


@dataclass
class SymbolicPath:
    """
    A symbolic execution path.
    
    Represents one possible execution trace through the program.
    """
    state: SymbolicMachineState
    trace: List[str] = field(default_factory=list)
    
    def copy(self) -> 'SymbolicPath':
        return SymbolicPath(
            state=self.state.copy(),
            trace=self.trace.copy()
        )


class SymbolicVM:
    """
    Symbolic bytecode executor.
    
    Explores paths through bytecode with Z3-backed symbolic values.
    """
    
    def __init__(
        self,
        solver: z3.Solver = None,
        oracle: Optional[ExecutionOracle] = None,
        verbose: bool = False,
        solver_timeout_ms: Optional[int] = None,
    ):
        self.solver = solver if solver else z3.Solver()
        if solver_timeout_ms is not None:
            # Prevent pathological hangs during feasibility checks.
            self.solver.set("timeout", int(solver_timeout_ms))
        self.oracle = oracle
        self.verbose = verbose
        self.paths: List[SymbolicPath] = []
        self._instruction_cache: Dict[int, Dict[int, dis.Instruction]] = {}
        self._obj_id_counter = 0

    def fresh_obj_id(self) -> int:
        """Return a fresh unique object ID for heap allocation."""
        self._obj_id_counter += 1
        return self._obj_id_counter

    def _solver_maybe_sat(self) -> bool:
        """
        Return True if SAT or UNKNOWN.
        UNKNOWN is treated as feasible to avoid unsound pruning when Z3 times out.
        """
        r = self.solver.check()
        return r == z3.sat or r == z3.unknown
    
    @staticmethod
    def make_default_builtins():
        """Return (builtins_dict, func_names_dict) populated with Python builtins."""
        builtins = {}
        # Exception types (hash-based IDs for CHECK_EXC_MATCH)
        exception_types_list = [
            'AssertionError', 'ZeroDivisionError', 'TypeError', 'ValueError',
            'IndexError', 'KeyError', 'AttributeError', 'NameError',
            'RuntimeError', 'RecursionError', 'FileNotFoundError', 'PermissionError',
            'IsADirectoryError', 'OSError', 'IOError', 'ImportError', 'ModuleNotFoundError',
            'StopIteration', 'StopAsyncIteration', 'GeneratorExit', 'NotImplementedError',
            'BaseException', 'Exception', 'SystemExit', 'UnboundLocalError',
            'OverflowError', 'ArithmeticError', 'LookupError', 'UnicodeError',
            'UnicodeDecodeError', 'UnicodeEncodeError', 'ConnectionError',
            'TimeoutError', 'EOFError', 'MemoryError',
        ]
        for exc_name in exception_types_list:
            exc_id = -1000 - abs(hash(exc_name)) % 10000
            exc_val = SymbolicValue(ValueTag.OBJ, z3.IntVal(exc_id))
            exc_val._exception_type = exc_name
            builtins[exc_name] = exc_val

        # Builtin functions
        builtin_funcs = [
            # Core type constructors
            'int', 'float', 'complex', 'bool', 'str', 'bytes', 'bytearray',
            'list', 'tuple', 'dict', 'set', 'frozenset', 'object',
            'type', 'slice', 'memoryview',
            # Numeric / math helpers
            'abs', 'round', 'pow', 'divmod', 'sum', 'max', 'min',
            # Sequence / iteration helpers
            'len', 'range', 'enumerate', 'zip', 'map', 'filter',
            'sorted', 'reversed', 'iter', 'next', 'all', 'any',
            # String / repr helpers
            'repr', 'ascii', 'chr', 'ord', 'hex', 'oct', 'bin', 'format',
            'hash', 'id',
            # Attribute / object helpers
            'getattr', 'setattr', 'delattr', 'hasattr', 'callable',
            'isinstance', 'issubclass', 'super', 'property',
            'staticmethod', 'classmethod',
            # I/O and misc
            'print', 'input', 'open',
            'globals', 'locals', 'vars', 'dir',
            'exec', 'eval', 'compile', 'breakpoint', '__import__',
        ]
        func_names = {}
        for func_name in builtin_funcs:
            stable_id = -200 - len(builtins)
            func_val = SymbolicValue(ValueTag.OBJ, z3.IntVal(stable_id))
            builtins[func_name] = func_val
            func_names[stable_id] = func_name
            func_names[id(func_val)] = func_name

        return builtins, func_names

    def load_code(self, code: types.CodeType) -> SymbolicPath:
        """
        Initialize symbolic execution with a code object.
        
        Returns initial symbolic path.
        """
        builtins, func_names = self.make_default_builtins()
        
        # Initialize heap early for string allocation
        heap = SymbolicHeap()
        
        # Initialize globals with common module-level attributes
        # This prevents NameError for standard module attributes and enables
        # idioms like `if __name__ == "__main__"` to execute symbolically
        globals_dict = {}
        
        # __name__: symbolic string representing the module name
        # Could be "__main__" or any module name
        # CRITICAL FIX: Make this truly symbolic so both branches of
        # `if __name__ == "__main__":` are explored
        # Allocate two possible string values: "__main__" and other module names
        main_str_id = heap.allocate_string("__main__")
        other_str_id = heap.allocate_string("__symbolic_module__")
        # Create a symbolic choice between the two
        name_symbolic = z3.Int('__name__')
        # This allows the solver to explore both possibilities
        globals_dict['__name__'] = SymbolicValue(ValueTag.STR, name_symbolic)
        
        # __file__: symbolic string representing the file path
        file_obj_id = heap.allocate_string("__symbolic_file__.py")
        globals_dict['__file__'] = SymbolicValue(ValueTag.STR, z3.IntVal(file_obj_id))
        
        # __package__: symbolic string for package name (or None for top-level)
        globals_dict['__package__'] = SymbolicValue(ValueTag.NONE, z3.IntVal(0))
        
        # __doc__: module docstring (symbolic string or None)
        globals_dict['__doc__'] = SymbolicValue(ValueTag.NONE, z3.IntVal(0))
        
        # __cached__: path to cached bytecode (symbolic string or None)
        globals_dict['__cached__'] = SymbolicValue(ValueTag.NONE, z3.IntVal(0))
        
        # __spec__: module spec object (symbolic object)
        globals_dict['__spec__'] = SymbolicValue(ValueTag.OBJ, z3.IntVal(-9000))
        
        # __loader__: module loader object (symbolic object)
        globals_dict['__loader__'] = SymbolicValue(ValueTag.OBJ, z3.IntVal(-9001))
        
        frame = SymbolicFrame(
            code=code,
            instruction_offset=0,
            locals={},
            globals=globals_dict,
            builtins=builtins,
            operand_stack=[]
        )
        
        # Initialize security tracking (barrier-certificate-theory.md §11)
        ensure_security_contracts_initialized()
        security_tracker = SecurityTracker()
        
        state = SymbolicMachineState(
            frame_stack=[frame],
            heap=heap,
            path_condition=z3.BoolVal(True),
            func_names=func_names,
            security_tracker=security_tracker
        )
        
        # ITERATION 569: Pre-populate user_functions by extracting all function code objects
        # from the module's constants. This allows function inlining to work even before
        # MAKE_FUNCTION is executed during symbolic execution.
        # This is critical for analyzing code like:
        #   def hash_password(password): return bcrypt.hashpw(...)
        #   def register(user, pwd): return hash_password(pwd)
        #   register(sys.argv[1], sys.argv[2])
        # where we need hash_password to be available when analyzing register.
        self._prepopulate_user_functions(state, code)
        
        return SymbolicPath(state=state, trace=[f"START: {code.co_name}"])
    
    def _prepopulate_user_functions(self, state: 'SymbolicMachineState', code: types.CodeType):
        """
        Pre-populate state.user_functions by extracting all function code objects from
        the module's constants. This makes functions available for inlining even before
        their MAKE_FUNCTION instruction is executed during symbolic execution.
        
        ITERATION 569: This fixes the issue where hash_password() is defined at module level
        but isn't available when inlining register() because MAKE_FUNCTION hasn't executed yet.
        
        Args:
            state: The symbolic machine state to populate
            code: The module-level code object to extract functions from
        """
        # Recursively extract all function code objects from constants
        def extract_functions(code_obj: types.CodeType, prefix: str = ""):
            """Recursively find all function code objects in a code object's constants."""
            for const in code_obj.co_consts:
                if isinstance(const, types.CodeType):
                    # This is a code object - check if it's a function (not a class or comprehension)
                    if const.co_name not in ('<module>', '<listcomp>', '<dictcomp>', '<setcomp>', '<genexpr>'):
                        # Generate a stable ID for this function based on its name and location
                        # Use the code object's id() as the stable ID
                        func_id = id(const)
                        
                        # Register the function
                        qualified_name = f"{prefix}.{const.co_name}" if prefix else const.co_name
                        state.user_functions[func_id] = {
                            'code': const,
                            'name': const.co_name,
                            'qualified_name': qualified_name,
                            'filename': const.co_filename,
                            'is_generator': bool(const.co_flags & 0x20),
                            'is_coroutine': bool(const.co_flags & 0x80),
                        }
                        
                        # Recursively extract nested functions
                        extract_functions(const, qualified_name)
        
        # Extract all functions from the module
        extract_functions(code)
    
    def step(self, path: SymbolicPath) -> List[SymbolicPath]:
        """
        Execute one symbolic instruction step.
        
        Returns list of successor paths (may branch on conditionals).
        Handles exception propagation via exception table.
        Integrates intraprocedural analysis for guard propagation.
        """
        state = path.state
        
        if state.halted:
            return [path]
        
        frame = state.current_frame
        if not frame:
            state.halted = True
            return [path]
        
        code = frame.code
        if frame.instruction_offset >= len(code.co_code):
            state.halted = True
            return [path]
        
        instruction = self._get_instruction(frame)
        if not instruction:
            state.halted = True
            return [path]
        
        # ====================================================================
        # INTRAPROCEDURAL ANALYSIS INTEGRATION
        # Update guards from dataflow analysis at this program point
        # ====================================================================
        state.update_guards_from_analysis(code, instruction.offset)
        
        # Track exception state before execution to detect both NEW exceptions
        # and exception CHANGES (e.g., UnboundLocalError raised inside a
        # ValueError handler body).
        exception_before = state.exception  # None, or the exception type string
        had_exception_before = exception_before is not None
        
        # If there's already an unhandled exception, dispatch to handler.
        # Following the CPython 3.11 model: unwind stack, push exception value
        # onto stack, clear state.exception, jump to handler.  This allows
        # PUSH_EXC_INFO to read the exception from the stack, and subsequent
        # handler body instructions execute with a clean exception state.
        if had_exception_before:
            # Look for exception handler (any depth)
            handler_info = self._get_exception_handler_info(code, instruction.offset, any_depth=True)
            if handler_info is not None:
                handler_offset, handler_depth, handler_lasti = handler_info
                # Unwind operand stack to the specified depth
                if len(frame.operand_stack) > handler_depth:
                    frame.operand_stack = frame.operand_stack[:handler_depth]
                if handler_lasti:
                    frame.operand_stack.append(
                        SymbolicValue(ValueTag.INT, z3.IntVal(instruction.offset))
                    )
                # Push exception value onto stack (CPython model)
                exc_val = SymbolicValue(ValueTag.OBJ, z3.IntVal(-2))
                exc_val._exception_type = state.exception
                frame.operand_stack.append(exc_val)
                # Establish catch guard and clear state.exception
                state.set_guard("catch", state.exception)
                state.exception = None
                # Jump to exception handler
                frame.instruction_offset = handler_offset
                path.trace.append(f"  -> EXCEPTION {exception_before}, jumping to handler at {handler_offset}")
                # Update tracking
                exception_before = None
                had_exception_before = False
            else:
                # No handler found - this path is done, halt to prevent infinite loop
                state.halted = True
                path.trace.append(f"  -> UNHANDLED EXCEPTION: {state.exception} (halting)")
                return [path]
        
        try:
            # ================================================================
            # ITERATION 348: Comprehensive Execution Trace Logging
            # ================================================================
            import os
            EXEC_TRACE = os.environ.get('EXEC_TRACE') == '1'
            
            if EXEC_TRACE:
                print(f"\n[EXEC] {instruction.offset:4d}: {instruction.opname:25s} {instruction.argrepr}")
                print(f"       Stack depth: {len(frame.operand_stack)}")
                
                # Log specific operations for σ-taint debugging
                if instruction.opname in ('STORE_FAST', 'STORE_NAME'):
                    # Get the variable name
                    var_name = instruction.argval if hasattr(instruction, 'argval') else instruction.argrepr
                    if len(frame.operand_stack) > 0:
                        val = frame.operand_stack[-1]
                        # Get taint label if available
                        taint_str = "no_taint"
                        if hasattr(state, 'security_tracker') and state.security_tracker:
                            val_id = id(val)
                            if val_id in state.security_tracker.value_labels:
                                label = state.security_tracker.value_labels[val_id]
                                taint_str = f"τ={label.tau:016b} κ={label.kappa:032b} σ={label.sigma:016b}"
                        print(f"       -> Storing to '{var_name}': {taint_str}")
                
                elif instruction.opname in ('LOAD_FAST', 'LOAD_NAME'):
                    # Get the variable name
                    var_name = instruction.argval if hasattr(instruction, 'argval') else instruction.argrepr
                    print(f"       -> Loading from '{var_name}'")
                    # After execution, we'll log the taint of the loaded value
                    
                elif instruction.opname == 'IMPORT_NAME':
                    module_name = instruction.argval if hasattr(instruction, 'argval') else instruction.argrepr
                    print(f"       -> Importing module '{module_name}'")
                
                elif instruction.opname in ('CALL', 'CALL_KW'):
                    # Log function name if available
                    if hasattr(state, 'security_tracker') and state.security_tracker:
                        # Will log sink detection after execution
                        print(f"       -> About to call function")
            
            # ITERATION 256: Log CALL instruction execution
            if instruction.opname in ('CALL', 'CALL_KW') and self.verbose:
                print(f"[VM STEP] Executing {instruction.opname} at offset {instruction.offset}")
                print(f"  Stack size: {len(frame.operand_stack)}")
                if len(frame.operand_stack) >= 3:
                    print(f"  Top of stack: {frame.operand_stack[-3:]}")
            
            # Increment per-instruction step counter (k-step reachability index).
            # Skip counting annotation bookkeeping instructions (Python 3.14 PEP 649)
            # so that type annotations don't consume the exploration budget.
            _annotation_bookkeeping = (
                instruction.opname == 'SETUP_ANNOTATIONS'
                or (instruction.opname == 'STORE_NAME' and instruction.argval in ('__annotate__', '__annotations__', '__conditional_annotations__'))
                or (instruction.opname == 'LOAD_NAME' and instruction.argval == '__conditional_annotations__')
                or (instruction.opname == 'SET_ADD' and hasattr(frame, 'locals') and '__conditional_annotations__' in getattr(frame, 'locals', {}))
            )
            if not _annotation_bookkeeping:
                state.step_count += 1

            self._execute_instruction(state, frame, instruction)
            path.trace.append(f"{instruction.offset:4d}: {instruction.opname} {instruction.argrepr}")
            
            # ================================================================
            # ITERATION 348: Post-execution trace logging
            # ================================================================
            if EXEC_TRACE:
                # Log loaded value taint
                if instruction.opname in ('LOAD_FAST', 'LOAD_NAME') and len(frame.operand_stack) > 0:
                    val = frame.operand_stack[-1]
                    taint_str = "no_taint"
                    if hasattr(state, 'security_tracker') and state.security_tracker:
                        val_id = id(val)
                        if val_id in state.security_tracker.value_labels:
                            label = state.security_tracker.value_labels[val_id]
                            taint_str = f"τ={label.tau:016b} κ={label.kappa:032b} σ={label.sigma:016b}"
                    print(f"       <- Loaded value: {taint_str}")
                
                # Log binary subscript (dict access) for σ-taint
                if instruction.opname == 'BINARY_SUBSCR' and len(frame.operand_stack) > 0:
                    val = frame.operand_stack[-1]
                    taint_str = "no_taint"
                    if hasattr(state, 'security_tracker') and state.security_tracker:
                        val_id = id(val)
                        if val_id in state.security_tracker.value_labels:
                            label = state.security_tracker.value_labels[val_id]
                            taint_str = f"τ={label.tau:016b} κ={label.kappa:032b} σ={label.sigma:016b}"
                    print(f"       <- Subscript result: {taint_str}")
                
                # Log CALL completion with sink detection
                if instruction.opname in ('CALL', 'CALL_KW'):
                    # Check if a sink was detected
                    if hasattr(state, 'security_violations') and state.security_violations:
                        print(f"       <- SECURITY VIOLATION DETECTED: {len(state.security_violations)} violation(s)")
                        for v in state.security_violations:
                            print(f"          {v}")
                    else:
                        print(f"       <- Call completed, no violations")
            
            # ITERATION 256: Log CALL completion
            if instruction.opname in ('CALL', 'CALL_KW') and self.verbose:
                print(f"[VM STEP] Completed {instruction.opname} at offset {instruction.offset}")
            
            # ================================================================
            # SECURITY TAINT PROPAGATION (§11): Post-instruction hook
            # ================================================================
            self._propagate_security_taints(state, frame, instruction)
            
            # ================================================================
            # GUARD TRACKING: Detect guard-establishing patterns
            # ================================================================
            self._track_guard_patterns(state, frame, instruction)
            
            # ================================================================
            # SPECULATIVE CATCH GUARD: If a new exception was raised by this
            # instruction AND a handler exists for it, pre-set the catch guard.
            # This prevents the analyzer's per-step bug check from flagging
            # caught exceptions as bugs before the handler dispatch runs
            # (which normally happens at the start of the NEXT step).
            # Also check parent frames (caller's try/except) for interprocedural
            # exception handling (e.g., callee raises, caller catches).
            # ================================================================
            exception_is_new = (state.exception is not None and not had_exception_before)
            exception_changed = (state.exception is not None and had_exception_before
                                 and state.exception != exception_before)
            if exception_is_new or exception_changed:
                found_handler = False
                # Check current frame first
                handler_info = self._get_exception_handler_info(frame.code, instruction.offset)
                if handler_info is not None:
                    found_handler = True
                else:
                    # Check parent frames (caller's try/except)
                    for parent_frame in reversed(state.frame_stack[:-1]):
                        parent_handler = self._get_exception_handler_info(
                            parent_frame.code, parent_frame.instruction_offset
                        )
                        if parent_handler is not None:
                            found_handler = True
                            break
                if found_handler:
                    state.set_guard("catch", state.exception)
            
            # ================================================================
            # RELATIONAL CASE PATH FORKING: Handle nondeterministic contracts
            # ================================================================
            if hasattr(state, 'fork_relational_cases') and state.fork_relational_cases:
                # Multiple relational cases matched (nondeterministic choice)
                # Fork paths for each alternative case
                import copy
                
                # Capture and clear fork info BEFORE deepcopy to prevent re-forking
                fork_cases = state.fork_relational_cases
                del state.fork_relational_cases
                # Also clear any fork_exception_types to prevent leaking to alt states
                saved_fork_exc = getattr(state, 'fork_exception_types', [])
                state.fork_exception_types = []
                
                alternative_paths = []
                # Skip the first case (already applied to current state in _apply_relational_summary)
                for case_info in fork_cases[1:]:
                    # Deep copy state (fork info already cleared, preventing re-fork)
                    alt_state = copy.deepcopy(state)
                    
                    # Apply the alternative case's postcondition
                    case = case_info['case']
                    args = case_info['args']
                    func_name = case_info['func_name']
                    fresh_id = case_info['fresh_id']
                    
                    # Get postcondition for this alternative
                    post = case.post(alt_state, args, fresh_id)
                    
                    # Clear any exception from the primary path before applying
                    alt_state.exception = None
                    
                    # Apply postcondition to alternative state
                    self._apply_postcondition(alt_state, post, func_name, case)
                    
                    # Handle the return value on the stack
                    # The primary case left a return value on the stack
                    # We need to replace it with the alternative case's return value
                    if alt_state.frame_stack:
                        alt_frame = alt_state.frame_stack[-1]
                        if len(alt_frame.operand_stack) > 0:
                            # Remove the primary return value
                            alt_frame.operand_stack.pop()
                            
                            # Push the alternative return value (if not an exception case)
                            if post.return_value is not None:
                                alt_frame.operand_stack.append(post.return_value)
                            # If post.return_value is None (exception case), don't push anything
                            # The exception is already set in alt_state by _apply_postcondition
                    
                    # If this alternative has an exception, handle it now
                    if alt_state.exception:
                        # Look for exception handler
                        handler_offset = self._get_exception_handler(frame.code, instruction.offset)
                        if handler_offset is not None:
                            # Jump to exception handler and establish catch guard
                            alt_state.frame_stack[-1].instruction_offset = handler_offset
                            alt_state.set_guard("catch", alt_state.exception)
                            alt_path_desc = f"  -> FORK: Alternative outcome '{case.name}' for {func_name} (exception -> handler at {handler_offset})"
                        else:
                            # No handler, this path will terminate with unhandled exception
                            alt_path_desc = f"  -> FORK: Alternative outcome '{case.name}' for {func_name} (unhandled exception)"
                    else:
                        # Success path, continues normally
                        alt_path_desc = f"  -> FORK: Alternative outcome '{case.name}' for {func_name}"
                    
                    # Create alternative path
                    alt_path = SymbolicPath(alt_state)
                    alt_path.trace = path.trace.copy()
                    alt_path.trace.append(alt_path_desc)
                    
                    alternative_paths.append(alt_path)
                
                # Restore fork_exception_types on primary state (they'll be
                # processed in the next check below)
                if saved_fork_exc:
                    state.fork_exception_types = saved_fork_exc
                
                # Return primary path + all alternative paths
                # Primary path continues normally with first case already applied
                return [path] + alternative_paths
            
            # ================================================================
            # EXCEPTION PATH FORKING: Handle may_raise from contracts
            # ================================================================
            MAX_EXCEPTION_FORK_DEPTH = 1  # Allow at most 1 level of exception forking
            if hasattr(state, 'fork_exception_types') and state.fork_exception_types:
                # Capture fork info BEFORE clearing (needed for trace messages)
                fork_func_name = getattr(state, 'fork_function_name', 'unknown')
                fork_case_name = getattr(state, 'fork_case_name', '')
                fork_exc_types = list(state.fork_exception_types)
                
                # Clear fork info on primary state FIRST to prevent re-fork
                state.fork_exception_types = []
                if hasattr(state, 'fork_function_name'):
                    del state.fork_function_name
                if hasattr(state, 'fork_case_name'):
                    del state.fork_case_name
                
                # Skip exception forking if we're already too deep in exception paths
                if state.exception_fork_depth >= MAX_EXCEPTION_FORK_DEPTH:
                    # Don't create more exception forks — just continue on
                    # the success path to avoid exponential path explosion
                    return [path]
                
                # Create forked paths for each exception type
                exception_paths = []
                for exc_type in fork_exc_types:
                    # Deep copy state for exception path
                    # CRITICAL: fork info is already cleared on state, so deepcopy
                    # won't carry fork_exception_types to the new state (prevents
                    # exponential re-forking at every subsequent step)
                    import copy
                    exc_state = copy.deepcopy(state)
                    exc_state.exception = exc_type
                    exc_state.exception_fork_depth += 1  # Track nesting depth
                    
                    # Mark specific bug types
                    if exc_type == "ValueError":
                        if fork_case_name and 'domain' in fork_case_name.lower():
                            exc_state.fp_domain_error_reached = True
                            exc_state.domain_error_context = f"{fork_func_name}: {fork_case_name}"
                    elif exc_type == "TypeError":
                        exc_state.type_confusion_reached = True
                    
                    # Look for exception handler in the current frame
                    handler_info = self._get_exception_handler_info(frame.code, instruction.offset)
                    if handler_info is not None:
                        handler_offset, handler_depth, handler_lasti = handler_info
                        # Truncate operand stack to the correct depth specified
                        # by the exception table.  The success path pushed the
                        # call result onto the stack, but on the exception path
                        # the call never returned — the stack must be unwound.
                        exc_frame = exc_state.frame_stack[-1]
                        if len(exc_frame.operand_stack) > handler_depth:
                            exc_frame.operand_stack = exc_frame.operand_stack[:handler_depth]
                        # If lasti, push the faulting instruction offset
                        if handler_lasti:
                            exc_frame.operand_stack.append(
                                SymbolicValue(ValueTag.INT, z3.IntVal(instruction.offset))
                            )
                        # Push exception value onto stack (CPython model)
                        exc_val = SymbolicValue(ValueTag.OBJ, z3.IntVal(-2))
                        exc_val._exception_type = exc_type
                        exc_frame.operand_stack.append(exc_val)
                        # Jump to exception handler, set catch guard, clear exception
                        exc_frame.instruction_offset = handler_offset
                        exc_state.set_guard("catch", exc_type)
                        exc_state.exception = None  # Exception is on the stack now
                        fork_desc = f"  -> FORK: {exc_type} from {fork_func_name} (handled at {handler_offset}, stack depth {handler_depth})"
                    else:
                        fork_desc = f"  -> FORK: {exc_type} from {fork_func_name} (unhandled)"
                    
                    # Create exception path with the same trace up to this point
                    exc_path = SymbolicPath(exc_state)
                    exc_path.trace = path.trace.copy()
                    exc_path.trace.append(fork_desc)
                    
                    exception_paths.append(exc_path)
                
                # Return both success path and exception paths
                # Success path continues normally
                return [path] + exception_paths
            
            # ================================================================
            # CONDITIONAL BRANCH FORKING: Handle both branches when feasible
            # ================================================================
            if hasattr(state, 'fork_branch_successors') and state.fork_branch_successors:
                # Create forked paths for alternative branch
                branch_paths = []
                
                # ITERATION 256: Log fork processing
                if self.verbose:
                    print(f"[STEP] Processing {len(state.fork_branch_successors)} forked branches")
                
                for i, branch_state in enumerate(state.fork_branch_successors):
                    # Create path for alternative branch with same trace up to this point
                    branch_path = SymbolicPath(branch_state)
                    branch_path.trace = path.trace.copy()
                    branch_path.trace.append(f"  -> FORK: Exploring alternative branch")
                    
                    # ITERATION 256: Log branch path details
                    if self.verbose:
                        branch_offset = branch_state.frame_stack[-1].instruction_offset if branch_state.frame_stack else None
                        print(f"[STEP] Fork {i}: Created branch_path with offset {branch_offset}")
                    
                    branch_paths.append(branch_path)
                
                # Clear fork info
                state.fork_branch_successors = []
                
                # ITERATION 256: Log return
                if self.verbose:
                    print(f"[STEP] Returning {len([path] + branch_paths)} paths (1 current + {len(branch_paths)} forks)")
                
                # Return both current path and alternative branch paths
                # Current path continues with one branch, alternative with the other
                return [path] + branch_paths
            
            # After instruction execution, check if exception was newly raised
            # or changed (e.g., UnboundLocalError inside a ValueError handler)
            exception_is_new = (state.exception and not had_exception_before)
            exception_changed = (state.exception and had_exception_before 
                                 and state.exception != exception_before)
            if exception_is_new or exception_changed:
                # Look for exception handler (with depth info for stack unwinding)
                # Use any_depth=True to find handlers at any nesting level (e.g.,
                # exceptions raised inside a handler body have depth > 0)
                handler_info = self._get_exception_handler_info(code, instruction.offset, any_depth=True)
                if handler_info is not None:
                    handler_offset, handler_depth, handler_lasti = handler_info
                    # Unwind operand stack to the depth specified by exception table
                    if len(frame.operand_stack) > handler_depth:
                        frame.operand_stack = frame.operand_stack[:handler_depth]
                    # If lasti, push the faulting instruction offset
                    if handler_lasti:
                        frame.operand_stack.append(
                            SymbolicValue(ValueTag.INT, z3.IntVal(instruction.offset))
                        )
                    # Push exception value onto stack (CPython model)
                    exc_val = SymbolicValue(ValueTag.OBJ, z3.IntVal(-2))
                    exc_val._exception_type = state.exception
                    frame.operand_stack.append(exc_val)
                    # Jump to exception handler
                    frame.instruction_offset = handler_offset
                    path.trace.append(f"  -> EXCEPTION {state.exception}, jumping to handler at {handler_offset} (stack depth {handler_depth})")
                    # Set catch guard only on the PRIMARY execution path
                    # (exception_fork_depth == 0).  On exception fork paths
                    # (already inside a handler body), secondary exceptions
                    # are real bugs that should NOT be suppressed.
                    # Example: DIV_ZERO/tn_03 — primary path, ZeroDivisionError
                    #   caught by except clause → set catch guard → SAFE ✓
                    # Example: UNINIT_MEMORY/tp_04 — exception fork path,
                    #   UnboundLocalError in ValueError handler → no catch
                    #   guard → detected as BUG ✓
                    if state.exception_fork_depth == 0:
                        state.set_guard("catch", state.exception)
                    # Clear state.exception — it's now on the stack
                    state.exception = None
                else:
                    # No handler, exception propagates
                    # Mark this as unhandled and halt execution
                    path.trace.append(f"  -> UNHANDLED EXCEPTION: {state.exception}")
                    # Don't advance instruction pointer - this path is done
                    return [path]
        
        except NotImplementedError as e:
            # Mark the path as having hit an unimplemented opcode.
            # Crucially, do NOT set state.exception — that would make downstream
            # PANIC detection treat this as a real runtime exception and report a
            # false-positive BUG.  Instead, flag the state so the analyzer can
            # conservatively return UNKNOWN for this path.
            state.halted = True
            state.unsupported_opcode = str(e)
            # Keep exception_is_specific False so it is NOT classified as PANIC
            path.trace.append(f"{instruction.offset:4d}: {instruction.opname} -> UNSUPPORTED: {e} (path halted, not a bug)")
        
        return [path]
    
    def _track_guard_patterns(
        self,
        state: SymbolicMachineState,
        frame: SymbolicFrame,
        instruction
    ):
        """
        Track guard-establishing patterns during execution.
        
        Detects patterns like:
        - 'if x is not None:' -> g_nonnull(x)
        - 'if isinstance(x, T):' -> g_type(x, T)
        - 'if x != 0:' -> g_div(x)
        - 'if 0 <= i < len(arr):' -> g_bounds(arr, i)
        """
        opname = instruction.opname
        
        # Track IS_OP for None checks
        if opname == 'IS_OP':
            # IS_OP 1 = 'is not', IS_OP 0 = 'is'
            is_not = instruction.arg == 1
            # The stack has [obj, None] and we're comparing
            if len(frame.operand_stack) >= 2:
                obj = frame.operand_stack[-2]
                const = frame.operand_stack[-1]
                # Check if const is None
                if hasattr(const, 'tag') and const.tag == ValueTag.NONE:
                    # This is a None check
                    # The guard is established on the appropriate branch
                    # We track it here; the branch handler will apply it
                    pass
        
        # Track COMPARE_OP for division guards
        if opname == 'COMPARE_OP' and instruction.argval == '!=':
            if len(frame.operand_stack) >= 2:
                left = frame.operand_stack[-2]
                right = frame.operand_stack[-1]
                
                # Check for x != 0 or 0 != x
                if hasattr(right, 'tag') and right.tag == ValueTag.INT:
                    try:
                        if hasattr(right, 'payload') and z3.is_int_value(right.payload):
                            if right.payload.as_long() == 0:
                                # x != 0 pattern
                                # Will be applied on true branch
                                pass
                    except Exception:
                        pass
    
    def explore_bounded(self, code: types.CodeType, max_steps: int = 100) -> List[SymbolicPath]:
        """
        Bounded symbolic execution.
        
        Explores all feasible paths up to max_steps.
        Returns list of completed paths.
        """
        initial_path = self.load_code(code)
        worklist = [initial_path]
        completed = []
        
        steps = 0
        while worklist and steps < max_steps:
            path = worklist.pop(0)
            
            # Complete paths that are halted
            if path.state.halted:
                completed.append(path)
                continue
            
            # Complete paths that have unhandled exceptions
            # An exception is unhandled only if there's no handler available
            # and we're not actively executing handler opcodes
            if path.state.exception:
                # If catch guard is established for this exception, we're inside the
                # handler body — let execution continue through POP_EXCEPT
                if hasattr(path.state, 'has_catch_guard') and path.state.has_catch_guard(path.state.exception):
                    pass  # Inside handler body, continue executing
                else:
                    frame = path.state.current_frame
                    if frame:
                        # Check if current instruction is a handler opcode that might clear the exception
                        instr = self._get_instruction(frame)
                        handler_clearing_opcodes = {'POP_EXCEPT', 'RERAISE', 'CHECK_EXC_MATCH', 'PUSH_EXC_INFO', 'NOT_TAKEN', 'POP_TOP'}
                        if instr and instr.opname in handler_clearing_opcodes:
                            # About to execute a handler opcode or handler body instruction, let it run
                            pass
                        else:
                            # Check if there's a handler available for the current location (any depth)
                            handler = self._get_exception_handler(frame.code, frame.instruction_offset, any_depth=True)
                            if handler is None:
                                # No handler available and not at a handler opcode, exception is unhandled
                                completed.append(path)
                                continue
                        # If handler exists or we're at handler opcode, continue executing
                    else:
                        # No frame, exception is unhandled
                        completed.append(path)
                        continue
            
            # Check path feasibility
            self.solver.push()
            self.solver.add(path.state.path_condition)
            
            # Add heap observer constraints for structural reasoning
            observer_constraints = path.state.heap.constrain_observers()
            for constraint in observer_constraints:
                self.solver.add(constraint)
            
            if self.solver.check() == z3.unsat:
                # Infeasible path, prune
                self.solver.pop()
                continue
            
            self.solver.pop()
            
            # Step and get successors
            successors = self.step(path)
            worklist.extend(successors)
            
            steps += 1
        
        # Add remaining paths
        completed.extend(worklist)
        
        self.paths = completed
        return completed
    
    def _get_instruction(self, frame: SymbolicFrame):
        """Get current instruction from code object."""
        code = frame.code
        offset = frame.instruction_offset
        
        if offset >= len(code.co_code):
            return None

        code_id = id(code)
        mapping = self._instruction_cache.get(code_id)
        if mapping is None:
            mapping = {instr.offset: instr for instr in dis.get_instructions(code)}
            self._instruction_cache[code_id] = mapping

        return mapping.get(offset)
    
    def _infer_attribute_type(self, attr_name: str) -> ValueTag:
        """
        Infer the likely type tag for an attribute based on naming conventions.
        
        This is type-aware havocking: still sound over-approximation (OBJ is valid
        for all types), but provides more precise types for common patterns.
        This enables comparisons like `request.method == "POST"` to be feasible.
        
        Type inference rules:
        - HTTP/web framework attributes (method, path, etc.) → STR
        - Collections (GET, POST, FILES, COOKIES, etc.) → DICT
        - Boolean predicates (is_ajax, is_secure, etc.) → BOOL
        - Fallback → OBJ (generic)
        
        Soundness: These are over-approximations - real values may have these types
        OR be None/other. We handle None separately with Z3 checks. For other cases,
        OBJ fallback maintains soundness.
        """
        from a3_python.z3model.values import ValueTag
        
        # String-valued attributes (HTTP/web framework patterns)
        string_attrs = {
            'method', 'path', 'path_info', 'content_type', 'user_agent',
            'remote_addr', 'remote_host', 'server_name', 'server_protocol',
            'scheme', 'query_string', 'http_host', 'url', 'base_url',
            'encoding', 'charset', 'name', 'filename', 'status_code',
            'reason', 'mimetype', 'protocol', 'command', 'args',
        }
        
        # Dict-valued attributes (HTTP collections, Django/Flask patterns)
        dict_attrs = {
            'GET', 'POST', 'FILES', 'COOKIES', 'SESSION', 'META',
            'headers', 'params', 'form', 'json', 'cookies', 'args',
            'values', 'data', 'environ', 'wsgi_environ',
        }
        
        # Boolean attributes (predicates)
        bool_attrs = {
            'is_ajax', 'is_secure', 'is_authenticated', 'is_staff', 
            'is_superuser', 'is_anonymous', 'is_active', 'debug',
        }
        
        # List-valued attributes
        list_attrs = {
            'items', 'keys', 'urlpatterns', 'middleware',
        }
        
        if attr_name in string_attrs:
            return ValueTag.STR
        elif attr_name in dict_attrs:
            return ValueTag.DICT
        elif attr_name in bool_attrs:
            return ValueTag.BOOL
        elif attr_name in list_attrs:
            return ValueTag.LIST
        else:
            # Default: OBJ (generic, maximally imprecise but sound)
            return ValueTag.OBJ
    
    def _next_offset(self, frame: SymbolicFrame, instr) -> int:
        """Compute the next instruction offset."""
        code = frame.code
        
        # Use a SEPARATE cache from _instruction_cache (which stores offset→Instruction).
        # This cache stores offset→next_offset (int→int).
        cache_key = id(code)
        if not hasattr(self, '_next_offset_cache'):
            self._next_offset_cache = {}
        
        if cache_key not in self._next_offset_cache:
            instructions = list(dis.get_instructions(code))
            # Build offset -> next_offset map for O(1) lookup
            offset_map = {}
            for i, inst in enumerate(instructions):
                if i + 1 < len(instructions):
                    offset_map[inst.offset] = instructions[i + 1].offset
                else:
                    offset_map[inst.offset] = len(code.co_code)
            self._next_offset_cache[cache_key] = offset_map
        
        offset_map = self._next_offset_cache[cache_key]
        return offset_map.get(instr.offset, instr.offset + 2)
    
    def _set_security_detection_flag(self, state: SymbolicMachineState, violation):
        """
        Map a security violation to the appropriate state detection flag.
        
        This enables the unsafe region predicates to detect the violation
        when checking the state (barrier-certificate-theory.md §11, leak_theory.md).
        
        Uses the new taint lattice SinkType from taint_lattice.py.
        """
        from a3_python.z3model.taint_lattice import SinkType
        
        sink_type = violation.sink_type
        state.security_violations.append(violation)

        # Provenance: this violation was discovered along a satisfiable symbolic
        # execution path in the contracted semantics (PTS_R). This is reporting
        # metadata only and must not affect BUG/SAFE/UNKNOWN semantics.
        try:
            from a3_python.confidence_interval import ReachabilityIntervalPTS
            violation.reachability_pts = ReachabilityIntervalPTS.reachable(
                evidence=["witness=symbolic_pts", f"at={violation.sink_location}"]
            )
            violation.depth_k = state.step_count
        except Exception:
            pass
        
        # Map new lattice SinkType to state flags
        if sink_type == SinkType.SQL_EXECUTE:
            state.sql_injection_detected = True
        elif sink_type == SinkType.COMMAND_SHELL:
            state.command_injection_detected = True
        elif sink_type == SinkType.CODE_EVAL:
            state.code_injection_detected = True
        elif sink_type == SinkType.FILE_PATH:
            state.path_injection_detected = True
        elif sink_type in (SinkType.HTML_OUTPUT, SinkType.TEMPLATE_RENDER):
            state.xss_detected = True
        elif sink_type == SinkType.HTTP_REQUEST:
            state.ssrf_detected = True
        elif sink_type == SinkType.DESERIALIZE:
            state.deserialization_detected = True
        elif sink_type == SinkType.XML_PARSE:
            state.xxe_detected = True
        elif sink_type == SinkType.LOG_OUTPUT:
            state.cleartext_logging_detected = True
        elif sink_type == SinkType.FILE_WRITE:
            state.cleartext_storage_detected = True
        elif sink_type == SinkType.LDAP_QUERY:
            if not hasattr(state, 'ldap_injection_detected'):
                state.ldap_injection_detected = False
            state.ldap_injection_detected = True
        elif sink_type == SinkType.XPATH_QUERY:
            if not hasattr(state, 'xpath_injection_detected'):
                state.xpath_injection_detected = False
            state.xpath_injection_detected = True
        elif sink_type == SinkType.NOSQL_QUERY:
            if not hasattr(state, 'nosql_injection_detected'):
                state.nosql_injection_detected = False
            state.nosql_injection_detected = True
        elif sink_type == SinkType.REGEX_PATTERN:
            if not hasattr(state, 'regex_injection_detected'):
                state.regex_injection_detected = False
            state.regex_injection_detected = True
        elif sink_type == SinkType.REDIRECT_URL:
            if not hasattr(state, 'redirect_detected'):
                state.redirect_detected = False
            state.redirect_detected = True
        elif sink_type == SinkType.HEADER_SET:
            if not hasattr(state, 'header_injection_detected'):
                state.header_injection_detected = False
            state.header_injection_detected = True
        elif sink_type == SinkType.LOG_FORGING:
            if not hasattr(state, 'log_injection_detected'):
                state.log_injection_detected = False
            state.log_injection_detected = True
        elif sink_type == SinkType.CRYPTO_WEAK:
            if not hasattr(state, 'weak_crypto_detected'):
                state.weak_crypto_detected = False
            state.weak_crypto_detected = True

    def _propagate_security_taints(self, state: SymbolicMachineState, frame: SymbolicFrame, instruction):
        """
        Propagate taint through operations (barrier-certificate-theory.md §11).
        
        Called after each instruction to maintain taint tracking invariants.
        This handles taint propagation for BINARY_OP, UNARY_*, and BINARY_SUBSCR.
        
        Rule: τ(result) = τ(op1) ∨ τ(op2), σ(result) = σ(op1) ∨ σ(op2)
        """
        if not state.security_tracker:
            return
        
        opname = instruction.opname
        
        # For BINARY_OP: result on TOS was computed from left and right operands
        # We need to track which values were involved, but they were popped
        # The cleanest approach is to record the last binary operands during execution
        # For now, we use a simplified approach: mark TOS as tainted if we're in 
        # a context where taint could propagate (e.g., string concatenation with tainted input)
        
        # The deep integration via security_tracker's handle_binop is already called
        # from the CALL handler for taint-relevant operations like str.format()
        # This hook is for catching low-level operations
        
        if opname == "BINARY_OP":
            # Taint propagation for binary ops is challenging because operands are popped
            # A full implementation would record operands before the instruction
            # For now, this is a placeholder for future enhancement
            pass
        
        elif opname in ("UNARY_NEGATIVE", "UNARY_POSITIVE", "UNARY_NOT", "UNARY_INVERT"):
            # Unary operations preserve taint from operand to result
            # Similar challenge: operand is popped before we can track it
            pass
        
        elif opname == "BUILD_STRING":
            # String building: result is tainted if any component is tainted
            # This is where format strings or f-strings could propagate taint
            if frame.operand_stack:
                result = frame.operand_stack[-1]
                # Check if any recently used values were tainted
                # For simplicity, if the result is a string built from tainted parts,
                # it should inherit taint (handled in BUILD_STRING in _execute_instruction)
                pass

    def _get_variable_name_for_value(self, state: SymbolicMachineState, value: SymbolicValue) -> Optional[str]:
        """
        Try to recover the variable name associated with a symbolic value.
        
        This is used for intraprocedural analysis integration - when we need to
        check if a guard has been established for a particular value, we need
        to know which variable it came from.
        
        Returns the variable name if found, None otherwise.
        """
        if not state.frame_stack:
            return None
        
        frame = state.frame_stack[-1]
        
        # Check locals
        for var_name, var_value in frame.locals.items():
            if var_value is value or (hasattr(var_value, 'payload') and 
                                       hasattr(value, 'payload') and
                                       var_value.payload is value.payload):
                return var_name
        
        # Check for z3 variable name embedded in payload
        if hasattr(value, 'payload') and isinstance(value.payload, z3.ExprRef):
            payload_str = str(value.payload)
            # Parse patterns like "local_x", "param_x", etc.
            for prefix in ['local_', 'param_', 'arg_']:
                if payload_str.startswith(prefix):
                    return payload_str[len(prefix):]
            # Also check z3_variable_map
            for var_name, z3_expr in state.z3_variable_map.items():
                if z3.eq(z3_expr, value.payload):
                    return var_name
        
        return None
    
    def _get_exception_handler(self, code: types.CodeType, offset: int, any_depth: bool = False):
        """
        Get exception handler target for a given instruction offset.
        
        Returns handler offset if there's an active exception handler, None otherwise.
        Uses Python 3.11+ exception table.
        
        If any_depth=True, returns handler at any depth (including cleanup handlers).
        If any_depth=False (default), only returns depth 0 handlers (main exception handlers).
        """
        # Access exception table if available (Python 3.11+)
        if not hasattr(code, 'co_exceptiontable') or code.co_exceptiontable is None:
            return None
        
        # Parse exception table using dis module helper
        import sys
        if sys.version_info >= (3, 11):
            try:
                from dis import _parse_exception_table
                # The exception table yields tuples: (start, end, target, depth, lasti)
                for start, end, target, depth, lasti in _parse_exception_table(code):
                    # Check if the offset is within the exception handler range
                    if start <= offset < end:
                        if any_depth or depth == 0:
                            return target
            except Exception:
                pass
        
        return None

    def _get_exception_handler_info(self, code: types.CodeType, offset: int, any_depth: bool = False):
        """
        Get full exception handler info for a given instruction offset.
        
        Returns (target, depth, lasti) tuple if there's an active exception handler,
        None otherwise.  Uses Python 3.11+ exception table.
        
        - target: handler offset to jump to
        - depth: expected operand stack depth at handler entry
        - lasti: whether to push last instruction offset before jumping
        """
        if not hasattr(code, 'co_exceptiontable') or code.co_exceptiontable is None:
            return None
        
        import sys
        if sys.version_info >= (3, 11):
            try:
                from dis import _parse_exception_table
                for start, end, target, depth, lasti in _parse_exception_table(code):
                    if start <= offset < end:
                        if any_depth or depth == 0:
                            return (target, depth, lasti)
            except Exception:
                pass
        
        return None

    def _can_inline_user_function(
        self,
        state: SymbolicMachineState,
        func_meta: dict,
        max_frame_depth: int = 10,
        allow_recursion: bool = False
    ) -> bool:
        """
        Check if a user-defined function can be safely inlined.
        
        Criteria:
        - Not exceeding maximum call depth (prevent infinite recursion)
        - Function is not already on the call stack (prevent direct recursion) unless allow_recursion=True
        - Function body is reasonably sized (prevent explosion)
        - All opcodes in the function are implemented (prevent PANIC from unimplemented opcodes)
        
        Args:
            allow_recursion: If True, allows recursive inlining (Phase 3+)
        
        Returns True if safe to inline, False otherwise.
        """
        # Check call depth limit
        if len(state.frame_stack) >= max_frame_depth:
            return False
        
        # Check for direct recursion: is this function already on the stack?
        # Phase 3: When allow_recursion=True, we permit bounded recursion with ranking functions
        func_code = func_meta['code']
        for frame in state.frame_stack:
            if frame.code is func_code:
                # Direct recursion detected
                if not allow_recursion:
                    return False
        
        # Check function size (number of instructions)
        # Inline only small functions to avoid path explosion
        # Heuristic: up to 50 instructions
        instructions = list(dis.get_instructions(func_code))
        if len(instructions) > 50:
            return False
        
        # Check if all opcodes in the function are supported
        # This prevents us from inlining functions that would hit unimplemented opcodes
        # and cause spurious PANIC bugs
        for instr in instructions:
            opname = instr.opname
            # Check if this opcode is one we have a handler for in step()
            # We could maintain a whitelist, but for now check for known problematic ones
            # These are opcodes that would raise "Opcode X" exceptions in step()
            if opname in [
                # Python 3.14 specific opcodes that may not be implemented yet
                'LOAD_CONST_LOAD_FAST',
                'JUMP_BACKWARD_NO_INTERRUPT',
                'LOAD_CLOSURE',
                'LOAD_FROM_DICT_OR_DEREF',
                'LOAD_FROM_DICT_OR_GLOBALS',
            ]:
                # Known unimplemented opcode - don't inline
                return False
        
        # All checks passed
        return True

    def _inline_user_function(
        self,
        state: SymbolicMachineState,
        func_meta: dict,
        args: List[SymbolicValue],
        func_name: Optional[str] = None,
        func_ref: Optional[SymbolicValue] = None
    ) -> bool:
        """
        Inline a user-defined function by creating a new frame and binding arguments.
        
        This implements simple intra-procedural analysis (Phase 2).
        
        Args:
            state: Current symbolic machine state
            func_meta: Metadata dictionary for the function to inline
            args: Arguments to pass to the function
            func_name: Name of the function being called (for handle_call_post)
            func_ref: Reference to the function object (for handle_call_post)
        
        Returns True if inlining succeeded, False if it should fall back to havoc.
        """
        func_code = func_meta['code']
        
        # Get parameter names from code object
        # co_varnames contains all local variable names; first co_argcount are parameters
        param_count = func_code.co_argcount
        param_names = func_code.co_varnames[:param_count]
        
        # Check argument count matches (simple case: no *args, **kwargs, defaults)
        if len(args) != param_count:
            # Argument count mismatch - can't inline
            return False
        
        # Create a new frame for the function
        new_frame = SymbolicFrame(
            code=func_code,
            instruction_offset=0,
            locals={},
            globals=state.frame_stack[-1].globals.copy(),  # Inherit globals from caller
            builtins=state.frame_stack[-1].builtins.copy(),  # Inherit builtins
            operand_stack=[],
            cells={},
            freevars={},
            call_context={
                'func_name': func_name or func_meta.get('name', '<unknown>'),
                'args': args,
                'func_ref': func_ref
            } if func_name or func_ref else None
        )
        
        # Bind arguments to parameters
        for param_name, arg_value in zip(param_names, args):
            new_frame.locals[param_name] = arg_value
            
            # ITERATION 442: Name-based sensitivity inference for function parameters
            # Infer sensitivity from parameter names to enable cleartext detection
            if state.security_tracker:
                inferred_source = infer_sensitivity_from_name(param_name)
                if inferred_source is not None:
                    from ..z3model.taint_lattice import TaintLabel, kappa_zero
                    current_label = state.security_tracker.get_label(arg_value)
                    new_label = TaintLabel(
                        tau=current_label.tau,
                        kappa=0,
                        sigma=current_label.sigma | (1 << inferred_source),
                        provenance=current_label.provenance | frozenset({inferred_source.name})
                    )
                    state.security_tracker.set_label(arg_value, new_label)
        
        # Push the new frame onto the stack
        state.frame_stack.append(new_frame)
        
        return True
    
    def _execute_class_body(
        self,
        state: SymbolicMachineState,
        class_body_meta: dict,
        namespace_id: int
    ) -> Optional[dict]:
        """
        Execute a class body function to populate the class namespace.
        
        The class body is a function that takes no arguments and uses its
        local variables to define class attributes and methods.
        
        Args:
            state: Current symbolic machine state
            class_body_meta: Metadata for the class body function (from user_functions)
            namespace_id: Heap ID for the class namespace dict
            
        Returns:
            Dictionary of class namespace (locals from class body execution),
            or None if execution failed (sound over-approximation fallback)
        """
        code = class_body_meta['code']
        
        # Create a new frame for class body execution
        class_frame = SymbolicFrame(
            code=code,
            instruction_offset=0,
            locals={},
            operand_stack=[],
            block_stack=[],
            line_number=code.co_firstlineno
        )
        
        # Class body has no arguments, starts with empty locals
        # __name__ and __qualname__ are typically injected by __build_class__
        # For simplicity, we skip these for now (sound over-approximation)
        
        # Execute up to a limited number of instructions (prevent infinite loops)
        max_iterations = 1000
        iterations = 0
        
        while iterations < max_iterations:
            iterations += 1
            
            # Get current instruction
            try:
                instr = self._get_instruction(class_frame)
            except IndexError:
                # Reached end of code without RETURN_VALUE (malformed)
                break
            
            # Check for RETURN_VALUE (class body completion)
            if instr.opname == 'RETURN_VALUE':
                # Class body returns None, locals become class namespace
                # Extract locals and store in class namespace dict
                for var_name, var_value in class_frame.locals.items():
                    # Add to the class namespace dict in the heap
                    if isinstance(var_value, SymbolicValue):
                        # For methods (function objects), store them
                        # For attributes, store their values
                        # Both go into the namespace dict
                        pass  # Heap dict already created, we don't need to populate it for soundness
                
                return class_frame.locals  # Return the locals as class namespace
            
            # Execute the instruction
            try:
                self._execute_instruction(state, class_frame, instr)
            except Exception:
                # If any instruction fails, fall back to sound over-approximation
                return None
            
            # Check for exceptions
            if state.exception:
                # Class body raised exception - this is an error in the class definition
                return None
        
        # Hit iteration limit - possible infinite loop, fall back to sound approximation
        return None
    
    def _analyze_recursion_with_ranking(
        self,
        state: SymbolicMachineState,
        func_meta: dict,
        args: List[SymbolicValue],
        max_recursion_depth: int = 5
    ) -> tuple[bool, Optional[str]]:
        """
        Analyze a recursive function call to determine if it terminates.
        
        Phase 3: Use ranking functions to prove termination of recursive calls.
        
        Strategy:
        1. Identify the recursive parameter (typically: n, i, counter that decreases)
        2. Try to construct a simple ranking function (e.g., R(n) = n)
        3. Check if ranking function decreases on recursive calls
        4. If termination proven, allow bounded inlining
        5. If termination cannot be proven, flag as NON_TERMINATION risk
        
        Args:
            state: Current symbolic machine state
            func_meta: Function metadata (code, name, etc.)
            args: Arguments to the recursive call
            max_recursion_depth: Maximum recursion depth to explore
        
        Returns:
            (terminates, reason) where:
            - terminates: True if we can prove termination via ranking function
            - reason: String explanation of result
        """
        func_code = func_meta['code']
        func_name = func_meta.get('name', '<anonymous>')
        
        # Simple heuristic: for small functions with single parameter, try simple ranking
        param_count = func_code.co_argcount
        
        # Phase 3 limitation: handle simple single-parameter recursion first
        # (e.g., factorial(n), fib(n), countdown(i))
        if param_count != 1:
            # Multi-parameter recursion is more complex (needs lexicographic ranking)
            # For now, report UNKNOWN for multi-parameter recursion
            return False, f"multi_parameter_recursion_{param_count}_params"
        
        if len(args) != 1:
            return False, "argument_mismatch"
        
        # Get the argument value (should be symbolic)
        arg_value = args[0]
        
        # Check if argument is an integer (required for simple ranking)
        # SymbolicValue.tag is a Z3 Int expression; avoid Python boolean coercion.
        try:
            is_int_tag = z3.is_int_value(arg_value.tag) and arg_value.tag.as_long() == ValueTag.INT.value
        except Exception:
            is_int_tag = False
        if not is_int_tag:
            return False, "non_integer_parameter"
        
        # Simple ranking function: R(n) = n
        # For termination, we need:
        # 1. n >= 0 initially (BoundedBelow)
        # 2. Recursive call with n' < n (Decreasing)
        
        # Check if argument could be non-negative
        arg_expr = arg_value.payload
        
        # Try to prove arg >= 0 or detect if it might be negative
        self.solver.push()
        self.solver.add(state.path_condition)
        self.solver.add(arg_expr < 0)
        
        can_be_negative = (self.solver.check() == z3.sat)
        self.solver.pop()
        
        if can_be_negative:
            # Argument can be negative → ranking function n might go to -∞
            # Cannot prove termination with simple ranking
            return False, "argument_can_be_negative"
        
        # Now check if we can prove the recursive call decreases the parameter
        # This requires analyzing the function body to find the recursive call site
        # and checking if the argument there is < current argument
        
        # For Phase 3, we use a simplified approach:
        # - Check call depth (if we've recursed deeply without base case, likely non-terminating)
        # - Count how many times this function appears on the stack
        recursion_count = sum(1 for frame in state.frame_stack if frame.code is func_code)
        
        # If we've recursed beyond a reasonable depth, likely non-terminating
        # or the ranking function is insufficient
        if recursion_count >= max_recursion_depth:
            return False, f"exceeded_depth_{max_recursion_depth}"
        
        # Conservative approximation: if argument is non-negative and not too deep,
        # allow bounded recursion
        # A full implementation would analyze the function body to verify the decreasing property
        
        # For now, we accept simple recursive patterns with non-negative integer parameter
        # and rely on depth bound to prevent infinite loops
        return True, f"simple_ranking_n_depth_{recursion_count}"
    
    def _apply_contract(
        self,
        state: SymbolicMachineState,
        frame: SymbolicFrame,
        contract: Contract,
        args: List[SymbolicValue],
        func_name: str
    ) -> SymbolicValue:
        """
        Apply a function contract to symbolically execute a call.
        
        This models the call as an over-approximating relation R_f,
        ensuring soundness: Sem_f ⊆ R_f.
        
        Returns the symbolic result value (or raises exception in state).
        """
        # Check for INTEGER_OVERFLOW at fixed-width boundary operations
        # struct.pack, array.array, int.to_bytes may raise OverflowError
        if func_name in {"struct.pack", "array.array", "int.to_bytes"}:
            if "OverflowError" in contract.exception_effect.may_raise:
                # These functions perform fixed-width conversions
                # Check if overflow is reachable symbolically
                # For now, we conservatively mark that overflow MAY occur
                # A full implementation would parse format strings and check ranges
                
                # Simplified: if any integer arg could be out of range, flag it
                for arg in args:
                    if arg.tag == ValueTag.INT:
                        arg_expr = arg.payload
                        
                        # Example range checks (would need format string parsing for precision)
                        # For struct.pack with 'b' (signed byte): -128 to 127
                        # For struct.pack with 'B' (unsigned byte): 0 to 255
                        # For struct.pack with 'i' (signed int): -(2**31) to 2**31-1
                        
                        # Conservative: check if value could be outside common ranges
                        # This is simplified; real implementation needs format parsing
                        overflow_possible = None
                        
                        # Check if value could overflow a 32-bit signed int (common case)
                        INT32_MIN = -(2**31)
                        INT32_MAX = 2**31 - 1
                        overflow_possible = z3.Or(arg_expr < INT32_MIN, arg_expr > INT32_MAX)
                        
                        # Check if overflow is reachable on this path
                        self.solver.push()
                        self.solver.add(state.path_condition)
                        self.solver.add(overflow_possible)
                        if self.solver.check() == z3.sat:
                            # INTEGER_OVERFLOW is reachable!
                            state.integer_overflow_reached = True
                            state.overflow_details = {
                                "function": func_name,
                                "reason": "value may be outside fixed-width target range"
                            }
                            state.exception = "OverflowError"
                        self.solver.pop()
                        
                        # If no exception, assume value is in range on this path
                        if not state.exception:
                            state.path_condition = z3.And(state.path_condition, z3.Not(overflow_possible))
        
        # Check domain precondition if present (FP_DOMAIN detection)
        if hasattr(contract.exception_effect, 'domain_precondition') and contract.exception_effect.domain_precondition:
            precond_str = contract.exception_effect.domain_precondition
            
            # Parse simple preconditions for math functions
            # Format: "x >= 0", "x > 0", "-1 <= x <= 1"
            if args and len(args) > 0:
                arg_val = args[0]
                
                # Extract numeric payload if it's an INT or FLOAT
                if arg_val.tag == ValueTag.INT or arg_val.tag == ValueTag.FLOAT:
                    arg_expr = arg_val.payload
                    
                    # Check if precondition can be violated
                    precond_violated = None
                    if precond_str == "x >= 0":
                        precond_violated = arg_expr < 0
                    elif precond_str == "x > 0":
                        precond_violated = arg_expr <= 0
                    elif precond_str == "-1 <= x <= 1":
                        precond_violated = z3.Or(arg_expr < -1, arg_expr > 1)
                    
                    if precond_violated is not None:
                        # Check if precondition violation is reachable
                        self.solver.push()
                        self.solver.add(state.path_condition)
                        self.solver.add(precond_violated)
                        if self.solver.check() == z3.sat:
                            # FP_DOMAIN error is reachable!
                            state.fp_domain_error_reached = True
                            state.domain_error_context = f"{func_name}: precondition '{precond_str}' violated"
                            state.exception = "ValueError"
                        self.solver.pop()
                        
                        # If no exception, assume precondition holds on this path
                        if not state.exception:
                            state.path_condition = z3.And(state.path_condition, z3.Not(precond_violated))
        
        # Check if contract allows exceptions
        if contract.exception_effect.may_raise:
            # For now, we model "may raise" nondeterministically
            # In a full BMC, we would fork paths here
            # For simplicity, we only model the non-exceptional path
            # but note that exceptions are possible
            
            # If may_raise is '*', any exception is possible
            if '*' in contract.exception_effect.may_raise:
                # For havoc contracts, we note that any exception is possible
                # but continue on the non-exception path for this exploration
                pass
            elif contract.exception_effect.may_raise:
                # Specific exceptions may be raised
                # For a complete analysis, we should fork paths here
                # For now, we model the success case
                pass
        
        # Apply heap effects
        if contract.heap_effect.may_write == {'*'}:
            # Havoc: arbitrary heap mutations
            # In a full implementation, we would havoc all heap locations
            # For now, we just mark that heap may be modified
            # (We need to be conservative: no assumptions about heap stability)
            pass
        
        # Generate return value based on contract
        return_constraint = contract.return_constraint
        
        # Create a fresh symbolic value for the return
        if return_constraint.type_constraint == "int":
            # Return a symbolic integer
            sym_int = z3.Int(f"ret_{func_name}_{id(state)}")
            
            # Apply range constraint if present
            if return_constraint.range_constraint:
                min_val, max_val = return_constraint.range_constraint
                if min_val is not None:
                    state.path_condition = z3.And(state.path_condition, sym_int >= min_val)
                if max_val is not None:
                    state.path_condition = z3.And(state.path_condition, sym_int <= max_val)
            
            return SymbolicValue(ValueTag.INT, sym_int)
        
        elif return_constraint.type_constraint == "bool":
            # Return a symbolic boolean
            sym_bool = z3.Bool(f"ret_{func_name}_{id(state)}")
            return SymbolicValue(ValueTag.BOOL, sym_bool)
        
        elif return_constraint.type_constraint == "str":
            # Return a symbolic string object
            obj_id = state.heap.allocate_string("")  # Placeholder
            return SymbolicValue(ValueTag.STR, z3.IntVal(obj_id))
        
        elif return_constraint.type_constraint == "numeric":
            # Could be int or float; for now return symbolic int
            sym_int = z3.Int(f"ret_{func_name}_{id(state)}")
            if return_constraint.range_constraint:
                min_val, max_val = return_constraint.range_constraint
                if min_val is not None:
                    state.path_condition = z3.And(state.path_condition, sym_int >= min_val)
                if max_val is not None:
                    state.path_condition = z3.And(state.path_condition, sym_int <= max_val)
            return SymbolicValue(ValueTag.INT, sym_int)
        
        elif return_constraint.type_constraint == "dict":
            # Return a symbolic dict object
            obj_id = state.heap.allocate_dict()
            return SymbolicValue(ValueTag.DICT, z3.IntVal(obj_id))
        
        elif return_constraint.type_constraint == "list":
            # Return a symbolic list object (empty list, length 0)
            obj_id = state.heap.allocate_sequence("list", z3.IntVal(0), {})
            return SymbolicValue(ValueTag.LIST, z3.IntVal(obj_id))
        
        elif return_constraint.type_constraint == "tuple":
            # Return a symbolic tuple object (empty tuple, length 0)
            obj_id = state.heap.allocate_tuple(0)
            return SymbolicValue(ValueTag.TUPLE, z3.IntVal(obj_id))
        
        else:
            # Unconstrained or unknown type: return fresh symbolic object
            obj_id = z3.Int(f"obj_{func_name}_{id(state)}")
            return SymbolicValue(ValueTag.OBJ, obj_id)
    
    def _apply_relational_summary(
        self,
        state: SymbolicMachineState,
        frame: SymbolicFrame,
        summary: RelationalSummary,
        args: List[SymbolicValue],
        func_name: str
    ) -> SymbolicValue:
        """
        Apply a relational summary using the "cases + havoc" pattern.
        
        This implements the uniform summary application mechanism from ELEVATION_PLAN.md:
        - Collect ALL cases where guards definitely hold (nondeterministic choice)
        - If multiple cases match, fork paths for each alternative
        - If only one case matches, apply directly
        - Always keep havoc fallback reachable (soundness)
        
        Returns the symbolic result value (or raises exception in state).
        """
        # Fresh symbol counter for this application - use step count to ensure uniqueness
        if not hasattr(state, '_relational_call_counter'):
            state._relational_call_counter = 0
        state._relational_call_counter += 1
        fresh_id = state._relational_call_counter
        
        # PHASE 1: Collect all matching cases (where guard definitely holds)
        matching_cases = []
        for case in summary.cases:
            try:
                # Evaluate the guard
                guard_holds = case.guard(state, args)
                
                # Check if guard is definitely true
                # Must simplify first because z3.is_true() only works for Z3 constant True,
                # not for expressions like "-1 < 0" that evaluate to true
                simplified = z3.simplify(guard_holds)
                if z3.is_true(simplified):
                    matching_cases.append(case)
                    
            except Exception as e:
                # Guard evaluation failed (e.g., wrong number of args)
                # Skip this case
                continue
        
        # PHASE 2: Handle nondeterministic choice (multiple matching cases)
        if len(matching_cases) > 1:
            # Multiple cases match! This is nondeterministic behavior.
            # Fork paths for each alternative outcome.
            # Store the alternative cases for path forking in step()
            if not hasattr(state, 'fork_relational_cases'):
                state.fork_relational_cases = []
            
            # Store all alternatives: (summary, case, args, func_name, fresh_id)
            for case in matching_cases:
                state.fork_relational_cases.append({
                    'case': case,
                    'args': args,
                    'func_name': func_name,
                    'fresh_id': fresh_id
                })
            
            # Apply the FIRST case as the primary path (arbitrary choice)
            # The step() method will fork for the other cases
            case = matching_cases[0]
            post = case.post(state, args, fresh_id)
            
            # Apply postcondition to current state
            self._apply_postcondition(state, post, func_name, case, args)
            
            return post.return_value if post.return_value is not None else SymbolicValue.none()
        
        # PHASE 3: Single matching case (deterministic)
        elif len(matching_cases) == 1:
            case = matching_cases[0]
            post = case.post(state, args, fresh_id)
            
            # Apply postcondition
            self._apply_postcondition(state, post, func_name, case, args)
            
            return post.return_value if post.return_value is not None else SymbolicValue.none()
        
        # PHASE 4: No case matched - fall back to havoc
        havoc = summary.havoc
        
        # Collect all potential exceptions from all cases
        all_may_raise = set()
        for case in summary.cases:
            all_may_raise.update(case.may_raise)
        
        if all_may_raise or havoc.may_raise_any:
            # Signal path forking for exceptions
            if not hasattr(state, 'fork_exception_types'):
                state.fork_exception_types = []
            state.fork_exception_types.extend(list(all_may_raise))
            state.fork_function_name = func_name
            state.fork_case_name = "havoc_fallback"
        
        # Return a fresh unconstrained symbolic value (success path)
        # This is the maximal over-approximation
        obj_id = z3.Int(f"havoc_{func_name}_{fresh_id}")
        return SymbolicValue(ValueTag.OBJ, obj_id)
    
    def _apply_postcondition(
        self,
        state: SymbolicMachineState,
        post: PostCondition,
        func_name: str,
        case,
        args: List[SymbolicValue] = None
    ):
        """
        Apply a postcondition from a relational case to the state.
        Extracted as a helper to avoid duplication between single/multi-case paths.
        """
        # Apply path constraints
        for constraint in post.path_constraints:
            state.path_condition = z3.And(state.path_condition, constraint)
        
        # Apply heap constraints (if any)
        for constraint in post.heap_constraints:
            state.path_condition = z3.And(state.path_condition, constraint)
        
        # Apply observer updates
        if hasattr(post, 'observer_updates') and post.observer_updates:
            for observer_type, update_data in post.observer_updates.items():
                if observer_type == 'seq_len':
                    # update_data is (obj_id, ret_sym)
                    obj_id, ret_sym = update_data
                    # Get the SeqLen observer and constrain it
                    seq_len = state.heap.get_seq_len_observer(obj_id)
                    state.path_condition = z3.And(
                        state.path_condition,
                        ret_sym == seq_len
                    )
                elif observer_type == 'dict_size':
                    obj_id, ret_sym = update_data
                    dict_size = state.heap.get_dict_size_observer(obj_id)
                    state.path_condition = z3.And(
                        state.path_condition,
                        ret_sym == dict_size
                    )
                elif observer_type == 'exception_raised':
                    # update_data is (exception_type, exception_msg)
                    exc_type, exc_msg = update_data
                    # Set the exception in the state
                    # This will trigger exception handling logic in the VM
                    state.exception = exc_type
                    
                    # Set additional context flags for specific bug detectors
                    if exc_type == "ValueError":
                        # Check if this is a math domain error
                        if "domain" in exc_msg.lower() or "math" in func_name.lower():
                            state.fp_domain_error_reached = True
                            state.domain_error_context = f"{func_name}: {exc_msg}"
        
        # Handle exceptions: store exception types for path forking
        if case.may_raise:
            # Filter out exceptions prevented by established guards
            exceptions_to_fork = []
            for exc_type in case.may_raise:
                # Check if this exception is prevented by guards
                should_fork = True
                
                # TypeError from len/operations: prevented by nonnull guard
                if exc_type == "TypeError" and args:
                    # For functions like len(), if we have nonnull guard on the argument,
                    # TypeError (from None argument) should not be raised
                    if func_name in ["len", "abs", "str", "repr", "hash", "iter", "next"]:
                        if len(args) >= 1:
                            arg_name = self._get_variable_name_for_value(state, args[0])
                            if arg_name and state.has_nonnull_guard(arg_name):
                                # Guard established: TypeError from None is prevented
                                should_fork = False
                                if self.verbose:
                                    print(f"  [GUARD] TypeError prevented by nonnull guard on {arg_name}")
                
                if should_fork:
                    exceptions_to_fork.append(exc_type)
            
            # Only fork if there are exceptions remaining after filtering
            if exceptions_to_fork:
                if not hasattr(state, 'fork_exception_types'):
                    state.fork_exception_types = []
                state.fork_exception_types.extend(exceptions_to_fork)
                state.fork_function_name = func_name
                state.fork_case_name = case.name

    def _symbolic_from_concrete(self, state: SymbolicMachineState, value: Any, depth: int = 0) -> SymbolicValue:
        """
        Convert a concrete Python value into a SymbolicValue + heap objects.

        This is used only for trace-guided replay / witness production
        (e.g., selective concolic execution of unknown libraries).
        """
        if depth > 3:
            return SymbolicValue(ValueTag.OBJ, z3.IntVal(-9999))

        if value is None:
            return SymbolicValue.none()

        if value is ...:
            return SymbolicValue.ellipsis()

        if isinstance(value, bool):
            return SymbolicValue.bool(value)

        if isinstance(value, int):
            return SymbolicValue.int(value)

        if isinstance(value, float):
            return SymbolicValue.float(value)

        if isinstance(value, str):
            obj_id = state.heap.allocate_string(value)
            return SymbolicValue(ValueTag.STR, z3.IntVal(obj_id))

        if isinstance(value, tuple):
            tuple_id = state.heap.allocate_tuple(len(value))
            for i, elem in enumerate(value):
                state.heap.set_tuple_element(tuple_id, i, self._symbolic_from_concrete(state, elem, depth + 1))
            return SymbolicValue(ValueTag.TUPLE, z3.IntVal(tuple_id))

        if isinstance(value, list):
            elements = {}
            for i, elem in enumerate(value[:16]):  # bound size for replay
                elements[i] = self._symbolic_from_concrete(state, elem, depth + 1)
            list_id = state.heap.allocate_sequence("list", z3.IntVal(len(value)), elements)
            return SymbolicValue(ValueTag.LIST, z3.IntVal(list_id))

        if isinstance(value, dict):
            keys = set()
            values = {}
            for k, v in list(value.items())[:32]:  # bound size for replay
                if isinstance(k, (str, int)):
                    keys.add(k)
                    values[k] = self._symbolic_from_concrete(state, v, depth + 1)
            dict_id = state.heap.allocate_dict(keys=keys, values=values)
            return SymbolicValue(ValueTag.DICT, z3.IntVal(dict_id))

        # Fallback: unknown concrete object
        return SymbolicValue(ValueTag.OBJ, z3.IntVal(-9998))

    
    def _execute_instruction(self, state: SymbolicMachineState, frame: SymbolicFrame, instr):
        """Execute a single symbolic instruction."""
        opname = instr.opname
        
        if opname == "RESUME":
            frame.instruction_offset = self._next_offset(frame, instr)
        
        elif opname == "LOAD_CONST":
            val = instr.argval
            if val is None:
                sym_val = SymbolicValue.none()
            elif val is ...:
                # Ellipsis singleton
                sym_val = SymbolicValue.ellipsis()
            elif isinstance(val, slice):
                # Slice object: store start, stop, step
                obj_id = state.heap.allocate_slice(
                    SymbolicValue.int(val.start) if val.start is not None else SymbolicValue.none(),
                    SymbolicValue.int(val.stop) if val.stop is not None else SymbolicValue.none(),
                    SymbolicValue.int(val.step) if val.step is not None else SymbolicValue.none()
                )
                sym_val = SymbolicValue.slice_obj(obj_id)
            elif isinstance(val, bool):
                sym_val = SymbolicValue.bool(val)
            elif isinstance(val, int):
                sym_val = SymbolicValue.int(val)
            elif isinstance(val, float):
                sym_val = SymbolicValue.float(val)
            elif isinstance(val, str):
                # Allocate a string object in the heap
                # For symbolic purposes, represent str by its length and an ObjId
                obj_id = state.heap.allocate_string(val)
                sym_val = SymbolicValue(ValueTag.STR, z3.IntVal(obj_id))
            elif isinstance(val, types.CodeType):
                # Handle code objects (for MAKE_FUNCTION)
                # Store the actual code object so we can access its flags
                code_id = id(val)
                sym_val = SymbolicValue(ValueTag.OBJ, z3.IntVal(code_id))
                # Track the code object for later lookup
                if not hasattr(state, 'code_objects'):
                    state.code_objects = {}
                state.code_objects[code_id] = val
            elif isinstance(val, tuple):
                # Allocate a tuple object in the heap
                length = z3.IntVal(len(val))
                elements = {}
                for i, elem in enumerate(val):
                    if isinstance(elem, int):
                        elements[i] = SymbolicValue.int(elem)
                    elif isinstance(elem, float):
                        elements[i] = SymbolicValue.float(elem)
                    elif isinstance(elem, bool):
                        elements[i] = SymbolicValue.bool(elem)
                    elif elem is None:
                        elements[i] = SymbolicValue.none()
                    elif isinstance(elem, str):
                        # Allocate string in heap
                        obj_id_str = state.heap.allocate_string(elem)
                        elements[i] = SymbolicValue(ValueTag.STR, z3.IntVal(obj_id_str))
                    elif isinstance(elem, tuple):
                        # Recursively handle nested tuples
                        nested_length = z3.IntVal(len(elem))
                        nested_elements = {}
                        for j, nested_elem in enumerate(elem):
                            if isinstance(nested_elem, int):
                                nested_elements[j] = SymbolicValue.int(nested_elem)
                            elif isinstance(nested_elem, float):
                                nested_elements[j] = SymbolicValue.float(nested_elem)
                            elif isinstance(nested_elem, bool):
                                nested_elements[j] = SymbolicValue.bool(nested_elem)
                            elif nested_elem is None:
                                nested_elements[j] = SymbolicValue.none()
                            elif isinstance(nested_elem, str):
                                obj_id_str = state.heap.allocate_string(nested_elem)
                                nested_elements[j] = SymbolicValue(ValueTag.STR, z3.IntVal(obj_id_str))
                            else:
                                nested_elements[j] = SymbolicValue.none()
                        nested_obj_id = state.heap.allocate_sequence("tuple", nested_length, nested_elements)
                        elements[i] = SymbolicValue.tuple(nested_obj_id)
                    elif isinstance(elem, list):
                        # Recursively handle nested lists
                        nested_length = z3.IntVal(len(elem))
                        nested_elements = {}
                        for j, nested_elem in enumerate(elem):
                            if isinstance(nested_elem, int):
                                nested_elements[j] = SymbolicValue.int(nested_elem)
                            elif isinstance(nested_elem, float):
                                nested_elements[j] = SymbolicValue.float(nested_elem)
                            elif isinstance(nested_elem, bool):
                                nested_elements[j] = SymbolicValue.bool(nested_elem)
                            elif nested_elem is None:
                                nested_elements[j] = SymbolicValue.none()
                            elif isinstance(nested_elem, str):
                                obj_id_str = state.heap.allocate_string(nested_elem)
                                nested_elements[j] = SymbolicValue(ValueTag.STR, z3.IntVal(obj_id_str))
                            else:
                                nested_elements[j] = SymbolicValue.none()
                        nested_obj_id = state.heap.allocate_sequence("list", nested_length, nested_elements)
                        elements[i] = SymbolicValue.list(nested_obj_id)
                    else:
                        # For now, other unsupported element types
                        elements[i] = SymbolicValue.none()
                
                obj_id = state.heap.allocate_sequence("tuple", length, elements)
                sym_val = SymbolicValue.tuple(obj_id)
            elif isinstance(val, list):
                # Similar for lists
                length = z3.IntVal(len(val))
                elements = {}
                for i, elem in enumerate(val):
                    if isinstance(elem, int):
                        elements[i] = SymbolicValue.int(elem)
                    elif isinstance(elem, float):
                        elements[i] = SymbolicValue.float(elem)
                    elif isinstance(elem, bool):
                        elements[i] = SymbolicValue.bool(elem)
                    elif elem is None:
                        elements[i] = SymbolicValue.none()
                    elif isinstance(elem, tuple):
                        # Recursively handle nested tuples
                        nested_length = z3.IntVal(len(elem))
                        nested_elements = {}
                        for j, nested_elem in enumerate(elem):
                            if isinstance(nested_elem, int):
                                nested_elements[j] = SymbolicValue.int(nested_elem)
                            elif isinstance(nested_elem, float):
                                nested_elements[j] = SymbolicValue.float(nested_elem)
                            elif isinstance(nested_elem, bool):
                                nested_elements[j] = SymbolicValue.bool(nested_elem)
                            elif nested_elem is None:
                                nested_elements[j] = SymbolicValue.none()
                            else:
                                nested_elements[j] = SymbolicValue.none()
                        nested_obj_id = state.heap.allocate_sequence("tuple", nested_length, nested_elements)
                        elements[i] = SymbolicValue.tuple(nested_obj_id)
                    elif isinstance(elem, list):
                        # Recursively handle nested lists
                        nested_length = z3.IntVal(len(elem))
                        nested_elements = {}
                        for j, nested_elem in enumerate(elem):
                            if isinstance(nested_elem, int):
                                nested_elements[j] = SymbolicValue.int(nested_elem)
                            elif isinstance(nested_elem, float):
                                nested_elements[j] = SymbolicValue.float(nested_elem)
                            elif isinstance(nested_elem, bool):
                                nested_elements[j] = SymbolicValue.bool(nested_elem)
                            elif nested_elem is None:
                                nested_elements[j] = SymbolicValue.none()
                            else:
                                nested_elements[j] = SymbolicValue.none()
                        nested_obj_id = state.heap.allocate_sequence("list", nested_length, nested_elements)
                        elements[i] = SymbolicValue.list(nested_obj_id)
                    else:
                        elements[i] = SymbolicValue.none()
                
                obj_id = state.heap.allocate_sequence("list", length, elements)
                sym_val = SymbolicValue.list(obj_id)
            elif isinstance(val, frozenset):
                # Frozenset: immutable set type
                # Model as a tuple-like collection with no ordering guarantees
                # For symbolic purposes, we don't track the unordered nature semantically;
                # we just ensure it's immutable and has the right tag
                length = z3.IntVal(len(val))
                elements = {}
                for i, elem in enumerate(sorted(val, key=lambda x: (type(x).__name__, x))):
                    # Sort for determinism in symbolic execution
                    if isinstance(elem, int):
                        elements[i] = SymbolicValue.int(elem)
                    elif isinstance(elem, float):
                        elements[i] = SymbolicValue.float(elem)
                    elif isinstance(elem, bool):
                        elements[i] = SymbolicValue.bool(elem)
                    elif isinstance(elem, str):
                        obj_id_str = state.heap.allocate_string(elem)
                        elements[i] = SymbolicValue(ValueTag.STR, z3.IntVal(obj_id_str))
                    elif elem is None:
                        elements[i] = SymbolicValue.none()
                    else:
                        # For unsupported element types, use OBJ as over-approximation
                        elements[i] = SymbolicValue(ValueTag.OBJ, z3.IntVal(-1))
                
                # Allocate as tuple (immutable sequence) - frozenset is immutable
                obj_id = state.heap.allocate_sequence("tuple", length, elements)
                sym_val = SymbolicValue.tuple(obj_id)
            else:
                raise NotImplementedError(f"LOAD_CONST for type {type(val)}")
            
            frame.operand_stack.append(sym_val)
            frame.instruction_offset = self._next_offset(frame, instr)
        
        elif opname == "LOAD_SMALL_INT":
            frame.operand_stack.append(SymbolicValue.int(instr.argval))
            frame.instruction_offset = self._next_offset(frame, instr)
        
        elif opname == "LOAD_FAST":
            var_name = instr.argval
            # Check if this is a cell variable (Python 3.11+ combined fast locals layout)
            # Fast locals layout: co_varnames + co_cellvars
            # If var_name is in cellvars, load from cells instead of locals
            if hasattr(frame.code, 'co_cellvars') and var_name in frame.code.co_cellvars:
                cell_index = frame.code.co_cellvars.index(var_name)
                if cell_index in frame.cells:
                    frame.operand_stack.append(frame.cells[cell_index])
                else:
                    state.exception = "UnboundLocalError"
                    return
            elif var_name in frame.locals:
                frame.operand_stack.append(frame.locals[var_name])
            else:
                state.exception = "UnboundLocalError"
                return
            frame.instruction_offset = self._next_offset(frame, instr)
        
        elif opname == "LOAD_FAST_BORROW":
            # LOAD_FAST_BORROW: Python 3.14+ performance optimization
            # Loads local variable with borrowed reference (no refcount increment)
            # Semantically identical to LOAD_FAST for symbolic execution
            var_name = instr.argval
            # Check if this is a cell variable (Python 3.11+ combined fast locals layout)
            if hasattr(frame.code, 'co_cellvars') and var_name in frame.code.co_cellvars:
                cell_index = frame.code.co_cellvars.index(var_name)
                if cell_index in frame.cells:
                    frame.operand_stack.append(frame.cells[cell_index])
                else:
                    state.exception = "UnboundLocalError"
                    return
            elif var_name in frame.locals:
                frame.operand_stack.append(frame.locals[var_name])
            else:
                state.exception = "UnboundLocalError"
                return
            frame.instruction_offset = self._next_offset(frame, instr)
        
        elif opname == "LOAD_FAST_AND_CLEAR":
            var_name = instr.argval
            if var_name in frame.locals:
                frame.operand_stack.append(frame.locals[var_name])
                del frame.locals[var_name]
            else:
                frame.operand_stack.append(SymbolicValue.none())
            frame.instruction_offset = self._next_offset(frame, instr)
        
        elif opname == "LOAD_FAST_CHECK":
            # LOAD_FAST_CHECK: Load local variable, raising UnboundLocalError if not set
            # Used after for loops to check if loop variable was bound
            var_name = instr.argval
            if var_name in frame.locals:
                frame.operand_stack.append(frame.locals[var_name])
            else:
                # This is an UNSAFE region for NULL_PTR (unbound local)
                state.null_ptr_reached = True
                state.exception = "UnboundLocalError"
                return
            frame.instruction_offset = self._next_offset(frame, instr)
        
        elif opname == "LOAD_NAME":
            # LOAD_NAME loads from locals, then globals, then builtins
            var_name = instr.argval
            if var_name in frame.locals:
                frame.operand_stack.append(frame.locals[var_name])
            elif var_name in frame.globals:
                frame.operand_stack.append(frame.globals[var_name])
            elif var_name in frame.builtins:
                frame.operand_stack.append(frame.builtins[var_name])
            else:
                state.exception = "NameError"
                return
            frame.instruction_offset = self._next_offset(frame, instr)
        
        elif opname == "LOAD_GLOBAL":
            # LOAD_GLOBAL loads from globals, then builtins
            # In Python 3.11+, the arg determines whether to push NULL:
            # - If arg is odd: push NULL before value (for function calls)
            # - If arg is even: push value only (for attribute access)
            # The actual name index is arg >> 1
            
            raw_arg = instr.arg
            push_null = (raw_arg & 1) == 1  # Check low bit
            name_index = raw_arg >> 1  # Shift right to get actual index
            
            # Get the name from co_names
            var_name = frame.code.co_names[name_index]
            
            # Determine the value to push
            value_to_push = None
            if var_name in frame.globals:
                value_to_push = frame.globals[var_name]
            elif var_name in frame.builtins:
                value_to_push = frame.builtins[var_name]
            else:
                # Check if this is an exception type being loaded
                exception_types = ['AssertionError', 'RuntimeError', 'ValueError', 'TypeError', 
                                 'KeyError', 'IndexError', 'AttributeError', 'ImportError',
                                 'NameError', 'OSError', 'IOError', 'ZeroDivisionError',
                                 'StopIteration', 'StopAsyncIteration', 'SystemExit',
                                 'NotImplementedError', 'FileNotFoundError', 'PermissionError',
                                 'BaseException', 'Exception', 'IsADirectoryError', 'ModuleNotFoundError',
                                 'RecursionError', 'GeneratorExit']
                
                if var_name in exception_types:
                    # Load exception type as a special marker
                    # IMPORTANT: Use same hash-based ID as in builtins initialization for CHECK_EXC_MATCH
                    exc_id = -1000 - abs(hash(var_name)) % 10000
                    exc_ref = SymbolicValue(ValueTag.OBJ, z3.IntVal(exc_id))
                    exc_ref._exception_type = var_name
                    value_to_push = exc_ref
                else:
                    # For unknown builtins, create a symbolic function reference
                    # Tag it with the function name for contract lookup
                    # ITERATION 499 FIX: Use unique ID per unknown global (not -1000 for all)
                    # This enables LOAD_ATTR to build qualified names like "cursor.execute"
                    if not hasattr(state, 'unknown_global_counter'):
                        state.unknown_global_counter = 1000
                    state.unknown_global_counter += 1
                    unique_id = -state.unknown_global_counter
                    func_ref = SymbolicValue(ValueTag.OBJ, z3.IntVal(unique_id))
                    # Store function name using stable ID (Z3 payload)
                    if not hasattr(state, 'func_names'):
                        state.func_names = {}
                    state.func_names[unique_id] = var_name
                    value_to_push = func_ref
            
            # Push values in correct order: NULL first (if present), then value
            if push_null:
                # Python 3.11+ calling convention: push NULL marker first
                null_marker = SymbolicValue.none()
                frame.operand_stack.append(null_marker)
            
            if value_to_push is not None:
                frame.operand_stack.append(value_to_push)
            else:
                # Name not found
                state.exception = "NameError"
                return
            
            frame.instruction_offset = self._next_offset(frame, instr)
        
        elif opname == "STORE_FAST":
            if not frame.operand_stack:
                state.exception = "StackUnderflow"
                return
            value = frame.operand_stack.pop()
            frame.locals[instr.argval] = value
            
            # Track user-defined function names for intra-procedural analysis
            # CRITICAL FIX (Iteration 490): Use stable ID instead of Python id()
            stable_id = get_stable_value_id(value)
            if stable_id is not None:
                if id(value) in state.user_functions:
                    state.func_names[stable_id] = instr.argval
                
                # CRITICAL FIX (Iteration 270 + 490): Track variable names for method call resolution
                # Store the variable name so we can later build qualified method names like
                # "cursor.execute" when cursor is accessed via LOAD_ATTR.
                # This enables security sink detection for method calls on local variables.
                # Use stable Z3 payload ID instead of Python id() so tracking persists across LOAD_FAST.
                if not hasattr(state, 'value_var_names'):
                    state.value_var_names = {}
                state.value_var_names[stable_id] = instr.argval
            
            # ITERATION 442: Name-based sensitivity inference
            # Infer sensitivity from parameter/variable names (e.g., "password", "api_key")
            # This matches CodeQL's heuristic approach and enables cleartext detection
            # when explicit source tracking is not available.
            if state.security_tracker:
                inferred_source = infer_sensitivity_from_name(instr.argval)
                if inferred_source is not None:
                    # Get current label and add inferred sensitivity
                    from ..z3model.taint_lattice import TaintLabel
                    current_label = state.security_tracker.get_label(value)
                    # Add sensitivity bit for inferred source
                    # Clear sanitization (kappa=0) since we're inferring this is sensitive data
                    new_label = TaintLabel(
                        tau=current_label.tau,
                        kappa=0,  # Not sanitized
                        sigma=current_label.sigma | (1 << inferred_source),
                        provenance=current_label.provenance | frozenset({inferred_source.name})
                    )
                    state.security_tracker.set_label(value, new_label)
            
            frame.instruction_offset = self._next_offset(frame, instr)
        
        elif opname == "STORE_FAST_LOAD_FAST":
            # Optimization: STORE_FAST followed by LOAD_FAST (atomic in comprehensions)
            # argval is a tuple: (store_name, load_name)
            if not frame.operand_stack:
                state.exception = "StackUnderflow"
                return
            value = frame.operand_stack.pop()
            
            # Parse argval - it's a tuple of (store_name, load_name)
            if isinstance(instr.argval, tuple) and len(instr.argval) == 2:
                store_name, load_name = instr.argval
            else:
                # Fallback: assume argval is the variable name for both
                store_name = load_name = instr.argval
            
            # Store to first variable
            frame.locals[store_name] = value
            
            # ITERATION 442: Name-based sensitivity inference
            if state.security_tracker:
                inferred_source = infer_sensitivity_from_name(store_name)
                if inferred_source is not None:
                    from ..z3model.taint_lattice import TaintLabel, kappa_zero
                    current_label = state.security_tracker.get_label(value)
                    new_label = TaintLabel(
                        tau=current_label.tau,
                        kappa=0,
                        sigma=current_label.sigma | (1 << inferred_source),
                        provenance=current_label.provenance | frozenset({inferred_source.name})
                    )
                    state.security_tracker.set_label(value, new_label)
            
            # Load from second variable and push
            if load_name in frame.locals:
                frame.operand_stack.append(frame.locals[load_name])
            else:
                # If not found, this is a NameError
                state.exception = "NameError"
                return
            
            frame.instruction_offset = self._next_offset(frame, instr)
        
        elif opname == "LOAD_FAST_BORROW_LOAD_FAST_BORROW":
            # Python 3.14+ optimization: loads two consecutive local variables
            # argval is a tuple (index1, var_name1, var_name2) or similar encoding
            # Semantically: push locals[var_name1] then push locals[var_name2]
            # Based on disassembly: arg encodes two variable indices/names
            
            # Parse argval - Python 3.14 uses special encoding
            # From testing: arg value encodes two variable indices
            # argval seems to be tuple of (idx1, name1, name2) or just names
            if isinstance(instr.argval, tuple):
                # Multiple variables in tuple
                if len(instr.argval) >= 2:
                    var_name1, var_name2 = instr.argval[0], instr.argval[1]
                else:
                    # Fallback: use arg to compute indices
                    arg = instr.arg
                    idx1 = arg & 0xFF
                    idx2 = (arg >> 8) & 0xFF
                    var_names = frame.code.co_varnames
                    var_name1 = var_names[idx1] if idx1 < len(var_names) else f"var_{idx1}"
                    var_name2 = var_names[idx2] if idx2 < len(var_names) else f"var_{idx2}"
            else:
                # Parse from arg value: low byte = first var, high byte = second var
                arg = instr.arg if instr.arg is not None else 0
                idx1 = arg & 0xFF
                idx2 = (arg >> 8) & 0xFF
                var_names = frame.code.co_varnames
                var_name1 = var_names[idx1] if idx1 < len(var_names) else f"var_{idx1}"
                var_name2 = var_names[idx2] if idx2 < len(var_names) else f"var_{idx2}"
            
            # Load first variable
            if var_name1 in frame.locals:
                frame.operand_stack.append(frame.locals[var_name1])
            else:
                state.exception = "UnboundLocalError"
                return
            
            # Load second variable
            if var_name2 in frame.locals:
                frame.operand_stack.append(frame.locals[var_name2])
            else:
                state.exception = "UnboundLocalError"
                return
            
            frame.instruction_offset = self._next_offset(frame, instr)
        
        elif opname == "STORE_FAST_STORE_FAST":
            # Python 3.14+ optimization: stores two values into two consecutive locals
            # Pops TOS and TOS1, stores into two variables
            # argval encodes two variable indices/names
            # Semantically: var2 = pop(); var1 = pop()
            
            if len(frame.operand_stack) < 2:
                state.exception = "StackUnderflow"
                return
            
            # Parse argval similar to LOAD_FAST_BORROW_LOAD_FAST_BORROW
            if isinstance(instr.argval, tuple):
                if len(instr.argval) >= 2:
                    var_name1, var_name2 = instr.argval[0], instr.argval[1]
                else:
                    arg = instr.arg
                    idx1 = arg & 0xFF
                    idx2 = (arg >> 8) & 0xFF
                    var_names = frame.code.co_varnames
                    var_name1 = var_names[idx1] if idx1 < len(var_names) else f"var_{idx1}"
                    var_name2 = var_names[idx2] if idx2 < len(var_names) else f"var_{idx2}"
            else:
                arg = instr.arg if instr.arg is not None else 0
                idx1 = arg & 0xFF
                idx2 = (arg >> 8) & 0xFF
                var_names = frame.code.co_varnames
                var_name1 = var_names[idx1] if idx1 < len(var_names) else f"var_{idx1}"
                var_name2 = var_names[idx2] if idx2 < len(var_names) else f"var_{idx2}"
            
            # Pop in reverse order: TOS goes to var2, TOS1 goes to var1
            value2 = frame.operand_stack.pop()
            value1 = frame.operand_stack.pop()
            
            frame.locals[var_name1] = value1
            frame.locals[var_name2] = value2
            
            # Track user-defined functions
            if id(value1) in state.user_functions:
                state.func_names[id(value1)] = var_name1
            if id(value2) in state.user_functions:
                state.func_names[id(value2)] = var_name2
            
            frame.instruction_offset = self._next_offset(frame, instr)
        
        elif opname == "UNPACK_SEQUENCE":
            # UNPACK_SEQUENCE(count) unpacks TOS into count values
            # Pops one sequence, pushes count values onto stack
            # Raises TypeError if TOS is not iterable
            # Raises ValueError if length mismatch
            if not frame.operand_stack:
                state.exception = "StackUnderflow"
                return
            
            count = instr.argval
            seq = frame.operand_stack.pop()
            
            # Check for None misuse
            self.solver.push()
            self.solver.add(state.path_condition)
            self.solver.add(seq.is_none())
            if self.solver.check() == z3.sat:
                state.none_misuse_reached = True
                state.exception = "TypeError"
                self.solver.pop()
                return
            self.solver.pop()
            
            # Type check: must be unpackable (list, tuple, or unknown OBJ)
            # Only flag TYPE_CONFUSION if we can PROVE it's definitely not unpackable
            # (i.e., it's definitely an int, str, bool, float, dict, etc.)
            # Sound over-approximation: OBJ values might be tuples, so accept them
            is_definitely_not_unpackable = z3.Or(
                seq.is_int(),
                seq.is_str(),
                seq.is_bool(),
                seq.is_float(),
                seq.is_dict()
            )
            self.solver.push()
            self.solver.add(state.path_condition)
            self.solver.add(is_definitely_not_unpackable)
            if self.solver.check() == z3.sat:
                state.type_confusion_reached = True
                state.exception = "TypeError"
                self.solver.pop()
                return
            self.solver.pop()
            
            # Get the sequence object from heap
            obj_id = None
            self.solver.push()
            self.solver.add(state.path_condition)
            if self.solver.check() == z3.sat:
                model = self.solver.model()
                obj_id_val = model.eval(seq.payload, model_completion=True)
                try:
                    obj_id = obj_id_val.as_long()
                except:
                    pass
            self.solver.pop()
            
            if obj_id is not None:
                seq_obj = state.heap.get_sequence(obj_id)
                if seq_obj:
                    # Check length matches
                    self.solver.push()
                    self.solver.add(state.path_condition)
                    self.solver.add(seq_obj.length != z3.IntVal(count))
                    if self.solver.check() == z3.sat:
                        # Length mismatch - ValueError
                        state.exception = "ValueError"
                        self.solver.pop()
                        return
                    self.solver.pop()
                    
                    # Unpack elements and push onto stack in REVERSE order
                    # so that TOS = first element (matches CPython semantics)
                    for i in range(count - 1, -1, -1):
                        if i in seq_obj.elements:
                            frame.operand_stack.append(seq_obj.elements[i])
                        else:
                            # Element not concretely known - create symbolic value
                            sym_elem = SymbolicValue(ValueTag.OBJ, z3.Int(f"unpack_{obj_id}_{i}"))
                            frame.operand_stack.append(sym_elem)
                else:
                    # Sequence object not found in heap - create symbolic unpacked values
                    for i in range(count - 1, -1, -1):
                        sym_elem = SymbolicValue(ValueTag.OBJ, z3.Int(f"unpack_unknown_{id(seq)}_{i}"))
                        frame.operand_stack.append(sym_elem)
            else:
                # Could not extract concrete obj_id - create symbolic unpacked values
                for i in range(count - 1, -1, -1):
                    sym_elem = SymbolicValue(ValueTag.OBJ, z3.Int(f"unpack_symbolic_{id(seq)}_{i}"))
                    frame.operand_stack.append(sym_elem)
            
            frame.instruction_offset = self._next_offset(frame, instr)
        
        elif opname == "STORE_SUBSCR":
            # STORE_SUBSCR: Implements container[index] = value
            # CPython stack layout: [..., value, container, index]
            # TOS=index, TOS1=container, TOS2=value
            # Pop order: index, container, value
            if len(frame.operand_stack) < 3:
                state.exception = "StackUnderflow"
                return
            
            index = frame.operand_stack.pop()      # TOS
            container = frame.operand_stack.pop()  # TOS1
            value = frame.operand_stack.pop()      # TOS2
            
            # Check for None misuse on container
            self.solver.push()
            self.solver.add(state.path_condition)
            self.solver.add(container.is_none())
            if self.solver.check() == z3.sat:
                state.none_misuse_reached = True
                state.exception = "TypeError"
                self.solver.pop()
                return
            self.solver.pop()
            
            # Check if container is a list or dict
            is_list = container.is_list()
            is_dict = container.is_dict()
            is_valid_container = z3.Or(is_list, is_dict)
            
            self.solver.push()
            self.solver.add(state.path_condition)
            self.solver.add(z3.Not(is_valid_container))
            if self.solver.check() == z3.sat:
                # Type error: object does not support item assignment
                state.type_confusion_reached = True
                state.exception = "TypeError"
                self.solver.pop()
                return
            self.solver.pop()
            
            # Try to get concrete obj_id for the container
            obj_id = None
            self.solver.push()
            self.solver.add(state.path_condition)
            if self.solver.check() == z3.sat:
                model = self.solver.model()
                obj_id_val = model.eval(container.payload, model_completion=True)
                try:
                    obj_id = obj_id_val.as_long()
                except:
                    pass
            self.solver.pop()
            
            if obj_id is not None:
                # Check if it's a list
                self.solver.push()
                self.solver.add(state.path_condition)
                self.solver.add(is_list)
                if self.solver.check() == z3.sat:
                    # List subscript assignment
                    self.solver.pop()
                    
                    seq_obj = state.heap.get_sequence(obj_id)
                    if seq_obj is None:
                        # Create new sequence object if not found
                        seq_obj = SequenceObject(
                            obj_type="list",
                            length=z3.Int(f"list_len_{obj_id}"),
                            elements={}
                        )
                        state.heap.sequences[obj_id] = seq_obj
                    
                    # Try to get concrete index
                    concrete_index = None
                    self.solver.push()
                    self.solver.add(state.path_condition)
                    if index.tag == ValueTag.INT:
                        idx_val = self.solver.model().eval(index.payload, model_completion=True)
                        try:
                            concrete_index = idx_val.as_long()
                        except:
                            pass
                    self.solver.pop()
                    
                    if concrete_index is not None:
                        # Check bounds
                        self.solver.push()
                        self.solver.add(state.path_condition)
                        # Check if index is negative or >= length
                        out_of_bounds = z3.Or(
                            index.payload < z3.IntVal(0),
                            index.payload >= seq_obj.length
                        )
                        self.solver.add(out_of_bounds)
                        if self.solver.check() == z3.sat:
                            # Out of bounds
                            state.bounds_violation_reached = True
                            state.exception = "IndexError"
                            self.solver.pop()
                            return
                        self.solver.pop()
                        
                        # Store the value
                        seq_obj.elements[concrete_index] = value
                    else:
                        # Symbolic index - conservatively don't track exact location
                        # but record that heap was mutated
                        state.heap_mutated = True
                else:
                    # Dict subscript assignment
                    self.solver.pop()
                    
                    dict_obj = state.heap.get_dict(obj_id)
                    if dict_obj is None:
                        # Create new dict object if not found
                        dict_obj = DictObject(keys=set(), values={})
                        state.heap.dicts[obj_id] = dict_obj
                    
                    # Try to get concrete key
                    concrete_key = None
                    if index.tag == ValueTag.INT:
                        self.solver.push()
                        self.solver.add(state.path_condition)
                        if self.solver.check() == z3.sat:
                            key_val = self.solver.model().eval(index.payload, model_completion=True)
                            try:
                                concrete_key = key_val.as_long()
                            except:
                                pass
                        self.solver.pop()
                    elif index.tag == ValueTag.STR:
                        # Try to extract string key
                        self.solver.push()
                        self.solver.add(state.path_condition)
                        if self.solver.check() == z3.sat:
                            model = self.solver.model()
                            key_val = model.eval(index.payload, model_completion=True)
                            try:
                                key_obj_id = key_val.as_long()
                                str_obj = state.heap.strings.get(key_obj_id)
                                if str_obj:
                                    concrete_key = str_obj.value
                            except:
                                pass
                        self.solver.pop()
                    
                    if concrete_key is not None:
                        # Store in dict
                        dict_obj.keys.add(concrete_key)
                        dict_obj.values[concrete_key] = value
                    else:
                        # Symbolic key - conservatively record heap mutation
                        state.heap_mutated = True
            else:
                # Could not get concrete obj_id - conservatively record heap mutation
                state.heap_mutated = True
            
            frame.instruction_offset = self._next_offset(frame, instr)
        
        elif opname == "STORE_NAME":
            # STORE_NAME stores in locals (or globals in module scope)
            if not frame.operand_stack:
                state.exception = "StackUnderflow"
                return
            value = frame.operand_stack.pop()
            frame.locals[instr.argval] = value
            
            # Track user-defined function names for intra-procedural analysis
            # ITERATION 493 FIX: Use qualified name (module.function) to match summaries
            # AND use stable value ID to match CALL lookup
            if id(value) in state.user_functions:
                import os
                module_name = os.path.splitext(os.path.basename(frame.code.co_filename))[0]
                qualified_name = f"{module_name}.{instr.argval}"
                # Store using stable ID (payload), not id(value)
                stable_id = get_stable_value_id(value)
                if stable_id is not None:
                    state.func_names[stable_id] = qualified_name
                # Also store by id() for backward compatibility
                state.func_names[id(value)] = qualified_name
            
            # ITERATION 442: Name-based sensitivity inference
            if state.security_tracker:
                inferred_source = infer_sensitivity_from_name(instr.argval)
                if inferred_source is not None:
                    from ..z3model.taint_lattice import TaintLabel, kappa_zero
                    current_label = state.security_tracker.get_label(value)
                    new_label = TaintLabel(
                        tau=current_label.tau,
                        kappa=0,
                        sigma=current_label.sigma | (1 << inferred_source),
                        provenance=current_label.provenance | frozenset({inferred_source.name})
                    )
                    state.security_tracker.set_label(value, new_label)
            
            frame.instruction_offset = self._next_offset(frame, instr)
        
        elif opname == "STORE_GLOBAL":
            # STORE_GLOBAL stores in global namespace
            if not frame.operand_stack:
                state.exception = "StackUnderflow"
                return
            value = frame.operand_stack.pop()
            frame.globals[instr.argval] = value
            
            # Track user-defined function names for intra-procedural analysis
            # ITERATION 493 FIX: Use qualified name (module.function) to match summaries
            # AND use stable value ID to match CALL lookup
            if id(value) in state.user_functions:
                import os
                module_name = os.path.splitext(os.path.basename(frame.code.co_filename))[0]
                qualified_name = f"{module_name}.{instr.argval}"
                # Store using stable ID (payload), not id(value)
                stable_id = get_stable_value_id(value)
                if stable_id is not None:
                    state.func_names[stable_id] = qualified_name
                # Also store by id() for backward compatibility
                state.func_names[id(value)] = qualified_name
            
            frame.instruction_offset = self._next_offset(frame, instr)
        
        elif opname == "CALL":
            # CALL(nargs): calls a function with nargs arguments
            # 
            # Python 3.11+ has two calling conventions:
            # 1. With NULL marker (function calls): NULL, callable, arg1, ..., argN, CALL N
            #    - Pops NULL + callable + N args
            # 2. Without NULL (method calls, LOAD_COMMON_CONSTANT): self/obj, callable, arg1, ..., argN, CALL N
            #    - Pops self + callable + N args, passing self as implicit first arg
            #    - Effectively N+1 total args
            #
            # For LOAD_COMMON_CONSTANT + CALL N: stack is [exc_class, arg1, ..., argN], CALL N
            # - This uses convention #2 where exc_class acts as first arg
            # - So CALL 0 with [exc_class, msg] → exc_class(msg)
            
            nargs = instr.argval
            
            # Check if there's a NULL marker on the stack
            # Python 3.11-3.13 calling convention: [NULL, callable, arg1, ..., argN]
            # Python 3.14+ calling convention via PUSH_NULL:
            #   LOAD_NAME/LOAD_GLOBAL pushes callable
            #   PUSH_NULL pushes NULL
            #   Stack becomes: [..., callable, NULL, arg1, ..., argN]
            #
            # For CALL(N):
            #   - If NULL present (3.14+): stack is [callable, NULL, arg1, ..., argN]
            #     callable at -(N+2), NULL at -(N+1)
            #   - If NULL present (3.11-3.13): stack is [NULL, callable, arg1, ..., argN]
            #     NULL at -(N+2), callable at -(N+1)
            #   - If no NULL (method call): stack is [self, method, arg1, ..., argN]
            #     self at -(N+2), method at -(N+1)
            #
            # Try both positions: first -(N+1) (3.14+), then -(N+2) (3.11-3.13)
            has_null = False
            null_position = None
            if len(frame.operand_stack) >= nargs + 2:
                # Try position -(nargs+1) first (Python 3.14+ with PUSH_NULL)
                if len(frame.operand_stack) >= nargs + 2:
                    potential_null = frame.operand_stack[-(nargs + 1)]
                    if potential_null.tag == ValueTag.NONE:
                        has_null = True
                        null_position = -(nargs + 1)
                
                # If not found, try position -(nargs+2) (Python 3.11-3.13)
                if not has_null and len(frame.operand_stack) >= nargs + 2:
                    potential_null = frame.operand_stack[-(nargs + 2)]
                    if potential_null.tag == ValueTag.NONE:
                        has_null = True
                        null_position = -(nargs + 2)
            
            # Determine effective number of args and pop order based on calling convention
            if has_null:
                # Convention 1: Function call with NULL marker
                # Stack layout depends on Python version:
                # - 3.11-3.13: [..., NULL, callable, arg1, ..., argN]  (NULL at -(N+2))
                # - 3.14+: [..., callable, NULL, arg1, ..., argN]  (NULL at -(N+1))
                effective_nargs = nargs
                
                # Determine pop order based on NULL position
                if null_position == -(nargs + 1):
                    # Python 3.14+: [callable, NULL, args...]
                    # Pop order: args, NULL, callable
                    needs_null_after_args = True
                    needs_null_after_callable = False
                else:
                    # Python 3.11-3.13: [NULL, callable, args...]
                    # Pop order: args, callable, NULL
                    needs_null_after_args = False
                    needs_null_after_callable = True
            else:
                # Convention 2: self/obj + method + nargs explicit args = nargs+1 total args
                # Stack: [..., self, method, arg1, ..., argN]
                # The self becomes first arg
                effective_nargs = nargs + 1
                needs_null_after_args = False
                needs_null_after_callable = False
            
            # Need at least NULL (if present) + callable + effective_nargs items
            min_stack_size = effective_nargs + 1 + (1 if has_null else 0)
            if len(frame.operand_stack) < min_stack_size:
                state.exception = "StackUnderflow"
                return
            
            # Pop in order determined by calling convention
            # 1. Pop arguments from top (in reverse order)
            args = []
            for _ in range(effective_nargs):
                args.insert(0, frame.operand_stack.pop())
            
            # 2. Pop NULL if it comes after args (Python 3.14+)
            if needs_null_after_args:
                if not frame.operand_stack:
                    state.exception = "StackUnderflow"
                    return
                null_marker = frame.operand_stack.pop()
            
            # 3. Pop callable
            if not frame.operand_stack:
                state.exception = "StackUnderflow"
                return
            func_ref = frame.operand_stack.pop()
            
            # 4. Pop NULL if it comes after callable (Python 3.11-3.13)
            if needs_null_after_callable:
                if not frame.operand_stack:
                    state.exception = "StackUnderflow"
                    return
                null_marker = frame.operand_stack.pop()
            
            # Check if this is a generator or coroutine function
            # If so, return a generator/coroutine object without executing the body
            # ITERATION 486: Use stable ID from payload
            func_meta_id = None
            if func_ref.tag == ValueTag.OBJ:
                if hasattr(func_ref.payload, 'as_long'):
                    try:
                        func_meta_id = int(func_ref.payload.as_long())
                    except:
                        pass
                elif hasattr(func_ref.payload, 'sexpr'):
                    try:
                        sexpr = func_ref.payload.sexpr()
                        if sexpr.startswith('func_'):
                            func_meta_id = int(sexpr[5:])
                    except:
                        pass
            
            # Try stable ID first, fall back to object ID
            metadata = None
            if hasattr(state, 'function_metadata'):
                if func_meta_id is not None and func_meta_id in state.function_metadata:
                    metadata = state.function_metadata[func_meta_id]
                elif id(func_ref) in state.function_metadata:
                    metadata = state.function_metadata[id(func_ref)]
            
            if metadata and (metadata.get('is_generator') or metadata.get('is_coroutine')):
                # Create and return a generator/coroutine object
                gen_id = id(metadata['code'])
                gen_obj = SymbolicValue(ValueTag.OBJ, z3.Int(f"generator_{gen_id}_{instr.offset}"))
                
                # Store the generator state for potential later resumption
                # (though we don't implement next() yet)
                if not hasattr(state, 'generator_states'):
                    state.generator_states = {}
                state.generator_states[id(gen_obj)] = {
                    'code': metadata['code'],
                    'args': args,
                    'suspended': True,
                    'is_coroutine': metadata.get('is_coroutine', False)
                }
                
                frame.operand_stack.append(gen_obj)
                frame.instruction_offset = self._next_offset(frame, instr)
                return
            
            # Special handling for exception type constructors
            # If func_ref has _exception_type attribute, this is a call to an exception constructor
            # (e.g., AssertionError("message")) and we need to preserve the exception type
            # This must be checked BEFORE func_name lookup, since exception types aren't in func_names
            exc_type_attr = getattr(func_ref, '_exception_type', None)
            if exc_type_attr:
                # This is an exception constructor call
                # Create an exception instance with the same _exception_type
                result = SymbolicValue(ValueTag.OBJ, z3.Int(f"exception_instance_{id(func_ref)}_{instr.offset}"))
                result._exception_type = exc_type_attr
                
                # Always push the exception instance to the stack
                # RAISE_VARARGS will pop it and set state.exception
                frame.operand_stack.append(result)
                frame.instruction_offset = self._next_offset(frame, instr)
                return
            
            # ========================================================================
            # ITERATION 415: Framework mock method calls
            # For request.args.get(), request.GET.get(), etc., return the tainted value
            # ========================================================================
            if hasattr(state, 'mock_methods') and id(func_ref) in state.mock_methods:
                mock_method = state.mock_methods[id(func_ref)]
                
                # Return the mock method's return value
                result_val = mock_method.return_value
                
                # Apply taint from the mock method definition
                if mock_method.taint_label and state.security_tracker:
                    state.security_tracker.set_label(result_val, mock_method.taint_label)
                if mock_method.symbolic_taint and state.security_tracker:
                    state.security_tracker.set_symbolic_label(result_val, mock_method.symbolic_taint)
                
                frame.operand_stack.append(result_val)
                frame.instruction_offset = self._next_offset(frame, instr)
                return
            
            # Determine function name for contract lookup
            func_name = None
            if hasattr(state, 'func_names'):
                # Use get_stable_value_id to handle both concrete and symbolic payloads
                func_id = get_stable_value_id(func_ref)
                if func_id is not None:
                    func_name = state.func_names.get(func_id)
                # Fallback: check if stored by id() for backward compatibility
                if not func_name:
                    func_name = state.func_names.get(id(func_ref))

            # Trace-guided replay: override call target using concrete observation keyed by callsite.
            call_obs: Optional[CallObservation] = None
            if self.oracle:
                call_obs = self.oracle.pop_call_observation(frame.code, instr.offset)
                if call_obs and call_obs.function_id:
                    func_name = call_obs.function_id

            # If the concrete run observed an exception at this call boundary, reproduce it.
            if call_obs and call_obs.exception_type:
                state.exception = call_obs.exception_type
                return
            
            # Special handling for class decorators (MUST happen before class instantiation check):
            # If the PREVIOUS instruction created a class via __build_class__, and this call
            # is to a known decorator, then the result will be a decorated class that should
            # also be tracked in class_objects for instantiation.
            # 
            # Pattern: decorator is on stack below the class object being decorated:
            # Stack before CALL: [decorator_func, class_obj, <args>...]
            # After CALL: result (decorated class)
            #
            # We detect this by checking if func_name is a known decorator AND
            # any of the args is a class object.
            known_class_decorators = {
                'dataclass', 'dataclasses.dataclass',
                'attr.s', 'attr.attrs', 'attr.s', 'attr.attrs',
                'click.command', 'click.group'
            }
            if func_name in known_class_decorators and len(args) >= 1:
                first_arg = args[0]
                if hasattr(state, 'class_objects') and id(first_arg) in state.class_objects:
                    # This is a decorator call on a class - we need to mark that the
                    # RESULT will also be a class (decorator transforms class to class).
                    # However, we don't have the result yet (it's computed later).
                    # So we'll store a flag and handle it after the result is computed.
                    if not hasattr(state, '_pending_class_decorator'):
                        state._pending_class_decorator = {}
                    state._pending_class_decorator[instr.offset] = {
                        'original_class_id': id(first_arg),
                        'original_class_meta': state.class_objects[id(first_arg)],
                        'decorator_name': func_name
                    }
            
            # Special handling for class instantiation
            # If func_ref is a class object (created by __build_class__), create an instance
            if hasattr(state, 'class_objects') and id(func_ref) in state.class_objects:
                class_meta = state.class_objects[id(func_ref)]
                
                # Check if this is a decorated class that might have auto-generated __init__
                is_decorated_class = 'decorator' in class_meta
                decorator_name = class_meta.get('decorator', '')
                
                # For dataclasses and similar decorators, the decorator generates __init__ that takes
                # field arguments. If the call has wrong arity, it would fail in CPython.
                # We conservatively allow any arity for decorated classes (sound over-approximation).
                # For regular classes without __init__, calling with args would also fail.
                # But since we're not executing __init__, we just create the instance and return.
                
                # For soundness: we create an instance regardless of arguments.
                # This is a sound over-approximation because:
                # - If __init__ would succeed, we return an instance ✓
                # - If __init__ would fail (wrong args), we still return an instance (over-approx) ✓
                # - The instance has symbolic/havoc state, so we don't under-approximate
                
                # Create an instance object
                instance_obj = SymbolicValue(ValueTag.OBJ, z3.Int(f"instance_{class_meta['name']}_{instr.offset}"))
                
                # Store instance metadata
                if not hasattr(state, 'instance_objects'):
                    state.instance_objects = {}
                state.instance_objects[id(instance_obj)] = {
                    'class_id': id(func_ref),
                    'class_meta': class_meta,
                    'is_decorated': is_decorated_class,
                    'decorator': decorator_name
                }
                
                # Note: We do NOT call __init__ - just return the instance
                # This is a sound over-approximation:
                # - For dataclasses with default fields, this allows instantiation to proceed
                # - For classes with custom __init__, we skip initialization (havoc state)
                # - This allows control flow to reach security-critical code (our goal for PyGoat)
                # - Any use of the instance's state is conservatively symbolic/unknown
                
                frame.operand_stack.append(instance_obj)
                frame.instruction_offset = self._next_offset(frame, instr)
                return
            
            # Special handling for globals() builtin
            # Returns a symbolic dict representing the current frame's global namespace
            if func_name == "globals":
                if len(args) != 0:
                    # globals() takes no arguments
                    state.exception = "TypeError"
                    return
                
                # Create a symbolic dict object representing the globals namespace
                # This allows code like `if "__name__" in globals()` to execute symbolically
                # Prepare the dict contents
                dict_keys = set(frame.globals.keys())
                dict_values = {}
                
                # Populate with symbolic string keys and their values from frame.globals
                for key, value in frame.globals.items():
                    # Use the string key directly (DictObject.values uses concrete keys)
                    dict_values[key] = value
                
                # Allocate the dict with the contents
                globals_dict_id = state.heap.allocate_dict(keys=dict_keys, values=dict_values)
                
                result = SymbolicValue(ValueTag.DICT, z3.IntVal(globals_dict_id))
                frame.operand_stack.append(result)
                frame.instruction_offset = self._next_offset(frame, instr)
                return
            
            # Special handling for __build_class__ builtin
            # This is used to construct classes at runtime
            if func_name == "__build_class__":
                # __build_class__(func, name, *bases, **kwds)
                # Minimum: func (class body function) and name (string)
                if len(args) < 2:
                    state.exception = "TypeError"
                    return
                
                class_body_func = args[0]
                class_name_val = args[1]
                # bases = args[2:] if len(args) > 2 else []
                
                # For symbolic execution, we'll execute the class body function
                # to populate the class namespace, then create a class object
                
                # Check if class_body_func is a user-defined function we can execute
                is_user_func = id(class_body_func) in state.user_functions
                
                if is_user_func:
                    # Execute the class body to build the class namespace
                    class_body_meta = state.user_functions[id(class_body_func)]
                    
                    # Create a new namespace dict for the class
                    class_namespace_id = state.heap.allocate_dict(keys=set(), values={})
                    
                    # Execute the class body function to populate the namespace
                    # The class body will populate __locals__ which becomes the class namespace
                    try:
                        class_body_result = self._execute_class_body(state, class_body_meta, class_namespace_id)
                        # class_body_result contains the final locals which become class attributes
                    except Exception as e:
                        # If execution fails, fall back to symbolic class (sound over-approximation)
                        class_body_result = None
                    
                    # Create a class object
                    class_obj = SymbolicValue(ValueTag.OBJ, z3.Int(f"class_{class_body_meta['name']}_{instr.offset}"))
                    
                    # Store metadata so we can track that this is a class
                    if not hasattr(state, 'class_objects'):
                        state.class_objects = {}
                    state.class_objects[id(class_obj)] = {
                        'name': class_name_val,
                        'body_func': class_body_meta,
                        'namespace_id': class_namespace_id,
                        'executed': class_body_result is not None
                    }
                    
                    frame.operand_stack.append(class_obj)
                    frame.instruction_offset = self._next_offset(frame, instr)
                    return
                else:
                    # Unknown class body function - create symbolic class object
                    class_obj = SymbolicValue(ValueTag.OBJ, z3.Int(f"class_symbolic_{instr.offset}"))
                    frame.operand_stack.append(class_obj)
                    frame.instruction_offset = self._next_offset(frame, instr)
                    return
            
            # Check if this is a call to a user-defined function
            # Phase 2: Implement simple intra-procedural analysis for non-recursive functions
            # ITERATION 486: Use stable ID from payload, not Python object id()
            func_stable_id = None
            if func_ref.tag == ValueTag.OBJ:
                # Try to extract stable ID from Z3 payload
                if hasattr(func_ref.payload, 'as_long'):
                    # IntNumRef - concrete value
                    try:
                        func_stable_id = int(func_ref.payload.as_long())
                    except:
                        pass
                elif hasattr(func_ref.payload, 'sexpr'):
                    # ArithRef - Z3 variable, extract ID from name like "func_123456"
                    try:
                        sexpr = func_ref.payload.sexpr()
                        if sexpr.startswith('func_'):
                            func_stable_id = int(sexpr[5:])  # Extract ID after "func_"
                    except:
                        pass
            
            # Try both stable ID (correct) and object ID (backward compatibility)
            is_user_function = (
                (func_stable_id is not None and func_stable_id in state.user_functions) or
                (id(func_ref) in state.user_functions)
            )
            
            # ITERATION 568: Also try lookup by function name if ID lookup fails
            # This handles cases where function objects have mismatched IDs but same name
            if not is_user_function and func_name:
                # Try to find a user function with matching name
                for func_id, func_meta in state.user_functions.items():
                    if func_meta['name'] == func_name:
                        # Found a match by name - use this
                        is_user_function = True
                        func_stable_id = func_id
                        break
            
            # ITERATION 538: Also check if we have an interprocedural summary for this function
            # Even if it's not in state.user_functions (e.g., when analyzing entry point in isolation),
            # if we have a summary, we should treat it as a user function
            has_summary = False
            matched_summary_name = None
            if not is_user_function and func_name and state.security_tracker:
                from .interprocedural_taint import InterproceduralTaintTracker
                if isinstance(state.security_tracker, InterproceduralTaintTracker):
                    if state.security_tracker.context:
                        # Try exact match first
                        summary = state.security_tracker.context.get_summary(func_name)
                        if summary is not None:
                            has_summary = True
                            matched_summary_name = func_name
                        else:
                            # Try partial match (for qualified names)
                            for qname in state.security_tracker.context.summaries.keys():
                                if qname.endswith(f'.{func_name}') or qname == func_name:
                                    summary = state.security_tracker.context.summaries[qname]
                                    has_summary = True
                                    matched_summary_name = qname
                                    break
                        
                        if has_summary:
                            # Create minimal user_func_meta from the summary
                            user_func_meta = {
                                'code': None,  # We don't have the code object
                                'name': matched_summary_name,  # Use qualified name for later lookup
                                'filename': 'unknown',
                                'is_generator': False,
                                'is_coroutine': False,
                            }
            
            if is_user_function or has_summary:
                # Get metadata using stable ID if available, else fallback to object ID
                if not has_summary:
                    if func_stable_id is not None and func_stable_id in state.user_functions:
                        user_func_meta = state.user_functions[func_stable_id]
                    else:
                        user_func_meta = state.user_functions[id(func_ref)]
                    func_name = user_func_meta['name']
                else:
                    # has_summary path: user_func_meta already set, update func_name to qualified
                    func_name = user_func_meta['name']
                
                # Track statistics for evaluation (how many user functions we analyze)
                if not hasattr(state, 'user_function_calls'):
                    state.user_function_calls = []
                state.user_function_calls.append({
                    'name': func_name,
                    'filename': user_func_meta['filename'],
                    'offset': instr.offset,
                    'nargs': nargs,
                    'analyzed': False  # Will be updated if we analyze it
                })
                
                # ITERATION 417: Phase 4B - Interprocedural taint tracking with summaries
                # If we have an InterproceduralTaintTracker with a summary for this function,
                # apply the summary instead of inlining (for cross-function taint analysis)
                use_summary = False
                if state.security_tracker:
                    from .interprocedural_taint import InterproceduralTaintTracker
                    if isinstance(state.security_tracker, InterproceduralTaintTracker):
                        if state.security_tracker.context and func_name:
                            summary = state.security_tracker.context.get_summary(func_name)
                            if summary is not None:
                                use_summary = True
                                state.user_function_calls[-1]['analyzed'] = True
                                state.user_function_calls[-1]['phase'] = 'phase4b_interprocedural_summary'
                                
                                # ITERATION 493 FIX: Create result BEFORE calling handle_call_post
                                # so the tracker can set taint labels on it
                                result = SymbolicValue(ValueTag.OBJ, z3.Int(f"summary_result_{func_name}_{instr.offset}"))
                                
                                # Apply the summary through handle_call_post
                                # This will check for security violations and propagate taint
                                location = f"{frame.code.co_filename}:{instr.offset}"
                                handle_call_post(
                                    state.security_tracker, func_name, func_ref, args, result, location
                                )
                                
                                # The summary propagates return taint to result via handle_call_post
                                # Security violations have been recorded by _apply_summary
                                
                                if not state.exception:
                                    frame.operand_stack.append(result)
                                frame.instruction_offset = self._next_offset(frame, instr)
                                return
                
                # Phase 2 & Phase 3: Try to analyze user functions (if not using summary)
                # Phase 2: Simple non-recursive functions
                # Phase 3: Recursive functions with ranking function analysis
                if not use_summary:
                    can_inline = self._can_inline_user_function(
                        state, user_func_meta, max_frame_depth=10, allow_recursion=False
                    )
                    
                    # Track if this is a recursive call
                    func_code = user_func_meta['code']
                    is_recursive = any(frame.code is func_code for frame in state.frame_stack)
                else:
                    can_inline = False
                    is_recursive = False
                
                if can_inline and not use_summary:
                    # Phase 2: Non-recursive function - inline it
                    # Mark that we analyzed this call
                    state.user_function_calls[-1]['analyzed'] = True
                    state.user_function_calls[-1]['phase'] = 'phase2_nonrecursive'
                    
                    # Inline the function by creating a new frame
                    success = self._inline_user_function(state, user_func_meta, args, func_name, func_ref)
                    
                    if success:
                        # The new frame has been pushed; continue execution there
                        # Don't advance the current frame offset yet - we'll return here later
                        return
                    # If inlining failed for any reason, fall through to havoc
                
                elif is_recursive:
                    # Phase 3: Recursive function - try ranking function analysis
                    terminates, reason = self._analyze_recursion_with_ranking(
                        state, user_func_meta, args, max_recursion_depth=5
                    )
                    
                    if terminates:
                        # Ranking function proves termination → allow bounded inlining
                        state.user_function_calls[-1]['analyzed'] = True
                        state.user_function_calls[-1]['phase'] = 'phase3_recursive_terminating'
                        state.user_function_calls[-1]['termination_reason'] = reason
                        
                        # Inline with allow_recursion=True
                        success = self._inline_user_function(state, user_func_meta, args, func_name, func_ref)
                        
                        if success:
                            # Track recursion depth for this function
                            if not hasattr(state, 'recursion_depths'):
                                state.recursion_depths = {}
                            func_id = id(func_ref)
                            state.recursion_depths[func_id] = state.recursion_depths.get(func_id, 0) + 1
                            
                            return
                        # If inlining failed, fall through to havoc
                    else:
                        # Cannot prove termination → flag as potential NON_TERMINATION
                        state.user_function_calls[-1]['analyzed'] = False
                        state.user_function_calls[-1]['phase'] = 'phase3_recursive_no_termination_proof'
                        state.user_function_calls[-1]['termination_reason'] = reason
                        
                        # Note: We don't immediately report NON_TERMINATION here
                        # The NON_TERMINATION detector will check for unbounded recursion
                        # by examining path length and recursion patterns
                        # For now, fall through to havoc (sound over-approximation)
                
                
                # Fallback: treat as unknown (havoc contract)
                # This maintains soundness when inlining isn't possible
                contract = Contract.havoc(f"user_function_{user_func_meta['name']}")
                result = self._apply_contract(state, frame, contract, args, user_func_meta['name'])
                
                if not state.exception:
                    frame.operand_stack.append(result)
                frame.instruction_offset = self._next_offset(frame, instr)
                return
            
            # Check if this is a dict view method call (keys, values, items)
            if hasattr(state, 'dict_view_methods'):
                func_ref_id = None
                if isinstance(func_ref.payload, z3.IntNumRef):
                    func_ref_id = func_ref.payload.as_long()
                
                if func_ref_id in state.dict_view_methods:
                    view_meta = state.dict_view_methods[func_ref_id]
                    method = view_meta['method']
                    dict_obj = view_meta['dict_obj']
                    
                    # Handle dict methods
                    if method in ("keys", "values", "items"):
                        # Verify no arguments (dict.keys(), dict.values(), dict.items() take no args)
                        if len(args) != 0:
                            state.exception = "TypeError"
                            return
                    
                    # Return an appropriate view based on the method
                    if method == "keys":
                        # Return a list of keys (simplified model)
                        # In real Python, this returns a dict_keys view object, but for symbolic execution
                        # we model it as an iterable that yields keys
                        if isinstance(dict_obj.payload, z3.IntNumRef):
                            dict_id = dict_obj.payload.as_long()
                            dict_meta = state.heap.get_dict(dict_id)
                            if dict_meta:
                                # Create a list containing the keys
                                keys_list_id = state.heap.allocate_list()
                                keys_list = state.heap.get_sequence(keys_list_id)
                                
                                # Populate with known keys
                                for idx, key in enumerate(dict_meta.keys):
                                    # Keys are strings in our model
                                    key_str_id = state.heap.allocate_string(key)
                                    key_val = SymbolicValue(ValueTag.STR, z3.IntVal(key_str_id))
                                    keys_list.elements[idx] = key_val
                                
                                keys_list.length = z3.IntVal(len(dict_meta.keys))
                                result = SymbolicValue(ValueTag.LIST, z3.IntVal(keys_list_id))
                            else:
                                # Dict not found, return symbolic list
                                result = SymbolicValue(ValueTag.LIST, z3.Int(f"dict_keys_{dict_id}"))
                        else:
                            # Symbolic dict, return symbolic list
                            result = SymbolicValue(ValueTag.LIST, z3.Int(f"dict_keys_{id(dict_obj)}"))
                    
                    elif method == "values":
                        # Return a list of values
                        if isinstance(dict_obj.payload, z3.IntNumRef):
                            dict_id = dict_obj.payload.as_long()
                            dict_meta = state.heap.get_dict(dict_id)
                            if dict_meta:
                                # Create a list containing the values
                                values_list_id = state.heap.allocate_list()
                                values_list = state.heap.get_sequence(values_list_id)
                                
                                # Populate with values (in key order)
                                for idx, key in enumerate(dict_meta.keys):
                                    if key in dict_meta.values:
                                        values_list.elements[idx] = dict_meta.values[key]
                                
                                values_list.length = z3.IntVal(len(dict_meta.keys))
                                result = SymbolicValue(ValueTag.LIST, z3.IntVal(values_list_id))
                            else:
                                result = SymbolicValue(ValueTag.LIST, z3.Int(f"dict_values_{dict_id}"))
                        else:
                            result = SymbolicValue(ValueTag.LIST, z3.Int(f"dict_values_{id(dict_obj)}"))
                    
                    elif method == "items":
                        # Return a list of (key, value) tuples
                        if isinstance(dict_obj.payload, z3.IntNumRef):
                            dict_id = dict_obj.payload.as_long()
                            dict_meta = state.heap.get_dict(dict_id)
                            if dict_meta:
                                # Create a list containing tuples
                                items_list_id = state.heap.allocate_list()
                                items_list = state.heap.get_sequence(items_list_id)
                                
                                # Populate with (key, value) tuples
                                for idx, key in enumerate(dict_meta.keys):
                                    # Create tuple
                                    tuple_id = state.heap.allocate_tuple(2)
                                    
                                    # Set key
                                    key_str_id = state.heap.allocate_string(key)
                                    key_val = SymbolicValue(ValueTag.STR, z3.IntVal(key_str_id))
                                    state.heap.set_tuple_element(tuple_id, 0, key_val)
                                    
                                    # Set value
                                    if key in dict_meta.values:
                                        state.heap.set_tuple_element(tuple_id, 1, dict_meta.values[key])
                                    
                                    # Add tuple to list
                                    items_list.elements[idx] = SymbolicValue(ValueTag.TUPLE, z3.IntVal(tuple_id))
                                
                                items_list.length = z3.IntVal(len(dict_meta.keys))
                                result = SymbolicValue(ValueTag.LIST, z3.IntVal(items_list_id))
                            else:
                                result = SymbolicValue(ValueTag.LIST, z3.Int(f"dict_items_{dict_id}"))
                        else:
                            result = SymbolicValue(ValueTag.LIST, z3.Int(f"dict_items_{id(dict_obj)}"))
                    
                    elif method == "get":
                        # dict.get(key, default=None) - returns value if key exists, else default
                        # Signature: get(key, default=None)
                        # Args: key (required), default (optional, defaults to None)
                        if len(args) < 1 or len(args) > 2:
                            state.exception = "TypeError"
                            return
                        
                        key_arg = args[0]
                        default_arg = args[1] if len(args) == 2 else SymbolicValue(ValueTag.NONE, z3.IntVal(0))
                        
                        # ITERATION 277: Check if this is an HTTP parameter dict
                        # HTTP parameter dicts (request.POST, request.GET, etc.) return STR values
                        # This prevents TypeError in patterns like: "nmap " + request.POST.get('ip')
                        is_http_param_dict = False
                        if isinstance(dict_obj.payload, z3.IntNumRef):
                            dict_id = dict_obj.payload.as_long()
                            if hasattr(state, 'http_param_dicts') and dict_id in state.http_param_dicts:
                                is_http_param_dict = True
                        
                        # For HTTP parameter dicts, always return STR (sound over-approximation)
                        if is_http_param_dict:
                            result = SymbolicValue(ValueTag.STR, z3.Int(f"http_param_{id(dict_obj)}_{id(key_arg)}"))
                        # For concrete dict with concrete key, try to retrieve
                        elif isinstance(dict_obj.payload, z3.IntNumRef) and isinstance(key_arg.payload, z3.IntNumRef):
                            dict_id = dict_obj.payload.as_long()
                            dict_meta = state.heap.get_dict(dict_id)
                            
                            if dict_meta and key_arg.tag == ValueTag.STR:
                                # Try to get the concrete key
                                key_str_id = key_arg.payload.as_long()
                                key_str = state.heap.get_string(key_str_id)
                                
                                if key_str and key_str in dict_meta.values:
                                    # Key exists, return value
                                    result = dict_meta.values[key_str]
                                else:
                                    # Key doesn't exist, return default
                                    result = default_arg
                            else:
                                # Unknown dict or non-string key
                                # Sound over-approximation: could be a value from dict OR the default
                                # If default has a known type, preserve it (helps downstream analysis)
                                if default_arg.tag in (ValueTag.INT, ValueTag.STR, ValueTag.BOOL, ValueTag.FLOAT, ValueTag.NONE):
                                    # Return a fresh symbolic value of the default's type
                                    result = SymbolicValue(default_arg.tag, z3.Int(f"dict_get_{dict_id}_{id(key_arg)}"))
                                else:
                                    # Default is OBJ or complex type, return OBJ
                                    result = SymbolicValue(ValueTag.OBJ, z3.Int(f"dict_get_{dict_id}_{id(key_arg)}"))
                        else:
                            # Symbolic dict or symbolic key: return could be anything (OBJ) or default
                            # If default has a known type, preserve it
                            if default_arg.tag in (ValueTag.INT, ValueTag.STR, ValueTag.BOOL, ValueTag.FLOAT, ValueTag.NONE):
                                result = SymbolicValue(default_arg.tag, z3.Int(f"dict_get_symbolic_{id(dict_obj)}_{id(key_arg)}"))
                            else:
                                result = SymbolicValue(ValueTag.OBJ, z3.Int(f"dict_get_symbolic_{id(dict_obj)}_{id(key_arg)}"))
                    
                    elif method == "setdefault":
                        # dict.setdefault(key, default=None) - returns value if key exists, else sets key=default and returns default
                        # Signature: setdefault(key, default=None)
                        # This mutates the dict (side effect)
                        if len(args) < 1 or len(args) > 2:
                            state.exception = "TypeError"
                            return
                        
                        key_arg = args[0]
                        default_arg = args[1] if len(args) == 2 else SymbolicValue(ValueTag.NONE, z3.IntVal(0))
                        
                        # For concrete dict with concrete key
                        if isinstance(dict_obj.payload, z3.IntNumRef) and isinstance(key_arg.payload, z3.IntNumRef):
                            dict_id = dict_obj.payload.as_long()
                            dict_meta = state.heap.get_dict(dict_id)
                            
                            if dict_meta and key_arg.tag == ValueTag.STR:
                                key_str_id = key_arg.payload.as_long()
                                key_str = state.heap.get_string(key_str_id)
                                
                                if key_str:
                                    if key_str in dict_meta.values:
                                        # Key exists, return existing value (no mutation)
                                        result = dict_meta.values[key_str]
                                    else:
                                        # Key doesn't exist, set it to default and return default
                                        dict_meta.values[key_str] = default_arg
                                        dict_meta.keys.add(key_str)
                                        result = default_arg
                                else:
                                    # Unknown key string - result could be existing value OR default
                                    if default_arg.tag in (ValueTag.INT, ValueTag.STR, ValueTag.BOOL, ValueTag.FLOAT, ValueTag.NONE):
                                        result = SymbolicValue(default_arg.tag, z3.Int(f"dict_setdefault_{dict_id}_{id(key_arg)}"))
                                    else:
                                        result = SymbolicValue(ValueTag.OBJ, z3.Int(f"dict_setdefault_{dict_id}_{id(key_arg)}"))
                            else:
                                # Unknown dict meta - result could be existing value OR default
                                if default_arg.tag in (ValueTag.INT, ValueTag.STR, ValueTag.BOOL, ValueTag.FLOAT, ValueTag.NONE):
                                    result = SymbolicValue(default_arg.tag, z3.Int(f"dict_setdefault_{dict_id}_{id(key_arg)}"))
                                else:
                                    result = SymbolicValue(ValueTag.OBJ, z3.Int(f"dict_setdefault_{dict_id}_{id(key_arg)}"))
                        else:
                            # Symbolic dict or key: model as mutation + return of value OR default
                            # If default has a known type, preserve it
                            if default_arg.tag in (ValueTag.INT, ValueTag.STR, ValueTag.BOOL, ValueTag.FLOAT, ValueTag.NONE):
                                result = SymbolicValue(default_arg.tag, z3.Int(f"dict_setdefault_symbolic_{id(dict_obj)}_{id(key_arg)}"))
                            else:
                                result = SymbolicValue(ValueTag.OBJ, z3.Int(f"dict_setdefault_symbolic_{id(dict_obj)}_{id(key_arg)}"))
                    
                    # ============================================================
                    # SECURITY BUG DETECTION: Call post-hook for dict methods
                    # ============================================================
                    if state.security_tracker:
                        location = f"{frame.code.co_filename}:{instr.offset}"
                        handle_call_post(
                            state.security_tracker, f"dict.{method}", func_ref, args, result, location
                        )
                    
                    frame.operand_stack.append(result)
                    frame.instruction_offset = self._next_offset(frame, instr)
                    return
            
            # Apply semantics: try relational summary first, then contract
            if func_name:
                # ============================================================
                # SECURITY BUG DETECTION (§11): Pre-call sink check
                # ============================================================
                import os
                if os.environ.get('TAINT_DEBUG') == '1':
                    print(f"[CALL] Calling {func_name}")
                    print(f"      state.security_tracker: {state.security_tracker}")
                    if state.security_tracker:
                        print(f"      security_tracker.enabled: {state.security_tracker.enabled}")
                
                if state.security_tracker:
                    location = f"{frame.code.co_filename}:{instr.offset}"
                    # Filter out NULL markers from args (Python 3.14 calling convention)
                    # NULL markers (ValueTag.NONE with payload 0) are not actual arguments
                    filtered_args = [arg for arg in args if not (arg.tag == ValueTag.NONE and arg.payload == 0)]
                    # ITERATION 495: Pass empty kwargs dict for consistency with CALL_KW
                    # ITERATION 526: Pass is_method_call=True if no NULL marker (method call convention)
                    violation = handle_call_pre(
                        state.security_tracker, func_name, filtered_args, location, {}, is_method_call=not has_null
                    )
                    if violation:
                        # Map violation to state detection flag
                        self._set_security_detection_flag(state, violation)
                else:
                    # Filter even if no security tracker, for consistency
                    filtered_args = [arg for arg in args if not (arg.tag == ValueTag.NONE and arg.payload == 0)]
                
                # Check if we have a relational summary for this function
                # ITERATION 409 FIX: Use filtered_args (without NULL markers)
                if has_relational_summary(func_name):
                    summary = get_relational_summary(func_name)
                    result = self._apply_relational_summary(state, frame, summary, filtered_args, func_name)
                else:
                    # Fall back to contract-based semantics
                    contract = get_contract(func_name)
                    result = self._apply_contract(state, frame, contract, args, func_name)
                
                if not state.exception:
                    # ============================================================
                    # SECURITY BUG DETECTION (§11): Post-call source/sanitizer
                    # ============================================================
                    if state.security_tracker:
                        location = f"{frame.code.co_filename}:{instr.offset}"
                        handle_call_post(
                            state.security_tracker, func_name, func_ref, args, result, location
                        )
                    
                    # Replay concretization: if the call target was unknown/unmodeled and we
                    # observed a concrete return, use it to produce a faithful witness state.
                    if call_obs and call_obs.exception_type is None and self.oracle and self.oracle.concretize_unknown_returns:
                        if call_obs.has_return_value:
                            result = self._symbolic_from_concrete(state, call_obs.return_value)
                    
                    # Special handling for class decorators:
                    # If func_name is a known class decorator (e.g., dataclass) and the first argument
                    # is a class object, then the result is also a class object (decorator returns modified class).
                    # This allows decorated classes to be instantiated properly.
                    known_class_decorators = {
                        'dataclass', 'dataclasses.dataclass',
                        'attr.s', 'attr.attrs',
                        'click.command', 'click.group'
                    }
                    if func_name in known_class_decorators and len(args) >= 1:
                        first_arg = args[0]
                        
                        # Handle class decorators: the result is also a class object
                        # Case 1: first_arg is already tracked in class_objects (ideal case)
                        if hasattr(state, 'class_objects') and id(first_arg) in state.class_objects:
                            # First argument is a class - result is also a class (decorator returns modified class)
                            original_class_meta = state.class_objects[id(first_arg)]
                            
                            # Copy class metadata to the result
                            # CRITICAL: This ensures that the decorated class can be instantiated later
                            # The result from the decorator call is a NEW object, so we need to copy
                            # the class metadata from the original class to the result
                            state.class_objects[id(result)] = {
                                'name': original_class_meta['name'],
                                'body_func': original_class_meta['body_func'],
                                'namespace_id': original_class_meta['namespace_id'],
                                'executed': original_class_meta['executed'],
                                'decorator': func_name  # Track which decorator was applied
                            }
                            
                            # Also ensure result has the right tag for class objects
                            # (though it should already be OBJ from _apply_contract)
                            if result.tag != ValueTag.OBJ:
                                # Fix: wrap in OBJ tag if needed
                                # CRITICAL: Store old result ID before creating new result
                                old_result_id = id(result)
                                result = SymbolicValue(ValueTag.OBJ, result.payload)
                                # Delete old result entry (from line 3011) since we created a new result
                                if old_result_id in state.class_objects:
                                    del state.class_objects[old_result_id]
                                # Update class_objects with new result ID
                                state.class_objects[id(result)] = {
                                    'name': original_class_meta['name'],
                                    'body_func': original_class_meta['body_func'],
                                    'namespace_id': original_class_meta['namespace_id'],
                                    'executed': original_class_meta['executed'],
                                    'decorator': func_name
                                }
                        else:
                            # Case 2: first_arg is not in class_objects (state was reset/forked)
                            # But we know this is a class decorator, so treat result as a class
                            if not hasattr(state, 'class_objects'):
                                state.class_objects = {}
                            
                            # Create minimal class metadata for the result
                            # We don't have the original class metadata, but that's OK for instantiation
                            state.class_objects[id(result)] = {
                                'name': 'DecoratedClass',  # Placeholder name
                                'body_func': None,  # No body function available
                                'namespace_id': None,  # No namespace
                                'executed': False,  # Wasn't executed
                                'decorator': func_name
                            }
                    
                    frame.operand_stack.append(result)
            else:
                # Unknown function: apply default havoc contract
                contract = Contract.havoc("unknown_function")
                result = self._apply_contract(state, frame, contract, args, "unknown_function")
                
                if not state.exception:
                    # ============================================================
                    # SECURITY BUG DETECTION (§11): Post-call for unknown functions
                    # Propagate taint from func_ref (for method calls on tainted objects)
                    # ============================================================
                    if state.security_tracker:
                        location = f"{frame.code.co_filename}:{instr.offset}"
                        handle_call_post(
                            state.security_tracker, "unknown_function", func_ref, args, result, location
                        )
                    
                    if call_obs and call_obs.exception_type is None and self.oracle and self.oracle.concretize_unknown_returns:
                        if call_obs.has_return_value:
                            result = self._symbolic_from_concrete(state, call_obs.return_value)
                    frame.operand_stack.append(result)
            
            if not state.exception:
                frame.instruction_offset = self._next_offset(frame, instr)
        
        elif opname == "CALL_KW":
            # CALL_KW(nargs): calls a function with positional and keyword arguments
            # Stack layout: [callable, NULL_or_self, arg1, ..., argN, kwnames_tuple]
            # where nargs is total number of arguments (positional + keyword)
            # kwnames is a tuple of keyword argument names (last len(kwnames) args are kwargs)
            nargs = instr.argval
            
            # Need at least nargs + 2 items (args + kwnames + NULL + callable)
            if len(frame.operand_stack) < nargs + 2:
                state.exception = "StackUnderflow"
                return
            
            # Pop kwnames tuple
            kwnames_tuple = frame.operand_stack.pop()
            
            # Extract keyword argument names from the tuple
            # kwnames_tuple is a SymbolicValue with TUPLE tag
            # The payload is an object ID pointing to a sequence in the heap
            kwnames = []
            try:
                # Get the tuple object ID from the payload
                # The payload is a Z3 IntVal for concrete tuples
                if hasattr(kwnames_tuple.payload, 'as_long'):
                    tuple_id = kwnames_tuple.payload.as_long()
                    # Get the tuple from the heap
                    tuple_obj = state.heap.get_sequence(tuple_id)
                    if tuple_obj:
                        # Extract string names from the tuple elements
                        for i in range(len(tuple_obj.elements)):
                            if i in tuple_obj.elements:
                                elem = tuple_obj.elements[i]
                                # Each element is a SymbolicValue with STR tag
                                if hasattr(elem.payload, 'as_long'):
                                    str_id = elem.payload.as_long()
                                    string_val = state.heap.get_string(str_id)
                                    if string_val:
                                        kwnames.append(string_val)
            except Exception as e:
                # If we can't extract kwnames, treat all args as positional
                if self.verbose:
                    print(f"Warning: Could not extract kwnames from tuple: {e}")
            
            # Pop all arguments (positional + keyword) in order
            args = []
            for _ in range(nargs):
                args.insert(0, frame.operand_stack.pop())
            
            # Build kwargs dict from the last len(kwnames) arguments
            kwargs = {}
            if kwnames:
                num_kwargs = len(kwnames)
                # Last num_kwargs elements of args are keyword arguments
                kwarg_values = args[-num_kwargs:]
                args = args[:-num_kwargs]  # Remove kwargs from args list
                
                # Map keyword names to values
                for name, value in zip(kwnames, kwarg_values):
                    kwargs[name] = value
            
            # Check if next item is NULL marker
            has_null_marker = False
            if frame.operand_stack and frame.operand_stack[-1].tag == ValueTag.NONE:
                # Pop the NULL marker
                frame.operand_stack.pop()
                has_null_marker = True
            
            # Pop function reference
            if not frame.operand_stack:
                state.exception = "StackUnderflow"
                return
            func_ref = frame.operand_stack.pop()
            
            # Check if this is a generator or coroutine function
            if hasattr(state, 'function_metadata') and id(func_ref) in state.function_metadata:
                metadata = state.function_metadata[id(func_ref)]
                if metadata.get('is_generator') or metadata.get('is_coroutine'):
                    # Create and return a generator/coroutine object
                    gen_id = id(metadata['code'])
                    gen_obj = SymbolicValue(ValueTag.OBJ, z3.Int(f"generator_{gen_id}_{instr.offset}"))
                    
                    if not hasattr(state, 'generator_states'):
                        state.generator_states = {}
                    state.generator_states[id(gen_obj)] = {
                        'code': metadata['code'],
                        'args': args,
                        'suspended': True,
                        'is_coroutine': metadata.get('is_coroutine', False)
                    }
                    
                    frame.operand_stack.append(gen_obj)
                    frame.instruction_offset = self._next_offset(frame, instr)
                    return
            
            # Determine function name for contract lookup
            func_name = None
            if hasattr(state, 'func_names'):
                # Use stable func_id from payload instead of Python object id()
                if func_ref.tag == ValueTag.OBJ and isinstance(func_ref.payload, z3.IntNumRef):
                    func_id = func_ref.payload.as_long()
                    func_name = state.func_names.get(func_id)
                # Fallback: check if stored by id() for backward compatibility
                if not func_name:
                    func_name = state.func_names.get(id(func_ref))

            call_obs: Optional[CallObservation] = None
            if self.oracle:
                call_obs = self.oracle.pop_call_observation(frame.code, instr.offset)
                if call_obs and call_obs.function_id:
                    func_name = call_obs.function_id

            if call_obs and call_obs.exception_type:
                state.exception = call_obs.exception_type
                return
            
            # Special handling for __build_class__ builtin (same as CALL opcode)
            if func_name == "__build_class__":
                # __build_class__(func, name, *bases, **kwds)
                # Minimum: func (class body function) and name (string)
                if len(args) < 2:
                    state.exception = "TypeError"
                    return
                
                class_body_func = args[0]
                class_name_val = args[1]
                
                # Check if class_body_func is a user-defined function we can execute
                is_user_func = id(class_body_func) in state.user_functions
                
                if is_user_func:
                    # Execute the class body to build the class namespace
                    class_body_meta = state.user_functions[id(class_body_func)]
                    
                    # Create a new namespace dict for the class
                    class_namespace_id = state.heap.allocate_dict(keys=set(), values={})
                    
                    # Execute the class body function to populate the namespace
                    try:
                        class_body_result = self._execute_class_body(state, class_body_meta, class_namespace_id)
                        # class_body_result contains the final locals which become class attributes
                    except Exception as e:
                        # If execution fails, fall back to symbolic class (sound over-approximation)
                        class_body_result = None
                    
                    # Create a class object
                    class_obj = SymbolicValue(ValueTag.OBJ, z3.Int(f"class_{class_body_meta['name']}_{instr.offset}"))
                    
                    # Store metadata so we can track that this is a class
                    if not hasattr(state, 'class_objects'):
                        state.class_objects = {}
                    state.class_objects[id(class_obj)] = {
                        'name': class_name_val,
                        'body_func': class_body_meta,
                        'namespace_id': class_namespace_id,
                        'executed': class_body_result is not None
                    }
                    
                    frame.operand_stack.append(class_obj)
                    frame.instruction_offset = self._next_offset(frame, instr)
                    return
                else:
                    # Unknown class body function - create symbolic class object
                    class_obj = SymbolicValue(ValueTag.OBJ, z3.Int(f"class_symbolic_{instr.offset}"))
                    frame.operand_stack.append(class_obj)
                    frame.instruction_offset = self._next_offset(frame, instr)
                    return
            
            # Apply semantics: try relational summary first, then contract
            if func_name:
                # ============================================================
                # SECURITY BUG DETECTION (§11): Pre-call sink check
                # ============================================================
                # Filter out NULL markers from args (Python 3.14 calling convention)
                filtered_args = [arg for arg in args if not (arg.tag == ValueTag.NONE and arg.payload == 0)]
                
                if state.security_tracker:
                    location = f"{frame.code.co_filename}:{instr.offset}"
                    # ITERATION 526: Pass is_method_call=True if no NULL marker (method call convention)
                    violation = handle_call_pre(
                        state.security_tracker, func_name, filtered_args, location, kwargs, is_method_call=not has_null_marker
                    )
                    if violation:
                        # Map violation to state detection flag
                        self._set_security_detection_flag(state, violation)
                
                # Check if we have a relational summary for this function
                # ITERATION 409 FIX: Use filtered_args (without NULL markers)
                if has_relational_summary(func_name):
                    summary = get_relational_summary(func_name)
                    result = self._apply_relational_summary(state, frame, summary, filtered_args, func_name)
                else:
                    # Fall back to contract-based semantics
                    contract = get_contract(func_name)
                    result = self._apply_contract(state, frame, contract, args, func_name)
                
                if not state.exception:
                    # ============================================================
                    # SECURITY BUG DETECTION (§11): Post-call source/sanitizer
                    # ============================================================
                    if state.security_tracker:
                        location = f"{frame.code.co_filename}:{instr.offset}"
                        handle_call_post(
                            state.security_tracker, func_name, func_ref, args, result, location
                        )
                    
                    if call_obs and call_obs.exception_type is None and self.oracle and self.oracle.concretize_unknown_returns:
                        if call_obs.has_return_value:
                            result = self._symbolic_from_concrete(state, call_obs.return_value)
                    frame.operand_stack.append(result)
            else:
                # Unknown function: apply default havoc contract
                contract = Contract.havoc("unknown_function")
                result = self._apply_contract(state, frame, contract, args, "unknown_function")
                
                if not state.exception:
                    # ============================================================
                    # SECURITY BUG DETECTION (§11): Post-call for unknown functions
                    # Propagate taint from func_ref (for method calls on tainted objects)
                    # ============================================================
                    if state.security_tracker:
                        location = f"{frame.code.co_filename}:{instr.offset}"
                        handle_call_post(
                            state.security_tracker, "unknown_function", func_ref, args, result, location
                        )
                    
                    if call_obs and call_obs.exception_type is None and self.oracle and self.oracle.concretize_unknown_returns:
                        if call_obs.has_return_value:
                            result = self._symbolic_from_concrete(state, call_obs.return_value)
                    frame.operand_stack.append(result)
            
            if not state.exception:
                frame.instruction_offset = self._next_offset(frame, instr)
        
        elif opname == "BINARY_OP":
            if len(frame.operand_stack) < 2:
                state.exception = "StackUnderflow"
                return
            
            right = frame.operand_stack.pop()
            left = frame.operand_stack.pop()
            
            op = instr.argval
            
            if op == 0:  # ADD
                result, type_ok, none_misuse = binary_op_add(left, right, self.solver)
                # Check for None misuse
                self.solver.push()
                self.solver.add(state.path_condition)
                self.solver.add(none_misuse)
                if self.solver.check() == z3.sat:
                    state.none_misuse_reached = True
                    state.exception = "TypeError"
                self.solver.pop()
                
                # Check for type confusion (type mismatch that isn't None misuse)
                if not state.exception:
                    self.solver.push()
                    self.solver.add(state.path_condition)
                    self.solver.add(z3.Not(type_ok))
                    self.solver.add(z3.Not(none_misuse))
                    if self.solver.check() == z3.sat:
                        state.type_confusion_reached = True
                        state.exception = "TypeError"
                    self.solver.pop()
                
                if not state.exception:
                    state.path_condition = z3.And(state.path_condition, type_ok, z3.Not(none_misuse))
                    frame.operand_stack.append(result)
                    
                    # SECURITY: Propagate taint through binary operation
                    if state.security_tracker:
                        from a3_python.semantics.security_tracker_lattice import handle_binop
                        handle_binop(state.security_tracker, left, right, result)
            
            elif op == 10:  # SUBTRACT
                result, type_ok, none_misuse = binary_op_sub(left, right, self.solver)
                # Check for None misuse
                self.solver.push()
                self.solver.add(state.path_condition)
                self.solver.add(none_misuse)
                if self.solver.check() == z3.sat:
                    state.none_misuse_reached = True
                    state.exception = "TypeError"
                self.solver.pop()
                
                # Check for type confusion (type mismatch that isn't None misuse)
                if not state.exception:
                    self.solver.push()
                    self.solver.add(state.path_condition)
                    self.solver.add(z3.Not(type_ok))
                    self.solver.add(z3.Not(none_misuse))
                    if self.solver.check() == z3.sat:
                        state.type_confusion_reached = True
                        state.exception = "TypeError"
                    self.solver.pop()
                
                if not state.exception:
                    state.path_condition = z3.And(state.path_condition, type_ok, z3.Not(none_misuse))
                    frame.operand_stack.append(result)
                    
                    # SECURITY: Propagate taint through binary operation
                    if state.security_tracker:
                        from a3_python.semantics.security_tracker_lattice import handle_binop
                        handle_binop(state.security_tracker, left, right, result)
            
            elif op == 5:  # MULTIPLY
                result, type_ok, none_misuse = binary_op_mul(left, right, self.solver)
                # Check for None misuse
                self.solver.push()
                self.solver.add(state.path_condition)
                self.solver.add(none_misuse)
                if self.solver.check() == z3.sat:
                    state.none_misuse_reached = True
                    state.exception = "TypeError"
                self.solver.pop()
                
                # Check for type confusion (type mismatch that isn't None misuse)
                if not state.exception:
                    self.solver.push()
                    self.solver.add(state.path_condition)
                    self.solver.add(z3.Not(type_ok))
                    self.solver.add(z3.Not(none_misuse))
                    if self.solver.check() == z3.sat:
                        state.type_confusion_reached = True
                        state.exception = "TypeError"
                    self.solver.pop()
                
                if not state.exception:
                    state.path_condition = z3.And(state.path_condition, type_ok, z3.Not(none_misuse))
                    frame.operand_stack.append(result)
                    
                    # SECURITY: Propagate taint through binary operation
                    if state.security_tracker:
                        from a3_python.semantics.security_tracker_lattice import handle_binop
                        handle_binop(state.security_tracker, left, right, result)
            
            elif op == 11:  # TRUE_DIVIDE
                result, type_ok, div_zero, none_misuse = binary_op_truediv(left, right, self.solver)
                
                new_exception = None
                
                # Check for None misuse first
                self.solver.push()
                self.solver.add(state.path_condition)
                self.solver.add(none_misuse)
                if self.solver.check() == z3.sat:
                    state.none_misuse_reached = True
                    new_exception = "TypeError"
                self.solver.pop()
                
                # Check if division by zero is reachable on this path (if no None misuse)
                if not new_exception:
                    self.solver.push()
                    self.solver.add(state.path_condition)
                    self.solver.add(z3.Not(none_misuse))
                    self.solver.add(div_zero)
                    if self.solver.check() == z3.sat:
                        state.div_by_zero_reached = True
                        new_exception = "ZeroDivisionError"
                        # Capture context for precise bug reporting
                        func_name = state.func_names.get(id(frame.code), frame.code.co_name)
                        state.div_by_zero_context = {
                            'operation': 'true_divide',
                            'offset': frame.instruction_offset,
                            'function_name': func_name,
                            'left_symbolic': str(left),
                            'right_symbolic': str(right),
                            'div_zero_constraint': str(div_zero)
                        }
                    self.solver.pop()
                
                if new_exception:
                    # New exception raised, replaces any existing exception
                    state.exception = new_exception
                    # Don't advance IP; exception handling will occur in explore_bounded
                    return
                else:
                    # Continue on non-error path
                    state.path_condition = z3.And(state.path_condition, type_ok, z3.Not(div_zero), z3.Not(none_misuse))
                    frame.operand_stack.append(result)
                    
                    # SECURITY: Propagate taint through binary operation
                    if state.security_tracker:
                        from a3_python.semantics.security_tracker_lattice import handle_binop
                        handle_binop(state.security_tracker, left, right, result)
            
            elif op == 2:  # FLOOR_DIVIDE
                result, type_ok, div_zero, none_misuse = binary_op_floordiv(left, right, self.solver)
                
                new_exception = None
                
                # Check for None misuse first
                self.solver.push()
                self.solver.add(state.path_condition)
                self.solver.add(none_misuse)
                if self.solver.check() == z3.sat:
                    state.none_misuse_reached = True
                    new_exception = "TypeError"
                self.solver.pop()
                
                if not new_exception:
                    # Check if division by zero is reachable on this path
                    self.solver.push()
                    self.solver.add(state.path_condition)
                    self.solver.add(z3.Not(none_misuse))
                    self.solver.add(div_zero)
                    if self.solver.check() == z3.sat:
                        state.div_by_zero_reached = True
                        new_exception = "ZeroDivisionError"
                        # Capture context for precise bug reporting
                        func_name = state.func_names.get(id(frame.code), frame.code.co_name)
                        state.div_by_zero_context = {
                            'operation': 'floor_divide',
                            'offset': frame.instruction_offset,
                            'function_name': func_name,
                            'left_symbolic': str(left),
                            'right_symbolic': str(right),
                            'div_zero_constraint': str(div_zero)
                        }
                    self.solver.pop()
                
                if new_exception:
                    state.exception = new_exception
                    return
                else:
                    state.path_condition = z3.And(state.path_condition, type_ok, z3.Not(div_zero), z3.Not(none_misuse))
                    frame.operand_stack.append(result)
                    
                    # SECURITY: Propagate taint through binary operation
                    if state.security_tracker:
                        from a3_python.semantics.security_tracker_lattice import handle_binop
                        handle_binop(state.security_tracker, left, right, result)
            
            elif op == 6:  # MODULO
                result, type_ok, div_zero, none_misuse = binary_op_mod(left, right, self.solver)
                
                new_exception = None
                
                # Check for None misuse first
                self.solver.push()
                self.solver.add(state.path_condition)
                self.solver.add(none_misuse)
                if self.solver.check() == z3.sat:
                    state.none_misuse_reached = True
                    new_exception = "TypeError"
                self.solver.pop()
                
                if not new_exception:
                    # Check if division by zero is reachable on this path
                    self.solver.push()
                    self.solver.add(state.path_condition)
                    self.solver.add(z3.Not(none_misuse))
                    self.solver.add(div_zero)
                    if self.solver.check() == z3.sat:
                        state.div_by_zero_reached = True
                        new_exception = "ZeroDivisionError"
                        # Capture context for precise bug reporting
                        func_name = state.func_names.get(id(frame.code), frame.code.co_name)
                        state.div_by_zero_context = {
                            'operation': 'modulo',
                            'offset': frame.instruction_offset,
                            'function_name': func_name,
                            'left_symbolic': str(left),
                            'right_symbolic': str(right),
                            'div_zero_constraint': str(div_zero)
                        }
                    self.solver.pop()
                
                if new_exception:
                    state.exception = new_exception
                    return
                else:
                    state.path_condition = z3.And(state.path_condition, type_ok, z3.Not(div_zero), z3.Not(none_misuse))
                    frame.operand_stack.append(result)
                    
                    # SECURITY: Propagate taint through binary operation
                    if state.security_tracker:
                        from a3_python.semantics.security_tracker_lattice import handle_binop
                        handle_binop(state.security_tracker, left, right, result)
            
            elif op == 26:  # SUBSCRIPT ([])
                result, type_ok, bounds_violated, none_misuse = binary_op_subscript(left, right, state.heap, self.solver)
                
                # ITERATION 277: For HTTP parameter dicts, override result type to STR
                # This prevents TypeError when concatenating: "nmap " + request.POST['ip']
                # ITERATION 310 FIX: Also override bounds_violated to False for http_param_dicts
                # Issue from iteration 309: request.POST['password'] raises KeyError before
                # reaching the sink, blocking CLEARTEXT_LOGGING detection.
                # HTTP parameter dicts are sound over-approximations: any key could exist,
                # so we return a tainted STR value without raising KeyError.
                if left.tag == ValueTag.DICT and isinstance(left.payload, z3.IntNumRef):
                    dict_id = left.payload.as_long()
                    if hasattr(state, 'http_param_dicts') and dict_id in state.http_param_dicts:
                        # HTTP parameter dict: return STR regardless of what binary_op_subscript returned
                        result = SymbolicValue(ValueTag.STR, z3.Int(f"http_param_subscr_{dict_id}_{id(right)}"))
                        # Override bounds_violated: HTTP parameter dicts never raise KeyError
                        # (sound over-approximation: any key could have been in the request)
                        bounds_violated = z3.BoolVal(False)
                
                # Check if None misuse is reachable on this path
                self.solver.push()
                self.solver.add(state.path_condition)
                self.solver.add(none_misuse)
                if self.solver.check() == z3.sat:
                    state.none_misuse_reached = True
                    state.exception = "TypeError"
                self.solver.pop()
                
                if not state.exception:
                    # Check if index out of bounds is reachable on this path
                    self.solver.push()
                    self.solver.add(state.path_condition)
                    self.solver.add(bounds_violated)
                    if self.solver.check() == z3.sat:
                        state.index_out_of_bounds = True
                        # Determine exception type based on container type
                        # Dict subscripts raise KeyError, list/tuple raise IndexError
                        if left.is_dict():
                            state.exception = "KeyError"
                        else:
                            state.exception = "IndexError"
                    self.solver.pop()
                
                if not state.exception:
                    # Continue on non-violation path
                    state.path_condition = z3.And(state.path_condition, type_ok, z3.Not(bounds_violated), z3.Not(none_misuse))
                    frame.operand_stack.append(result)
                    
                    # SECURITY: Propagate taint through subscript operation
                    # Note: subscript uses handle_subscript, not handle_binop
                    if state.security_tracker:
                        from a3_python.semantics.security_tracker_lattice import handle_subscript
                        handle_subscript(state.security_tracker, left, right, result)
                        
                        # ITERATION 463: Runtime sensitivity inference for dict subscripts
                        # If subscripting with a string literal key that looks sensitive,
                        # add σ-taint (sensitivity) to the result value
                        # Pattern: request.POST['password'] or request.POST.get('pass')
                        # FIXED: Remove ValueTag.DICT restriction - works on any subscript with tainted result
                        import os
                        DEBUG_SIGMA = os.environ.get('DEBUG_SIGMA') == '1'
                        from a3_python.frontend.entry_points import SENSITIVE_PARAM_PATTERNS
                        
                        if DEBUG_SIGMA:
                            print(f"[DEBUG_SIGMA] Checking subscript for sensitivity:")
                            print(f"  left.tag={left.tag}, right.tag={right.tag}")
                        
                        # Check if result has any taint (τ or σ) - if so, check key for sensitivity
                        result_label = state.security_tracker.get_label(result)
                        if DEBUG_SIGMA:
                            print(f"  result_label={result_label}")
                            if result_label:
                                print(f"  has_any_taint={result_label.has_any_taint()}")
                        
                        if result_label and result_label.has_any_taint() and right.tag == ValueTag.STR:
                            if DEBUG_SIGMA:
                                print(f"[DEBUG_SIGMA] Dict subscript detected: left.tag={left.tag}, right.tag={right.tag}")
                            # Try to extract string literal from key
                            key_str = None
                            if isinstance(right.payload, str):
                                key_str = right.payload
                            elif isinstance(right.payload, z3.IntNumRef):
                                # String is stored in heap, look it up
                                str_id = right.payload.as_long()
                                key_str = state.heap.get_string(str_id)
                            elif hasattr(right, 'concrete_value') and isinstance(right.concrete_value, str):
                                key_str = right.concrete_value
                            
                            if DEBUG_SIGMA:
                                print(f"[DEBUG_SIGMA] Extracted key: {key_str}")
                            
                            # Check if key name matches sensitive patterns
                            if key_str:
                                key_lower = key_str.lower()
                                matched_pattern = None
                                for pattern in SENSITIVE_PARAM_PATTERNS:
                                    if pattern in key_lower:
                                        matched_pattern = pattern
                                        break
                                
                                if matched_pattern:
                                    if DEBUG_SIGMA:
                                        print(f"[DEBUG_SIGMA] Matched sensitive pattern: {matched_pattern}")
                                    # Add sensitivity to result (both concrete and symbolic labels)
                                    from a3_python.z3model.taint_lattice import SourceType
                                    
                                    # Update concrete label
                                    concrete_label = state.security_tracker.get_label(result)
                                    if DEBUG_SIGMA:
                                        print(f"[DEBUG_SIGMA] Before σ-taint: concrete_label={concrete_label}")
                                    if concrete_label:
                                        sensitive_concrete = concrete_label.with_sensitivity(SourceType.PASSWORD)
                                        state.security_tracker.set_label(result, sensitive_concrete)
                                        if DEBUG_SIGMA:
                                            print(f"[DEBUG_SIGMA] After σ-taint: sensitive_concrete={sensitive_concrete}")
                                    
                                    # Update symbolic label
                                    symbolic_label = state.security_tracker.get_symbolic_label(result)
                                    if symbolic_label:
                                        sensitive_symbolic = symbolic_label.with_sensitivity(SourceType.PASSWORD)
                                        state.security_tracker.set_symbolic_label(result, sensitive_symbolic)
                                elif DEBUG_SIGMA:
                                    print(f"[DEBUG_SIGMA] No sensitive pattern matched for key: {key_str}")
                            elif DEBUG_SIGMA:
                                print(f"[DEBUG_SIGMA] Could not extract key string")
            
            elif op == 8:  # POWER (**)
                result, type_ok, fp_domain, none_misuse = binary_op_pow(left, right, self.solver)
                
                new_exception = None
                
                # Check for None misuse first
                self.solver.push()
                self.solver.add(state.path_condition)
                self.solver.add(none_misuse)
                if self.solver.check() == z3.sat:
                    state.none_misuse_reached = True
                    new_exception = "TypeError"
                self.solver.pop()
                
                if not new_exception:
                    # Check for FP domain error (0**neg or neg**frac)
                    self.solver.push()
                    self.solver.add(state.path_condition)
                    self.solver.add(z3.Not(none_misuse))
                    self.solver.add(fp_domain)
                    if self.solver.check() == z3.sat:
                        state.fp_domain_error_reached = True
                        # 0**negative raises ZeroDivisionError, negative**fractional raises ValueError
                        # For simplicity, mark as ValueError (both are domain errors)
                        new_exception = "ValueError"
                        func_name = state.func_names.get(id(frame.code), frame.code.co_name)
                        state.domain_error_context = f"power at {func_name}:{frame.instruction_offset}: base={left}, exp={right}"
                    self.solver.pop()
                
                # Check for type confusion (type mismatch that isn't None misuse or FP domain)
                if not new_exception:
                    self.solver.push()
                    self.solver.add(state.path_condition)
                    self.solver.add(z3.Not(type_ok))
                    self.solver.add(z3.Not(none_misuse))
                    if self.solver.check() == z3.sat:
                        state.type_confusion_reached = True
                        new_exception = "TypeError"
                    self.solver.pop()
                
                if new_exception:
                    state.exception = new_exception
                    return
                else:
                    state.path_condition = z3.And(state.path_condition, type_ok, z3.Not(fp_domain), z3.Not(none_misuse))
                    frame.operand_stack.append(result)
                    
                    # SECURITY: Propagate taint through binary operation
                    if state.security_tracker:
                        from a3_python.semantics.security_tracker_lattice import handle_binop
                        handle_binop(state.security_tracker, left, right, result)
            
            elif op == 3:  # LEFT_SHIFT (<<)
                result, type_ok, domain_error, none_misuse = binary_op_lshift(left, right, self.solver)
                
                new_exception = None
                
                # Check for None misuse first
                self.solver.push()
                self.solver.add(state.path_condition)
                self.solver.add(none_misuse)
                if self.solver.check() == z3.sat:
                    state.none_misuse_reached = True
                    new_exception = "TypeError"
                self.solver.pop()
                
                # Check for domain error (negative shift count)
                if not new_exception:
                    self.solver.push()
                    self.solver.add(state.path_condition)
                    self.solver.add(z3.Not(none_misuse))
                    self.solver.add(domain_error)
                    if self.solver.check() == z3.sat:
                        state.fp_domain_error_reached = True
                        new_exception = "ValueError"
                        func_name = state.func_names.get(id(frame.code), frame.code.co_name)
                        state.domain_error_context = f"lshift at {func_name}:{frame.instruction_offset}: negative shift count {right}"
                    self.solver.pop()
                
                # Check for type confusion
                if not new_exception:
                    self.solver.push()
                    self.solver.add(state.path_condition)
                    self.solver.add(z3.Not(type_ok))
                    self.solver.add(z3.Not(none_misuse))
                    if self.solver.check() == z3.sat:
                        state.type_confusion_reached = True
                        new_exception = "TypeError"
                    self.solver.pop()
                
                if new_exception:
                    state.exception = new_exception
                    return
                else:
                    state.path_condition = z3.And(state.path_condition, type_ok, z3.Not(domain_error), z3.Not(none_misuse))
                    frame.operand_stack.append(result)
                    
                    # SECURITY: Propagate taint through binary operation
                    if state.security_tracker:
                        from a3_python.semantics.security_tracker_lattice import handle_binop
                        handle_binop(state.security_tracker, left, right, result)
            
            elif op == 9:  # RIGHT_SHIFT (>>)
                result, type_ok, domain_error, none_misuse = binary_op_rshift(left, right, self.solver)
                
                new_exception = None
                
                # Check for None misuse first
                self.solver.push()
                self.solver.add(state.path_condition)
                self.solver.add(none_misuse)
                if self.solver.check() == z3.sat:
                    state.none_misuse_reached = True
                    new_exception = "TypeError"
                self.solver.pop()
                
                # Check for domain error (negative shift count)
                if not new_exception:
                    self.solver.push()
                    self.solver.add(state.path_condition)
                    self.solver.add(z3.Not(none_misuse))
                    self.solver.add(domain_error)
                    if self.solver.check() == z3.sat:
                        state.fp_domain_error_reached = True
                        new_exception = "ValueError"
                        func_name = state.func_names.get(id(frame.code), frame.code.co_name)
                        state.domain_error_context = f"rshift at {func_name}:{frame.instruction_offset}: negative shift count {right}"
                    self.solver.pop()
                
                # Check for type confusion
                if not new_exception:
                    self.solver.push()
                    self.solver.add(state.path_condition)
                    self.solver.add(z3.Not(type_ok))
                    self.solver.add(z3.Not(none_misuse))
                    if self.solver.check() == z3.sat:
                        state.type_confusion_reached = True
                        new_exception = "TypeError"
                    self.solver.pop()
                
                if new_exception:
                    state.exception = new_exception
                    return
                else:
                    state.path_condition = z3.And(state.path_condition, type_ok, z3.Not(domain_error), z3.Not(none_misuse))
                    frame.operand_stack.append(result)
                    
                    # SECURITY: Propagate taint through binary operation
                    if state.security_tracker:
                        from a3_python.semantics.security_tracker_lattice import handle_binop
                        handle_binop(state.security_tracker, left, right, result)
            
            elif op == 1:  # BITWISE_AND (&)
                result, type_ok, none_misuse = binary_op_and(left, right, self.solver)
                # Check for None misuse
                self.solver.push()
                self.solver.add(state.path_condition)
                self.solver.add(none_misuse)
                if self.solver.check() == z3.sat:
                    state.none_misuse_reached = True
                    state.exception = "TypeError"
                self.solver.pop()
                
                # Check for type confusion
                if not state.exception:
                    self.solver.push()
                    self.solver.add(state.path_condition)
                    self.solver.add(z3.Not(type_ok))
                    self.solver.add(z3.Not(none_misuse))
                    if self.solver.check() == z3.sat:
                        state.type_confusion_reached = True
                        state.exception = "TypeError"
                    self.solver.pop()
                
                if not state.exception:
                    state.path_condition = z3.And(state.path_condition, type_ok, z3.Not(none_misuse))
                    frame.operand_stack.append(result)
                    
                    # SECURITY: Propagate taint through binary operation
                    if state.security_tracker:
                        from a3_python.semantics.security_tracker_lattice import handle_binop
                        handle_binop(state.security_tracker, left, right, result)
            
            elif op == 7:  # BITWISE_OR (|)
                result, type_ok, none_misuse = binary_op_or(left, right, self.solver)
                # Check for None misuse
                self.solver.push()
                self.solver.add(state.path_condition)
                self.solver.add(none_misuse)
                if self.solver.check() == z3.sat:
                    state.none_misuse_reached = True
                    state.exception = "TypeError"
                self.solver.pop()
                
                # Check for type confusion
                if not state.exception:
                    self.solver.push()
                    self.solver.add(state.path_condition)
                    self.solver.add(z3.Not(type_ok))
                    self.solver.add(z3.Not(none_misuse))
                    if self.solver.check() == z3.sat:
                        state.type_confusion_reached = True
                        state.exception = "TypeError"
                    self.solver.pop()
                
                if not state.exception:
                    state.path_condition = z3.And(state.path_condition, type_ok, z3.Not(none_misuse))
                    frame.operand_stack.append(result)
                    
                    # SECURITY: Propagate taint through binary operation
                    if state.security_tracker:
                        from a3_python.semantics.security_tracker_lattice import handle_binop
                        handle_binop(state.security_tracker, left, right, result)
            
            elif op == 12:  # BITWISE_XOR (^)
                result, type_ok, none_misuse = binary_op_xor(left, right, self.solver)
                # Check for None misuse
                self.solver.push()
                self.solver.add(state.path_condition)
                self.solver.add(none_misuse)
                if self.solver.check() == z3.sat:
                    state.none_misuse_reached = True
                    state.exception = "TypeError"
                self.solver.pop()
                
                # Check for type confusion
                if not state.exception:
                    self.solver.push()
                    self.solver.add(state.path_condition)
                    self.solver.add(z3.Not(type_ok))
                    self.solver.add(z3.Not(none_misuse))
                    if self.solver.check() == z3.sat:
                        state.type_confusion_reached = True
                        state.exception = "TypeError"
                    self.solver.pop()
                
                if not state.exception:
                    state.path_condition = z3.And(state.path_condition, type_ok, z3.Not(none_misuse))
                    frame.operand_stack.append(result)
                    
                    # SECURITY: Propagate taint through binary operation
                    if state.security_tracker:
                        from a3_python.semantics.security_tracker_lattice import handle_binop
                        handle_binop(state.security_tracker, left, right, result)
            
            # Augmented assignment operators (INPLACE_* variants)
            # These are semantically equivalent to their non-augmented versions
            # for immutable types (int, float, str), but may mutate for mutable types
            
            elif op == 13:  # INPLACE_ADD (+=)
                result, type_ok, none_misuse = binary_op_add(left, right, self.solver)
                # Check for None misuse
                self.solver.push()
                self.solver.add(state.path_condition)
                self.solver.add(none_misuse)
                if self.solver.check() == z3.sat:
                    state.none_misuse_reached = True
                    state.exception = "TypeError"
                self.solver.pop()
                
                if not state.exception:
                    self.solver.push()
                    self.solver.add(state.path_condition)
                    self.solver.add(z3.Not(type_ok))
                    self.solver.add(z3.Not(none_misuse))
                    if self.solver.check() == z3.sat:
                        state.type_confusion_reached = True
                        state.exception = "TypeError"
                    self.solver.pop()
                
                if not state.exception:
                    state.path_condition = z3.And(state.path_condition, type_ok, z3.Not(none_misuse))
                    frame.operand_stack.append(result)
                    if state.security_tracker:
                        from a3_python.semantics.security_tracker_lattice import handle_binop
                        handle_binop(state.security_tracker, left, right, result)
            
            elif op == 23:  # INPLACE_SUBTRACT (-=)
                result, type_ok, none_misuse = binary_op_sub(left, right, self.solver)
                self.solver.push()
                self.solver.add(state.path_condition)
                self.solver.add(none_misuse)
                if self.solver.check() == z3.sat:
                    state.none_misuse_reached = True
                    state.exception = "TypeError"
                self.solver.pop()
                
                if not state.exception:
                    self.solver.push()
                    self.solver.add(state.path_condition)
                    self.solver.add(z3.Not(type_ok))
                    self.solver.add(z3.Not(none_misuse))
                    if self.solver.check() == z3.sat:
                        state.type_confusion_reached = True
                        state.exception = "TypeError"
                    self.solver.pop()
                
                if not state.exception:
                    state.path_condition = z3.And(state.path_condition, type_ok, z3.Not(none_misuse))
                    frame.operand_stack.append(result)
                    if state.security_tracker:
                        from a3_python.semantics.security_tracker_lattice import handle_binop
                        handle_binop(state.security_tracker, left, right, result)
            
            elif op == 18:  # INPLACE_MULTIPLY (*=)
                result, type_ok, none_misuse = binary_op_mul(left, right, self.solver)
                self.solver.push()
                self.solver.add(state.path_condition)
                self.solver.add(none_misuse)
                if self.solver.check() == z3.sat:
                    state.none_misuse_reached = True
                    state.exception = "TypeError"
                self.solver.pop()
                
                if not state.exception:
                    self.solver.push()
                    self.solver.add(state.path_condition)
                    self.solver.add(z3.Not(type_ok))
                    self.solver.add(z3.Not(none_misuse))
                    if self.solver.check() == z3.sat:
                        state.type_confusion_reached = True
                        state.exception = "TypeError"
                    self.solver.pop()
                
                if not state.exception:
                    state.path_condition = z3.And(state.path_condition, type_ok, z3.Not(none_misuse))
                    frame.operand_stack.append(result)
                    if state.security_tracker:
                        from a3_python.semantics.security_tracker_lattice import handle_binop
                        handle_binop(state.security_tracker, left, right, result)
            
            elif op == 15:  # INPLACE_FLOOR_DIVIDE (//=)
                result, type_ok, div_zero, none_misuse = binary_op_floordiv(left, right, self.solver)
                
                new_exception = None
                
                # Check for None misuse first
                self.solver.push()
                self.solver.add(state.path_condition)
                self.solver.add(none_misuse)
                if self.solver.check() == z3.sat:
                    state.none_misuse_reached = True
                    new_exception = "TypeError"
                self.solver.pop()
                
                if not new_exception:
                    # Check if division by zero is reachable
                    self.solver.push()
                    self.solver.add(state.path_condition)
                    self.solver.add(z3.Not(none_misuse))
                    self.solver.add(div_zero)
                    if self.solver.check() == z3.sat:
                        state.div_by_zero_reached = True
                        new_exception = "ZeroDivisionError"
                    self.solver.pop()
                
                if not new_exception:
                    # Check for type confusion
                    self.solver.push()
                    self.solver.add(state.path_condition)
                    self.solver.add(z3.Not(type_ok))
                    self.solver.add(z3.Not(none_misuse))
                    if self.solver.check() == z3.sat:
                        state.type_confusion_reached = True
                        new_exception = "TypeError"
                    self.solver.pop()
                
                if new_exception:
                    state.exception = new_exception
                    return
                else:
                    state.path_condition = z3.And(state.path_condition, type_ok, z3.Not(div_zero), z3.Not(none_misuse))
                    frame.operand_stack.append(result)
                    if state.security_tracker:
                        from a3_python.semantics.security_tracker_lattice import handle_binop
                        handle_binop(state.security_tracker, left, right, result)
            
            elif op == 19:  # INPLACE_MODULO (%=)
                result, type_ok, div_zero, none_misuse = binary_op_mod(left, right, self.solver)
                
                new_exception = None
                
                # Check for None misuse first
                self.solver.push()
                self.solver.add(state.path_condition)
                self.solver.add(none_misuse)
                if self.solver.check() == z3.sat:
                    state.none_misuse_reached = True
                    new_exception = "TypeError"
                self.solver.pop()
                
                if not new_exception:
                    # Check if division by zero is reachable
                    self.solver.push()
                    self.solver.add(state.path_condition)
                    self.solver.add(z3.Not(none_misuse))
                    self.solver.add(div_zero)
                    if self.solver.check() == z3.sat:
                        state.div_by_zero_reached = True
                        new_exception = "ZeroDivisionError"
                    self.solver.pop()
                
                if not new_exception:
                    # Check for type confusion
                    self.solver.push()
                    self.solver.add(state.path_condition)
                    self.solver.add(z3.Not(type_ok))
                    self.solver.add(z3.Not(none_misuse))
                    if self.solver.check() == z3.sat:
                        state.type_confusion_reached = True
                        new_exception = "TypeError"
                    self.solver.pop()
                
                if new_exception:
                    state.exception = new_exception
                    return
                else:
                    state.path_condition = z3.And(state.path_condition, type_ok, z3.Not(div_zero), z3.Not(none_misuse))
                    frame.operand_stack.append(result)
                    if state.security_tracker:
                        from a3_python.semantics.security_tracker_lattice import handle_binop
                        handle_binop(state.security_tracker, left, right, result)
            
            elif op == 21:  # INPLACE_POWER (**=)
                result, type_ok, fp_domain, none_misuse = binary_op_pow(left, right, self.solver)
                
                new_exception = None
                
                # Check for None misuse first
                self.solver.push()
                self.solver.add(state.path_condition)
                self.solver.add(none_misuse)
                if self.solver.check() == z3.sat:
                    state.none_misuse_reached = True
                    new_exception = "TypeError"
                self.solver.pop()
                
                if not new_exception:
                    # Check for FP domain error (0**neg or neg**frac)
                    self.solver.push()
                    self.solver.add(state.path_condition)
                    self.solver.add(z3.Not(none_misuse))
                    self.solver.add(fp_domain)
                    if self.solver.check() == z3.sat:
                        state.fp_domain_error_reached = True
                        new_exception = "ValueError"
                    self.solver.pop()
                
                if not new_exception:
                    # Check for type confusion
                    self.solver.push()
                    self.solver.add(state.path_condition)
                    self.solver.add(z3.Not(type_ok))
                    self.solver.add(z3.Not(fp_domain))
                    self.solver.add(z3.Not(none_misuse))
                    if self.solver.check() == z3.sat:
                        state.type_confusion_reached = True
                        new_exception = "TypeError"
                    self.solver.pop()
                
                if new_exception:
                    state.exception = new_exception
                    return
                else:
                    state.path_condition = z3.And(state.path_condition, type_ok, z3.Not(fp_domain), z3.Not(none_misuse))
                    frame.operand_stack.append(result)
                    if state.security_tracker:
                        from a3_python.semantics.security_tracker_lattice import handle_binop
                        handle_binop(state.security_tracker, left, right, result)
            
            elif op == 16:  # INPLACE_LSHIFT (<<=)
                result, type_ok, domain_error, none_misuse = binary_op_lshift(left, right, self.solver)
                
                new_exception = None
                
                # Check for None misuse first
                self.solver.push()
                self.solver.add(state.path_condition)
                self.solver.add(none_misuse)
                if self.solver.check() == z3.sat:
                    state.none_misuse_reached = True
                    new_exception = "TypeError"
                self.solver.pop()
                
                if not new_exception:
                    # Check for domain error (negative shift count)
                    self.solver.push()
                    self.solver.add(state.path_condition)
                    self.solver.add(z3.Not(none_misuse))
                    self.solver.add(domain_error)
                    if self.solver.check() == z3.sat:
                        state.fp_domain_error_reached = True
                        new_exception = "ValueError"
                    self.solver.pop()
                
                if not new_exception:
                    # Check for type confusion
                    self.solver.push()
                    self.solver.add(state.path_condition)
                    self.solver.add(z3.Not(type_ok))
                    self.solver.add(z3.Not(none_misuse))
                    if self.solver.check() == z3.sat:
                        state.type_confusion_reached = True
                        new_exception = "TypeError"
                    self.solver.pop()
                
                if new_exception:
                    state.exception = new_exception
                    return
                else:
                    state.path_condition = z3.And(state.path_condition, type_ok, z3.Not(domain_error), z3.Not(none_misuse))
                    frame.operand_stack.append(result)
                    if state.security_tracker:
                        from a3_python.semantics.security_tracker_lattice import handle_binop
                        handle_binop(state.security_tracker, left, right, result)
            
            elif op == 22:  # INPLACE_RSHIFT (>>=)
                result, type_ok, domain_error, none_misuse = binary_op_rshift(left, right, self.solver)
                
                new_exception = None
                
                # Check for None misuse first
                self.solver.push()
                self.solver.add(state.path_condition)
                self.solver.add(none_misuse)
                if self.solver.check() == z3.sat:
                    state.none_misuse_reached = True
                    new_exception = "TypeError"
                self.solver.pop()
                
                if not new_exception:
                    # Check for domain error (negative shift count)
                    self.solver.push()
                    self.solver.add(state.path_condition)
                    self.solver.add(z3.Not(none_misuse))
                    self.solver.add(domain_error)
                    if self.solver.check() == z3.sat:
                        state.fp_domain_error_reached = True
                        new_exception = "ValueError"
                    self.solver.pop()
                
                if not new_exception:
                    # Check for type confusion
                    self.solver.push()
                    self.solver.add(state.path_condition)
                    self.solver.add(z3.Not(type_ok))
                    self.solver.add(z3.Not(none_misuse))
                    if self.solver.check() == z3.sat:
                        state.type_confusion_reached = True
                        new_exception = "TypeError"
                    self.solver.pop()
                
                if new_exception:
                    state.exception = new_exception
                    return
                else:
                    state.path_condition = z3.And(state.path_condition, type_ok, z3.Not(domain_error), z3.Not(none_misuse))
                    frame.operand_stack.append(result)
                    if state.security_tracker:
                        from a3_python.semantics.security_tracker_lattice import handle_binop
                        handle_binop(state.security_tracker, left, right, result)
            
            elif op == 14:  # INPLACE_AND (&=)
                result, type_ok, none_misuse = binary_op_and(left, right, self.solver)
                self.solver.push()
                self.solver.add(state.path_condition)
                self.solver.add(none_misuse)
                if self.solver.check() == z3.sat:
                    state.none_misuse_reached = True
                    state.exception = "TypeError"
                self.solver.pop()
                
                if not state.exception:
                    self.solver.push()
                    self.solver.add(state.path_condition)
                    self.solver.add(z3.Not(type_ok))
                    self.solver.add(z3.Not(none_misuse))
                    if self.solver.check() == z3.sat:
                        state.type_confusion_reached = True
                        state.exception = "TypeError"
                    self.solver.pop()
                
                if not state.exception:
                    state.path_condition = z3.And(state.path_condition, type_ok, z3.Not(none_misuse))
                    frame.operand_stack.append(result)
                    if state.security_tracker:
                        from a3_python.semantics.security_tracker_lattice import handle_binop
                        handle_binop(state.security_tracker, left, right, result)
            
            elif op == 20:  # INPLACE_OR (|=)
                result, type_ok, none_misuse = binary_op_or(left, right, self.solver)
                self.solver.push()
                self.solver.add(state.path_condition)
                self.solver.add(none_misuse)
                if self.solver.check() == z3.sat:
                    state.none_misuse_reached = True
                    state.exception = "TypeError"
                self.solver.pop()
                
                if not state.exception:
                    self.solver.push()
                    self.solver.add(state.path_condition)
                    self.solver.add(z3.Not(type_ok))
                    self.solver.add(z3.Not(none_misuse))
                    if self.solver.check() == z3.sat:
                        state.type_confusion_reached = True
                        state.exception = "TypeError"
                    self.solver.pop()
                
                if not state.exception:
                    state.path_condition = z3.And(state.path_condition, type_ok, z3.Not(none_misuse))
                    frame.operand_stack.append(result)
                    if state.security_tracker:
                        from a3_python.semantics.security_tracker_lattice import handle_binop
                        handle_binop(state.security_tracker, left, right, result)
            
            elif op == 25:  # INPLACE_XOR (^=)
                result, type_ok, none_misuse = binary_op_xor(left, right, self.solver)
                self.solver.push()
                self.solver.add(state.path_condition)
                self.solver.add(none_misuse)
                if self.solver.check() == z3.sat:
                    state.none_misuse_reached = True
                    state.exception = "TypeError"
                self.solver.pop()
                
                if not state.exception:
                    self.solver.push()
                    self.solver.add(state.path_condition)
                    self.solver.add(z3.Not(type_ok))
                    self.solver.add(z3.Not(none_misuse))
                    if self.solver.check() == z3.sat:
                        state.type_confusion_reached = True
                        state.exception = "TypeError"
                    self.solver.pop()
                
                if not state.exception:
                    state.path_condition = z3.And(state.path_condition, type_ok, z3.Not(none_misuse))
                    frame.operand_stack.append(result)
                    if state.security_tracker:
                        from a3_python.semantics.security_tracker_lattice import handle_binop
                        handle_binop(state.security_tracker, left, right, result)
            
            else:
                raise NotImplementedError(f"BINARY_OP {op}")
            
            frame.instruction_offset = self._next_offset(frame, instr)
        
        elif opname == "BINARY_SUBSCR":
            # BINARY_SUBSCR: Python 3.11 opcode for container[index]
            # Stack: [..., container, index] → [..., result]
            # In Python 3.12+ this became BINARY_OP(26/SUBSCRIPT), but 3.11 uses
            # the dedicated BINARY_SUBSCR opcode.
            if len(frame.operand_stack) < 2:
                state.exception = "StackUnderflow"
                return
            
            index = frame.operand_stack.pop()   # TOS = index/key
            container = frame.operand_stack.pop()  # TOS1 = container
            
            result, type_ok, bounds_violated, none_misuse = binary_op_subscript(
                container, index, state.heap, self.solver
            )
            
            # Check if None misuse is reachable on this path
            self.solver.push()
            self.solver.add(state.path_condition)
            self.solver.add(none_misuse)
            if self.solver.check() == z3.sat:
                state.none_misuse_reached = True
                state.exception = "TypeError"
            self.solver.pop()
            
            if not state.exception:
                # Check if index out of bounds is reachable on this path
                self.solver.push()
                self.solver.add(state.path_condition)
                self.solver.add(bounds_violated)
                if self.solver.check() == z3.sat:
                    state.index_out_of_bounds = True
                    # Determine exception type based on container type
                    if container.is_dict():
                        state.exception = "KeyError"
                    else:
                        state.exception = "IndexError"
                self.solver.pop()
            
            if not state.exception:
                # Continue on non-violation path
                state.path_condition = z3.And(
                    state.path_condition, type_ok,
                    z3.Not(bounds_violated), z3.Not(none_misuse)
                )
                frame.operand_stack.append(result)
                
                # Propagate taint through subscript
                if state.security_tracker:
                    from a3_python.semantics.security_tracker_lattice import handle_subscript
                    handle_subscript(state.security_tracker, container, index, result)
            
            if not state.exception:
                frame.instruction_offset = self._next_offset(frame, instr)
        
        elif opname == "UNARY_NEGATIVE":
            # UNARY_NEGATIVE: -x
            # Stack: [..., x] → [..., -x]
            if len(frame.operand_stack) < 1:
                state.exception = "StackUnderflow"
                return
            
            operand = frame.operand_stack.pop()
            result, type_ok, none_misuse = unary_op_negative(operand, self.solver)
            
            # Check for None misuse
            self.solver.push()
            self.solver.add(state.path_condition)
            self.solver.add(none_misuse)
            if self.solver.check() == z3.sat:
                state.none_misuse_reached = True
                state.exception = "TypeError"
            self.solver.pop()
            
            # Check for type confusion
            if not state.exception:
                self.solver.push()
                self.solver.add(state.path_condition)
                self.solver.add(z3.Not(type_ok))
                self.solver.add(z3.Not(none_misuse))
                if self.solver.check() == z3.sat:
                    state.type_confusion_reached = True
                    state.exception = "TypeError"
                self.solver.pop()
            
            if not state.exception:
                state.path_condition = z3.And(state.path_condition, type_ok, z3.Not(none_misuse))
                frame.operand_stack.append(result)
            
            frame.instruction_offset = self._next_offset(frame, instr)
        
        elif opname == "UNARY_INVERT":
            # UNARY_INVERT: ~x (bitwise NOT)
            # Stack: [..., x] → [..., ~x]
            if len(frame.operand_stack) < 1:
                state.exception = "StackUnderflow"
                return
            
            operand = frame.operand_stack.pop()
            result, type_ok, none_misuse = unary_op_invert(operand, self.solver)
            
            # Check for None misuse
            self.solver.push()
            self.solver.add(state.path_condition)
            self.solver.add(none_misuse)
            if self.solver.check() == z3.sat:
                state.none_misuse_reached = True
                state.exception = "TypeError"
            self.solver.pop()
            
            # Check for type confusion
            if not state.exception:
                self.solver.push()
                self.solver.add(state.path_condition)
                self.solver.add(z3.Not(type_ok))
                self.solver.add(z3.Not(none_misuse))
                if self.solver.check() == z3.sat:
                    state.type_confusion_reached = True
                    state.exception = "TypeError"
                self.solver.pop()
            
            if not state.exception:
                state.path_condition = z3.And(state.path_condition, type_ok, z3.Not(none_misuse))
                frame.operand_stack.append(result)
            
            frame.instruction_offset = self._next_offset(frame, instr)
        
        elif opname == "UNARY_NOT":
            # UNARY_NOT: not x (logical NOT)
            # Stack: [..., x] → [..., not x]
            # Note: TO_BOOL must be called before UNARY_NOT
            if len(frame.operand_stack) < 1:
                state.exception = "StackUnderflow"
                return
            
            operand = frame.operand_stack.pop()
            result, none_misuse = unary_op_not(operand, self.solver)
            
            # 'not' never raises TypeError (None is valid)
            # Just push result and continue
            frame.operand_stack.append(result)
            frame.instruction_offset = self._next_offset(frame, instr)
        
        elif opname == "COMPARE_OP":
            if len(frame.operand_stack) < 2:
                state.exception = "StackUnderflow"
                return
            
            right = frame.operand_stack.pop()
            left = frame.operand_stack.pop()
            
            op = instr.argval
            
            # Special case: tuple comparison (lexicographic)
            # This handles sys.version_info >= (3, 11) pattern
            if left.tag == ValueTag.TUPLE and right.tag == ValueTag.TUPLE:
                # For tuple comparisons, we need to compare element-by-element
                # For now, treat as always succeeding (conservative overapproximation)
                # A proper implementation would compare tuple elements lexicographically
                if op in ("<", "<=", ">", ">=", "==", "!="):
                    # Return symbolic bool (nondeterministic result)
                    result = SymbolicValue(ValueTag.BOOL, z3.Int(f"tuple_cmp_{id(left)}_{id(right)}"))
                    type_ok = z3.BoolVal(True)  # Tuples can always be compared
                    frame.operand_stack.append(result)
                    state.path_condition = z3.And(state.path_condition, type_ok)
                else:
                    raise NotImplementedError(f"COMPARE_OP {op}")
                frame.instruction_offset = self._next_offset(frame, instr)
                return
            
            if op == "<":
                result, type_ok = compare_op_lt(left, right, self.solver)
            elif op == "<=":
                result, type_ok = compare_op_le(left, right, self.solver)
            elif op == "==":
                result, type_ok = compare_op_eq(left, right, self.solver)
            elif op == "!=":
                result, type_ok = compare_op_ne(left, right, self.solver)
            elif op == ">":
                result, type_ok = compare_op_gt(left, right, self.solver)
            elif op == ">=":
                result, type_ok = compare_op_ge(left, right, self.solver)
            else:
                raise NotImplementedError(f"COMPARE_OP {op}")
            
            # Check for type confusion in comparisons
            # Note: == and != always succeed, so type_ok is always True
            # For ordering comparisons (<, <=, >, >=), type mismatch causes TypeError
            if op in ("<", "<=", ">", ">="):
                self.solver.push()
                self.solver.add(state.path_condition)
                self.solver.add(z3.Not(type_ok))
                if self.solver.check() == z3.sat:
                    state.type_confusion_reached = True
                    state.exception = "TypeError"
                self.solver.pop()
            
            if not state.exception:
                state.path_condition = z3.And(state.path_condition, type_ok)
                frame.operand_stack.append(result)
            frame.instruction_offset = self._next_offset(frame, instr)
        
        elif opname == "CONTAINS_OP":
            # CONTAINS_OP: item in container (arg=0) or item not in container (arg=1)
            # Stack: [..., item, container] → [..., result]
            if len(frame.operand_stack) < 2:
                state.exception = "StackUnderflow"
                return
            
            container = frame.operand_stack.pop()
            item = frame.operand_stack.pop()
            
            invert = instr.arg == 1  # 0 = 'in', 1 = 'not in'
            
            # Perform containment check
            result, type_ok, none_misuse = contains_op(item, container, state.heap, self.solver)
            
            # Check for None misuse (NULL_PTR bug class)
            if self.solver:
                self.solver.push()
                self.solver.add(state.path_condition)
                self.solver.add(none_misuse)
                if self.solver.check() == z3.sat:
                    state.null_ptr_reached = True
                    state.exception = "TypeError"
                self.solver.pop()
            
            # Check for type confusion (container not iterable)
            if not state.exception:
                self.solver.push()
                self.solver.add(state.path_condition)
                self.solver.add(z3.Not(type_ok))
                if self.solver.check() == z3.sat:
                    state.type_confusion_reached = True
                    state.exception = "TypeError"
                self.solver.pop()
            
            # If 'not in', invert the result
            if invert and not state.exception:
                # Invert boolean: if result is True (1), make it False (0) and vice versa
                inverted_payload = z3.If(result.payload == z3.IntVal(1), z3.IntVal(0), z3.IntVal(1))
                result = SymbolicValue(ValueTag.BOOL, inverted_payload)
            
            if not state.exception:
                state.path_condition = z3.And(state.path_condition, type_ok)
                frame.operand_stack.append(result)
            frame.instruction_offset = self._next_offset(frame, instr)
        
        elif opname == "IS_OP":
            # IS_OP: identity comparison (is / is not)
            # arg=0 means 'is', arg=1 means 'is not'
            # Stack: [..., left, right] → [..., result]
            if len(frame.operand_stack) < 2:
                state.exception = "StackUnderflow"
                return
            
            right = frame.operand_stack.pop()
            left = frame.operand_stack.pop()
            
            invert = instr.arg == 1  # 0 = 'is', 1 = 'is not'
            
            # Identity check: for None, check tag equality
            # For objects, check if they have the same heap ID
            if left.tag == ValueTag.NONE and right.tag == ValueTag.NONE:
                # None is None -> True
                result_val = z3.IntVal(0 if invert else 1)
            elif left.tag == ValueTag.NONE or right.tag == ValueTag.NONE:
                # One is None, other is not -> False (or True if inverted)
                if left.tag == ValueTag.NONE:
                    # left is None, right is something else
                    is_none = right.tag == ValueTag.NONE
                else:
                    # right is None, left is something else
                    is_none = left.tag == ValueTag.NONE
                result_val = z3.IntVal(1 if invert else 0)
            elif left.tag == ValueTag.OBJ and right.tag == ValueTag.OBJ:
                # Object identity: check if payloads (heap IDs) are equal
                identity = left.payload == right.payload
                if invert:
                    result_val = z3.If(identity, z3.IntVal(0), z3.IntVal(1))
                else:
                    result_val = z3.If(identity, z3.IntVal(1), z3.IntVal(0))
            elif left.tag == ValueTag.INT and right.tag == ValueTag.INT:
                # Small integer caching: integers in [-5, 256] have identity
                # For simplicity, use value equality as identity for small ints
                identity = left.payload == right.payload
                if invert:
                    result_val = z3.If(identity, z3.IntVal(0), z3.IntVal(1))
                else:
                    result_val = z3.If(identity, z3.IntVal(1), z3.IntVal(0))
            else:
                # Different types: never identical
                result_val = z3.IntVal(1 if invert else 0)
            
            result = SymbolicValue(ValueTag.BOOL, result_val)
            frame.operand_stack.append(result)
            frame.instruction_offset = self._next_offset(frame, instr)
        
        elif opname == "RETURN_VALUE":
            if not frame.operand_stack:
                return_val = SymbolicValue.none()
            else:
                return_val = frame.operand_stack.pop()
            
            # Check if we're returning from an inlined user function
            # If so, call handle_call_post to propagate taint/sanitization
            returned_frame = frame  # Save reference before popping
            
            # Pop the current frame
            state.frame_stack.pop()
            
            if not state.frame_stack:
                # Top-level return: halt execution
                state.return_value = return_val
                state.halted = True
            else:
                # Returning from inlined function: apply call contracts
                if returned_frame.call_context:
                    ctx = returned_frame.call_context
                    func_name = ctx.get('func_name')
                    func_ref = ctx.get('func_ref')
                    args = ctx.get('args', [])
                    
                    # Get location from caller frame
                    caller_frame = state.frame_stack[-1]
                    current_instr = self._get_instruction(caller_frame)
                    location = f"{caller_frame.code.co_filename}:{current_instr.offset if current_instr else 0}"
                    
                    # ITERATION 571 FIX: Only call handle_call_post for LIBRARY functions, not user functions
                    # For user functions, taint was already tracked during inline execution
                    # Calling handle_call_post here would apply the wrong contract context
                    # (e.g., hash_password() is not a sanitizer, but bcrypt.hashpw() inside it is)
                    #
                    # Check if this is a user function by looking in state.user_functions
                    is_user_function = False
                    if func_ref and hasattr(state, 'user_functions'):
                        # Try both stable ID and object ID
                        func_stable_id = None
                        if func_ref.tag == ValueTag.OBJ:
                            if hasattr(func_ref.payload, 'as_long'):
                                try:
                                    func_stable_id = int(func_ref.payload.as_long())
                                except:
                                    pass
                            elif hasattr(func_ref.payload, 'sexpr'):
                                try:
                                    sexpr = func_ref.payload.sexpr()
                                    if sexpr.startswith('func_'):
                                        func_stable_id = int(sexpr[5:])
                                except:
                                    pass
                        
                        is_user_function = (
                            (func_stable_id is not None and func_stable_id in state.user_functions) or
                            (id(func_ref) in state.user_functions)
                        )
                    
                    # Only apply contracts for library functions
                    if state.security_tracker and func_name and not is_user_function:
                        handle_call_post(
                            state.security_tracker,
                            func_name,
                            func_ref,
                            args,
                            return_val,
                            location
                        )
                
                # Push result to caller's stack
                caller_frame = state.frame_stack[-1]
                caller_frame.operand_stack.append(return_val)
                # Advance the caller's instruction pointer past the CALL instruction
                # Find the next instruction after the current call
                current_instr = self._get_instruction(caller_frame)
                if current_instr:
                    caller_frame.instruction_offset = self._next_offset(caller_frame, current_instr)
        
        elif opname == "POP_TOP":
            if frame.operand_stack:
                frame.operand_stack.pop()
            frame.instruction_offset = self._next_offset(frame, instr)
        
        elif opname == "LOAD_COMMON_CONSTANT":
            # LOAD_COMMON_CONSTANT is used for built-in exceptions and other constants (Python 3.12+)
            # argrepr contains the string representation (e.g., "AssertionError")
            # argval is an index into a common constants table
            const_repr = instr.argrepr
            
            # Common exception types (including NotImplementedError which is
            # raised by compiler-generated __annotate__ functions in Python 3.14+)
            exception_types = ['AssertionError', 'RuntimeError', 'ValueError', 'TypeError', 
                             'KeyError', 'IndexError', 'AttributeError', 'ImportError',
                             'NameError', 'OSError', 'IOError', 'ZeroDivisionError',
                             'StopIteration', 'StopAsyncIteration', 'SystemExit',
                             'NotImplementedError', 'OverflowError', 'UnicodeError',
                             'UnicodeDecodeError', 'UnicodeEncodeError',
                             'FileNotFoundError', 'PermissionError', 'TimeoutError',
                             'ConnectionError', 'BrokenPipeError',
                             'BaseException', 'Exception']
            
            matched_exc = None
            for exc_type in exception_types:
                if exc_type in const_repr:
                    matched_exc = exc_type
                    break
            
            if matched_exc:
                # Load the exception type as a special marker
                sym_val = SymbolicValue(ValueTag.OBJ, z3.IntVal(-1))  # Special marker for exception type
                sym_val._exception_type = matched_exc
            else:
                # For non-exception constants (like None, ellipsis, etc.), use OBJ
                sym_val = SymbolicValue(ValueTag.OBJ, z3.IntVal(self.fresh_obj_id()))
            frame.operand_stack.append(sym_val)
            frame.instruction_offset = self._next_offset(frame, instr)
        
        elif opname == "LOAD_ASSERTION_ERROR":
            # LOAD_ASSERTION_ERROR is Python 3.11-specific opcode for loading AssertionError
            # In Python 3.12+, this was replaced by LOAD_COMMON_CONSTANT
            # Semantics: push AssertionError exception type onto the stack
            sym_val = SymbolicValue(ValueTag.OBJ, z3.IntVal(-1))  # Special marker for exception type
            sym_val._exception_type = "AssertionError"
            frame.operand_stack.append(sym_val)
            frame.instruction_offset = self._next_offset(frame, instr)
        
        elif opname == "RAISE_VARARGS":
            # RAISE_VARARGS raises an exception
            # argval is the number of arguments:
            #   0 = re-raise (raise with no args in except handler)
            #   1 = exception instance or type
            #   2 = exception + cause
            nargs = instr.argval
            if nargs == 0:
                # Re-raise: should already have exception in state
                if not state.exception:
                    state.exception = "RuntimeError"  # raise with no active exception
            elif nargs == 1:
                if frame.operand_stack:
                    exc = frame.operand_stack.pop()
                    # Check if it's an exception type we recognize
                    if hasattr(exc, '_exception_type'):
                        state.exception = exc._exception_type
                    else:
                        state.exception = "UnknownException"
                else:
                    state.exception = "StackUnderflow"
            else:
                # nargs == 2: exception + cause
                if len(frame.operand_stack) >= 2:
                    frame.operand_stack.pop()  # cause
                    exc = frame.operand_stack.pop()  # exception
                    if hasattr(exc, '_exception_type'):
                        state.exception = exc._exception_type
                    else:
                        state.exception = "UnknownException"
                else:
                    state.exception = "StackUnderflow"
            # Don't advance instruction pointer; exception handling in step() will jump to handler
        
        elif opname == "POP_JUMP_IF_TRUE" or opname == "POP_JUMP_FORWARD_IF_TRUE":
            # Conditional jump: pop TOS, jump if true
            # POP_JUMP_IF_TRUE is Python 3.12+ (absolute)
            # POP_JUMP_FORWARD_IF_TRUE is Python 3.11 (relative forward)
            if not frame.operand_stack:
                state.exception = "StackUnderflow"
                return
            
            condition = frame.operand_stack.pop()
            condition_true = is_true(condition, self.solver)
            
            # The jump happens if condition is true
            target_offset = instr.argval
            fallthrough_offset = self._next_offset(frame, instr)

            # Trace-guided replay: if an oracle provides the observed successor offset,
            # force the same branch and record the corresponding constraint.
            if self.oracle:
                expected_next = self.oracle.pop_branch_next_offset(frame.code, instr.offset)
                if expected_next in (target_offset, fallthrough_offset):
                    took_jump = expected_next == target_offset
                    state.path_condition = z3.And(
                        state.path_condition,
                        condition_true if took_jump else z3.Not(condition_true),
                    )
                    frame.instruction_offset = expected_next
                    return
            
            # Check if true path is feasible
            self.solver.push()
            self.solver.add(state.path_condition)
            self.solver.add(condition_true)
            true_feasible = self._solver_maybe_sat()
            self.solver.pop()
            
            # Check if false path is feasible
            self.solver.push()
            self.solver.add(state.path_condition)
            self.solver.add(z3.Not(condition_true))
            false_feasible = self._solver_maybe_sat()
            self.solver.pop()
            
            # Implement proper path branching when both branches are feasible
            if true_feasible and false_feasible:
                # Both branches feasible: fork the path
                import copy
                
                # Create forked state for true branch
                true_state = copy.deepcopy(state)
                true_state.path_condition = z3.And(state.path_condition, condition_true)
                true_state.frame_stack[-1].instruction_offset = target_offset
                
                # Keep current state as false branch
                state.path_condition = z3.And(state.path_condition, z3.Not(condition_true))
                frame.instruction_offset = fallthrough_offset
                
                # Signal forking by storing the alternative state
                # This will be picked up by step() method
                state.fork_branch_successors = [true_state]
                
            elif false_feasible:
                # Only false path feasible
                state.path_condition = z3.And(state.path_condition, z3.Not(condition_true))
                frame.instruction_offset = fallthrough_offset
            elif true_feasible:
                # Only true path feasible
                state.path_condition = z3.And(state.path_condition, condition_true)
                frame.instruction_offset = target_offset
            else:
                # No feasible path
                state.exception = "InfeasiblePath"
        
        elif opname == "POP_JUMP_IF_FALSE" or opname == "POP_JUMP_FORWARD_IF_FALSE":
            # Conditional jump: pop TOS, jump if false
            # POP_JUMP_IF_FALSE is Python 3.12+ (absolute)
            # POP_JUMP_FORWARD_IF_FALSE is Python 3.11 (relative forward)
            if not frame.operand_stack:
                state.exception = "StackUnderflow"
                return
            
            condition = frame.operand_stack.pop()
            condition_true = is_true(condition, self.solver)
            
            # The jump happens if condition is false
            target_offset = instr.argval
            fallthrough_offset = self._next_offset(frame, instr)
            
            # ITERATION 257: Log before feasibility checks
            if self.verbose:
                print(f"[FEASIBILITY] At offset {instr.offset}: Checking branch feasibility")
                print(f"  Condition: {condition}")
                print(f"  Condition_true: {condition_true}")
                print(f"  Target offset (false): {target_offset}")
                print(f"  Fallthrough offset (true): {fallthrough_offset}")

            if self.oracle:
                expected_next = self.oracle.pop_branch_next_offset(frame.code, instr.offset)
                if expected_next in (target_offset, fallthrough_offset):
                    took_jump = expected_next == target_offset
                    # Jump taken iff condition is false
                    state.path_condition = z3.And(
                        state.path_condition,
                        z3.Not(condition_true) if took_jump else condition_true,
                    )
                    frame.instruction_offset = expected_next
                    return
            
            # Check if false path is feasible (jump taken)
            self.solver.push()
            self.solver.add(state.path_condition)
            self.solver.add(z3.Not(condition_true))
            false_feasible = self._solver_maybe_sat()
            self.solver.pop()
            
            # Check if true path is feasible (fall through)
            self.solver.push()
            self.solver.add(state.path_condition)
            self.solver.add(condition_true)
            true_feasible = self._solver_maybe_sat()
            self.solver.pop()
            
            # Implement proper path branching when both branches are feasible
            if true_feasible and false_feasible:
                # Both branches feasible: fork the path
                import copy
                
                # ITERATION 256: Log path forking
                if self.verbose:
                    print(f"[FORK] At offset {instr.offset}: Both branches feasible")
                    print(f"  True branch (fallthrough): offset {fallthrough_offset}")
                    print(f"  False branch (jump): offset {target_offset}")
                
                # Create forked state for false branch
                false_state = copy.deepcopy(state)
                false_state.path_condition = z3.And(state.path_condition, z3.Not(condition_true))
                false_state.frame_stack[-1].instruction_offset = target_offset
                
                # Keep current state as true branch
                state.path_condition = z3.And(state.path_condition, condition_true)
                frame.instruction_offset = fallthrough_offset
                
                # Signal forking by storing the alternative state
                # This will be picked up by step() method
                state.fork_branch_successors = [false_state]
                
                # ITERATION 256: Log state after fork
                if self.verbose:
                    print(f"[FORK] Created false_state fork, current state continues as true branch")
                
            elif true_feasible:
                # Only true path feasible
                if self.verbose:
                    print(f"[BRANCH] At offset {instr.offset}: Only true branch feasible, fallthrough to {fallthrough_offset}")
                state.path_condition = z3.And(state.path_condition, condition_true)
                frame.instruction_offset = fallthrough_offset
            elif false_feasible:
                # Only false path feasible
                if self.verbose:
                    print(f"[BRANCH] At offset {instr.offset}: Only false branch feasible, jump to {target_offset}")
                state.path_condition = z3.And(state.path_condition, z3.Not(condition_true))
                frame.instruction_offset = target_offset
            else:
                # No feasible path
                state.exception = "InfeasiblePath"
        
        elif opname == "POP_JUMP_IF_NOT_NONE":
            # Python 3.14 opcode: pop TOS, jump if it is not None
            if not frame.operand_stack:
                state.exception = "StackUnderflow"
                return
            
            value = frame.operand_stack.pop()
            is_none = (value.tag == z3.IntVal(ValueTag.NONE.value))
            
            # Try to get variable name for guard tracking
            var_name = self._get_variable_name_for_value(state, value)
            
            # The jump happens if value is not None
            target_offset = instr.argval
            fallthrough_offset = self._next_offset(frame, instr)

            if self.oracle:
                expected_next = self.oracle.pop_branch_next_offset(frame.code, instr.offset)
                if expected_next in (target_offset, fallthrough_offset):
                    took_jump = expected_next == target_offset
                    state.path_condition = z3.And(
                        state.path_condition,
                        z3.Not(is_none) if took_jump else is_none,
                    )
                    # Track guard on the taken path
                    if took_jump and var_name:
                        state.established_guards[f"nonnull:{var_name}"] = True
                    frame.instruction_offset = expected_next
                    return
            
            # Check if not-none path is feasible (jump taken)
            self.solver.push()
            self.solver.add(state.path_condition)
            self.solver.add(z3.Not(is_none))
            not_none_feasible = (self.solver.check() == z3.sat)
            self.solver.pop()
            
            # Check if none path is feasible (fall through)
            self.solver.push()
            self.solver.add(state.path_condition)
            self.solver.add(is_none)
            none_feasible = (self.solver.check() == z3.sat)
            self.solver.pop()
            
            # Implement proper path branching when both branches are feasible
            if not_none_feasible and none_feasible:
                # Both branches feasible: fork the path
                import copy
                
                if self.verbose:
                    print(f"[FORK] POP_JUMP_IF_NOT_NONE: Both branches feasible")
                    print(f"  Not-None branch (jump): offset {target_offset}")
                    print(f"  None branch (fallthrough): offset {fallthrough_offset}")
                
                # Create forked state for not-none branch (jump taken)
                not_none_state = copy.deepcopy(state)
                not_none_state.path_condition = z3.And(state.path_condition, z3.Not(is_none))
                if var_name:
                    not_none_state.established_guards[f"nonnull:{var_name}"] = True
                not_none_state.frame_stack[-1].instruction_offset = target_offset
                
                # Keep current state as none branch (fallthrough)
                state.path_condition = z3.And(state.path_condition, is_none)
                frame.instruction_offset = fallthrough_offset
                
                # Signal forking by storing the alternative state
                state.fork_branch_successors = [not_none_state]
                
            elif not_none_feasible:
                # Only not-none path feasible
                state.path_condition = z3.And(state.path_condition, z3.Not(is_none))
                # Establish nonnull guard on this path
                if var_name:
                    state.established_guards[f"nonnull:{var_name}"] = True
                frame.instruction_offset = target_offset
            elif none_feasible:
                # Only none path feasible
                state.path_condition = z3.And(state.path_condition, is_none)
                frame.instruction_offset = fallthrough_offset
            else:
                # No feasible path
                state.exception = "InfeasiblePath"
        
        elif opname == "POP_JUMP_IF_NONE":
            # Python 3.14 opcode: pop TOS, jump if it is None
            if not frame.operand_stack:
                state.exception = "StackUnderflow"
                return
            
            value = frame.operand_stack.pop()
            is_none = (value.tag == z3.IntVal(ValueTag.NONE.value))
            
            # Try to get variable name for guard tracking
            var_name = self._get_variable_name_for_value(state, value)
            
            # The jump happens if value is None
            target_offset = instr.argval
            fallthrough_offset = self._next_offset(frame, instr)

            if self.oracle:
                expected_next = self.oracle.pop_branch_next_offset(frame.code, instr.offset)
                if expected_next in (target_offset, fallthrough_offset):
                    took_jump = expected_next == target_offset
                    state.path_condition = z3.And(
                        state.path_condition,
                        is_none if took_jump else z3.Not(is_none),
                    )
                    # Track guard on the not-None path (fall through when jump not taken)
                    if not took_jump and var_name:
                        state.established_guards[f"nonnull:{var_name}"] = True
                    frame.instruction_offset = expected_next
                    return
            
            # Check if none path is feasible (jump taken)
            self.solver.push()
            self.solver.add(state.path_condition)
            self.solver.add(is_none)
            none_feasible = (self.solver.check() == z3.sat)
            self.solver.pop()
            
            # Check if not-none path is feasible (fall through)
            self.solver.push()
            self.solver.add(state.path_condition)
            self.solver.add(z3.Not(is_none))
            not_none_feasible = (self.solver.check() == z3.sat)
            self.solver.pop()
            
            # Implement proper path branching when both branches are feasible
            if none_feasible and not_none_feasible:
                # Both branches feasible: fork the path
                import copy
                
                if self.verbose:
                    print(f"[FORK] POP_JUMP_IF_NONE: Both branches feasible")
                    print(f"  None branch (jump): offset {target_offset}")
                    print(f"  Not-None branch (fallthrough): offset {fallthrough_offset}")
                
                # Create forked state for none branch (jump taken)
                none_state = copy.deepcopy(state)
                none_state.path_condition = z3.And(state.path_condition, is_none)
                none_state.frame_stack[-1].instruction_offset = target_offset
                
                # Keep current state as not-none branch (fallthrough)
                state.path_condition = z3.And(state.path_condition, z3.Not(is_none))
                if var_name:
                    state.established_guards[f"nonnull:{var_name}"] = True
                frame.instruction_offset = fallthrough_offset
                
                # Signal forking by storing the alternative state
                state.fork_branch_successors = [none_state]
                
            elif not_none_feasible:
                # Only not-none path feasible
                state.path_condition = z3.And(state.path_condition, z3.Not(is_none))
                # Establish nonnull guard on this path
                if var_name:
                    state.established_guards[f"nonnull:{var_name}"] = True
                frame.instruction_offset = fallthrough_offset
            elif none_feasible:
                # Only none path feasible
                state.path_condition = z3.And(state.path_condition, is_none)
                frame.instruction_offset = target_offset
            else:
                # No feasible path
                state.exception = "InfeasiblePath"
        
        elif opname == "PUSH_EXC_INFO":
            # Python 3.11+: PUSH_EXC_INFO
            # CPython model: TOS has exception value (pushed by handler dispatch).
            # PUSH_EXC_INFO saves prev_exc_info, then stack becomes:
            #   [prev_exc, exc_val]
            # where exc_val was already on TOS.
            #
            # Our handler dispatch pushes exc_val to TOS and clears
            # state.exception.  PUSH_EXC_INFO inserts prev_exc below TOS.
            if frame.operand_stack:
                exc_val = frame.operand_stack[-1]  # exc already on TOS
                prev_exc = SymbolicValue.none()
                frame.operand_stack.insert(len(frame.operand_stack) - 1, prev_exc)
            elif state.exception:
                # Fallback: if no exc on stack but state.exception set
                # (legacy path — shouldn't happen with new dispatch model)
                if state.exception in frame.builtins:
                    exc_val = frame.builtins[state.exception]
                else:
                    exc_val = SymbolicValue(ValueTag.OBJ, z3.IntVal(-2))
                    exc_val._exception_type = state.exception
                prev_exc = SymbolicValue.none()
                frame.operand_stack.append(prev_exc)
                frame.operand_stack.append(exc_val)
            frame.instruction_offset = self._next_offset(frame, instr)
        
        elif opname == "CHECK_EXC_MATCH":
            # Python 3.11+: CHECK_EXC_MATCH (left, right -- left, bool)
            # TOS = match_type (exception class to compare against)
            # TOS1 = exc_value (stays on stack)
            # Result: pushes boolean indicating whether exc matches match_type
            if len(frame.operand_stack) < 2:
                state.exception = "StackUnderflow"
                return
            
            match_type = frame.operand_stack.pop()    # TOS = type to match
            exc_value = frame.operand_stack[-1]        # TOS1 = stays on stack
            
            # Compare exception types
            if hasattr(exc_value, '_exception_type') and hasattr(match_type, '_exception_type'):
                matches = exc_value._exception_type == match_type._exception_type
                frame.operand_stack.append(SymbolicValue.bool(matches))
            elif exc_value.tag == ValueTag.OBJ and match_type.tag == ValueTag.OBJ:
                matches_expr = exc_value.payload == match_type.payload
                match_result = SymbolicValue(ValueTag.BOOL, matches_expr)
                frame.operand_stack.append(match_result)
            else:
                # Unknown types, conservatively assume it could match
                frame.operand_stack.append(SymbolicValue.bool(True))
            
            frame.instruction_offset = self._next_offset(frame, instr)
        
        elif opname == "POP_EXCEPT":
            # Python 3.11+: POP_EXCEPT pops one value (the exception)
            if frame.operand_stack:
                frame.operand_stack.pop()
            
            # Clear exception state
            state.exception = None
            state.exception_value = None
            frame.instruction_offset = self._next_offset(frame, instr)
        
        elif opname == "RERAISE":
            # Re-raise the current exception (CPython 3.11 model).
            # RERAISE always pops ONE item from TOS — the exception value.
            # The oparg controls lasti peeking (for exception groups), but
            # does not affect the number of items popped.
            
            # Pop exception value from TOS
            exc_val = None
            if frame.operand_stack:
                exc_val = frame.operand_stack.pop()
            
            # Recover exception type from the popped value
            if exc_val and hasattr(exc_val, '_exception_type') and exc_val._exception_type:
                state.exception = exc_val._exception_type
            elif not state.exception:
                # No exception type available — use RuntimeError as fallback
                state.exception = "RuntimeError"
            
            # Dispatch to exception handler in the exception table
            handler_info = self._get_exception_handler_info(
                frame.code, instr.offset, any_depth=True
            )
            if handler_info is not None:
                handler_offset, handler_depth, handler_lasti = handler_info
                # Unwind operand stack to the specified depth
                if len(frame.operand_stack) > handler_depth:
                    frame.operand_stack = frame.operand_stack[:handler_depth]
                if handler_lasti:
                    frame.operand_stack.append(
                        SymbolicValue(ValueTag.INT, z3.IntVal(instr.offset))
                    )
                # Push exception value onto stack (CPython model)
                re_exc_val = SymbolicValue(ValueTag.OBJ, z3.IntVal(-2))
                re_exc_val._exception_type = state.exception
                frame.operand_stack.append(re_exc_val)
                # Clear state.exception (now on stack) and jump
                state.exception = None
                frame.instruction_offset = handler_offset
            else:
                # No handler in this frame — leave state.exception set.
                # Don't advance instruction pointer — explore_bounded or
                # the caller frame will handle the propagation.
                pass
        
        elif opname == "NOP":
            # No operation
            frame.instruction_offset = self._next_offset(frame, instr)
        
        elif opname == "MAKE_CELL":
            # MAKE_CELL(i): Creates a cell for variable at position i in combined fast locals
            # This is called at function entry for variables that will be captured by closures
            # The cell is initially empty (or contains None); STORE_DEREF will fill it later
            # In Python 3.11+, the index is into combined fast locals: co_varnames + co_cellvars
            var_index = instr.arg
            
            # Calculate offsets
            num_varnames = len(frame.code.co_varnames)
            num_cellvars = len(frame.code.co_cellvars)
            
            if var_index < num_varnames:
                # Variable in co_varnames - this shouldn't happen for MAKE_CELL
                # but handle it anyway
                pass
            elif var_index < num_varnames + num_cellvars:
                # This is a cellvar (variable in this function that inner functions will reference)
                cell_index = var_index - num_varnames
                frame.cells[cell_index] = SymbolicValue.none()  # Initialize as empty cell
            else:
                # This is a freevar (variable from outer scope)
                freevar_index = var_index - num_varnames - num_cellvars
                frame.freevars[freevar_index] = SymbolicValue.none()  # Initialize as empty
            
            frame.instruction_offset = self._next_offset(frame, instr)
        
        elif opname == "STORE_DEREF":
            # STORE_DEREF(i): Stores TOS into cell or freevar at index i
            # Stack: value →
            # In Python 3.11+, the index is into the combined fast locals layout:
            # combined = co_varnames + co_cellvars + co_freevars
            # We need to map this to the actual cell/freevar index
            var_index = instr.arg  # Combined fast locals index
            
            if len(frame.operand_stack) < 1:
                state.exception = "StackUnderflow"
                return
            
            value = frame.operand_stack.pop()
            
            # Calculate offsets
            num_varnames = len(frame.code.co_varnames)
            num_cellvars = len(frame.code.co_cellvars)
            
            if var_index < num_varnames:
                # This shouldn't happen - STORE_DEREF should only be for cells/freevars
                # But handle it by storing to locals
                var_name = frame.code.co_varnames[var_index]
                frame.locals[var_name] = value
            elif var_index < num_varnames + num_cellvars:
                # Store into cell
                cell_index = var_index - num_varnames
                frame.cells[cell_index] = value
            else:
                # Store into freevar
                freevar_index = var_index - num_varnames - num_cellvars
                frame.freevars[freevar_index] = value
            
            frame.instruction_offset = self._next_offset(frame, instr)
        
        elif opname == "LOAD_DEREF":
            # LOAD_DEREF(i): Loads cell or freevar at index i onto stack
            # Stack: → value
            # In Python 3.11+, the index is into the combined fast locals layout:
            # combined = co_varnames + co_cellvars + co_freevars
            var_index = instr.arg
            
            # Calculate offsets
            num_varnames = len(frame.code.co_varnames)
            num_cellvars = len(frame.code.co_cellvars)
            
            if var_index < num_varnames:
                # This shouldn't normally happen for LOAD_DEREF
                # But handle it by loading from locals
                var_name = frame.code.co_varnames[var_index]
                if var_name in frame.locals:
                    value = frame.locals[var_name]
                else:
                    state.exception = "UnboundLocalError"
                    return
            elif var_index < num_varnames + num_cellvars:
                # Load from cell
                cell_index = var_index - num_varnames
                if cell_index in frame.cells:
                    value = frame.cells[cell_index]
                else:
                    state.exception = "UnboundLocalError"
                    return
            else:
                # Load from freevar
                freevar_index = var_index - num_varnames - num_cellvars
                if freevar_index in frame.freevars:
                    value = frame.freevars[freevar_index]
                else:
                    state.exception = "NameError"
                    return
            
            frame.operand_stack.append(value)
            frame.instruction_offset = self._next_offset(frame, instr)
        
        elif opname == "COPY_FREE_VARS":
            # COPY_FREE_VARS(n): Copies n free variables from the closure into the frame
            # This is called at function entry for functions with closures
            # The closure values are expected to be in the function object's __closure__ attribute
            # For symbolic execution, we create symbolic free variables
            n = instr.argval
            
            # In a real implementation, we'd get these from the function's closure tuple
            # For symbolic execution, we create fresh symbolic values for each free variable
            for i in range(n):
                if i < len(frame.code.co_freevars):
                    freevar_name = frame.code.co_freevars[i]
                    # Create a symbolic value for this free variable
                    sym_val = SymbolicValue(ValueTag.INT, z3.Int(f"freevar_{freevar_name}_{id(frame)}"))
                    frame.freevars[i] = sym_val
                else:
                    # If we don't have the name, create a generic symbolic value
                    sym_val = SymbolicValue(ValueTag.INT, z3.Int(f"freevar_{i}_{id(frame)}"))
                    frame.freevars[i] = sym_val
            
            frame.instruction_offset = self._next_offset(frame, instr)
        
        elif opname == "PUSH_NULL":
            # PUSH_NULL: pushes a NULL marker onto the stack
            # In Python 3.11+, this is used before function calls to mark
            # whether the callable is a method or function
            # For symbolic execution, we push a NULL symbolic value
            null_val = SymbolicValue.none()
            frame.operand_stack.append(null_val)
            frame.instruction_offset = self._next_offset(frame, instr)
        
        elif opname == "COPY":
            # COPY n: push a copy of the item n items from the top
            n = instr.argval
            if len(frame.operand_stack) < n:
                state.exception = "StackUnderflow"
                return
            item = frame.operand_stack[-n]
            frame.operand_stack.append(item)
            frame.instruction_offset = self._next_offset(frame, instr)
        
        elif opname == "NOT_TAKEN":
            # Python 3.14 quickening hint - ignore for symbolic execution
            frame.instruction_offset = self._next_offset(frame, instr)
        
        elif opname == "IMPORT_NAME":
            # IMPORT_NAME(namei): Imports the module co_names[namei]
            # Stack: level, fromlist → module
            # For symbolic execution, we model stdlib modules as symbolic objects
            # with their functions available via LOAD_ATTR
            
            # Track import count for module-init phase detection
            state.import_count += 1
            
            # Improved module-init phase detection:
            # Check if we're in module-level code (co_name == '<module>') AND at shallow frame depth
            # This distinguishes module-level imports from function-level imports
            is_module_level = (frame.code.co_name == '<module>')
            is_shallow_frame = (len(state.frame_stack) <= 1)  # Module frame only, or one function deep
            
            # Flag as module-init if we're at module level with 3+ imports
            # This correctly identifies "import-heavy module initialization" vs "function with imports"
            if is_module_level and is_shallow_frame and state.import_count >= 3:
                state.module_init_phase = True
            
            module_name = instr.argval
            
            # Pop fromlist and level (unused for now, but needed for stack consistency)
            if len(frame.operand_stack) < 2:
                state.exception = "StackUnderflow"
                return
            frame.operand_stack.pop()  # fromlist
            frame.operand_stack.pop()  # level
            
            # Create a symbolic module object
            # We use a negative object ID to distinguish modules from regular objects
            module_id = -2000 - hash(module_name) % 10000
            module_obj = SymbolicValue(ValueTag.OBJ, z3.IntVal(module_id))
            
            # Store module name as metadata for LOAD_ATTR/IMPORT_FROM
            if not hasattr(state, 'module_names'):
                state.module_names = {}
            state.module_names[module_id] = module_name
            
            # If this is a known stdlib module with stubs, populate its exports
            # into a module_exports registry so LOAD_ATTR can find them
            if is_known_stdlib_module(module_name):
                exports = get_module_exports(module_name)
                if not hasattr(state, 'module_exports'):
                    state.module_exports = {}
                state.module_exports[module_id] = exports
            
            frame.operand_stack.append(module_obj)
            frame.instruction_offset = self._next_offset(frame, instr)
        
        elif opname == "LOAD_ATTR":
            # LOAD_ATTR(namei): Loads attribute co_names[namei] from TOS object
            # Stack: obj → obj.attr
            # Python 3.11+ optimization: when (arg & 1) == 1, pushes NULL+attr for method calls
            attr_name = instr.argval
            
            def push_attr_result(attr_value):
                """Helper to push LOAD_ATTR result, handling NULL|self optimization"""
                if instr.arg is not None and (instr.arg & 1):
                    # Method call form: push NULL marker, then the attribute (self)
                    null_marker = SymbolicValue.none()
                    frame.operand_stack.append(null_marker)
                    frame.operand_stack.append(attr_value)
                else:
                    # Regular attribute: just push the value
                    frame.operand_stack.append(attr_value)
                frame.instruction_offset = self._next_offset(frame, instr)
            
            if not frame.operand_stack:
                state.exception = "StackUnderflow"
                return
            
            obj = frame.operand_stack.pop()
            
            # ========================================================================
            # ITERATION 415: Framework mock object attribute lookup
            # For request.args, request.GET, etc., return the properly mocked attribute
            # ========================================================================
            if hasattr(state, 'framework_mocks') and id(obj) in state.framework_mocks:
                mock = state.framework_mocks[id(obj)]
                
                # Check if this is an attribute on the mock
                if attr_name in mock.attributes:
                    mock_attr = mock.attributes[attr_name]
                    attr_val = mock_attr.value
                    
                    # Register the attribute value so we can lookup its mock later
                    # (for nested access like request.args.get())
                    if hasattr(mock, '_nested_mocks') and attr_val in mock._nested_mocks:
                        nested_mock = mock._nested_mocks[attr_val]
                        state.framework_mocks[id(attr_val)] = nested_mock
                    
                    # Apply taint if specified in the mock
                    if mock_attr.taint_label and state.security_tracker:
                        state.security_tracker.set_label(attr_val, mock_attr.taint_label)
                    if mock_attr.symbolic_taint and state.security_tracker:
                        state.security_tracker.set_symbolic_label(attr_val, mock_attr.symbolic_taint)
                    
                    # Track qualified name for contract matching
                    if not hasattr(state, 'func_names'):
                        state.func_names = {}
                    obj_name = state.func_names.get(id(obj), "unknown")
                    state.func_names[id(attr_val)] = f"{obj_name}.{attr_name}"
                    
                    push_attr_result(attr_val)
                    return
                
                # Check if this is a method on the mock
                if attr_name in mock.methods:
                    mock_method = mock.methods[attr_name]
                    method_val = mock_method.return_value
                    
                    # Store mock method info for CALL handling
                    if not hasattr(state, 'mock_methods'):
                        state.mock_methods = {}
                    state.mock_methods[id(method_val)] = mock_method
                    
                    # Track qualified name
                    if not hasattr(state, 'func_names'):
                        state.func_names = {}
                    obj_name = state.func_names.get(id(obj), "unknown")
                    state.func_names[id(method_val)] = f"{obj_name}.{attr_name}"
                    
                    push_attr_result(method_val)
                    return
            
            # ========================================================================
            # CRITICAL: Check for None dereference (NULL_PTR)
            # Accessing any attribute on None is an AttributeError
            # ========================================================================
            
            # Case 1: Definitely None (concrete tag)
            if obj.tag == ValueTag.NONE:
                state.none_misuse_reached = True
                state.exception = "AttributeError"
                return
            
            # Case 2: Symbolically could be None (check with Z3)
            # For OBJ types, check if None is possible under current path condition
            if obj.tag == ValueTag.OBJ:
                # Check if intraprocedural analysis establishes this is non-null
                var_name = self._get_variable_name_for_value(state, obj)
                is_proven_nonnull = False
                
                if var_name:
                    analysis = state.get_intraproc_analysis(frame.code)
                    if analysis and analysis.is_nonnull(instr.offset, var_name):
                        is_proven_nonnull = True
                    # Also check established guards
                    guard_key = f"nonnull:{var_name}"
                    if guard_key in state.established_guards:
                        is_proven_nonnull = True
                
                if not is_proven_nonnull:
                    # Check if obj could be None using Z3
                    self.solver.push()
                    self.solver.add(state.path_condition)
                    self.solver.add(obj.is_none())
                    could_be_none = (self.solver.check() == z3.sat)
                    self.solver.pop()
                    
                    if could_be_none:
                        state.none_misuse_reached = True
                        state.exception = "AttributeError"
                        return
            
            # For module objects, resolve qualified function names
            if obj.tag == ValueTag.OBJ and hasattr(state, 'module_names'):
                # Extract module ID from payload
                if isinstance(obj.payload, z3.IntNumRef):
                    module_id = obj.payload.as_long()
                    if module_id in state.module_names:
                        module_name = state.module_names[module_id]
                        
                        # Check for special module attributes (os.environ, sys.version_info, etc.)
                        special_attr = get_special_attribute(module_name, attr_name)
                        if special_attr is not None:
                            # Handle special attributes with concrete/semi-concrete semantics
                            attr_type = special_attr.get("type")
                            
                            if attr_type == "environ":
                                # os.environ: dict-like with string keys/values
                                # Model as symbolic dict (not fully havoced)
                                environ_id = state.heap.allocate_dict()
                                environ_val = SymbolicValue(ValueTag.DICT, z3.IntVal(environ_id))
                                
                                # Propagate taint
                                if state.security_tracker and state.security_tracker.enabled:
                                    state.security_tracker.handle_getattr(obj, attr_name, environ_val)
                                
                                push_attr_result(environ_val)
                                return
                            
                            elif attr_type == "version_info":
                                # sys.version_info: concrete tuple with (major, minor, micro, releaselevel, serial)
                                # For symbolic execution, treat as semi-concrete: major/minor are concrete, rest symbolic
                                # This allows version checks like `sys.version_info >= (3, 11)` to work
                                version_id = state.heap.allocate_tuple(5)
                                version_val = SymbolicValue(ValueTag.TUPLE, z3.IntVal(version_id))
                                # Store concrete values for major=3, minor=11+ (matching target_python)
                                # This is justified: we're analyzing for Python 3.11+ semantics
                                state.heap.set_tuple_element(version_id, 0, SymbolicValue(ValueTag.INT, z3.IntVal(3)))
                                state.heap.set_tuple_element(version_id, 1, SymbolicValue(ValueTag.INT, z3.IntVal(11)))
                                # micro, releaselevel, serial: symbolic (less critical for version checks)
                                state.heap.set_tuple_element(version_id, 2, SymbolicValue(ValueTag.INT, z3.Int(f"version_micro")))
                                state.heap.set_tuple_element(version_id, 3, SymbolicValue(ValueTag.STR, z3.Int(f"version_releaselevel")))
                                state.heap.set_tuple_element(version_id, 4, SymbolicValue(ValueTag.INT, z3.Int(f"version_serial")))
                                
                                # Propagate taint
                                if state.security_tracker and state.security_tracker.enabled:
                                    state.security_tracker.handle_getattr(obj, attr_name, version_val)
                                
                                push_attr_result(version_val)
                                return
                            
                            elif attr_type == "exception_class":
                                # Exception base classes: always available
                                # Model as class objects (type tag)
                                exc_class_id = -4000 - hash(attr_name) % 10000
                                exc_class = SymbolicValue(ValueTag.OBJ, z3.IntVal(exc_class_id))
                                # Store exception class name for CHECK_EXC_MATCH
                                if not hasattr(state, 'exception_classes'):
                                    state.exception_classes = {}
                                state.exception_classes[exc_class_id] = attr_name
                                
                                # Propagate taint
                                if state.security_tracker and state.security_tracker.enabled:
                                    state.security_tracker.handle_getattr(obj, attr_name, exc_class)
                                
                                push_attr_result(exc_class)
                                return
                            
                            elif special_attr.get("concrete"):
                                # Concrete value attributes (sys.maxsize, os.name, sys.platform)
                                # Model as symbolic but annotated as concrete
                                if attr_type == "int":
                                    concrete_val = SymbolicValue(ValueTag.INT, z3.Int(f"{module_name}_{attr_name}"))
                                elif attr_type == "str":
                                    concrete_val = SymbolicValue(ValueTag.STR, z3.Int(f"{module_name}_{attr_name}"))
                                else:
                                    concrete_val = SymbolicValue(ValueTag.OBJ, z3.Int(f"{module_name}_{attr_name}"))
                                
                                # Propagate taint
                                if state.security_tracker and state.security_tracker.enabled:
                                    state.security_tracker.handle_getattr(obj, attr_name, concrete_val)
                                
                                push_attr_result(concrete_val)
                                return
                        
                        # Check if this is a known export (avoid AttributeError)
                        if hasattr(state, 'module_exports') and module_id in state.module_exports:
                            exports = state.module_exports[module_id]
                            if attr_name not in exports:
                                # Trying to access unknown attribute from known module
                                state.exception = "AttributeError"
                                return
                        
                        qualified_name = f"{module_name}.{attr_name}"
                        
                        # Create a symbolic function reference with stable ID
                        func_id = -3000 - hash(qualified_name) % 10000
                        func_ref = SymbolicValue(ValueTag.OBJ, z3.IntVal(func_id))
                        
                        # Store qualified function name for contract lookup using stable func_id
                        if not hasattr(state, 'func_names'):
                            state.func_names = {}
                        state.func_names[func_id] = qualified_name
                        
                        # Propagate taint through module attribute access
                        if state.security_tracker and state.security_tracker.enabled:
                            state.security_tracker.handle_getattr(obj, attr_name, func_ref)
                        
                        push_attr_result(func_ref)
                        return
            
            # Special handling for dict methods (keys, values, items, get, setdefault)
            # These are common patterns in real code and worth modeling semantically
            if attr_name in ("keys", "values", "items", "get", "setdefault"):
                # Check if the object is a dict
                if obj.tag == ValueTag.DICT:
                    # Return a method-bound object that represents the dict view/method
                    # We model this as a callable OBJ with special metadata
                    method_id = state.heap.allocate_dict_view(obj, attr_name)
                    method_val = SymbolicValue(ValueTag.OBJ, z3.IntVal(method_id))
                    
                    # Store metadata for later CALL handling
                    if not hasattr(state, 'dict_view_methods'):
                        state.dict_view_methods = {}
                    state.dict_view_methods[method_id] = {
                        'method': attr_name,
                        'dict_obj': obj,
                        'dict_id': obj.payload.as_long() if isinstance(obj.payload, z3.IntNumRef) else None
                    }
                    
                    # Propagate taint from dict object to method
                    if state.security_tracker and state.security_tracker.enabled:
                        state.security_tracker.handle_getattr(obj, attr_name, method_val)
                    
                    push_attr_result(method_val)
                    return
                
                elif obj.tag == ValueTag.NONE:
                    # Calling dict methods on None → NULL_PTR
                    state.none_misuse_reached = True
                    state.exception = "AttributeError"
                    return
                
                elif obj.tag in (ValueTag.LIST, ValueTag.TUPLE, ValueTag.STR, 
                                ValueTag.INT, ValueTag.FLOAT, ValueTag.BOOL):
                    # Calling dict methods on non-dict types → AttributeError (PANIC)
                    state.exception = "AttributeError"
                    return
                
                # For OBJ (unknown type), fall through to havoc (sound over-approximation)
            
            # For non-module objects, havoc the result with type-aware inference
            # Infer likely tag from attribute name patterns (still sound over-approximation)
            inferred_tag = self._infer_attribute_type(attr_name)
            
            # ITERATION 277: Type-aware havocking for HTTP request dicts
            # When loading HTTP parameter dicts (request.POST, request.GET, etc.),
            # tag them as HTTP_PARAM_DICT so that dict.get() knows to return STR.
            # This prevents TypeError when concatenating: "nmap " + request.POST.get('ip')
            is_http_param_dict = False
            if inferred_tag == ValueTag.DICT and attr_name in {
                'GET', 'POST', 'FILES', 'COOKIES', 'SESSION',
                'headers', 'params', 'form', 'args', 'values', 'data'
            }:
                is_http_param_dict = True
            
            attr_val = SymbolicValue(inferred_tag, z3.Int(f"attr_{id(obj)}_{attr_name}"))
            
            # If this is an HTTP parameter dict, mark it in the dict metadata
            if is_http_param_dict and inferred_tag == ValueTag.DICT:
                # Allocate a proper dict object with HTTP_PARAM_DICT tag
                dict_id = state.heap.allocate_dict()
                attr_val = SymbolicValue(ValueTag.DICT, z3.IntVal(dict_id))
                
                # Mark this dict as an HTTP parameter dict
                if not hasattr(state, 'http_param_dicts'):
                    state.http_param_dicts = set()
                state.http_param_dicts.add(dict_id)
            
            # Track potential method names for contract matching
            # For attribute access on objects (especially tainted request objects),
            # track the attribute name so it can be matched against security contracts.
            # This enables matching patterns like "request.POST.get" or "cursor.execute".
            #
            # Build a qualified name from the object's existing name (if any) + attribute
            qualified_attr_name = attr_name  # Default fallback
            
            # CRITICAL FIX (Iteration 490): Use stable Z3 payload ID instead of Python id()
            obj_stable_id = get_stable_value_id(obj)
            
            if obj_stable_id is not None:
                if hasattr(state, 'func_names') and obj_stable_id in state.func_names:
                    # Obj already has a name (e.g., "request.POST", "os", "sqlite3")
                    obj_name = state.func_names[obj_stable_id]
                    qualified_attr_name = f"{obj_name}.{attr_name}"
                elif hasattr(state, 'value_var_names') and obj_stable_id in state.value_var_names:
                    # CRITICAL FIX (Iteration 270 + 490): Use variable name for method call resolution
                    # Object is stored in a local variable - use the variable name
                    # This enables patterns like: cursor = conn.cursor(); cursor.execute(...)
                    # where cursor.execute needs to be detected as a SQL_EXECUTE sink
                    var_name = state.value_var_names[obj_stable_id]
                    qualified_attr_name = f"{var_name}.{attr_name}"
            
            # Store the qualified name for this attribute result
            # ITERATION 499 FIX: Try stable ID first, fall back to Python ID for symbolic values
            # This ensures methods on undefined globals (like cursor.execute) are properly named
            if not hasattr(state, 'func_names'):
                state.func_names = {}
            attr_stable_id = get_stable_value_id(attr_val)
            if attr_stable_id is not None:
                state.func_names[attr_stable_id] = qualified_attr_name
            else:
                # For symbolic values, use Python ID as fallback
                state.func_names[id(attr_val)] = qualified_attr_name
            
            # CRITICAL: Propagate taint through attribute access
            # If obj is tainted, attr_val should inherit that taint
            if state.security_tracker and state.security_tracker.enabled:
                state.security_tracker.handle_getattr(obj, attr_name, attr_val)
            
            push_attr_result(attr_val)
        
        elif opname == "GET_ITER":
            # GET_ITER: TOS = iter(TOS)
            # Converts the TOS object to an iterator
            if not frame.operand_stack:
                state.exception = "StackUnderflow"
                return
            
            obj = frame.operand_stack.pop()
            
            # Check for None (NULL_PTR detection)
            if obj.tag == ValueTag.NONE:
                state.none_misuse_reached = True
                state.exception = "TypeError"
                return
            
            # For sequences (list, tuple, str), create an iterator object
            if obj.tag in (ValueTag.LIST, ValueTag.TUPLE, ValueTag.STR):
                # Allocate an iterator object in the heap
                # Iterator has: reference to collection, current index
                iter_id = state.heap.allocate_iterator(obj)
                iter_val = SymbolicValue(ValueTag.OBJ, z3.IntVal(iter_id))
                
                # Track active iterator for ITERATOR_INVALID detection
                if hasattr(obj, 'payload') and isinstance(obj.payload, z3.IntNumRef):
                    collection_id = obj.payload.as_long()
                    state.active_iterators.append((collection_id, iter_id))
                
                frame.operand_stack.append(iter_val)
            else:
                # For unknown objects, create a generic iterator (havoc)
                iter_id = z3.Int(f"iter_{id(obj)}")
                iter_val = SymbolicValue(ValueTag.OBJ, iter_id)
                frame.operand_stack.append(iter_val)
            
            frame.instruction_offset = self._next_offset(frame, instr)
        
        elif opname == "FOR_ITER":
            # FOR_ITER: Attempt to get next item from iterator
            # If successful, pushes item and continues
            # If exhausted, pops iterator and jumps to target
            if not frame.operand_stack:
                state.exception = "StackUnderflow"
                return
            
            iterator = frame.operand_stack[-1]  # Peek, don't pop yet
            
            # Check if iterator is exhausted (nondeterministic)
            # We model this as a symbolic branch:
            # Path 1: iterator has next item
            # Path 2: iterator is exhausted
            
            # For now, implement simple bounded iteration.
            # Create a fresh symbolic boolean for *this* FOR_ITER occurrence.
            if not hasattr(state, "_for_iter_counter"):
                state._for_iter_counter = 0
            state._for_iter_counter += 1
            iter_occurrence = state._for_iter_counter

            has_next = z3.Bool(f"has_next_{id(iterator)}_{iter_occurrence}")

            # Trace-guided replay: if an oracle provides the observed successor offset,
            # deterministically pick the corresponding branch.
            expected_next: Optional[int] = None
            if self.oracle:
                expected_next = self.oracle.pop_branch_next_offset(frame.code, instr.offset)

            # Check both possibilities
            self.solver.push()
            self.solver.add(state.path_condition)
            self.solver.add(has_next)
            has_next_feasible = (self.solver.check() == z3.sat)
            self.solver.pop()
            
            self.solver.push()
            self.solver.add(state.path_condition)
            self.solver.add(z3.Not(has_next))
            exhausted_feasible = (self.solver.check() == z3.sat)
            self.solver.pop()

            fallthrough_offset = self._next_offset(frame, instr)
            target_offset = instr.argval

            if expected_next is not None:
                if expected_next == fallthrough_offset and has_next_feasible:
                    state.path_condition = z3.And(state.path_condition, has_next)

                    next_item = SymbolicValue(ValueTag.OBJ, z3.Int(f"next_{id(iterator)}_{iter_occurrence}"))
                    frame.operand_stack.append(next_item)

                    frame.instruction_offset = fallthrough_offset
                    return

                # Some CPython versions may jump to an END_FOR cleanup block and the
                # first observed instruction after FOR_ITER can be *after* instr.argval.
                # For replay, treat any non-fallthrough successor as the exhausted branch
                # and jump to the observed successor offset.
                if expected_next != fallthrough_offset and exhausted_feasible:
                    state.path_condition = z3.And(state.path_condition, z3.Not(has_next))
                    frame.operand_stack.pop()
                    frame.instruction_offset = expected_next
                    return

                state.exception = "InfeasiblePath"
                return

            # No oracle guidance: prefer the has_next path first (bounded model checking).
            if has_next_feasible:
                # Iterator has next item
                state.path_condition = z3.And(state.path_condition, has_next)
                
                # Create a symbolic value for the next item
                next_item = SymbolicValue(ValueTag.OBJ, z3.Int(f"next_{id(iterator)}_{iter_occurrence}"))
                frame.operand_stack.append(next_item)
                
                frame.instruction_offset = fallthrough_offset
            elif exhausted_feasible:
                # Iterator is exhausted
                state.path_condition = z3.And(state.path_condition, z3.Not(has_next))
                
                # Pop the iterator
                frame.operand_stack.pop()
                
                # Jump to target (loop exit)
                frame.instruction_offset = target_offset
            else:
                # No feasible path
                state.exception = "InfeasiblePath"
        
        elif opname == "END_FOR":
            # END_FOR: Marks the end of a for loop (no operation in most Python versions)
            # In Python 3.12+, this is used for cleanup
            frame.instruction_offset = self._next_offset(frame, instr)
        
        elif opname == "POP_ITER":
            # POP_ITER: Pops the iterator from the stack when loop is done
            if frame.operand_stack:
                iterator = frame.operand_stack.pop()
                
                # Remove from active iterators tracking
                if hasattr(iterator, 'payload') and isinstance(iterator.payload, z3.IntNumRef):
                    iter_id = iterator.payload.as_long()
                    state.active_iterators = [
                        (cid, iid) for cid, iid in state.active_iterators if iid != iter_id
                    ]
            
            frame.instruction_offset = self._next_offset(frame, instr)
        
        elif opname == "JUMP_BACKWARD":
            # JUMP_BACKWARD: Unconditional backward jump (for loops)
            # In Python 3.11+, this is used for loop backedges
            target_offset = instr.argval
            frame.instruction_offset = target_offset
        
        elif opname == "JUMP_FORWARD":
            # JUMP_FORWARD: Unconditional forward jump
            # Used for control flow (e.g., jumping over else blocks)
            # argval contains the target offset
            target_offset = instr.argval
            frame.instruction_offset = target_offset
        
        elif opname == "SWAP":
            # SWAP n: Swap TOS with n-th item from the top
            n = instr.argval
            if len(frame.operand_stack) < n:
                state.exception = "StackUnderflow"
                return
            
            # Swap TOS (index -1) with item at index (-n)
            tos = frame.operand_stack[-1]
            nth_item = frame.operand_stack[-n]
            frame.operand_stack[-1] = nth_item
            frame.operand_stack[-n] = tos
            
            frame.instruction_offset = self._next_offset(frame, instr)
        
        elif opname == "LOAD_SPECIAL":
            # LOAD_SPECIAL: Load special method from TOS object
            # Used in with statements to load __enter__ and __exit__
            # argval: 0 for __enter__, 1 for __exit__
            if not frame.operand_stack:
                state.exception = "StackUnderflow"
                return
            
            obj = frame.operand_stack[-1]  # Peek, don't pop
            
            method_index = instr.argval
            method_name = "__enter__" if method_index == 0 else "__exit__"
            
            # Create a symbolic method reference
            method_ref = SymbolicValue(ValueTag.OBJ, z3.Int(f"{method_name}_{id(obj)}"))
            frame.operand_stack.append(method_ref)
            
            frame.instruction_offset = self._next_offset(frame, instr)
        
        elif opname == "WITH_EXCEPT_START":
            # WITH_EXCEPT_START: Calls __exit__ with exception info
            # Stack: ..., exit, exc_type, exc_value, exc_tb
            # Calls exit(exc_type, exc_value, exc_tb)
            # Result indicates whether exception was handled
            if len(frame.operand_stack) < 4:
                state.exception = "StackUnderflow"
                return
            
            # For now, model this as calling __exit__ with havoc
            # Pop exc_tb, exc_value, exc_type
            frame.operand_stack.pop()  # exc_tb
            frame.operand_stack.pop()  # exc_value
            frame.operand_stack.pop()  # exc_type
            
            # Pop and call __exit__ (simplified)
            exit_method = frame.operand_stack.pop()
            
            # __exit__ returns True if exception is handled, False otherwise
            handled = z3.Bool(f"exit_handled_{id(exit_method)}")
            result = SymbolicValue(ValueTag.BOOL, handled)
            frame.operand_stack.append(result)
            
            frame.instruction_offset = self._next_offset(frame, instr)
        
        elif opname == "TO_BOOL":
            # TO_BOOL: Convert TOS to boolean (checks truthiness)
            if not frame.operand_stack:
                state.exception = "StackUnderflow"
                return
            
            val = frame.operand_stack.pop()
            
            # Convert to boolean using is_true helper
            # is_true returns z3.ExprRef (BoolRef), we need to wrap it in a SymbolicValue
            bool_expr = is_true(val, self.solver)
            bool_val = SymbolicValue(
                ValueTag.BOOL,
                z3.If(bool_expr, z3.IntVal(1), z3.IntVal(0))
            )
            frame.operand_stack.append(bool_val)
            
            frame.instruction_offset = self._next_offset(frame, instr)
        
        elif opname == "LOAD_BUILD_CLASS":
            # LOAD_BUILD_CLASS: Loads the __build_class__ builtin
            # This is used for class definitions
            # For symbolic execution, create a symbolic __build_class__ function
            build_class_func = SymbolicValue(ValueTag.OBJ, z3.IntVal(-4000))
            
            # Store function name for contract lookup
            if not hasattr(state, 'func_names'):
                state.func_names = {}
            state.func_names[id(build_class_func)] = "__build_class__"
            
            frame.operand_stack.append(build_class_func)
            frame.instruction_offset = self._next_offset(frame, instr)
        
        elif opname == "MAKE_FUNCTION":
            # MAKE_FUNCTION: Creates a function object from code object
            # In Python 3.14+, only code object is on stack (simplified from 3.11)
            # Stack: code_obj → function
            # Additional attributes (defaults, annotations, etc.) are set via SET_FUNCTION_ATTRIBUTE
            
            # Pop code object
            if not frame.operand_stack:
                state.exception = "StackUnderflow"
                return
            
            code_obj_val = frame.operand_stack.pop()
            
            # Create a symbolic function object
            func_id = int(code_obj_val.payload.as_long()) if hasattr(code_obj_val.payload, 'as_long') else id(code_obj_val)
            func_obj = SymbolicValue(ValueTag.OBJ, z3.Int(f"func_{func_id}"))
            
            # Track the function's code object for generator/coroutine detection
            if hasattr(state, 'code_objects') and func_id in state.code_objects:
                code = state.code_objects[func_id]
                
                # Store function metadata
                # ITERATION 486: Use stable func_id from payload, not id(func_obj)
                if not hasattr(state, 'function_metadata'):
                    state.function_metadata = {}
                state.function_metadata[func_id] = {
                    'code': code,
                    'is_generator': bool(code.co_flags & 0x20),  # CO_GENERATOR
                    'is_coroutine': bool(code.co_flags & 0x80),  # CO_COROUTINE
                }
                
                # Register as user-defined function for intra-procedural analysis
                # This allows us to analyze the function's body instead of treating it as unknown
                # ITERATION 486: Use stable func_id from payload, not id(func_obj)
                state.user_functions[func_id] = {
                    'code': code,
                    'name': code.co_name,
                    'filename': code.co_filename,
                    'is_generator': bool(code.co_flags & 0x20),
                    'is_coroutine': bool(code.co_flags & 0x80),
                }
            
            frame.operand_stack.append(func_obj)
            
            frame.instruction_offset = self._next_offset(frame, instr)
        
        elif opname == "SET_FUNCTION_ATTRIBUTE":
            # SET_FUNCTION_ATTRIBUTE: Sets an attribute on a function object
            # In Python 3.14+, this replaces the flags in MAKE_FUNCTION
            # argval: 1=defaults, 2=kwdefaults, 4=annotations, 8=closure
            # Stack: function, value → function
            if len(frame.operand_stack) < 2:
                state.exception = "StackUnderflow"
                return
            
            func = frame.operand_stack.pop()   # TOS = function
            attr = frame.operand_stack.pop()   # TOS1 = attribute value (consumed)
            frame.operand_stack.append(func)   # Push function back on stack
            
            # For symbolic execution, we don't need to track these attributes yet
            # Just consume the attr value and keep the function
            
            frame.instruction_offset = self._next_offset(frame, instr)
        
        elif opname == "RETURN_GENERATOR":
            # RETURN_GENERATOR: Converts a function into a generator/coroutine object
            # This opcode appears at the beginning of generator/coroutine functions
            # It doesn't consume or produce stack items in the caller's context
            # Instead, it marks that this frame is a generator
            state.is_generator_frame = True
            
            # Create a generator object to return to caller (if there is one)
            gen_id = id(frame.code)
            gen_obj = SymbolicValue(ValueTag.OBJ, z3.Int(f"generator_{gen_id}"))
            
            # Store generator state: snapshot of frame for later resumption
            state.generator_states[gen_id] = {
                'frame': frame.copy(),
                'suspended': True,
                'offset': self._next_offset(frame, instr)
            }
            
            # In Python 3.11+, RETURN_GENERATOR doesn't immediately return
            # It continues execution; the generator is yielded implicitly
            # We advance to next instruction
            frame.instruction_offset = self._next_offset(frame, instr)
        
        elif opname == "YIELD_VALUE":
            # YIELD_VALUE: Yields a value from generator/coroutine
            # Stack: value → (suspended, waiting for next/send)
            # argval: 0 for regular yield, 1 for yield in await context
            if not frame.operand_stack:
                state.exception = "StackUnderflow"
                return
            
            value = frame.operand_stack.pop()
            
            # In symbolic execution, we model YIELD_VALUE as a potential suspension point
            # For reachability analysis, we treat it as potentially returning control
            # For now, we'll continue execution (modeling send(None) resumption)
            
            # Store yielded value as a potential return value
            # (in reality, this would be returned to the caller)
            state.return_value = value
            
            # Advance past the yield
            frame.instruction_offset = self._next_offset(frame, instr)
        
        elif opname == "SEND":
            # SEND: Sends a value to generator/coroutine
            # Stack: receiver, value → receiver, result OR exception
            # argval: jump target if StopIteration (end of generator)
            if len(frame.operand_stack) < 2:
                state.exception = "StackUnderflow"
                return
            
            value = frame.operand_stack.pop()  # Value to send
            receiver = frame.operand_stack[-1]  # Keep receiver on stack
            
            # In symbolic execution, we model SEND as having two outcomes:
            # 1. Generator yields a value (normal case)
            # 2. Generator raises StopIteration (end case)
            
            # For bounded analysis, we'll model the normal case (generator yields)
            # Push a symbolic result representing what the generator might yield
            result = SymbolicValue(ValueTag.OBJ, z3.Int(f"send_result_{instr.offset}"))
            frame.operand_stack.append(result)
            
            # Note: We're not modeling the StopIteration branch yet
            # That would require branching the path with jump to instr.argval
            
            frame.instruction_offset = self._next_offset(frame, instr)
        
        elif opname == "END_SEND":
            # END_SEND: Finalizes a SEND operation
            # Stack: receiver, result → result
            # Pops the receiver, leaves the result
            if len(frame.operand_stack) < 2:
                state.exception = "StackUnderflow"
                return
            
            result = frame.operand_stack.pop()
            receiver = frame.operand_stack.pop()
            frame.operand_stack.append(result)
            
            frame.instruction_offset = self._next_offset(frame, instr)
        
        elif opname == "GET_AWAITABLE":
            # GET_AWAITABLE: Converts a value to an awaitable
            # Stack: value → awaitable
            # argval: flags (0 for normal await, 1 for async with/for context)
            if not frame.operand_stack:
                state.exception = "StackUnderflow"
                return
            
            value = frame.operand_stack.pop()
            
            # In Python, GET_AWAITABLE calls __await__ if present
            # For symbolic execution, we model the awaitable as an opaque object
            # that can be sent to
            awaitable = SymbolicValue(ValueTag.OBJ, z3.Int(f"awaitable_{instr.offset}"))
            frame.operand_stack.append(awaitable)
            
            frame.instruction_offset = self._next_offset(frame, instr)
        
        elif opname == "GET_AITER":
            # GET_AITER: Gets async iterator from async iterable
            # Stack: iterable → aiterator
            if not frame.operand_stack:
                state.exception = "StackUnderflow"
                return
            
            iterable = frame.operand_stack.pop()
            
            # Call __aiter__ method
            # For symbolic execution, create a symbolic async iterator
            aiter_id = z3.Int(f"aiter_{instr.offset}")
            aiter = SymbolicValue(ValueTag.OBJ, aiter_id)
            frame.operand_stack.append(aiter)
            
            # Track async iterator (similar to regular iterators)
            if hasattr(iterable, 'payload'):
                state.active_iterators.append(('async', id(iterable.payload), id(aiter_id)))
            
            frame.instruction_offset = self._next_offset(frame, instr)
        
        elif opname == "GET_ANEXT":
            # GET_ANEXT: Gets next item from async iterator
            # Stack: aiterator → aiterator, awaitable
            if not frame.operand_stack:
                state.exception = "StackUnderflow"
                return
            
            aiterator = frame.operand_stack[-1]  # Keep on stack
            
            # Call __anext__ which returns an awaitable
            # Model as symbolic awaitable that will eventually produce a value
            awaitable = SymbolicValue(ValueTag.OBJ, z3.Int(f"anext_awaitable_{instr.offset}"))
            frame.operand_stack.append(awaitable)
            
            frame.instruction_offset = self._next_offset(frame, instr)
        
        elif opname == "END_ASYNC_FOR":
            # END_ASYNC_FOR: Handles end of async for loop
            # Similar to END_FOR but for async iteration
            # Stack: aiterator, value → (empty)
            if len(frame.operand_stack) < 2:
                state.exception = "StackUnderflow"
                return
            
            frame.operand_stack.pop()  # value
            frame.operand_stack.pop()  # aiterator
            
            frame.instruction_offset = self._next_offset(frame, instr)
        
        elif opname == "CLEANUP_THROW":
            # CLEANUP_THROW: Exception handling for async/generator throw operations
            # Used in exception handlers for async for/with and yield from
            # Stack effects vary by context but typically:
            # Stack: exc_info, yield_result → resumed_value
            # In Python 3.14+, this is used in cleanup paths after async operations fail
            # For symbolic execution, we model this as a no-op that preserves the top value
            if len(frame.operand_stack) < 1:
                state.exception = "StackUnderflow"
                return
            
            # Keep the current value on stack (no change needed for taint tracking)
            frame.instruction_offset = self._next_offset(frame, instr)
        
        elif opname == "GET_YIELD_FROM_ITER":
            # GET_YIELD_FROM_ITER: Prepares iterator for yield from
            # Stack: iterable → iterator
            if not frame.operand_stack:
                state.exception = "StackUnderflow"
                return
            
            iterable = frame.operand_stack.pop()
            
            # If it's already an iterator (generator), use it as-is
            # Otherwise, call __iter__
            # For symbolic execution, treat as creating an iterator
            iterator = SymbolicValue(ValueTag.OBJ, z3.Int(f"yield_from_iter_{instr.offset}"))
            frame.operand_stack.append(iterator)
            
            frame.instruction_offset = self._next_offset(frame, instr)
        
        elif opname == "IMPORT_FROM":
            # IMPORT_FROM(namei): Loads attribute co_names[namei] from the module at TOS
            # Stack: module → module, attr
            # Unlike LOAD_ATTR, this doesn't pop the module (to support multiple imports)
            attr_name = instr.argval
            
            if not frame.operand_stack:
                state.exception = "StackUnderflow"
                return
            
            # Peek at TOS (don't pop - module stays for potential next IMPORT_FROM)
            module_obj = frame.operand_stack[-1]
            
            # For module objects, resolve qualified function/class names
            if module_obj.tag == ValueTag.OBJ and hasattr(state, 'module_names'):
                # Extract module ID from payload
                if isinstance(module_obj.payload, z3.IntNumRef):
                    module_id = module_obj.payload.as_long()
                    if module_id in state.module_names:
                        module_name = state.module_names[module_id]
                        
                        # NOTE: We do NOT raise ImportError for unknown exports from known modules.
                        # Our stdlib stubs are incomplete, so we conservatively allow any import.
                        # This is sound: we over-approximate by assuming the import succeeds.
                        # The alternative (raising ImportError) would cause false positives.
                        
                        # ITERATION 575 FIX: Handle nested module imports correctly
                        # For "import xml.etree.ElementTree as ET", the bytecode does:
                        #   IMPORT_NAME 'xml.etree.ElementTree'  -> module_name = "xml.etree.ElementTree"
                        #   IMPORT_FROM 'etree'                   -> should get "xml.etree", not "xml.etree.ElementTree.etree"
                        #   IMPORT_FROM 'ElementTree'             -> should get "xml.etree.ElementTree", not "xml.etree.etree.ElementTree"
                        # When attr_name is part of module_name path, extract the correct submodule path.
                        parts = module_name.split('.')
                        if attr_name in parts:
                            # Extract the path up to and including attr_name
                            idx = parts.index(attr_name)
                            qualified_name = '.'.join(parts[:idx+1])
                        else:
                            # Regular attribute/submodule access
                            qualified_name = f"{module_name}.{attr_name}"
                        
                        # Create a symbolic reference for the imported name
                        # ITERATION 575 FIX: Use consistent ID scheme for submodules
                        import_ref_id = -3000 - hash(qualified_name) % 10000
                        import_ref = SymbolicValue(ValueTag.OBJ, z3.IntVal(import_ref_id))
                        
                        # ITERATION 575 FIX: Register submodule in module_names so LOAD_ATTR can resolve it
                        # This fixes XXE detection for "import xml.etree.ElementTree as ET; ET.fromstring()"
                        # Without this, ET.fromstring doesn't resolve to xml.etree.ElementTree.fromstring
                        state.module_names[import_ref_id] = qualified_name
                        
                        # Store qualified name for contract lookup
                        if not hasattr(state, 'func_names'):
                            state.func_names = {}
                        state.func_names[id(import_ref)] = qualified_name
                        
                        frame.operand_stack.append(import_ref)
                        frame.instruction_offset = self._next_offset(frame, instr)
                        return
            
            # Fallback: for non-module objects or untracked modules, havoc (over-approximate)
            # This is sound but imprecise
            attr_val = SymbolicValue(ValueTag.OBJ, z3.Int(f"import_from_{id(module_obj)}_{attr_name}"))
            frame.operand_stack.append(attr_val)
            frame.instruction_offset = self._next_offset(frame, instr)
        
        elif opname == "BUILD_LIST":
            # BUILD_LIST: Creates a list from N items on the stack
            # Stack: item1, item2, ..., itemN → list
            # argval: N (number of items to pop)
            count = instr.argval
            
            if len(frame.operand_stack) < count:
                state.exception = "StackUnderflow"
                return
            
            # Pop N items from stack (in reverse order - first item pushed is at bottom)
            items = []
            for _ in range(count):
                items.insert(0, frame.operand_stack.pop())
            
            # Allocate list in heap with proper SymbolicValue.list() tag
            length = z3.IntVal(count)
            elements = {i: items[i] for i in range(len(items))}
            obj_id = state.heap.allocate_sequence("list", length, elements)
            list_obj = SymbolicValue.list(obj_id)
            
            frame.operand_stack.append(list_obj)
            frame.instruction_offset = self._next_offset(frame, instr)
        
        elif opname == "LIST_EXTEND":
            # LIST_EXTEND: Extends a list with items from an iterable
            # Stack: list, iterable → list
            # argval: 1 (usually - indicates position below TOS)
            # This is used by compiler optimizations for list literals
            if len(frame.operand_stack) < 2:
                state.exception = "StackUnderflow"
                return
            
            iterable = frame.operand_stack.pop()
            list_obj = frame.operand_stack[-1]  # Keep list on stack
            
            # Handle case where iterable is a tuple (common for literals)
            if not hasattr(state.heap, 'list_metadata'):
                state.heap.list_metadata = {}
            
            list_id = id(list_obj)
            if list_id not in state.heap.list_metadata:
                # Initialize if not already tracked
                state.heap.list_metadata[list_id] = {'items': [], 'length': 0}
            
            # If iterable is a known tuple/list in heap, extend with its items
            if hasattr(state.heap, 'tuples') and id(iterable) in state.heap.tuples:
                tuple_items = state.heap.tuples[id(iterable)]
                state.heap.list_metadata[list_id]['items'].extend(tuple_items)
                state.heap.list_metadata[list_id]['length'] += len(tuple_items)
            elif id(iterable) in state.heap.list_metadata:
                # Extending with another list
                other_items = state.heap.list_metadata[id(iterable)]['items']
                state.heap.list_metadata[list_id]['items'].extend(other_items)
                state.heap.list_metadata[list_id]['length'] += len(other_items)
            else:
                # Unknown iterable - conservatively assume it adds symbolic items
                # We don't know the exact items but track that list was extended
                state.heap.list_metadata[list_id]['length'] = z3.Int(f"list_len_after_extend_{instr.offset}")
            
            frame.instruction_offset = self._next_offset(frame, instr)
        
        elif opname == "LIST_APPEND":
            # LIST_APPEND: Appends TOS to the list at stack position -argval (after pop)
            # Stack: ..., list, ..., item → ..., list, ...
            # argval: position of the list after popping item (e.g., 2 means stack[-2])
            # Used primarily in list comprehensions
            i = instr.argval
            if len(frame.operand_stack) < i:
                state.exception = "StackUnderflow"
                return
            
            item = frame.operand_stack.pop()
            list_obj = frame.operand_stack[-i]  # -i position after popping
            
            # Ensure heap tracking exists
            if not hasattr(state.heap, 'list_metadata'):
                state.heap.list_metadata = {}
            
            list_id = id(list_obj)
            if list_id not in state.heap.list_metadata:
                # Initialize list metadata if not tracked yet
                state.heap.list_metadata[list_id] = {'items': [], 'length': 0}
            
            # Append the item
            state.heap.list_metadata[list_id]['items'].append(item)
            if isinstance(state.heap.list_metadata[list_id]['length'], int):
                state.heap.list_metadata[list_id]['length'] += 1
            else:
                # If length is symbolic, create new symbolic length
                state.heap.list_metadata[list_id]['length'] = z3.Int(f"list_len_after_append_{instr.offset}")
            
            frame.instruction_offset = self._next_offset(frame, instr)
        
        elif opname == "MAP_ADD":
            # MAP_ADD: Adds a key-value pair to the dict at stack position -argval (after pop)
            # Stack: ..., dict, ..., key, value → ..., dict, ...
            # argval: position of the dict after popping key and value (e.g., 2 means stack[-2])
            # Used primarily in dict comprehensions
            i = instr.argval
            if len(frame.operand_stack) < i:
                state.exception = "StackUnderflow"
                return
            
            value = frame.operand_stack.pop()
            key = frame.operand_stack.pop()
            dict_obj = frame.operand_stack[-i]  # -i position after popping
            
            # Ensure heap tracking exists
            if not hasattr(state.heap, 'dict_metadata'):
                state.heap.dict_metadata = {}
            
            dict_id = id(dict_obj)
            if dict_id not in state.heap.dict_metadata:
                # Initialize dict metadata if not tracked yet
                state.heap.dict_metadata[dict_id] = {'pairs': [], 'length': 0}
            
            # Add the key-value pair
            state.heap.dict_metadata[dict_id]['pairs'].append((key, value))
            if isinstance(state.heap.dict_metadata[dict_id]['length'], int):
                state.heap.dict_metadata[dict_id]['length'] += 1
            else:
                # If length is symbolic, create new symbolic length
                state.heap.dict_metadata[dict_id]['length'] = z3.Int(f"dict_len_after_add_{instr.offset}")
            
            frame.instruction_offset = self._next_offset(frame, instr)
        
        elif opname == "SET_ADD":
            # SET_ADD: Adds TOS to the set at stack position -argval (after pop)
            # Stack: ..., set, ..., item → ..., set, ...
            # argval: position of the set after popping item (e.g., 2 means stack[-2])
            # Used primarily in set comprehensions
            i = instr.argval
            if len(frame.operand_stack) < i:
                state.exception = "StackUnderflow"
                return
            
            item = frame.operand_stack.pop()
            set_obj = frame.operand_stack[-i]  # -i position after popping
            
            # Ensure heap tracking exists
            if not hasattr(state.heap, 'set_metadata'):
                state.heap.set_metadata = {}
            
            set_id = id(set_obj)
            if set_id not in state.heap.set_metadata:
                # Initialize set metadata if not tracked yet
                state.heap.set_metadata[set_id] = {'items': [], 'length': 0}
            
            # Add the item (sets don't have duplicates, but we track symbolically)
            # In true set semantics, we'd check for membership first, but for
            # bounded symbolic execution we just track that the item was added
            state.heap.set_metadata[set_id]['items'].append(item)
            if isinstance(state.heap.set_metadata[set_id]['length'], int):
                state.heap.set_metadata[set_id]['length'] += 1
            else:
                # If length is symbolic, create new symbolic length
                state.heap.set_metadata[set_id]['length'] = z3.Int(f"set_len_after_add_{instr.offset}")
            
            frame.instruction_offset = self._next_offset(frame, instr)
        
        elif opname == "SET_UPDATE":
            # SET_UPDATE(i): Calls set.update(TOS1[-i], TOS). Used to build sets.
            # Stack: ..., set, iterable → ..., set
            # argval: position of the set after popping iterable (e.g., 1 means stack[-1])
            # Pops TOS (iterable) and updates set at stack[-argval] with elements from iterable
            i = instr.argval
            if len(frame.operand_stack) < i:
                state.exception = "StackUnderflow"
                return
            
            iterable = frame.operand_stack.pop()
            set_obj = frame.operand_stack[-i]  # -i position after popping iterable
            
            # Ensure heap tracking exists
            if not hasattr(state.heap, 'set_metadata'):
                state.heap.set_metadata = {}
            
            set_id = id(set_obj)
            if set_id not in state.heap.set_metadata:
                # Initialize set metadata if not tracked yet
                state.heap.set_metadata[set_id] = {'items': [], 'length': 0}
            
            # For symbolic execution, we need to iterate over the iterable
            # and add each element to the set. For frozenset/tuple constants,
            # we can extract elements if they're concrete.
            
            # Check if iterable is a tuple (frozenset is loaded as tuple in LOAD_CONST)
            if iterable.tag == ValueTag.TUPLE:
                # Get tuple elements from heap
                tuple_id = iterable.payload
                if hasattr(state.heap, 'sequences') and tuple_id in state.heap.sequences:
                    seq_data = state.heap.sequences[tuple_id]
                    elements = seq_data.get('elements', {})
                    # Add all elements from the tuple to the set
                    for idx in sorted(elements.keys()):
                        elem = elements[idx]
                        state.heap.set_metadata[set_id]['items'].append(elem)
                    # Update length
                    if isinstance(state.heap.set_metadata[set_id]['length'], int):
                        state.heap.set_metadata[set_id]['length'] += len(elements)
                    else:
                        state.heap.set_metadata[set_id]['length'] = z3.Int(f"set_len_after_update_{instr.offset}")
                else:
                    # Symbolic tuple - havoc set (over-approximate)
                    state.heap.set_metadata[set_id]['items'] = []
                    state.heap.set_metadata[set_id]['length'] = z3.Int(f"set_len_symbolic_{instr.offset}")
            else:
                # Other iterable types - havoc set (over-approximate)
                state.heap.set_metadata[set_id]['items'] = []
                state.heap.set_metadata[set_id]['length'] = z3.Int(f"set_len_unknown_{instr.offset}")
            
            frame.instruction_offset = self._next_offset(frame, instr)
        
        elif opname == "SETUP_ANNOTATIONS":
            # SETUP_ANNOTATIONS: Creates the __annotations__ dict if it doesn't exist
            # Used for type annotations at module and class scope
            # Stack: unchanged (no stack effect)
            # Checks if __annotations__ is in locals; if not, creates an empty dict
            
            # In symbolic execution, we model this as creating a symbolic dict object
            # if __annotations__ is not already present in locals
            if '__annotations__' not in frame.locals:
                # Create an empty dict for annotations
                # IMPORTANT: Use ValueTag.DICT so STORE_SUBSCR recognizes it as a valid container
                annotations_dict_id = z3.Int(f"annotations_{instr.offset}_{id(frame)}")
                annotations_dict = SymbolicValue(ValueTag.DICT, annotations_dict_id)
                
                # Initialize empty dict metadata in heap
                if not hasattr(state.heap, 'dict_metadata'):
                    state.heap.dict_metadata = {}
                state.heap.dict_metadata[id(annotations_dict)] = {
                    'pairs': [],
                    'length': 0
                }
                
                # Also track in heap.dicts for consistency with BUILD_MAP
                obj_id_val = annotations_dict_id
                try:
                    # Try to get a concrete id for the dict
                    self.solver.push()
                    if self.solver.check() == z3.sat:
                        model = self.solver.model()
                        obj_id_eval = model.eval(annotations_dict_id, model_completion=True)
                        if z3.is_int_value(obj_id_eval):
                            concrete_id = obj_id_eval.as_long()
                            state.heap.dicts[concrete_id] = {}
                    self.solver.pop()
                except:
                    pass
                
                # Store in locals
                frame.locals['__annotations__'] = annotations_dict
            
            # No stack changes, just advance to next instruction
            frame.instruction_offset = self._next_offset(frame, instr)
        
        elif opname == "BUILD_MAP":
            # BUILD_MAP: Creates a dict from key-value pairs on the stack
            # Stack: key1, value1, key2, value2, ..., keyN, valueN → dict
            # argval: N (number of key-value pairs to pop)
            count = instr.argval
            
            if len(frame.operand_stack) < count * 2:
                state.exception = "StackUnderflow"
                return
            
            # Pop N key-value pairs from stack
            # Keys and values are pushed in order: key1, value1, key2, value2, ...
            pairs = []
            for _ in range(count):
                value = frame.operand_stack.pop()
                key = frame.operand_stack.pop()
                pairs.append((key, value))
            
            # Reverse to get insertion order (first pair is at bottom of stack)
            pairs.reverse()
            
            # Create a dict in the heap with the key-value pairs
            # For concrete string keys, store in the DictObject
            keys_set = set()
            values_dict = {}
            
            for key_val, val in pairs:
                # If key is a concrete string, store it
                if key_val.tag == ValueTag.STR and isinstance(key_val.payload, z3.IntNumRef):
                    key_str_id = key_val.payload.as_long()
                    key_str = state.heap.get_string(key_str_id)
                    if key_str:
                        keys_set.add(key_str)
                        values_dict[key_str] = val
            
            # Allocate dict in heap
            dict_id = state.heap.allocate_dict(keys=keys_set, values=values_dict)
            dict_obj = SymbolicValue(ValueTag.DICT, z3.IntVal(dict_id))
            
            # Also store in dict_metadata for backward compatibility
            if not hasattr(state.heap, 'dict_metadata'):
                state.heap.dict_metadata = {}
            state.heap.dict_metadata[dict_id] = {
                'pairs': pairs,
                'length': count
            }
            
            frame.operand_stack.append(dict_obj)
            frame.instruction_offset = self._next_offset(frame, instr)
        
        elif opname == "DICT_UPDATE":
            # DICT_UPDATE: Updates the dict at TOS1 with the dict at TOS
            # Stack: ..., dict_target, dict_source → ..., dict_target
            # argval: typically 1 (function argument position for **kwargs)
            # Used for dict unpacking: {**d1, **d2} or func(**kwargs)
            
            if len(frame.operand_stack) < 2:
                state.exception = "StackUnderflow"
                return
            
            # Pop source dict from TOS
            source = frame.operand_stack.pop()
            
            # Target dict is at TOS (after pop)
            target = frame.operand_stack[-1]
            
            # Check if source is None (NULL_PTR)
            if hasattr(source, 'tag'):
                is_none = (source.tag == z3.IntVal(ValueTag.NONE.value))
                if self.solver:
                    self.solver.push()
                    self.solver.add(state.path_condition)
                    self.solver.add(is_none)
                    if self.solver.check() == z3.sat:
                        state.null_ptr_reached = True
                    self.solver.pop()
                
                # Check if source is not an object (TYPE_CONFUSION)
                # dict should have OBJ tag
                is_obj = (source.tag == z3.IntVal(ValueTag.OBJ.value))
                if self.solver:
                    self.solver.push()
                    self.solver.add(state.path_condition)
                    self.solver.add(z3.Not(is_obj))
                    if self.solver.check() == z3.sat:
                        # Path where source is not an object
                        state.type_confusion_reached = True
                    self.solver.pop()
                
                # On paths where source is invalid, set exception
                # (Conservative: if either None or non-OBJ is possible, we detect it above)
                # Here we continue on the "success" path
            
            # Ensure heap tracking exists
            if not hasattr(state.heap, 'dict_metadata'):
                state.heap.dict_metadata = {}
            
            target_id = id(target)
            source_id = id(source)
            
            # Initialize target metadata if not tracked
            if target_id not in state.heap.dict_metadata:
                state.heap.dict_metadata[target_id] = {'pairs': [], 'length': 0}
            
            # Get source metadata (if available; if unknown, havoc)
            if source_id in state.heap.dict_metadata:
                source_pairs = state.heap.dict_metadata[source_id]['pairs']
                source_len = state.heap.dict_metadata[source_id]['length']
                
                # Merge source into target (dict.update semantics: source overwrites target)
                # Note: In symbolic execution, we overapproximate by adding all pairs
                # (we don't track which keys are identical)
                state.heap.dict_metadata[target_id]['pairs'].extend(source_pairs)
                
                # Update length: conservative overapprox (sum of lengths)
                # In reality, duplicates reduce length, but we don't track that
                old_len = state.heap.dict_metadata[target_id]['length']
                if isinstance(old_len, int) and isinstance(source_len, int):
                    state.heap.dict_metadata[target_id]['length'] = old_len + source_len
                else:
                    # Symbolic length: create new symbolic variable
                    new_len = z3.Int(f"dict_len_after_update_{instr.offset}")
                    # Conservative constraint: new length is at most sum of both
                    if isinstance(old_len, int):
                        old_len_z3 = z3.IntVal(old_len)
                    else:
                        old_len_z3 = old_len
                    if isinstance(source_len, int):
                        source_len_z3 = z3.IntVal(source_len)
                    else:
                        source_len_z3 = source_len
                    state.path_condition = z3.And(state.path_condition, new_len <= old_len_z3 + source_len_z3)
                    state.path_condition = z3.And(state.path_condition, new_len >= z3.If(old_len_z3 > source_len_z3, old_len_z3, source_len_z3))
                    state.heap.dict_metadata[target_id]['length'] = new_len
            else:
                # Source dict is unknown (e.g., from a call): havoc target
                # Conservative: assume target may have been updated with arbitrary content
                # We keep existing pairs but mark length as symbolic/unknown
                new_len = z3.Int(f"dict_len_after_unknown_update_{instr.offset}")
                # Constraint: length is at least the current length (we only add, never remove)
                old_len = state.heap.dict_metadata[target_id]['length']
                if isinstance(old_len, int):
                    state.path_condition = z3.And(state.path_condition, new_len >= old_len)
                else:
                    state.path_condition = z3.And(state.path_condition, new_len >= old_len)
                state.heap.dict_metadata[target_id]['length'] = new_len
            
            # Target dict remains on stack (TOS after source pop)
            frame.instruction_offset = self._next_offset(frame, instr)
        
        elif opname == "DICT_MERGE":
            # DICT_MERGE: Merges a dict into another dict (for **kwargs in function calls)
            # Stack: ..., target_dict, source_dict → ..., target_dict
            # argval: function argument position (1 for first **kwargs)
            # Semantics: target.update(source), raises TypeError if source is not a dict
            # Used in CALL_FUNCTION_EX with **kwargs: func(**d1, **d2)
            
            if len(frame.operand_stack) < 2:
                state.exception = "StackUnderflow"
                return
            
            # Pop source dict from TOS
            source = frame.operand_stack.pop()
            
            # Target dict is at TOS (after pop)
            target = frame.operand_stack[-1]
            
            # Check if source is None (NULL_PTR - would raise TypeError)
            if hasattr(source, 'tag'):
                is_none = (source.tag == z3.IntVal(ValueTag.NONE.value))
                if self.solver:
                    self.solver.push()
                    self.solver.add(state.path_condition)
                    self.solver.add(is_none)
                    if self.solver.check() == z3.sat:
                        state.null_ptr_reached = True
                    self.solver.pop()
                
                # Check if source is not a dict-like object (TYPE_CONFUSION)
                # DICT_MERGE requires dict or mapping protocol
                is_dict_like = z3.Or(
                    source.tag == z3.IntVal(ValueTag.DICT.value),
                    source.tag == z3.IntVal(ValueTag.OBJ.value)  # Could be mapping
                )
                if self.solver:
                    self.solver.push()
                    self.solver.add(state.path_condition)
                    self.solver.add(z3.Not(is_dict_like))
                    if self.solver.check() == z3.sat:
                        # Path where source is not dict-like - TypeError
                        state.type_confusion_reached = True
                    self.solver.pop()
            
            # Ensure heap tracking exists
            if not hasattr(state.heap, 'dict_metadata'):
                state.heap.dict_metadata = {}
            
            target_id = id(target)
            source_id = id(source)
            
            # Initialize target metadata if not tracked
            if target_id not in state.heap.dict_metadata:
                state.heap.dict_metadata[target_id] = {'pairs': [], 'length': 0}
            
            # Get source metadata (if available; if unknown, havoc)
            if source_id in state.heap.dict_metadata:
                source_pairs = state.heap.dict_metadata[source_id]['pairs']
                source_len = state.heap.dict_metadata[source_id]['length']
                
                # Merge source into target (same semantics as DICT_UPDATE)
                state.heap.dict_metadata[target_id]['pairs'].extend(source_pairs)
                
                # Update length: conservative overapprox
                old_len = state.heap.dict_metadata[target_id]['length']
                if isinstance(old_len, int) and isinstance(source_len, int):
                    state.heap.dict_metadata[target_id]['length'] = old_len + source_len
                else:
                    # Symbolic length
                    new_len = z3.Int(f"dict_len_after_merge_{instr.offset}")
                    if isinstance(old_len, int):
                        old_len_z3 = z3.IntVal(old_len)
                    else:
                        old_len_z3 = old_len
                    if isinstance(source_len, int):
                        source_len_z3 = z3.IntVal(source_len)
                    else:
                        source_len_z3 = source_len
                    state.path_condition = z3.And(state.path_condition, new_len <= old_len_z3 + source_len_z3)
                    state.path_condition = z3.And(state.path_condition, new_len >= z3.If(old_len_z3 > source_len_z3, old_len_z3, source_len_z3))
                    state.heap.dict_metadata[target_id]['length'] = new_len
            else:
                # Source dict is unknown: havoc target
                new_len = z3.Int(f"dict_len_after_unknown_merge_{instr.offset}")
                old_len = state.heap.dict_metadata[target_id]['length']
                if isinstance(old_len, int):
                    state.path_condition = z3.And(state.path_condition, new_len >= old_len)
                else:
                    state.path_condition = z3.And(state.path_condition, new_len >= old_len)
                state.heap.dict_metadata[target_id]['length'] = new_len
            
            # Target dict remains on stack (TOS after source pop)
            frame.instruction_offset = self._next_offset(frame, instr)
        
        elif opname == "BUILD_SET":
            # BUILD_SET: Creates a set from N items on the stack
            # Stack: item1, item2, ..., itemN → set
            # argval: N (number of items to pop)
            count = instr.argval
            
            if len(frame.operand_stack) < count:
                state.exception = "StackUnderflow"
                return
            
            # Pop N items from stack (in reverse order - first item pushed is at bottom)
            items = []
            for _ in range(count):
                items.insert(0, frame.operand_stack.pop())
            
            # Create a symbolic set object
            set_id = z3.Int(f"set_{instr.offset}_{id(frame)}")
            set_obj = SymbolicValue(ValueTag.OBJ, set_id)
            
            # Store set contents in heap metadata (for BOUNDS checking and membership)
            if not hasattr(state.heap, 'set_metadata'):
                state.heap.set_metadata = {}
            
            state.heap.set_metadata[id(set_obj)] = {
                'items': items,
                'length': count
            }
            
            frame.operand_stack.append(set_obj)
            frame.instruction_offset = self._next_offset(frame, instr)
        
        elif opname == "BUILD_TUPLE":
            # BUILD_TUPLE: Creates a tuple from N items on the stack
            # Stack: item1, item2, ..., itemN → tuple
            # argval: N (number of items to pop)
            count = instr.argval
            
            if len(frame.operand_stack) < count:
                state.exception = "StackUnderflow"
                return
            
            # Pop N items from stack (in reverse order - first item pushed is at bottom)
            items = []
            for _ in range(count):
                items.insert(0, frame.operand_stack.pop())
            
            # Allocate tuple in heap with proper SymbolicValue.tuple() tag
            length = z3.IntVal(count)
            elements = {i: items[i] for i in range(len(items))}
            obj_id = state.heap.allocate_sequence("tuple", length, elements)
            tuple_obj = SymbolicValue.tuple(obj_id)
            
            frame.operand_stack.append(tuple_obj)
            frame.instruction_offset = self._next_offset(frame, instr)
        
        elif opname == "FORMAT_SIMPLE":
            # FORMAT_SIMPLE: Format a value as a string (f-string formatting)
            # Stack: value → str
            # This is used in f-strings like f"{x}"
            if len(frame.operand_stack) < 1:
                state.exception = "StackUnderflow"
                return
            
            value = frame.operand_stack.pop()
            
            # Convert value to string symbolically
            # For now, create a fresh symbolic string (over-approximate)
            str_id = z3.Int(f"fmt_str_{instr.offset}_{id(frame)}")
            str_obj = SymbolicValue.str(str_id)
            
            # ITERATION 442: Propagate taint through formatting
            # When a value is formatted as a string, taint should be preserved
            if state.security_tracker:
                value_label = state.security_tracker.get_label(value)
                state.security_tracker.set_label(str_obj, value_label)
                
                value_symbolic = state.security_tracker.get_symbolic_label(value)
                state.security_tracker.set_symbolic_label(str_obj, value_symbolic)
            
            frame.operand_stack.append(str_obj)
            frame.instruction_offset = self._next_offset(frame, instr)
        
        elif opname == "BUILD_STRING":
            # BUILD_STRING: Concatenate N strings from the stack into one string
            # Stack: str1, str2, ..., strN → concatenated_str
            # argval: N (number of strings to pop and concatenate)
            # Used in f-strings after FORMAT_SIMPLE operations: f"{a}{b}{c}" becomes
            # LOAD a, FORMAT_SIMPLE, LOAD b, FORMAT_SIMPLE, LOAD c, FORMAT_SIMPLE, BUILD_STRING 3
            
            count = instr.argval
            if len(frame.operand_stack) < count:
                state.exception = "StackUnderflow"
                return
            
            # Pop N strings from the stack
            parts = []
            for _ in range(count):
                parts.append(frame.operand_stack.pop())
            parts.reverse()  # They were pushed in order, so reverse to get correct concatenation order
            
            # Check for NULL_PTR (None in string concatenation)
            for i, part in enumerate(parts):
                if part.tag == ValueTag.NONE:
                    # None cannot be concatenated as a string (would raise TypeError in CPython)
                    # This is a NULL_PTR semantic bug
                    state.exception = "TypeError"
                    # Add to path condition that we reached this error
                    state.path_condition = z3.And(state.path_condition, z3.BoolVal(True))
                    return
                
                # Check for TYPE_CONFUSION: non-string types
                if part.tag not in (ValueTag.STR, ValueTag.OBJ):
                    # If we have a concrete type that's not a string, this is TYPE_CONFUSION
                    # (BUILD_STRING expects strings; FORMAT_SIMPLE should produce strings)
                    state.exception = "TypeError"
                    state.path_condition = z3.And(state.path_condition, z3.BoolVal(True))
                    return
            
            # Symbolically: create a fresh string representing the concatenation
            # We conservatively over-approximate by creating a new symbolic string
            # (We don't track precise string contents in Z3 for scalability)
            result_str_id = z3.Int(f"build_string_{instr.offset}_{id(frame)}")
            result_str = SymbolicValue.str(result_str_id)
            
            # ITERATION 442: Propagate taint from all parts to result
            # String concatenation should preserve taint (if any part is tainted, result is tainted)
            if state.security_tracker:
                # Merge taints from all parts
                part_labels = [state.security_tracker.get_label(part) for part in parts]
                from ..z3model.taint_lattice import label_join_many
                merged_label = label_join_many(part_labels)
                state.security_tracker.set_label(result_str, merged_label)
                
                # Also propagate symbolic labels
                part_symbolic = [state.security_tracker.get_symbolic_label(part) for part in parts]
                from ..z3model.taint_lattice import symbolic_label_join_many
                merged_symbolic = symbolic_label_join_many(part_symbolic)
                state.security_tracker.set_symbolic_label(result_str, merged_symbolic)
            
            frame.operand_stack.append(result_str)
            frame.instruction_offset = self._next_offset(frame, instr)
        
        elif opname == "CALL_INTRINSIC_1":
            # CALL_INTRINSIC_1: Execute Python internal operations
            # Stack: arg → result (or side effect with no result for some intrinsics)
            # Intrinsic ID is stored in instr.arg (the argval)
            # Common intrinsics:
            #   2 = INTRINSIC_IMPORT_STAR (from module import *)
            #   3 = INTRINSIC_STOPITERATION_ERROR (converts StopIteration to RuntimeError)
            #   4 = INTRINSIC_ASYNC_GEN_WRAP
            #   5 = INTRINSIC_UNARY_POSITIVE (+x)
            #   6 = INTRINSIC_LIST_TO_TUPLE
            if len(frame.operand_stack) < 1:
                state.exception = "StackUnderflow"
                return
            
            intrinsic_id = instr.arg
            arg = frame.operand_stack.pop()
            
            # Semantically model the most common intrinsics
            if intrinsic_id == 2:  # INTRINSIC_IMPORT_STAR
                # Star import: from module import *
                # Stack: module → (nothing, no result pushed)
                # Semantic: populates the current namespace (globals) with all module exports
                # For symbolic execution, we model this as a havoc of globals with module attributes
                
                # Extract module info if available
                module_id = None
                if hasattr(arg, 'payload'):
                    # The payload contains the module ID (either int or Z3 expr)
                    payload = arg.payload
                    if isinstance(payload, int):
                        module_id = payload
                    elif z3.is_int_value(payload):
                        module_id = payload.as_long()
                
                # If we have module exports metadata, populate them into globals
                # This is sound because we're adding names to the namespace (over-approximation)
                if module_id is not None and hasattr(state, 'module_exports') and module_id in state.module_exports:
                    exports = state.module_exports[module_id]
                    # For each exported name, add it to globals as a symbolic object
                    # This models "all module attributes are now available"
                    for export_name in exports:
                        # Create a symbolic value for each export
                        # We model this as accessing the attribute from the module
                        export_id = z3.Int(f"star_import_{module_id}_{export_name}_{instr.offset}")
                        export_obj = SymbolicValue(ValueTag.OBJ, export_id)
                        frame.globals[export_name] = export_obj
                
                # Star import doesn't push a result (it mutates the namespace)
                frame.instruction_offset = self._next_offset(frame, instr)
            elif intrinsic_id == 3:  # INTRINSIC_STOPITERATION_ERROR
                # This converts a StopIteration to RuntimeError in async contexts
                # Semantics: raises RuntimeError wrapping the StopIteration
                # For symbolic execution, we model this as raising an exception
                state.exception = "RuntimeError"
                return
            elif intrinsic_id == 5:  # INTRINSIC_UNARY_POSITIVE
                # Unary positive (+x): like -x but returns positive
                # Semantic: int/float/bool→int, TypeError on None/others
                result, type_ok, none_misuse = unary_op_positive(arg, self.solver)
                
                # Check for None misuse
                self.solver.push()
                self.solver.add(state.path_condition)
                self.solver.add(none_misuse)
                if self.solver.check() == z3.sat:
                    state.none_misuse_reached = True
                    state.exception = "TypeError"
                self.solver.pop()
                
                # Check for type confusion
                if not state.exception:
                    self.solver.push()
                    self.solver.add(state.path_condition)
                    self.solver.add(z3.Not(type_ok))
                    self.solver.add(z3.Not(none_misuse))
                    if self.solver.check() == z3.sat:
                        state.type_confusion_reached = True
                        state.exception = "TypeError"
                    self.solver.pop()
                
                if not state.exception:
                    state.path_condition = z3.And(state.path_condition, type_ok, z3.Not(none_misuse))
                    frame.operand_stack.append(result)
                
                frame.instruction_offset = self._next_offset(frame, instr)
            elif intrinsic_id == 6:  # INTRINSIC_LIST_TO_TUPLE
                # Converts list to tuple (structural operation)
                # Symbolically: create a fresh tuple object
                tuple_id = z3.Int(f"intrinsic_tuple_{instr.offset}_{id(frame)}")
                tuple_obj = SymbolicValue(ValueTag.TUPLE, tuple_id)  # ✓ Correct: TUPLE not OBJ
                frame.operand_stack.append(tuple_obj)
                frame.instruction_offset = self._next_offset(frame, instr)
            else:
                # For other intrinsics, over-approximate: create fresh symbolic value
                # This is sound but may lose precision
                result_id = z3.Int(f"intrinsic_{intrinsic_id}_{instr.offset}_{id(frame)}")
                result = SymbolicValue(ValueTag.OBJ, result_id)
                frame.operand_stack.append(result)
                frame.instruction_offset = self._next_offset(frame, instr)
        
        # ================================================================
        # Python 3.11-specific opcodes
        # ================================================================

        elif opname == "FORMAT_VALUE":
            # FORMAT_VALUE(flags): Format TOS as a string (f-string formatting).
            # flags & 0x03: conversion type (0=none, 1=str, 2=repr, 3=ascii)
            # flags & 0x04: if set, TOS is format_spec, TOS1 is value
            # Stack (no fmt_spec): value → formatted_str
            # Stack (with fmt_spec): value, fmt_spec → formatted_str
            flags = instr.arg if instr.arg is not None else 0
            has_fmt_spec = (flags & 0x04) != 0

            if has_fmt_spec:
                if len(frame.operand_stack) < 2:
                    state.exception = "StackUnderflow"
                    return
                fmt_spec = frame.operand_stack.pop()
                value = frame.operand_stack.pop()
            else:
                if len(frame.operand_stack) < 1:
                    state.exception = "StackUnderflow"
                    return
                value = frame.operand_stack.pop()

            # Over-approximate: produce a fresh symbolic string
            str_id = z3.Int(f"fmtval_{instr.offset}_{id(frame)}")
            result = SymbolicValue.str(str_id)

            # Propagate taint through formatting
            if state.security_tracker:
                value_label = state.security_tracker.get_label(value)
                state.security_tracker.set_label(result, value_label)
                value_sym = state.security_tracker.get_symbolic_label(value)
                state.security_tracker.set_symbolic_label(result, value_sym)

            frame.operand_stack.append(result)
            frame.instruction_offset = self._next_offset(frame, instr)

        elif opname == "LOAD_METHOD":
            # Python 3.11 LOAD_METHOD: loads a method from TOS.
            # Stack: obj → NULL|self, method
            # In 3.12+ this was merged into LOAD_ATTR with (arg & 1).
            # Semantically identical to LOAD_ATTR with the method-call bit.
            attr_name = instr.argval

            if not frame.operand_stack:
                state.exception = "StackUnderflow"
                return

            obj = frame.operand_stack.pop()

            # --- None dereference check (NULL_PTR) ---
            if obj.tag == ValueTag.NONE:
                state.none_misuse_reached = True
                state.exception = "AttributeError"
                return

            if obj.tag == ValueTag.OBJ:
                var_name = self._get_variable_name_for_value(state, obj)
                is_proven_nonnull = False
                if var_name:
                    analysis = state.get_intraproc_analysis(frame.code)
                    if analysis and analysis.is_nonnull(instr.offset, var_name):
                        is_proven_nonnull = True
                    guard_key = f"nonnull:{var_name}"
                    if guard_key in state.established_guards:
                        is_proven_nonnull = True

                if not is_proven_nonnull:
                    self.solver.push()
                    self.solver.add(state.path_condition)
                    self.solver.add(obj.is_none())
                    could_be_none = (self.solver.check() == z3.sat)
                    self.solver.pop()
                    if could_be_none:
                        state.none_misuse_reached = True
                        state.exception = "AttributeError"
                        return

            # --- Framework mock lookup ---
            if hasattr(state, 'framework_mocks') and id(obj) in state.framework_mocks:
                mock = state.framework_mocks[id(obj)]
                if attr_name in mock.methods:
                    mock_method = mock.methods[attr_name]
                    method_val = mock_method.return_value
                    if not hasattr(state, 'mock_methods'):
                        state.mock_methods = {}
                    state.mock_methods[id(method_val)] = mock_method
                    if not hasattr(state, 'func_names'):
                        state.func_names = {}
                    obj_name = state.func_names.get(id(obj), "unknown")
                    state.func_names[id(method_val)] = f"{obj_name}.{attr_name}"
                    # Push NULL (self placeholder) then method
                    frame.operand_stack.append(obj)
                    frame.operand_stack.append(method_val)
                    frame.instruction_offset = self._next_offset(frame, instr)
                    return
                if attr_name in mock.attributes:
                    mock_attr = mock.attributes[attr_name]
                    attr_val = mock_attr.value
                    if mock_attr.taint_label and state.security_tracker:
                        state.security_tracker.set_label(attr_val, mock_attr.taint_label)
                    frame.operand_stack.append(obj)
                    frame.operand_stack.append(attr_val)
                    frame.instruction_offset = self._next_offset(frame, instr)
                    return

            # --- Module attribute lookup ---
            if obj.tag == ValueTag.OBJ and hasattr(state, 'module_names'):
                if isinstance(obj.payload, z3.IntNumRef):
                    module_id = obj.payload.as_long()
                    if module_id in state.module_names:
                        module_name = state.module_names[module_id]
                        qualified = f"{module_name}.{attr_name}"
                        method_val = SymbolicValue(ValueTag.OBJ,
                            z3.Int(f"method_{qualified}_{instr.offset}"))
                        if not hasattr(state, 'func_names'):
                            state.func_names = {}
                        state.func_names[id(method_val)] = qualified
                        # Propagate taint
                        if state.security_tracker and state.security_tracker.enabled:
                            state.security_tracker.handle_getattr(obj, attr_name, method_val)
                        # Push self, then unbound method
                        frame.operand_stack.append(obj)
                        frame.operand_stack.append(method_val)
                        frame.instruction_offset = self._next_offset(frame, instr)
                        return

            # --- General case: create fresh symbolic attribute ---
            attr_val = SymbolicValue(ValueTag.OBJ,
                z3.Int(f"attr_{attr_name}_{instr.offset}_{id(frame)}"))
            if not hasattr(state, 'func_names'):
                state.func_names = {}
            obj_name = state.func_names.get(id(obj), "")
            if obj_name:
                state.func_names[id(attr_val)] = f"{obj_name}.{attr_name}"
            else:
                state.func_names[id(attr_val)] = attr_name

            # Propagate taint from object to attribute
            if state.security_tracker:
                state.security_tracker.handle_getattr(obj, attr_name, attr_val)

            # Push self (obj) then method on the stack
            frame.operand_stack.append(obj)
            frame.operand_stack.append(attr_val)
            frame.instruction_offset = self._next_offset(frame, instr)

        elif opname == "STORE_ATTR":
            # STORE_ATTR(namei): obj.attr = value
            # Stack: value, obj → (consumed)
            attr_name = instr.argval
            if len(frame.operand_stack) < 2:
                state.exception = "StackUnderflow"
                return

            obj = frame.operand_stack.pop()   # TOS
            value = frame.operand_stack.pop()  # TOS1

            # None dereference check
            if obj.tag == ValueTag.NONE:
                state.none_misuse_reached = True
                state.exception = "AttributeError"
                return

            # Store attribute symbolically
            if not hasattr(state, 'heap_attrs'):
                state.heap_attrs = {}
            state.heap_attrs[(id(obj), attr_name)] = value

            # Propagate taint from value to object
            if state.security_tracker:
                val_label = state.security_tracker.get_label(value)
                obj_label = state.security_tracker.get_label(obj)
                from ..z3model.taint_lattice import label_join
                state.security_tracker.set_label(obj, label_join(obj_label, val_label))

            frame.instruction_offset = self._next_offset(frame, instr)

        elif opname == "DELETE_FAST":
            # DELETE_FAST(var_num): Deletes local variable co_varnames[var_num]
            var_name = instr.argval
            if var_name in frame.locals:
                del frame.locals[var_name]
            # else: would raise UnboundLocalError at runtime, but we
            # over-approximate and skip (harmless for bug finding)
            frame.instruction_offset = self._next_offset(frame, instr)

        elif opname == "DELETE_NAME":
            # DELETE_NAME(namei): Deletes name co_names[namei] from local namespace
            var_name = instr.argval
            if var_name in frame.locals:
                del frame.locals[var_name]
            frame.instruction_offset = self._next_offset(frame, instr)

        elif opname == "DELETE_SUBSCR":
            # DELETE_SUBSCR: Implements del container[index]
            # Stack: container, index → (consumed)
            if len(frame.operand_stack) < 2:
                state.exception = "StackUnderflow"
                return

            index = frame.operand_stack.pop()      # TOS
            container = frame.operand_stack.pop()   # TOS1

            # None dereference check
            if container.tag == ValueTag.NONE:
                state.none_misuse_reached = True
                state.exception = "TypeError"
                return

            # For symbolic execution we simply consume the operands.
            # The heap entry remains unchanged (sound over-approximation:
            # the deleted key *may* still appear reachable symbolically).
            frame.instruction_offset = self._next_offset(frame, instr)

        elif opname == "BUILD_CONST_KEY_MAP":
            # BUILD_CONST_KEY_MAP(count): Builds a dict from `count` values and
            # a tuple of keys on TOS.
            # Stack: val_1, val_2, ..., val_count, keys_tuple → dict
            count = instr.argval if instr.argval is not None else instr.arg
            if len(frame.operand_stack) < count + 1:
                state.exception = "StackUnderflow"
                return

            keys_tuple_val = frame.operand_stack.pop()   # TOS: tuple of key names
            values = []
            for _ in range(count):
                values.append(frame.operand_stack.pop())
            values.reverse()

            # The keys tuple is a constant from co_consts — try to recover the
            # actual Python tuple.  If it was loaded via LOAD_CONST the raw
            # Python tuple lives on the SymbolicValue payload (or we can look
            # it up from the code object constants).
            keys_set = set()
            values_dict = {}
            raw_keys = None
            if hasattr(keys_tuple_val, 'concrete_value'):
                raw_keys = keys_tuple_val.concrete_value
            elif keys_tuple_val.tag == ValueTag.TUPLE and hasattr(keys_tuple_val, '_items'):
                raw_keys = keys_tuple_val._items
            # Fallback: try looking up what LOAD_CONST pushed – the payload
            # might be the index into co_consts.

            if raw_keys and hasattr(raw_keys, '__iter__'):
                for i, key in enumerate(raw_keys):
                    if i < len(values):
                        if isinstance(key, str):
                            keys_set.add(key)
                            values_dict[key] = values[i]

            dict_id = state.heap.allocate_dict(keys=keys_set, values=values_dict)
            result = SymbolicValue(ValueTag.DICT, z3.IntVal(dict_id))

            # Propagate taint from values
            if state.security_tracker:
                for v in values:
                    v_label = state.security_tracker.get_label(v)
                    existing = state.security_tracker.get_label(result)
                    from ..z3model.taint_lattice import label_join
                    state.security_tracker.set_label(result, label_join(existing, v_label))

            frame.operand_stack.append(result)
            frame.instruction_offset = self._next_offset(frame, instr)

        elif opname == "BUILD_SLICE":
            # BUILD_SLICE(argc): Build a slice object.
            # argc == 2: Stack: start, stop → slice
            # argc == 3: Stack: start, stop, step → slice
            argc = instr.argval if instr.argval is not None else instr.arg
            if len(frame.operand_stack) < argc:
                state.exception = "StackUnderflow"
                return

            if argc == 3:
                step = frame.operand_stack.pop()
                stop = frame.operand_stack.pop()
                start = frame.operand_stack.pop()
            else:
                stop = frame.operand_stack.pop()
                start = frame.operand_stack.pop()
                step = SymbolicValue.none()

            obj_id = state.heap.allocate_slice(start, stop, step)
            result = SymbolicValue.slice_obj(obj_id)
            frame.operand_stack.append(result)
            frame.instruction_offset = self._next_offset(frame, instr)

        elif opname == "KW_NAMES":
            # KW_NAMES(consti): Python 3.11 instruction that precedes CALL.
            # Stores a tuple of keyword argument names (co_consts[consti])
            # to be used by the next CALL instruction.
            # We stash the tuple on the state for the CALL handler to consume.
            kw_names = instr.argval  # Tuple of keyword argument name strings
            if not hasattr(state, 'kw_names'):
                state.kw_names = None
            state.kw_names = kw_names
            frame.instruction_offset = self._next_offset(frame, instr)

        elif opname == "CALL_FUNCTION_EX":
            # CALL_FUNCTION_EX(flags): Call with *args and optionally **kwargs.
            # flags & 0x01: if set, TOS is **kwargs, TOS1 is *args, TOS2 is callable
            # else: TOS is *args, TOS1 is callable
            flags = instr.arg if instr.arg is not None else 0
            has_kwargs = (flags & 0x01) != 0

            if has_kwargs:
                if len(frame.operand_stack) < 3:
                    state.exception = "StackUnderflow"
                    return
                kwargs = frame.operand_stack.pop()
                args = frame.operand_stack.pop()
                callable_obj = frame.operand_stack.pop()
            else:
                if len(frame.operand_stack) < 2:
                    state.exception = "StackUnderflow"
                    return
                args = frame.operand_stack.pop()
                callable_obj = frame.operand_stack.pop()

            # Over-approximate: produce a fresh symbolic result.
            # Taint from all arguments is merged into the result.
            result = SymbolicValue(ValueTag.OBJ,
                z3.Int(f"call_ex_{instr.offset}_{id(frame)}"))

            if state.security_tracker:
                for source in ([args, callable_obj] + ([kwargs] if has_kwargs else [])):
                    src_label = state.security_tracker.get_label(source)
                    existing = state.security_tracker.get_label(result)
                    from ..z3model.taint_lattice import label_join
                    state.security_tracker.set_label(result, label_join(existing, src_label))

            frame.operand_stack.append(result)
            frame.instruction_offset = self._next_offset(frame, instr)

        elif opname == "JUMP_IF_TRUE_OR_POP":
            # JUMP_IF_TRUE_OR_POP(target): If TOS is true, jump to target
            # (leaving TOS on stack). Otherwise pop TOS and fall through.
            if not frame.operand_stack:
                state.exception = "StackUnderflow"
                return

            condition = frame.operand_stack[-1]  # peek, don't pop yet
            condition_true = is_true(condition, self.solver)

            target_offset = instr.argval
            fallthrough_offset = self._next_offset(frame, instr)

            # Check feasibility of both branches
            self.solver.push()
            self.solver.add(state.path_condition)
            self.solver.add(condition_true)
            true_feasible = self._solver_maybe_sat()
            self.solver.pop()

            self.solver.push()
            self.solver.add(state.path_condition)
            self.solver.add(z3.Not(condition_true))
            false_feasible = self._solver_maybe_sat()
            self.solver.pop()

            if true_feasible and false_feasible:
                import copy
                # True branch: keep TOS, jump
                true_state = copy.deepcopy(state)
                true_state.path_condition = z3.And(state.path_condition, condition_true)
                true_state.frame_stack[-1].instruction_offset = target_offset

                # False branch: pop TOS, fall through
                frame.operand_stack.pop()
                state.path_condition = z3.And(state.path_condition, z3.Not(condition_true))
                frame.instruction_offset = fallthrough_offset

                state.fork_branch_successors = [true_state]

            elif true_feasible:
                # Only true: keep TOS, jump
                state.path_condition = z3.And(state.path_condition, condition_true)
                frame.instruction_offset = target_offset
            elif false_feasible:
                # Only false: pop TOS, fall through
                frame.operand_stack.pop()
                state.path_condition = z3.And(state.path_condition, z3.Not(condition_true))
                frame.instruction_offset = fallthrough_offset
            else:
                state.exception = "InfeasiblePath"

        elif opname == "POP_JUMP_FORWARD_IF_NONE":
            # Python 3.11: pop TOS, jump forward if None.
            # Semantically identical to POP_JUMP_IF_NONE (3.12+).
            if not frame.operand_stack:
                state.exception = "StackUnderflow"
                return

            value = frame.operand_stack.pop()
            is_none = (value.tag == z3.IntVal(ValueTag.NONE.value))

            var_name = self._get_variable_name_for_value(state, value)

            target_offset = instr.argval
            fallthrough_offset = self._next_offset(frame, instr)

            if self.oracle:
                expected_next = self.oracle.pop_branch_next_offset(frame.code, instr.offset)
                if expected_next in (target_offset, fallthrough_offset):
                    took_jump = expected_next == target_offset
                    state.path_condition = z3.And(
                        state.path_condition,
                        is_none if took_jump else z3.Not(is_none),
                    )
                    if not took_jump and var_name:
                        state.established_guards[f"nonnull:{var_name}"] = True
                    frame.instruction_offset = expected_next
                    return

            self.solver.push()
            self.solver.add(state.path_condition)
            self.solver.add(is_none)
            none_feasible = (self.solver.check() == z3.sat)
            self.solver.pop()

            self.solver.push()
            self.solver.add(state.path_condition)
            self.solver.add(z3.Not(is_none))
            not_none_feasible = (self.solver.check() == z3.sat)
            self.solver.pop()

            if none_feasible and not_none_feasible:
                import copy
                none_state = copy.deepcopy(state)
                none_state.path_condition = z3.And(state.path_condition, is_none)
                none_state.frame_stack[-1].instruction_offset = target_offset

                state.path_condition = z3.And(state.path_condition, z3.Not(is_none))
                if var_name:
                    state.established_guards[f"nonnull:{var_name}"] = True
                frame.instruction_offset = fallthrough_offset

                state.fork_branch_successors = [none_state]
            elif none_feasible:
                state.path_condition = z3.And(state.path_condition, is_none)
                frame.instruction_offset = target_offset
            elif not_none_feasible:
                state.path_condition = z3.And(state.path_condition, z3.Not(is_none))
                if var_name:
                    state.established_guards[f"nonnull:{var_name}"] = True
                frame.instruction_offset = fallthrough_offset
            else:
                state.exception = "InfeasiblePath"

        elif opname == "POP_JUMP_FORWARD_IF_NOT_NONE":
            # Python 3.11: pop TOS, jump forward if NOT None.
            # Semantically identical to POP_JUMP_IF_NOT_NONE (3.12+).
            if not frame.operand_stack:
                state.exception = "StackUnderflow"
                return

            value = frame.operand_stack.pop()
            is_none = (value.tag == z3.IntVal(ValueTag.NONE.value))

            var_name = self._get_variable_name_for_value(state, value)

            target_offset = instr.argval
            fallthrough_offset = self._next_offset(frame, instr)

            if self.oracle:
                expected_next = self.oracle.pop_branch_next_offset(frame.code, instr.offset)
                if expected_next in (target_offset, fallthrough_offset):
                    took_jump = expected_next == target_offset
                    state.path_condition = z3.And(
                        state.path_condition,
                        z3.Not(is_none) if took_jump else is_none,
                    )
                    if took_jump and var_name:
                        state.established_guards[f"nonnull:{var_name}"] = True
                    frame.instruction_offset = expected_next
                    return

            self.solver.push()
            self.solver.add(state.path_condition)
            self.solver.add(z3.Not(is_none))
            not_none_feasible = (self.solver.check() == z3.sat)
            self.solver.pop()

            self.solver.push()
            self.solver.add(state.path_condition)
            self.solver.add(is_none)
            none_feasible = (self.solver.check() == z3.sat)
            self.solver.pop()

            if not_none_feasible and none_feasible:
                import copy
                not_none_state = copy.deepcopy(state)
                not_none_state.path_condition = z3.And(state.path_condition, z3.Not(is_none))
                if var_name:
                    not_none_state.established_guards[f"nonnull:{var_name}"] = True
                not_none_state.frame_stack[-1].instruction_offset = target_offset

                state.path_condition = z3.And(state.path_condition, is_none)
                frame.instruction_offset = fallthrough_offset

                state.fork_branch_successors = [not_none_state]
            elif not_none_feasible:
                state.path_condition = z3.And(state.path_condition, z3.Not(is_none))
                if var_name:
                    state.established_guards[f"nonnull:{var_name}"] = True
                frame.instruction_offset = target_offset
            elif none_feasible:
                state.path_condition = z3.And(state.path_condition, is_none)
                frame.instruction_offset = fallthrough_offset
            else:
                state.exception = "InfeasiblePath"

        elif opname == "POP_JUMP_BACKWARD_IF_FALSE":
            # Python 3.11: pop TOS, jump backward if false.
            # Same semantics as POP_JUMP_FORWARD_IF_FALSE but target is backward.
            if not frame.operand_stack:
                state.exception = "StackUnderflow"
                return

            condition = frame.operand_stack.pop()
            condition_true = is_true(condition, self.solver)

            target_offset = instr.argval
            fallthrough_offset = self._next_offset(frame, instr)

            self.solver.push()
            self.solver.add(state.path_condition)
            self.solver.add(condition_true)
            true_feasible = self._solver_maybe_sat()
            self.solver.pop()

            self.solver.push()
            self.solver.add(state.path_condition)
            self.solver.add(z3.Not(condition_true))
            false_feasible = self._solver_maybe_sat()
            self.solver.pop()

            if true_feasible and false_feasible:
                import copy
                false_state = copy.deepcopy(state)
                false_state.path_condition = z3.And(state.path_condition, z3.Not(condition_true))
                false_state.frame_stack[-1].instruction_offset = target_offset

                state.path_condition = z3.And(state.path_condition, condition_true)
                frame.instruction_offset = fallthrough_offset

                state.fork_branch_successors = [false_state]
            elif false_feasible:
                state.path_condition = z3.And(state.path_condition, z3.Not(condition_true))
                frame.instruction_offset = target_offset
            elif true_feasible:
                state.path_condition = z3.And(state.path_condition, condition_true)
                frame.instruction_offset = fallthrough_offset
            else:
                state.exception = "InfeasiblePath"

        elif opname == "POP_JUMP_BACKWARD_IF_TRUE":
            # Python 3.11: pop TOS, jump backward if true.
            if not frame.operand_stack:
                state.exception = "StackUnderflow"
                return

            condition = frame.operand_stack.pop()
            condition_true = is_true(condition, self.solver)

            target_offset = instr.argval
            fallthrough_offset = self._next_offset(frame, instr)

            self.solver.push()
            self.solver.add(state.path_condition)
            self.solver.add(condition_true)
            true_feasible = self._solver_maybe_sat()
            self.solver.pop()

            self.solver.push()
            self.solver.add(state.path_condition)
            self.solver.add(z3.Not(condition_true))
            false_feasible = self._solver_maybe_sat()
            self.solver.pop()

            if true_feasible and false_feasible:
                import copy
                true_state = copy.deepcopy(state)
                true_state.path_condition = z3.And(state.path_condition, condition_true)
                true_state.frame_stack[-1].instruction_offset = target_offset

                state.path_condition = z3.And(state.path_condition, z3.Not(condition_true))
                frame.instruction_offset = fallthrough_offset

                state.fork_branch_successors = [true_state]
            elif true_feasible:
                state.path_condition = z3.And(state.path_condition, condition_true)
                frame.instruction_offset = target_offset
            elif false_feasible:
                state.path_condition = z3.And(state.path_condition, z3.Not(condition_true))
                frame.instruction_offset = fallthrough_offset
            else:
                state.exception = "InfeasiblePath"

        # ================================================================
        # Bookkeeping / no-op opcodes
        # ================================================================

        elif opname == "EXTENDED_ARG":
            # EXTENDED_ARG is a prefix instruction that extends the argument of the next instruction.
            # dis.get_instructions() already resolves EXTENDED_ARG and includes the combined argument
            # in the arg/argval fields of the following instruction. We simply skip EXTENDED_ARG.
            # Semantically: EXTENDED_ARG does not modify machine state, it only affects bytecode decoding.
            frame.instruction_offset = self._next_offset(frame, instr)
        
        elif opname == "PRECALL":
            # Python 3.11 bookkeeping instruction that precedes CALL.
            # PRECALL performs adaptive specialisation housekeeping; it has
            # no effect on the abstract machine state.  Simply advance PC.
            frame.instruction_offset = self._next_offset(frame, instr)
        
        elif opname == "CACHE":
            # Python 3.11+ inline-cache slot.  dis.get_instructions() may
            # surface CACHE entries.  They are no-ops at the semantic level.
            frame.instruction_offset = self._next_offset(frame, instr)
        
        elif opname == "BEFORE_WITH":
            # Python 3.11 replaces the older SETUP_WITH with BEFORE_WITH.
            # It calls __enter__ on TOS and pushes the context-manager exit
            # method.  For soundness we over-approximate: push a fresh
            # symbolic object for the __enter__ result and advance.
            if len(frame.operand_stack) >= 1:
                cm = frame.operand_stack.pop()
                # Push __exit__ placeholder (will be used by WITH_EXCEPT_START)
                exit_obj = SymbolicValue(ValueTag.OBJ,
                    z3.Int(f"with_exit_{instr.offset}_{id(frame)}"))
                frame.operand_stack.append(exit_obj)
                # Push __enter__() result
                enter_result = SymbolicValue(ValueTag.OBJ,
                    z3.Int(f"with_enter_{instr.offset}_{id(frame)}"))
                frame.operand_stack.append(enter_result)
            frame.instruction_offset = self._next_offset(frame, instr)
        
        elif opname == "JUMP_BACKWARD_NO_INTERRUPT":
            # Python 3.11+  unconditional backward jump that does NOT check
            # for pending interrupts / signals.  Used inside generators and
            # comprehensions.  Treat identically to JUMP_BACKWARD.
            target = instr.argval if instr.argval is not None else instr.arg
            frame.instruction_offset = target
        
        else:
            raise NotImplementedError(f"Opcode {opname}")
    
    def check_termination(self, code_obj, config=None) -> list:
        """
        Check termination for all loops in a code object.
        
        This method integrates ranking function synthesis with the symbolic VM
        to automatically check whether loops in the bytecode terminate.
        
        Args:
            code_obj: Python code object to analyze
            config: Optional RankingSynthesisConfig
        
        Returns:
            List of TerminationCheckResult, one per loop
        
        Usage:
            vm = SymbolicVM()
            results = vm.check_termination(code_obj)
            for result in results:
                if result.is_safe():
                    print(f"Loop at {result.loop_offset} terminates")
                    print(f"  Ranking: {result.ranking.name}")
                elif result.is_bug():
                    print(f"Loop at {result.loop_offset} may not terminate")
                else:
                    print(f"Loop at {result.loop_offset}: UNKNOWN")
        """
        from .termination_integration import TerminationIntegrator
        
        integrator = TerminationIntegrator(config)
        return integrator.check_all_loops(code_obj)


def symbolic_execute(source: str, max_steps: int = 100, mode: str = "auto") -> List[SymbolicPath]:
    """
    Convenience function: compile source and symbolically execute.
    
    Returns list of completed symbolic paths.
    
    Args:
        source: Python source code string
        max_steps: Maximum number of bytecode steps per path
        mode: Compilation mode - "auto" (default), "exec" for statements, "eval" for expressions
              "auto" tries "eval" first, falls back to "exec"
    """
    if mode == "auto":
        # Try eval first (for simple expressions), fall back to exec
        try:
            code = compile(source, "<string>", "eval")
        except SyntaxError:
            code = compile(source, "<string>", "exec")
    else:
        code = compile(source, "<string>", mode)
    
    vm = SymbolicVM()
    return vm.explore_bounded(code, max_steps)
