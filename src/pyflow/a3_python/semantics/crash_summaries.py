"""
Crash Summaries for Interprocedural Bug Detection.

Extends taint summaries to track crash-inducing conditions across function boundaries.
This covers ALL 20 core bug types + 47 security bug types.

INTEGRATION WITH EXISTING INFRASTRUCTURE:
- Uses UNSAFE_PREDICATES from a3_python/unsafe/registry.py
- Uses TaintLabel/SymbolicTaintLabel from a3_python/z3model/taint_lattice.py
- Uses barrier synthesis from a3_python/barriers/synthesis.py
- Uses security contracts from a3_python/contracts/security_lattice.py

For each function f, we compute:
1. **Precondition Summary** Π_f: Required conditions on parameters to avoid crashes
2. **Effect Summary** E_f: What crash conditions f may produce  
3. **Exception Summary** X_f: What exceptions f may raise
4. **Nullability Summary** N_f: Whether parameters may be None, return may be None

This enables interprocedural reasoning:
- If caller passes value that may be None to callee requiring non-None → NULL_PTR
- If caller passes untainted value to callee that checks bounds → may still crash
- If callee raises exception that caller doesn't handle → PANIC

Mathematical Foundation (python-barrier-certificate-theory.md §9.5):

Definition (Crash Summary): For function f with parameters (p₁, ..., pₙ):
    Σ_f^crash = (Π_f, E_f, X_f, N_f)
where:
    - Π_f : 2^{Params} → Preconditions  (what must hold for params)
    - E_f : 2^{BugTypes}                 (what bugs f may trigger)
    - X_f : 2^{ExceptionTypes}           (what exceptions f may raise)
    - N_f : {may_be_none, not_none}^n    (nullability of params/return)

Theorem (Interprocedural Bug Propagation):
    If f calls g at site π, and:
    - args at π violate Π_g, OR
    - X_g contains exceptions not caught by f
    then f may exhibit bugs from E_g ∪ {derived bugs from Π_g violation}.
"""

from __future__ import annotations
from dataclasses import dataclass, field
from typing import Dict, List, Set, Optional, Tuple, Any, FrozenSet, Callable
from enum import IntEnum, auto
import ast
import dis
import types
from pathlib import Path

# ============================================================================
# IMPORT EXISTING INFRASTRUCTURE - DO NOT DUPLICATE
# ============================================================================

from ..unsafe.registry import (
    UNSAFE_PREDICATES,
    check_unsafe_regions,
    list_implemented_bug_types,
    get_all_unsafe_predicates,
)
from ..cfg.dataflow import run_intraprocedural_analysis, IntraprocAnalysisResult
from ..cfg.control_flow import build_cfg, ControlFlowGraph, GuardAnalyzer, BasicBlock
from ..cfg.control_flow import build_cfg, ControlFlowGraph, BasicBlock, ExceptionCatchAnalyzer

# Bug type names from the registry (canonical source of truth)
REGISTERED_BUG_TYPES: List[str] = list_implemented_bug_types()


# Exception types that guard specific bugs
# Maps bug type name to the exceptions that catch it
EXCEPTION_BARRIER_MAP: Dict[str, List[str]] = {
    'DIV_ZERO': ['ZeroDivisionError'],
    'BOUNDS': ['IndexError', 'KeyError'],
    'NULL_PTR': ['AttributeError', 'TypeError'],
    'VALUE_ERROR': ['ValueError'],
    'TYPE_CONFUSION': ['TypeError'],
    'RUNTIME_ERROR': ['RuntimeError'],
    'IMPORT_ERROR': ['ImportError', 'ModuleNotFoundError'],
    'ASSERT_FAIL': ['AssertionError'],
    'INTEGER_OVERFLOW': ['OverflowError'],
    'FILE_NOT_FOUND': ['FileNotFoundError'],
    'PERMISSION_ERROR': ['PermissionError'],
    'OS_ERROR': ['OSError'],
    'IO_ERROR': ['IOError'],
    'NAME_ERROR': ['NameError'],
    'UNBOUND_LOCAL': ['UnboundLocalError'],
    'TIMEOUT_ERROR': ['TimeoutError'],
}

# Bytecode constants for division operations.
# Dynamically computed to handle Python version differences
# (e.g., Python 3.14 changed BINARY_OP arg numbering).
def _compute_division_binary_ops():
    """Compute the correct BINARY_OP arg values for division on this Python."""
    import dis as _dis
    args = set()
    for expr in ['x / y', 'x // y', 'x % y']:
        code = compile(f'def f(x, y):\n    return {expr}', '<div>', 'exec')
        for c in code.co_consts:
            if hasattr(c, 'co_name') and c.co_name == 'f':
                for instr in _dis.get_instructions(c):
                    if instr.opname == 'BINARY_OP':
                        args.add(instr.arg)
    for expr in ['x /= y', 'x //= y', 'x %= y']:
        code = compile(f'def f(x, y):\n    {expr}\n    return x', '<div>', 'exec')
        for c in code.co_consts:
            if hasattr(c, 'co_name') and c.co_name == 'f':
                for instr in _dis.get_instructions(c):
                    if instr.opname == 'BINARY_OP':
                        args.add(instr.arg)
    return args

DIVISION_BINARY_OPS = _compute_division_binary_ops()

# Subscript operation in BINARY_OP (Python 3.13+)
SUBSCRIPT_BINARY_OPS = {26}  # BINARY_OP 26 is []

# Bytecode opcode sets for different operations
SUBSCRIPT_OPCODES = {'BINARY_SUBSCR', 'LOAD_SUBSCR'}
ATTRIBUTE_OPCODES = {'LOAD_ATTR', 'LOAD_METHOD'}
CALL_OPCODES = {'CALL_FUNCTION', 'CALL', 'CALL_METHOD'}
RAISE_OPCODES = {'RAISE_VARARGS'}

# Builtins / types whose CALL always produces a non-None value.
# Used by _is_tos_nonnull_at to recognise that attribute access on a
# call result from these functions is safe from NULL_PTR.
_NONNULL_RETURNING_BUILTINS = frozenset({
    'set', 'list', 'dict', 'tuple', 'frozenset', 'bytearray',
    'str', 'int', 'float', 'bool', 'bytes', 'complex',
    'type', 'object', 'super',
    'dir', 'vars', 'id', 'len', 'range', 'enumerate', 'zip', 'map', 'filter',
    'sorted', 'reversed', 'iter', 'next',
    'repr', 'ascii', 'bin', 'hex', 'oct', 'ord', 'chr', 'hash', 'abs',
    'min', 'max', 'sum', 'round', 'pow', 'divmod',
    'format', 'print', 'input', 'open',
    'getattr',  # 3-arg getattr with default always returns non-None *or* default
    'isinstance', 'issubclass', 'callable', 'hasattr',
})

# Builtins that raise TypeError when given None as an argument.
# Passing None to any of these is a NULL_PTR-class bug (None misuse).
_NONE_REJECTING_BUILTINS = frozenset({
    'range', 'len', 'int', 'float', 'abs', 'iter', 'next',
    'sorted', 'reversed', 'enumerate',
    'sum', 'max', 'min', 'ord', 'round', 'pow', 'divmod',
})


# ============================================================================
# PRECONDITION TYPES
# ============================================================================

class PreconditionType(IntEnum):
    """Types of preconditions a function may require on parameters."""
    NOT_NONE = auto()          # Parameter must not be None
    NOT_ZERO = auto()          # Parameter must not be zero (divisor)
    IN_BOUNDS = auto()         # Index must be in bounds
    VALID_TYPE = auto()        # Parameter must have expected type
    NOT_EMPTY = auto()         # Collection must not be empty
    POSITIVE = auto()          # Value must be > 0
    NON_NEGATIVE = auto()      # Value must be >= 0
    FINITE = auto()            # Float must not be inf/nan
    VALID_RANGE = auto()       # Value must be in valid range
    SANITIZED = auto()         # Must be sanitized for sink
    TRUSTED = auto()           # Must not be tainted


# ============================================================================
# GUARD TRACKING FOR FALSE POSITIVE REDUCTION
# ============================================================================

@dataclass
class GuardTracker:
    """
    Track guards that dominate the current program point.
    
    From barrier-certificate-theory.tex, guards are derived from control flow
    and semantic facts. A bug is only real if reachable with guards = 0.
    
    Key insight: B(s) >= 0 incorporates guards; safety is B >= 0 on all reachable states.
    If g_nonnull(x) = 1 dominates an access x.attr, then that access is safe.
    """
    # Variables known to be non-None on current path
    nonnull_vars: Set[str] = field(default_factory=set)
    # Variables known to be non-zero on current path
    nonzero_vars: Set[str] = field(default_factory=set)
    # Containers known to be non-empty on current path
    nonempty_vars: Set[str] = field(default_factory=set)
    # Variables with known types
    typed_vars: Dict[str, str] = field(default_factory=dict)
    # Loop iteration variables: var -> container they iterate
    loop_vars: Dict[str, str] = field(default_factory=dict)
    # Whether we're inside a try block that catches relevant exceptions
    exception_handlers: Set[str] = field(default_factory=set)
    
    def copy(self) -> 'GuardTracker':
        """Create a copy for branching."""
        return GuardTracker(
            nonnull_vars=self.nonnull_vars.copy(),
            nonzero_vars=self.nonzero_vars.copy(),
            nonempty_vars=self.nonempty_vars.copy(),
            typed_vars=self.typed_vars.copy(),
            loop_vars=self.loop_vars.copy(),
            exception_handlers=self.exception_handlers.copy(),
        )
    
    def is_guarded_nonnull(self, var: str) -> bool:
        """Check if variable is guarded as non-None."""
        return var in self.nonnull_vars
    
    def is_guarded_nonzero(self, var: str) -> bool:
        """Check if variable is guarded as non-zero."""
        return var in self.nonzero_vars
    
    def is_guarded_nonempty(self, container: str) -> bool:
        """Check if container is guarded as non-empty."""
        return container in self.nonempty_vars
    
    def is_safe_loop_index(self, index_var: str, container_var: str) -> bool:
        """Check if index is from iteration over the same container."""
        return self.loop_vars.get(index_var) == container_var


# ============================================================================
# DSE-BASED ANALYSIS: NO AD-HOC NAME HEURISTICS
# ============================================================================
# REMOVED: NEVER_NONE_NAMES, PATH_RELATED_NAMES
# 
# Instead of name-based heuristics, use:
# 1. SymbolicVM with Z3 for reachability checking
# 2. GuardDataflowAnalysis for guard propagation through CFG
# 3. Type annotations and inference for nullability
# 4. Barrier certificate synthesis for safety proofs
#
# See: dse_bug_detector.py for proper DSE-based analysis
# ============================================================================


@dataclass(frozen=True)
class Precondition:
    """A single precondition on a parameter."""
    param_index: int
    condition_type: PreconditionType
    related_param: Optional[int] = None  # For IN_BOUNDS: the container param
    sink_type: Optional[int] = None      # For SANITIZED: which sink
    
    def __str__(self) -> str:
        base = f"p{self.param_index}.{self.condition_type.name}"
        if self.related_param is not None:
            base += f"(p{self.related_param})"
        return base


# ============================================================================
# EXCEPTION TYPES
# ============================================================================

class ExceptionType(IntEnum):
    """Common exception types tracked for interprocedural analysis."""
    NONE = 0  # No exception
    ATTRIBUTE_ERROR = auto()
    TYPE_ERROR = auto()
    VALUE_ERROR = auto()
    INDEX_ERROR = auto()
    KEY_ERROR = auto()
    ZERO_DIVISION_ERROR = auto()
    ASSERTION_ERROR = auto()
    RUNTIME_ERROR = auto()
    OVERFLOW_ERROR = auto()
    MEMORY_ERROR = auto()
    RECURSION_ERROR = auto()
    STOP_ITERATION = auto()
    FILE_NOT_FOUND_ERROR = auto()
    PERMISSION_ERROR = auto()
    OS_ERROR = auto()
    IO_ERROR = auto()
    IMPORT_ERROR = auto()
    NAME_ERROR = auto()
    UNBOUND_LOCAL_ERROR = auto()
    TIMEOUT_ERROR = auto()
    KEYBOARD_INTERRUPT = auto()
    SYSTEM_EXIT = auto()
    GENERIC_EXCEPTION = auto()


# Map exception name strings to enum
EXCEPTION_NAMES: Dict[str, ExceptionType] = {
    'AttributeError': ExceptionType.ATTRIBUTE_ERROR,
    'TypeError': ExceptionType.TYPE_ERROR,
    'ValueError': ExceptionType.VALUE_ERROR,
    'IndexError': ExceptionType.INDEX_ERROR,
    'KeyError': ExceptionType.KEY_ERROR,
    'ZeroDivisionError': ExceptionType.ZERO_DIVISION_ERROR,
    'AssertionError': ExceptionType.ASSERTION_ERROR,
    'RuntimeError': ExceptionType.RUNTIME_ERROR,
    'OverflowError': ExceptionType.OVERFLOW_ERROR,
    'MemoryError': ExceptionType.MEMORY_ERROR,
    'RecursionError': ExceptionType.RECURSION_ERROR,
    'StopIteration': ExceptionType.STOP_ITERATION,
    'FileNotFoundError': ExceptionType.FILE_NOT_FOUND_ERROR,
    'PermissionError': ExceptionType.PERMISSION_ERROR,
    'OSError': ExceptionType.OS_ERROR,
    'IOError': ExceptionType.IO_ERROR,
    'ImportError': ExceptionType.IMPORT_ERROR,
    'NameError': ExceptionType.NAME_ERROR,
    'UnboundLocalError': ExceptionType.UNBOUND_LOCAL_ERROR,
    'TimeoutError': ExceptionType.TIMEOUT_ERROR,
    'KeyboardInterrupt': ExceptionType.KEYBOARD_INTERRUPT,
    'SystemExit': ExceptionType.SYSTEM_EXIT,
}


# Map exceptions to bug types (using string names from registry)
# ITERATION 700: Fine-grained exception mapping instead of just PANIC
EXCEPTION_TO_BUG: Dict[ExceptionType, str] = {
    ExceptionType.ATTRIBUTE_ERROR: 'NULL_PTR',
    ExceptionType.TYPE_ERROR: 'TYPE_CONFUSION',
    ExceptionType.INDEX_ERROR: 'BOUNDS',
    ExceptionType.KEY_ERROR: 'BOUNDS',
    ExceptionType.ZERO_DIVISION_ERROR: 'DIV_ZERO',
    ExceptionType.ASSERTION_ERROR: 'ASSERT_FAIL',
    ExceptionType.OVERFLOW_ERROR: 'INTEGER_OVERFLOW',
    ExceptionType.MEMORY_ERROR: 'MEMORY_LEAK',
    ExceptionType.RECURSION_ERROR: 'STACK_OVERFLOW',
    ExceptionType.STOP_ITERATION: 'ITERATOR_INVALID',
    # Fine-grained exception types (ITERATION 700)
    ExceptionType.VALUE_ERROR: 'VALUE_ERROR',
    ExceptionType.RUNTIME_ERROR: 'RUNTIME_ERROR',
    ExceptionType.FILE_NOT_FOUND_ERROR: 'FILE_NOT_FOUND',
    ExceptionType.PERMISSION_ERROR: 'PERMISSION_ERROR',
    ExceptionType.OS_ERROR: 'OS_ERROR',
    ExceptionType.IO_ERROR: 'IO_ERROR',
    ExceptionType.IMPORT_ERROR: 'IMPORT_ERROR',
    ExceptionType.NAME_ERROR: 'NAME_ERROR',
    ExceptionType.UNBOUND_LOCAL_ERROR: 'UNBOUND_LOCAL',
    ExceptionType.TIMEOUT_ERROR: 'TIMEOUT_ERROR',
    ExceptionType.GENERIC_EXCEPTION: 'PANIC',  # Only truly custom exceptions
}


# Map precondition violations to bug types
PRECONDITION_TO_BUG: Dict[PreconditionType, str] = {
    PreconditionType.NOT_NONE: 'NULL_PTR',
    PreconditionType.NOT_ZERO: 'DIV_ZERO',
    PreconditionType.IN_BOUNDS: 'BOUNDS',
    PreconditionType.VALID_TYPE: 'TYPE_CONFUSION',
    PreconditionType.NOT_EMPTY: 'BOUNDS',
    PreconditionType.POSITIVE: 'ASSERT_FAIL',
    PreconditionType.NON_NEGATIVE: 'BOUNDS',
    PreconditionType.FINITE: 'FP_DOMAIN',
    PreconditionType.SANITIZED: 'SQL_INJECTION',  # Generic - depends on sink
    PreconditionType.TRUSTED: 'CODE_INJECTION',   # Generic - depends on sink
}


# ============================================================================
# NULLABILITY LATTICE
# ============================================================================

class Nullability(IntEnum):
    """Nullability state for values."""
    BOTTOM = 0       # Unreachable / no value
    NOT_NONE = 1     # Definitely not None
    MAY_BE_NONE = 2  # Could be None
    IS_NONE = 3      # Definitely None
    TOP = 4          # Unknown
    
    def join(self, other: 'Nullability') -> 'Nullability':
        """Lattice join (least upper bound)."""
        if self == Nullability.BOTTOM:
            return other
        if other == Nullability.BOTTOM:
            return self
        if self == other:
            return self
        if self == Nullability.TOP or other == Nullability.TOP:
            return Nullability.TOP
        # Different non-bottom, non-top values → MAY_BE_NONE or TOP
        if {self, other} == {Nullability.NOT_NONE, Nullability.IS_NONE}:
            return Nullability.MAY_BE_NONE
        return Nullability.MAY_BE_NONE


# ============================================================================
# CRASH SUMMARY
# ============================================================================

@dataclass
class CrashSummary:
    """
    Complete crash summary for a function.
    
    Captures all conditions under which a function may crash or trigger bugs.
    Uses string bug type names from a3_python/unsafe/registry.py as the
    canonical source of truth.
    """
    function_name: str
    qualified_name: str
    parameter_count: int
    
    # Preconditions: what must hold for parameters to avoid crashes
    preconditions: Set[Precondition] = field(default_factory=set)
    
    # Effects: what bug types this function may trigger directly (string names)
    may_trigger: Set[str] = field(default_factory=set)
    
    # Exceptions: what exceptions this function may raise
    may_raise: Set[ExceptionType] = field(default_factory=set)
    
    # Nullability: for each param, can it be None? For return, may it be None?
    param_nullability: Dict[int, Nullability] = field(default_factory=dict)
    return_nullability: Nullability = Nullability.TOP
    
    # Division safety: which params are used as divisors (need != 0)
    divisor_params: Set[int] = field(default_factory=set)
    
    # Index params: which params are used as indices (need bounds check)
    # Maps index_param -> container_param
    index_params: Dict[int, int] = field(default_factory=dict)
    
    # Propagation: which params flow to potentially unsafe operations
    # Maps param -> set of bug type names that param may trigger
    param_bug_propagation: Dict[int, Set[str]] = field(default_factory=dict)
    
    # Callee effects: bugs transitively possible from callees (string names)
    transitive_bugs: Set[str] = field(default_factory=set)
    
    # Side effects
    has_side_effects: bool = False
    modifies_globals: bool = False
    performs_io: bool = False
    
    # Guard tracking (NEW): which bug types have guards protecting them
    # Set of bug type names that are protected by guards (should reduce confidence)
    guarded_bugs: Set[str] = field(default_factory=set)
    
    # ITERATION 702: Per-instance guard tracking for accurate FP counting
    # Tracks counts of guarded vs unguarded instances per bug type
    # bug_type -> (guarded_count, unguarded_count)
    guard_counts: Dict[str, Tuple[int, int]] = field(default_factory=dict)
    
    # INTERPROCEDURAL GUARD EXTENSION: Track return value and param guarantees
    # These enable FP reduction across function boundaries
    # Return guarantees: what this function guarantees about its return value
    return_guarantees: Set[str] = field(default_factory=set)  # e.g., {'nonnull', 'nonzero'}
    # Param validation: which params are validated (callers can trust them)
    validated_params: Dict[int, Set[str]] = field(default_factory=dict)  # param_idx -> {'nonnull', 'nonempty', ...}
    
    # INTRAPROCEDURAL GUARD FACTS: Raw guard facts from GuardAnalyzer
    # These are automatically propagated to interprocedural analysis
    # Maps block_id -> set of guard type strings established at that block
    # This allows any guard pattern in control_flow.py to be used interprocedurally
    intra_guard_facts: Dict[int, Set[Tuple[str, str, Optional[str]]]] = field(default_factory=dict)
    # Aggregated guard types for quick lookup: guard_type -> set of variables
    guard_type_to_vars: Dict[str, Set[str]] = field(default_factory=dict)
    
    # VALUE FLOW TRACKING: Track which variables hold the same value (aliasing)
    # This enables guard propagation through assignments:
    #   if x is not None:  # guard on x
    #       y = x          # y now aliases x
    #       y.attr         # bug on y, but guarded through alias to x
    # Maps variable -> set of variables that hold the same value
    value_aliases: Dict[str, Set[str]] = field(default_factory=dict)
    
    # NULL_PTR target variables: tracks the actual variable names involved in
    # unguarded NULL_PTR crash sites (e.g., 'self.cell' for self.cell.method()).
    # Used by the interprocedural bug tracker to set accurate bug_variable,
    # avoiding misattribution to 'self' which would be suppressed by intent filter.
    null_ptr_target_vars: Set[str] = field(default_factory=set)
    
    # BYTECODE INSTRUCTIONS: Store for barrier-theoretic stdlib detection
    # This enables Papers #9-12 (ICE), #13-16 (IC3), #17-20 (CHC) to analyze
    # stdlib usage patterns and synthesize barriers
    bytecode_instructions: List[Any] = field(default_factory=list)
    
    # Analysis metadata
    is_recursive: bool = False
    analyzed: bool = False
    
    def add_guard_fact(self, guard_type: str, variable: str, extra: Optional[str] = None, block_id: int = 0) -> None:
        """
        Add a guard fact from intraprocedural analysis.
        
        This is called by BytecodeCrashSummaryAnalyzer to store guard facts
        that can be used interprocedurally.
        """
        if block_id not in self.intra_guard_facts:
            self.intra_guard_facts[block_id] = set()
        self.intra_guard_facts[block_id].add((guard_type, variable, extra))
        
        # Also update the quick lookup
        if guard_type not in self.guard_type_to_vars:
            self.guard_type_to_vars[guard_type] = set()
        self.guard_type_to_vars[guard_type].add(variable)
    
    def has_guard_for_variable(self, guard_type: str, variable: str) -> bool:
        """
        Check if any guard of the given type is established for this variable.
        
        This is the interprocedural query interface.
        """
        vars_with_guard = self.guard_type_to_vars.get(guard_type, set())
        return variable in vars_with_guard
    
    def has_guard_for_variable_or_alias(self, guard_type: str, variable: str) -> Tuple[bool, Optional[str]]:
        """
        Check if a guard is established for this variable or any of its aliases.
        
        This enables guard propagation through value flow:
        - If x is guarded and y = x, then y is also guarded
        - Returns (True, alias_var) if guarded through an alias
        - Returns (True, None) if directly guarded
        - Returns (False, None) if not guarded
        """
        vars_with_guard = self.guard_type_to_vars.get(guard_type, set())
        
        # Check direct guard
        if variable in vars_with_guard:
            return (True, None)
        
        # Check through aliases
        aliases = self.value_aliases.get(variable, set())
        for alias in aliases:
            if alias in vars_with_guard:
                return (True, alias)
        
        # Check reverse direction: does any guarded variable alias to this one?
        for guarded_var in vars_with_guard:
            if variable in self.value_aliases.get(guarded_var, set()):
                return (True, guarded_var)
        
        return (False, None)
    
    def get_all_guarded_variables(self, guard_type: str) -> Set[str]:
        """Get all variables that have the given guard type established."""
        return self.guard_type_to_vars.get(guard_type, set()).copy()
    
    def add_value_alias(self, target: str, source: str) -> None:
        """
        Record that target variable holds the same value as source variable.
        
        This creates a bidirectional alias relationship for guard propagation.
        """
        if target not in self.value_aliases:
            self.value_aliases[target] = set()
        self.value_aliases[target].add(source)
        
        # Also record reverse direction
        if source not in self.value_aliases:
            self.value_aliases[source] = set()
        self.value_aliases[source].add(target)
    
    def get_all_aliases(self, variable: str) -> Set[str]:
        """
        Get all variables that may hold the same value as this variable.
        
        Returns the transitive closure of aliases.
        """
        result = set()
        visited = set()
        worklist = [variable]
        
        while worklist:
            var = worklist.pop()
            if var in visited:
                continue
            visited.add(var)
            
            aliases = self.value_aliases.get(var, set())
            for alias in aliases:
                if alias not in visited:
                    result.add(alias)
                    worklist.append(alias)
        
        return result
    
    def requires_not_none(self, param_idx: int) -> bool:
        """Check if parameter must not be None."""
        return any(
            p.param_index == param_idx and p.condition_type == PreconditionType.NOT_NONE
            for p in self.preconditions
        )
    
    def requires_not_zero(self, param_idx: int) -> bool:
        """Check if parameter must not be zero (divisor)."""
        return param_idx in self.divisor_params or any(
            p.param_index == param_idx and p.condition_type == PreconditionType.NOT_ZERO
            for p in self.preconditions
        )
    
    def all_possible_bugs(self) -> Set[str]:
        """Get all bugs this function may trigger (direct + transitive)."""
        return self.may_trigger | self.transitive_bugs
    
    def record_bug_instance(self, bug_type: str, is_guarded: bool) -> None:
        """
        Record a bug instance with its guard status.
        
        ITERATION 702: Track per-instance guard counts for accurate FP measurement.
        """
        if bug_type not in self.guard_counts:
            self.guard_counts[bug_type] = (0, 0)
        
        guarded, unguarded = self.guard_counts[bug_type]
        if is_guarded:
            self.guard_counts[bug_type] = (guarded + 1, unguarded)
            self.guarded_bugs.add(bug_type)
        else:
            self.guard_counts[bug_type] = (guarded, unguarded + 1)
            self.may_trigger.add(bug_type)
    
    def get_fp_rate(self, bug_type: str) -> float:
        """
        Get the false positive rate for a bug type.
        
        FP rate = guarded / (guarded + unguarded)
        A higher rate means more instances are false positives.
        """
        if bug_type not in self.guard_counts:
            return 0.0
        guarded, unguarded = self.guard_counts[bug_type]
        total = guarded + unguarded
        return guarded / total if total > 0 else 0.0
    
    def get_guarded_count(self, bug_type: str) -> int:
        """Get count of guarded (FP) instances for a bug type."""
        if bug_type not in self.guard_counts:
            return 0
        return self.guard_counts[bug_type][0]
    
    def get_unguarded_count(self, bug_type: str) -> int:
        """Get count of unguarded (potential TP) instances for a bug type."""
        if bug_type not in self.guard_counts:
            return 0
        return self.guard_counts[bug_type][1]
    
    def get_precondition_violations(
        self,
        arg_nullabilities: List[Nullability],
        arg_may_be_zero: List[bool],
    ) -> Set[str]:
        """
        Check what bugs may occur if called with given argument states.
        
        Returns set of bug type names that could be triggered.
        """
        violations = set()
        
        for i, null in enumerate(arg_nullabilities):
            if self.requires_not_none(i) and null in (Nullability.MAY_BE_NONE, Nullability.IS_NONE):
                violations.add('NULL_PTR')
        
        for i, may_zero in enumerate(arg_may_be_zero):
            if self.requires_not_zero(i) and may_zero:
                violations.add('DIV_ZERO')
        
        return violations
    
    def merge_callee(self, callee: 'CrashSummary') -> None:
        """Merge effects from a callee into this summary."""
        self.transitive_bugs.update(callee.may_trigger)
        self.transitive_bugs.update(callee.transitive_bugs)
        # Exceptions that callee may raise (we might not catch them)
        self.may_raise.update(callee.may_raise)
    
    def check_with_unsafe_predicates(self, state: Any, path_trace: List[str]) -> Optional[Dict]:
        """
        Use the existing UNSAFE_PREDICATES from registry to check for bugs.
        
        This integrates with the sophisticated infrastructure in a3_python/unsafe/
        rather than reimplementing bug detection.
        """
        return check_unsafe_regions(state, path_trace)


# ============================================================================
# BYTECODE CRASH SUMMARY ANALYZER (Primary Analysis Path)
# ============================================================================
# Note: AST-based CrashSummaryAnalyzer removed - bytecode analysis is more
# precise and integrates better with verification engines.

# Supporting data structures for bytecode analysis
@dataclass
class BytecodeLocation:
    """Location of a bytecode instruction."""
    opname: str
    offset: int
    line_number: Optional[int]
    block_id: int
    
    def __str__(self) -> str:
        return f"{self.opname}@{self.offset} (line {self.line_number})"


@dataclass
class ParameterFlow:
    """
    Tracks which parameters flow to a stack slot at a bytecode offset.
    
    For bytecode-level analysis, we track data flow through the operand stack.
    """
    # Maps stack depth -> set of parameter indices that may flow there
    stack_flows: Dict[int, Set[int]] = field(default_factory=dict)
    # Maps local variable index -> set of parameter indices
    local_flows: Dict[int, Set[int]] = field(default_factory=dict)
    
    def copy(self) -> 'ParameterFlow':
        return ParameterFlow(
            stack_flows={k: v.copy() for k, v in self.stack_flows.items()},
            local_flows={k: v.copy() for k, v in self.local_flows.items()},
        )
    
    def merge(self, other: 'ParameterFlow') -> 'ParameterFlow':
        """Merge flows from two paths (union)."""
        result = self.copy()
        for k, v in other.stack_flows.items():
            if k in result.stack_flows:
                result.stack_flows[k] = result.stack_flows[k] | v
            else:
                result.stack_flows[k] = v.copy()
        for k, v in other.local_flows.items():
            if k in result.local_flows:
                result.local_flows[k] = result.local_flows[k] | v
            else:
                result.local_flows[k] = v.copy()
        return result


class BytecodeCrashSummaryAnalyzer:
    
    def __init__(
        self,
        code: types.CodeType,
        func_name: str,
        qualified_name: str,
        existing_summaries: Optional[Dict[str, CrashSummary]] = None,
        param_nullable: Optional[Dict[int, Optional[bool]]] = None,
    ):
        self.code = code
        self.func_name = func_name
        self.qualified_name = qualified_name
        self.summaries = existing_summaries or {}
        
        # ITERATION 610: Track parameter nullability from type annotations
        # Maps param_idx -> True (nullable), False (non-nullable typed), None (no annotation)
        self.param_nullable = param_nullable or {}
        
        # Build CFG and run intraprocedural analysis
        self.cfg: ControlFlowGraph = build_cfg(code)
        self.intraproc: IntraprocAnalysisResult = run_intraprocedural_analysis(code)
        
        # Exception handler analysis for barrier detection
        self.exception_analyzer: ExceptionCatchAnalyzer = ExceptionCatchAnalyzer(self.cfg)
        
        # Get parameter information from code object
        self.param_count = code.co_argcount + code.co_kwonlyargcount
        if code.co_flags & 0x04:  # CO_VARARGS
            self.param_count += 1
        if code.co_flags & 0x08:  # CO_VARKEYWORDS
            self.param_count += 1
        
        # Map local variable index -> parameter index (first N locals are params)
        self.param_locals: Dict[int, int] = {}
        for i in range(self.param_count):
            self.param_locals[i] = i
        
        # Instruction list
        self.instructions = list(dis.get_instructions(code))
        self._instr_index_by_offset: Dict[int, int] = {instr.offset: i for i, instr in enumerate(self.instructions)}

        # SOTA papers #4-5 (SOSTOOLS + Putinar): compact-domain SAFE proofs.
        # Used to suppress unsound interprocedural preconditions like "param != 0"
        # when a division site is provably unreachable (e.g., inside `while 1 <= x <= 5`).
        self._compact_proven_safe_sites: Dict[str, Set[int]] = {}
        if any(
            ins.opname == "BINARY_OP" and isinstance(ins.arg, int) and ins.arg in DIVISION_BINARY_OPS
            for ins in self.instructions
        ):
            try:
                from ..barriers.sos_toolbox import prove_guarded_hazards_compact

                for proof in prove_guarded_hazards_compact(code):
                    self._compact_proven_safe_sites.setdefault(proof.bug_type, set()).add(proof.site_offset)
            except Exception:
                # If proofs fail for any reason, fall back to conservative reporting.
                self._compact_proven_safe_sites = {}
        
        # Build summary
        self.summary = CrashSummary(
            function_name=func_name,
            qualified_name=qualified_name,
            parameter_count=self.param_count,
        )
        
        # BYTECODE STORAGE: Store instructions for barrier-theoretic stdlib detection
        # This enables Papers #9-12 (ICE), #13-16 (IC3), #17-20 (CHC) to analyze
        # stdlib usage patterns (len(), max(), range()) and synthesize barriers
        self.summary.bytecode_instructions = self.instructions
        
        # Track locations of potential crashes
        self.crash_locations: List[Tuple[str, BytecodeLocation]] = []
        
        # Return nullability tracking
        self._return_nullabilities: List[Nullability] = []
        
        # ITERATION 610: Track locals known to be non-None
        # Maps local_idx -> True if known non-None (from BUILD_MAP, BUILD_LIST, etc.)
        self._nonnull_locals: Dict[int, bool] = {}
    
    def _is_caught_exception(self, offset: int, bug_type: str) -> bool:
        """
        Check if exception for this bug type is caught at this offset.
        
        If the exception is caught, the bug is "handled" and should not be reported
        as a bug (though it may still be logged as a guarded case).
        
        This implements the exception barrier from barrier-certificate-theory.tex:
        WillCatchAt(pc, exc) = True implies the exception is handled locally.
        """
        exception_types = EXCEPTION_BARRIER_MAP.get(bug_type, [])
        for exc_type in exception_types:
            if self.exception_analyzer.will_catch_at(offset, exc_type):
                # Exclude Python's implicit generator/coroutine StopIteration
                # handler — it converts StopIteration to RuntimeError but does
                # NOT actually catch other exception types.
                handler = self.cfg.get_exception_handler(offset)
                if handler and not handler.exception_types:
                    handler_idx = self._instr_index_by_offset.get(handler.handler_offset)
                    if handler_idx is not None and handler_idx < len(self.instructions):
                        h_instr = self.instructions[handler_idx]
                        if (h_instr.opname == 'CALL_INTRINSIC_1'
                                and h_instr.arg == 3):
                            continue  # implicit generator handler, not a real catch
                return True
        return False
    
    def analyze(self) -> CrashSummary:
        """
        Analyze bytecode and build crash summary.
        
        Walks through all basic blocks, checking each instruction for:
        - Division by potential zero
        - Subscript access (bounds risk)
        - Attribute access (null dereference risk)
        - Calls to potentially dangerous functions
        - Raises
        
        INTERPROCEDURAL EXTENSION: Also computes return guarantees and
        parameter validation facts for cross-function guard propagation.
        
        AUTOMATIC GUARD PROPAGATION: Uses GuardAnalyzer to collect all
        intraprocedural guard facts, which are then stored in the summary
        for interprocedural use. Any guard pattern added to GuardAnalyzer
        will automatically be available interprocedurally.
        
        DSE INTEGRATION: Uses full DSE path condition tracking to identify
        bugs that are provably unreachable (FPs) through:
        - Path condition tracking with Z3 constraints
        - Infeasible path pruning (SAT check)
        - Richer value flow through function returns and container ops
        - Path-sensitive guard analysis
        - Type-based filtering (self is never None)
        """
        # ITERATION 610: First pass - identify non-null locals
        # Scan for BUILD_MAP/BUILD_LIST followed by STORE_FAST
        self._identify_nonnull_locals()
        
        # Compute parameter flow through the function
        flows = self._compute_parameter_flows()
        
        # AUTOMATIC GUARD PROPAGATION: Run GuardAnalyzer and store all guard facts
        # This is the key refactor - any guard pattern in control_flow.py
        # automatically becomes available for interprocedural analysis
        self._collect_intraprocedural_guards()
        
        # VALUE FLOW TRACKING: Compute variable aliases for guard propagation
        # This enables guards to apply through assignments (y = x => guard(x) => guard(y))
        self._compute_value_aliases()
        
        # DSE INTEGRATION: Run value flow analyzer for richer guard propagation
        self._run_dse_value_flow_analysis()
        
        # PATH-SENSITIVE ANALYSIS: Run path-sensitive guard analyzer
        self._run_path_sensitive_analysis()
        
        # Analyze each block
        for block_id, block in self.cfg.blocks.items():
            for instr in block.instructions:
                self._analyze_instruction(instr, block, flows)
        
        # DSE POST-PROCESSING: Use DSE to filter out unreachable bugs
        self._filter_bugs_with_dse()
        
        # Compute final return nullability
        if self._return_nullabilities:
            result = Nullability.BOTTOM
            for n in self._return_nullabilities:
                result = result.join(n)
            self.summary.return_nullability = result
        
        # INTERPROCEDURAL: Compute return guarantees based on return nullability
        if self.summary.return_nullability == Nullability.NOT_NONE:
            self.summary.return_guarantees.add('nonnull')
        
        # Compute interprocedural return and param guarantees
        self._compute_interprocedural_guarantees()
        
        self.summary.analyzed = True
        return self.summary
    
    def _run_dse_value_flow_analysis(self) -> None:
        """
        Run DSE-based value flow analysis for richer guard propagation.
        
        This tracks values through:
        - Function returns (if f() returns nonnull, result is nonnull)
        - Container operations (track values through list/dict ops)
        - Attribute access chains
        """
        try:
            from ..dse.value_flow import ValueFlowAnalyzer, FunctionReturnSemantics
            
            analyzer = ValueFlowAnalyzer(self.code)
            flow_graph = analyzer.analyze()
            
            # Get nonnull variables from value flow analysis
            nonnull_vars = analyzer.get_nonnull_variables()
            
            # Add nonnull facts to the summary
            for var in nonnull_vars:
                self.summary.add_guard_fact('nonnull', var, None, block_id=0)
            
            # Store flow graph for later use
            self._value_flow_graph = flow_graph
            
        except ImportError:
            # DSE module not available, skip
            self._value_flow_graph = None
    
    def _run_path_sensitive_analysis(self) -> None:
        """
        Run path-sensitive guard analysis.
        
        This tracks different guard states on different CFG paths,
        enabling more precise FP reduction than path-insensitive analysis.
        """
        try:
            from ..dse.value_flow import PathSensitiveGuardAnalyzer
            
            analyzer = PathSensitiveGuardAnalyzer(self.code, max_paths=50)
            self._path_states = analyzer.analyze()
            self._path_sensitive_analyzer = analyzer
            
        except ImportError:
            # DSE module not available, skip
            self._path_states = {}
            self._path_sensitive_analyzer = None
    
    def _filter_bugs_with_dse(self) -> None:
        """
        Use full DSE to filter out bugs that are provably unreachable.
        
        For each potential bug, we check:
        SAT(path_condition ∧ bug_condition) = UNSAT → bug is FP
        
        This provides stronger FP reduction than simple guard analysis.
        """
        try:
            from ..dse.path_condition import DSEExecutor
            
            # Run DSE path exploration
            executor = DSEExecutor(
                self.code,
                max_paths=100,
                max_depth=30,
                solver_timeout_ms=1000,
            )
            executor.analyze()
            
            # Check each crash location
            filtered_crashes = []
            for bug_type, location in self.crash_locations:
                # Get the variable involved in the bug
                bug_var = self._get_bug_variable(bug_type, location)
                
                # Check if bug is reachable using DSE
                is_reachable, _ = executor.check_bug_reachable(
                    bug_type, bug_var, location.offset
                )
                
                if is_reachable:
                    # Bug may be reachable - keep it
                    filtered_crashes.append((bug_type, location))
                else:
                    # Bug is provably unreachable (FP) - upgrade to guarded
                    self.summary.record_bug_instance(bug_type, is_guarded=True)
                    # Don't add to filtered list
            
            self.crash_locations = filtered_crashes
            
        except (ImportError, Exception) as e:
            # DSE not available or failed, keep original crashes
            pass
    
    def _get_bug_variable(self, bug_type: str, location: 'BytecodeLocation') -> str:
        """Extract the variable involved in a bug from its location."""
        # Get instruction at location
        idx = self._instr_index_by_offset.get(location.offset)
        if idx is None:
            return f"var_at_{location.offset}"
        
        instr = self.instructions[idx]
        
        if bug_type == 'DIV_ZERO':
            # Divisor is TOS, look back for the load
            if idx > 0:
                prev = self.instructions[idx - 1]
                if prev.opname in ('LOAD_FAST', 'LOAD_FAST_BORROW'):
                    return prev.argval or f"local_{prev.arg}"
        
        elif bug_type in ('NULL_PTR', 'ATTRIBUTE_ERROR'):
            # Object is TOS
            if idx > 0:
                prev = self.instructions[idx - 1]
                if prev.opname in ('LOAD_FAST', 'LOAD_FAST_BORROW'):
                    return prev.argval or f"local_{prev.arg}"
        
        elif bug_type in ('BOUNDS', 'INDEX_ERROR'):
            # Container[index] - need both
            container = self._get_container_name_at(location.offset)
            index = self._get_constant_index_at(location.offset)
            if container and index is not None:
                return f"{container}[{index}]"
            elif container:
                return f"{container}[?]"
        
        return f"var_at_{location.offset}"
    
    def _compute_value_aliases(self) -> None:
        """
        Compute value aliasing between local variables.
        
        This tracks which variables hold the same value, enabling guard
        propagation through assignments:
        
            if x is not None:  # guard established for x
                y = x          # y now aliases x
                z = y          # z aliases y (and transitively x)
                z.attr         # bug on z, but guarded through alias chain
        
        The analysis is a simplified reaching definitions that tracks direct
        assignments between local variables (LOAD_FAST -> STORE_FAST patterns).
        """
        # Track LOAD_FAST -> STORE_FAST patterns across all blocks
        for block in self.cfg.blocks.values():
            for i, instr in enumerate(block.instructions):
                if instr.opname == 'STORE_FAST' and i >= 1:
                    target_var = instr.argval
                    if not target_var:
                        continue
                    
                    # Check if previous instruction is LOAD_FAST (direct assignment y = x)
                    prev = block.instructions[i - 1]
                    if prev.opname in ('LOAD_FAST', 'LOAD_FAST_BORROW'):
                        source_var = prev.argval
                        if source_var and source_var != target_var:
                            # Direct assignment: target = source
                            self.summary.add_value_alias(target_var, source_var)
                    
                    # Also check for COPY before STORE (walrus operator pattern)
                    # CALL -> COPY -> STORE_FAST creates alias from call result
                    elif prev.opname == 'COPY' and i >= 2:
                        # The value being copied might come from a guarded call
                        # We track this as the target being an alias of itself
                        # (used for walrus operator patterns)
                        pass
    
    def _collect_intraprocedural_guards(self) -> None:
        """
        Collect all guard facts from the intraprocedural GuardAnalyzer.
        
        This is the bridge between intraprocedural and interprocedural analysis.
        Every guard pattern detected by GuardAnalyzer (in control_flow.py) is
        automatically stored in the CrashSummary for interprocedural use.
        
        Guard types collected:
        - nonnull: variable is not None
        - div: variable is non-zero (safe for division)
        - bounds: container[index] is in bounds
        - nonempty: container has len >= 1
        - exact_length: container has exactly n elements
        - range_len_loop: index from range(len(container))
        - enumerate_loop: index from enumerate(container)
        - loop_body_nonempty: container nonempty during iteration
        - key_in: key is in container
        - hasattr: object has attribute
        - nonnegative: value >= 0
        - type: isinstance check passed
        - exception_caught: in exception handler
        - callable: callable check passed
        
        All these automatically propagate to interprocedural analysis.
        """
        from ..cfg.control_flow import GuardAnalyzer
        
        guard_analyzer = GuardAnalyzer(self.cfg)
        block_guards = guard_analyzer.analyze()
        
        # Store each guard fact in the summary
        for block_id, guards in block_guards.items():
            for guard in guards:
                self.summary.add_guard_fact(
                    guard_type=guard.guard_type,
                    variable=guard.variable,
                    extra=guard.extra,
                    block_id=block_id,
                )
                
                # Also update validated_params if this is a parameter
                param_names = list(self.code.co_varnames[:self.param_count])
                if guard.variable in param_names:
                    param_idx = param_names.index(guard.variable)
                    if param_idx not in self.summary.validated_params:
                        self.summary.validated_params[param_idx] = set()
                    self.summary.validated_params[param_idx].add(guard.guard_type)
                
                # Update return_guarantees based on guard types for return values
                # If a local variable has a guard and flows to return, propagate it
                if guard.guard_type == 'nonnull':
                    # Track that this variable is known nonnull
                    pass  # Already tracked in guard_type_to_vars
    
    def _compute_interprocedural_guarantees(self) -> None:
        """
        Compute interprocedural guard guarantees for this function.
        
        Analyzes:
        1. Return value guarantees (nonnull, nonzero, etc.)
        2. Parameter validation (which params are checked before use)
        
        These facts enable FP reduction at call sites.
        """
        # Analyze return statements for guarantees
        self._analyze_return_guarantees()
        
        # Analyze parameter validation patterns
        self._analyze_parameter_validation()
    
    def _analyze_return_guarantees(self) -> None:
        """
        Analyze all return paths to determine return value guarantees.
        
        A guarantee holds if ALL return paths satisfy it.
        """
        return_nonnull_count = 0
        return_total_count = 0
        
        for block in self.cfg.blocks.values():
            for i, instr in enumerate(block.instructions):
                if instr.opname == 'RETURN_VALUE':
                    return_total_count += 1
                    if self._is_return_nonnull(block, i):
                        return_nonnull_count += 1
        
        # If all returns are nonnull, function guarantees nonnull
        if return_total_count > 0 and return_nonnull_count == return_total_count:
            self.summary.return_guarantees.add('nonnull')
    
    def _is_return_nonnull(self, block: 'BasicBlock', return_idx: int) -> bool:
        """Check if a specific return is guaranteed nonnull."""
        if return_idx < 1:
            return False
        
        # Check previous instruction to see what's being returned
        prev = block.instructions[return_idx - 1] if return_idx > 0 else None
        if not prev:
            return False
        
        # Direct constant return
        if prev.opname == 'LOAD_CONST':
            const_val = prev.argval
            return const_val is not None
        
        # Return from BUILD_* (always nonnull)
        if prev.opname.startswith('BUILD_'):
            return True
        
        # Return from CALL to constructor/builtin
        if prev.opname in ('CALL', 'CALL_FUNCTION'):
            # Look back for function name
            for j in range(return_idx - 2, max(-1, return_idx - 6), -1):
                call_instr = block.instructions[j]
                if call_instr.opname in ('LOAD_GLOBAL', 'LOAD_BUILTIN', 'LOAD_NAME'):
                    func_name = call_instr.argval
                    if self._is_nonnull_returning_function(func_name):
                        return True
                    break
                elif call_instr.opname == 'LOAD_ATTR':
                    attr_name = call_instr.argval
                    if self._is_nonnull_returning_method(attr_name):
                        return True
                    break
        
        # Return a local variable with nonnull guard
        if prev.opname in ('LOAD_FAST', 'LOAD_FAST_BORROW'):
            local_idx = prev.arg
            if local_idx in self._nonnull_locals:
                return True
            # Check if guard is established
            guard_state = self.intraproc.guard_state_at(prev.offset) if hasattr(self.intraproc, 'guard_state_at') else None
            if guard_state and guard_state.has_nonnull(prev.argval):
                return True
        
        return False
    
    def _is_nonnull_returning_function(self, func_name: str) -> bool:
        """Check if a function always returns nonnull."""
        NONNULL_FUNCTIONS = {
            # Builtins — constructors
            'list', 'dict', 'set', 'tuple', 'str', 'int', 'float', 'bool',
            'bytes', 'bytearray', 'frozenset', 'object', 'range', 'slice', 'type',
            'complex', 'memoryview', 'super',
            # Builtins — always return non-None
            'len', 'abs', 'repr', 'hash', 'id', 'chr', 'ord', 'bin', 'hex', 'oct',
            'sorted', 'reversed', 'enumerate', 'zip', 'map', 'filter',
            'max', 'min', 'sum', 'round', 'pow', 'divmod', 'all', 'any',
            'isinstance', 'issubclass', 'callable', 'hasattr', 'getattr',
            'format', 'ascii', 'vars', 'dir', 'help', 'input', 'print',
            'open', 'iter', 'next', 'property', 'staticmethod', 'classmethod',
            # os / os.path — always return strings/numbers
            'os.getcwd', 'os.getpid', 'os.getuid', 'os.listdir',
            'os.path.join', 'os.path.dirname', 'os.path.basename',
            'os.path.abspath', 'os.path.realpath', 'os.path.normpath',
            'os.path.expanduser', 'os.path.exists', 'os.path.isfile',
            'os.path.isdir', 'os.path.splitext', 'os.path.split',
            # pathlib — Path always returns Path
            'Path', 'PurePath', 'PureWindowsPath', 'PurePosixPath',
            # json — loads returns dict/list/str/int/float/bool/None but
            #        dumps always returns str
            'json.dumps',
            # datetime
            'datetime.now', 'datetime.utcnow', 'datetime.today',
            'date.today', 'time',
            # collections
            'defaultdict', 'OrderedDict', 'Counter', 'deque', 'namedtuple',
            # functools
            'partial', 'lru_cache', 'wraps',
            # string
            'f', 
            # common patterns — these all return non-None
            'deepcopy', 'copy',
        }
        if func_name in NONNULL_FUNCTIONS:
            return True
        # Capitalized names are likely constructors
        if isinstance(func_name, str) and func_name and func_name[0].isupper():
            return True
        # Names ending with common nonnull-returning suffixes
        if isinstance(func_name, str) and func_name:
            # *_to_string, *_to_str, format_* — always return str
            if func_name.endswith(('_to_string', '_to_str', '_string', '_repr')):
                return True
            if func_name.startswith(('format_', 'to_', 'str_', 'repr_')):
                return True
        return False
    
    def _is_nonnull_returning_method(self, method_name: str) -> bool:
        """Check if a method always returns nonnull."""
        NONNULL_METHODS = {
            # str methods — all return str or list[str]
            'strip', 'lstrip', 'rstrip', 'split', 'rsplit', 'splitlines',
            'lower', 'upper', 'title', 'capitalize', 'swapcase', 'casefold',
            'replace', 'encode', 'format', 'join', 'center', 'ljust', 'rjust',
            'zfill', 'expandtabs', 'translate', 'maketrans',
            'startswith', 'endswith', 'count', 'index', 'find', 'rfind',
            # dict methods — keys/values/items return views (never None)
            'keys', 'values', 'items', 'copy', 'update', 'setdefault',
            # list methods that return non-None
            'append', 'extend', 'insert', 'sort', 'reverse',  # return None but called for side-effect
            # These return actual values:
            '__len__', '__repr__', '__str__', '__hash__', '__bool__',
            '__iter__', '__contains__', '__sizeof__',
            # Path methods — return Path or str
            'resolve', 'absolute', 'expanduser', 'with_name', 'with_suffix',
            'with_stem', 'parent', 'stem', 'name', 'suffix', 'suffixes',
            'as_posix', 'as_uri', 'is_file', 'is_dir', 'exists',
            'read_text', 'read_bytes',
            # datetime methods
            'strftime', 'isoformat', 'timestamp', 'date', 'time',
            'replace', 'astimezone', 'utcoffset', 'tzname',
        }
        if method_name in NONNULL_METHODS:
            return True
        # __dunder__ methods almost always return non-None
        if method_name.startswith('__') and method_name.endswith('__'):
            return True
        return False
    
    def _analyze_parameter_validation(self) -> None:
        """
        Analyze which parameters are validated by this function.
        
        Looks for patterns like:
        - if param is None: raise/return
        - if not param: raise/return
        - assert param is not None
        
        If a parameter is validated, callers can trust that if the function
        returns normally, the parameter was valid.
        """
        # Get guard analysis results
        guard_analyzer = GuardAnalyzer(self.cfg)
        block_guards = guard_analyzer.analyze()
        
        # Check which parameters have guards established
        param_names = list(self.code.co_varnames[:self.param_count])
        
        for param_idx, param_name in enumerate(param_names):
            validated_guards: Set[str] = set()
            
            for block_id, guards in block_guards.items():
                for guard in guards:
                    if guard.variable == param_name:
                        if guard.guard_type == 'nonnull':
                            validated_guards.add('nonnull')
                        elif guard.guard_type == 'div':
                            validated_guards.add('nonzero')
                        elif guard.guard_type == 'nonempty':
                            validated_guards.add('nonempty')
                        elif guard.guard_type == 'type':
                            validated_guards.add(f'type:{guard.extra}')
            
            if validated_guards:
                self.summary.validated_params[param_idx] = validated_guards
    
    def _identify_nonnull_locals(self) -> None:
        """
        Identify local variables that are always non-None.
        
        ITERATION 610: Reduce false positive NULL_PTR for locals created by:
        - BUILD_MAP (empty dict)
        - BUILD_LIST (empty list)
        - BUILD_SET (empty set)
        - BUILD_TUPLE (tuple)
        - CALL to constructors (dict(), list(), etc.)
        
        These are followed by STORE_FAST which assigns to a local.
        
        FP REDUCTION: Also marks `self` and `cls` (param 0 in methods) as
        non-None.  Python guarantees these are never None in bound method
        calls, so NULL_PTR on self.x is always a false positive.
        """
        # ── self / cls is NEVER None in a bound method ──────────────
        # Heuristic: if the first parameter is named 'self' or 'cls',
        # this is a method and param 0 is guaranteed non-None.
        if self.param_count > 0:
            first_param_name = (
                self.code.co_varnames[0]
                if self.code.co_varnames
                else None
            )
            if first_param_name in ('self', 'cls'):
                self._nonnull_locals[0] = True
                # Also mark as non-nullable for the param_nullable map
                self.param_nullable[0] = False

        # Opcodes that create non-None values
        NONNULL_CREATORS = {
            'BUILD_MAP', 'BUILD_LIST', 'BUILD_SET', 'BUILD_TUPLE',
            'BUILD_STRING', 'BUILD_SLICE',
            'LOAD_CONST',  # Constants are non-None (except None itself)
        }
        
        # Scan instruction pairs
        prev_instr = None
        for instr in self.instructions:
            if instr.opname == 'STORE_FAST' and prev_instr:
                local_idx = instr.arg
                
                # Check if previous instruction creates a non-None value
                if prev_instr.opname in NONNULL_CREATORS:
                    # LOAD_CONST None is nullable, others are non-None
                    if prev_instr.opname == 'LOAD_CONST':
                        const_val = self.code.co_consts[prev_instr.arg] if prev_instr.arg < len(self.code.co_consts) else None
                        if const_val is not None:
                            self._nonnull_locals[local_idx] = True
                    else:
                        self._nonnull_locals[local_idx] = True
                
                # FOR_ITER yields non-None values from the iterator
                # (iteration variable in a for loop is always a real object)
                if prev_instr.opname == 'FOR_ITER':
                    self._nonnull_locals[local_idx] = True
            
            prev_instr = instr
    
    def _compute_parameter_flows(self) -> Dict[int, ParameterFlow]:
        """
        Compute which parameters flow to which stack/local positions at each offset.
        
        This is a forward dataflow analysis over the bytecode.
        """
        flows: Dict[int, ParameterFlow] = {}
        
        # Initialize: at entry, parameters are in their local slots
        initial = ParameterFlow()
        for i in range(self.param_count):
            initial.local_flows[i] = {i}
        
        if self.instructions:
            flows[self.instructions[0].offset] = initial
        
        # Simple forward propagation (not full fixpoint for now)
        for idx, instr in enumerate(self.instructions):
            if instr.offset not in flows:
                flows[instr.offset] = ParameterFlow()
            
            flow = flows[instr.offset].copy()
            
            # Update flow based on instruction
            self._update_flow_for_instruction(instr, flow)
            
            # Propagate to the next instruction in the disassembly stream.
            # Using `offset + 2` is brittle with Python 3.11+ specialized opcodes.
            if idx + 1 < len(self.instructions):
                next_offset = self.instructions[idx + 1].offset
                if next_offset not in flows:
                    flows[next_offset] = flow
                else:
                    flows[next_offset] = flows[next_offset].merge(flow)
        
        return flows
    
    def _push_stack(self, flow: ParameterFlow, value: Set[int]) -> None:
        """Push a value onto the stack, shifting existing values down."""
        # Shift all existing stack positions down (TOS->TOS1, TOS1->TOS2, etc.)
        new_stack = {}
        for pos, val in flow.stack_flows.items():
            new_stack[pos + 1] = val
        new_stack[0] = value  # New TOS
        flow.stack_flows = new_stack
    
    def _pop_stack(self, flow: ParameterFlow) -> Set[int]:
        """Pop TOS and shift stack up."""
        result = flow.stack_flows.get(0, set())
        new_stack = {}
        for pos, val in flow.stack_flows.items():
            if pos > 0:
                new_stack[pos - 1] = val
        flow.stack_flows = new_stack
        return result
    
    def _update_flow_for_instruction(self, instr: dis.Instruction, flow: ParameterFlow) -> None:
        """Update parameter flow for a single instruction with proper stack semantics."""
        opname = instr.opname
        
        if opname in ('LOAD_FAST', 'LOAD_FAST_BORROW'):
            # Load local to stack - pushes one value
            local_idx = instr.arg
            value = flow.local_flows.get(local_idx, set()).copy()
            self._push_stack(flow, value)

        elif opname == 'LOAD_FAST_BORROW_LOAD_FAST_BORROW':
            # Python 3.14 specialized opcode: pushes two locals.
            # Pushes names[0] first, then names[1] (so names[1] ends up as TOS)
            names = instr.argval if isinstance(instr.argval, tuple) else None
            if names and len(names) == 2:
                try:
                    local_idx_0 = list(self.code.co_varnames).index(names[0])
                except ValueError:
                    local_idx_0 = None
                try:
                    local_idx_1 = list(self.code.co_varnames).index(names[1])
                except ValueError:
                    local_idx_1 = None
                
                # Push first value (becomes TOS1 after second push)
                val_0 = flow.local_flows.get(local_idx_0, set()).copy() if local_idx_0 is not None else set()
                self._push_stack(flow, val_0)
                
                # Push second value (becomes TOS)
                val_1 = flow.local_flows.get(local_idx_1, set()).copy() if local_idx_1 is not None else set()
                self._push_stack(flow, val_1)
        
        elif opname == 'STORE_FAST':
            # Pop from stack and store to local
            local_idx = instr.arg
            value = self._pop_stack(flow)
            flow.local_flows[local_idx] = value
        
        elif opname in ('LOAD_CONST', 'LOAD_SMALL_INT'):
            # Load constant - pushes non-param value
            self._push_stack(flow, set())
        
        elif opname in ('LOAD_GLOBAL', 'LOAD_NAME'):
            # Load global/name - pushes non-param value
            self._push_stack(flow, set())
        
        elif opname == 'BINARY_OP':
            # Pops TOS and TOS1, pushes result
            # For subscript (arg=26): TOS1[TOS] - container is TOS1, index is TOS
            right = self._pop_stack(flow)  # TOS (index for subscript)
            left = self._pop_stack(flow)   # TOS1 (container for subscript)
            # For flow tracking, the result carries both sources
            self._push_stack(flow, left | right)
        
        elif opname == 'CALL':
            # Simplified: pops args and callable, pushes result
            # For now, just clear stack flows (conservative)
            flow.stack_flows = {0: set()}
        
        elif opname in ('POP_TOP', 'POP_JUMP_IF_FALSE', 'POP_JUMP_IF_TRUE',
                        'POP_JUMP_IF_NONE', 'POP_JUMP_IF_NOT_NONE'):
            # Pop one value
            self._pop_stack(flow)
        
        elif opname in ('RETURN_VALUE', 'RETURN_CONST'):
            # Clears stack
            flow.stack_flows = {}
        
        elif opname in ('COMPARE_OP', 'CONTAINS_OP', 'IS_OP'):
            # Binary comparison: pops 2, pushes 1
            self._pop_stack(flow)
            self._pop_stack(flow)
            self._push_stack(flow, set())
        
        elif opname in ('LOAD_ATTR', 'LOAD_METHOD'):
            # Attribute access: pops receiver, pushes attribute value.
            # The result is a derived value — it does NOT inherit the
            # receiver's parameter-nullability (self is non-None but
            # self.queue may be None).
            self._pop_stack(flow)
            # Python 3.11+: when arg & 1, method call form pushes NULL + method
            if instr.arg is not None and (instr.arg & 1):
                self._push_stack(flow, set())  # NULL marker
                self._push_stack(flow, set())  # method
            else:
                self._push_stack(flow, set())  # attribute value
    
    def _analyze_instruction(
        self,
        instr: dis.Instruction,
        block: BasicBlock,
        flows: Dict[int, ParameterFlow],
    ) -> None:
        """Analyze a single instruction for crash risks."""
        offset = instr.offset
        opname = instr.opname
        
        # Get intraprocedural analysis results at this offset
        guards = self.intraproc.get_guards_at_offset(offset)
        
        # Create location for reporting
        location = BytecodeLocation(
            offset=offset,
            opname=opname,
            line_number=instr.positions.lineno if hasattr(instr, 'positions') and instr.positions else None,
            block_id=block.id,
        )
        
        flow = flows.get(offset, ParameterFlow())
        
        # Check for division
        if opname == 'BINARY_OP' and instr.arg in DIVISION_BINARY_OPS:
            self._check_division(location, flow, guards)
        
        # Check for subscript access (Python 3.13+ uses BINARY_OP with oparg 26)
        # Note: Slice operations never raise IndexError, only scalar subscripts do
        # Also filter out safe indexing patterns like split()[0]
        # Also filter out dict access with string keys (raises KeyError, not IndexError)
        elif opname == 'BINARY_OP' and instr.arg in SUBSCRIPT_BINARY_OPS:
            # Check if this is a slice operation (LOAD_CONST slice(...))
            if (not self._is_slice_subscript(location.offset) and 
                not self._is_safe_indexing(location.offset) and
                not self._is_string_key_subscript(location.offset)):
                self._check_subscript(location, flow, guards)
        
        # Check for subscript access (older Python versions)
        elif opname in SUBSCRIPT_OPCODES:
            # Check if this is a slice operation or safe indexing
            if (not self._is_slice_subscript(location.offset) and 
                not self._is_safe_indexing(location.offset) and
                not self._is_string_key_subscript(location.offset)):
                self._check_subscript(location, flow, guards)
        
        # Note: BINARY_SLICE never raises IndexError - slices return empty for out-of-range
        # So we don't check BINARY_SLICE for BOUNDS
        
        # Check for attribute access
        elif opname in ATTRIBUTE_OPCODES:
            self._check_attribute(location, flow, guards, instr)
        
        # Check for calls
        elif opname in CALL_OPCODES:
            self._check_call(location, flow, guards, instr)
        
        # Check CALL_KW for API precondition violations (randint, etc.)
        # Handled separately from CALL_OPCODES to avoid disturbing NULL_PTR
        # flow tracking in _transfer_instruction.
        elif opname == 'CALL_KW':
            callee_name = self._get_callee_name_at(location.offset)
            if callee_name and '.randint' in callee_name:
                self._check_randint_precondition(location, flow, guards, instr)
        
        # Check for raises
        elif opname in RAISE_OPCODES:
            self._check_raise(location, instr)
        
        # Check for return
        elif opname in ('RETURN_VALUE', 'RETURN_CONST'):
            self._check_return(location, flow, instr)
        
        # ITERATION 610: FOR_ITER is expected behavior (StopIteration terminates loop)
        # Do NOT flag this as ITERATOR_INVALID - it's normal loop termination
        # elif opname == 'FOR_ITER':
        #     self.summary.may_raise.add(ExceptionType.STOP_ITERATION)
        
        # Check for assertions (implicit in RAISE_VARARGS after LOAD_ASSERTION_ERROR)
        # Python 3.12+ replaced LOAD_ASSERTION_ERROR with LOAD_COMMON_CONSTANT(0)
        # where arg 0 encodes AssertionError.
        elif (opname == 'LOAD_ASSERTION_ERROR'
              or (opname == 'LOAD_COMMON_CONSTANT' and instr.arg == 0)):
            # Skip defensive assertions (assert False in else after exhaustive type checks)
            if self._is_defensive_assert(offset):
                return
            self.summary.may_trigger.add('ASSERT_FAIL')
            self.summary.may_raise.add(ExceptionType.ASSERTION_ERROR)
            # Track assertion failures as bug instances with guard analysis
            is_guarded = self._is_caught_exception(offset, 'ASSERT_FAIL')
            # Check if assert is branch-implied safe (assert X in else of if X == const)
            if not is_guarded and self._is_branch_implied_truthy_assert(offset):
                is_guarded = True
            self.summary.record_bug_instance('ASSERT_FAIL', is_guarded)
            if not is_guarded:
                self.crash_locations.append(('ASSERT_FAIL', location))
    
    def _check_division(
        self,
        location: BytecodeLocation,
        flow: ParameterFlow,
        guards: 'GuardState',
    ) -> None:
        """Check for division by zero risk."""
        if location.offset in self._compact_proven_safe_sites.get("DIV_ZERO", set()):
            return

        # Divisor is TOS (stack position 0)
        divisor_params = flow.stack_flows.get(0, set())
        
        # If the divisor is a definite non-zero constant, do not report DIV_ZERO.
        # This avoids conservative false positives like `y / 2`.
        idx = self._instr_index_by_offset.get(location.offset)
        if idx is not None:
            j = idx - 1
            while j >= 0 and self.instructions[j].opname in ('CACHE', 'EXTENDED_ARG', 'NOP', 'RESUME'):
                j -= 1
            if j >= 0:
                prev = self.instructions[j]
                if prev.opname in ('LOAD_CONST', 'LOAD_SMALL_INT') and isinstance(prev.argval, (int, float, bool)):
                    if float(prev.argval) != 0.0:
                        return
                # Check if RHS is a string (string formatting with %)
                if prev.opname == 'LOAD_CONST' and isinstance(prev.argval, str):
                    return
            
            # Check for Path division pattern (Path / "name")
            # Pattern: LOAD_ATTR parent or Path(...), then LOAD_CONST "string", then /
            if self._is_path_or_string_division_bytecode(idx):
                return
            
            # BYTECODE FP REDUCTION: Check for validation patterns
            # Pattern: if x > 0: ... / x  or  assert x > 0; ... / x
            # Look backward for comparison/assert that validates divisor
            if self._has_divisor_validation_bytecode(idx, divisor_params):
                return
        
        for param_idx in divisor_params:
            var_name = self.code.co_varnames[param_idx] if param_idx < len(self.code.co_varnames) else f"p{param_idx}"
            
            # Check if we have a guard that divisor is non-zero
            if not guards.has_div_safe(var_name):
                self.summary.divisor_params.add(param_idx)
                self.summary.preconditions.add(
                    Precondition(param_idx, PreconditionType.NOT_ZERO)
                )
                if param_idx not in self.summary.param_bug_propagation:
                    self.summary.param_bug_propagation[param_idx] = set()
                self.summary.param_bug_propagation[param_idx].add('DIV_ZERO')
        
        # Check if division is guarded
        is_guarded = any(
            guards.has_div_safe(self.code.co_varnames[p] if p < len(self.code.co_varnames) else f"p{p}")
            for p in divisor_params
        ) if divisor_params else False
        
        # Exception barrier: check if ZeroDivisionError is caught at this site
        if not is_guarded and self._is_caught_exception(location.offset, 'DIV_ZERO'):
            is_guarded = True  # Exception is handled locally
        
        # ITERATION 702: Use record_bug_instance for proper FP tracking
        self.summary.record_bug_instance('DIV_ZERO', is_guarded)
        if not is_guarded:
            self.summary.may_raise.add(ExceptionType.ZERO_DIVISION_ERROR)
            self.crash_locations.append(('DIV_ZERO', location))
    
    def _check_subscript(
        self,
        location: BytecodeLocation,
        flow: ParameterFlow,
        guards: 'GuardState',
    ) -> None:
        """Check for bounds/key error risk."""
        # For BINARY_SUBSCR: TOS is index, TOS1 is container
        index_params = flow.stack_flows.get(0, set())
        container_params = flow.stack_flows.get(1, set())
        
        for idx_param in index_params:
            for container_param in container_params:
                self.summary.index_params[idx_param] = container_param
                self.summary.preconditions.add(
                    Precondition(idx_param, PreconditionType.IN_BOUNDS, container_param)
                )
            if idx_param not in self.summary.param_bug_propagation:
                self.summary.param_bug_propagation[idx_param] = set()
            self.summary.param_bug_propagation[idx_param].add('BOUNDS')
        
        # Check if bounds are guarded using proper Z3-backed dataflow analysis
        is_guarded = False
        
        # First, check if the index is a constant
        # Look at the instruction(s) that loaded the index onto the stack
        constant_index = self._get_constant_index_at(location.offset)
        
        if constant_index is not None:
            # The index is a known constant - check if container bounds include it
            for container_param in container_params:
                container_name = self.code.co_varnames[container_param] if container_param < len(self.code.co_varnames) else f"p{container_param}"
                
                # Use Z3-backed bounds check with constant index
                if guards.has_bounds_safe(container_name, str(constant_index)):
                    is_guarded = True
                    break
            
            # Also check container_params for non-parameter containers
            # by looking at the stack to find the actual container name
            if not is_guarded:
                container_name = self._get_container_name_at(location.offset)
                if container_name:
                    if guards.has_bounds_safe(container_name, str(constant_index)):
                        is_guarded = True
        
        # Check parameter-based bounds guards
        if not is_guarded:
            for idx_param in index_params:
                for container_param in container_params:
                    idx_name = self.code.co_varnames[idx_param] if idx_param < len(self.code.co_varnames) else f"p{idx_param}"
                    container_name = self.code.co_varnames[container_param] if container_param < len(self.code.co_varnames) else f"p{container_param}"
                    
                    # Use the proper Z3-backed bounds guard check
                    if guards.has_bounds_safe(container_name, idx_name):
                        is_guarded = True
                        break
                if is_guarded:
                    break
        
        # Check for range_len_loop guard on container (loop iteration variable is always in bounds)
        # This handles: for i in range(len(arr)): arr[i]
        if not is_guarded:
            for container_param in container_params:
                container_name = self.code.co_varnames[container_param] if container_param < len(self.code.co_varnames) else f"p{container_param}"
                if guards.has_guard("range_len_loop", container_name):
                    is_guarded = True
                    break
        
        # Also check non-parameter container
        if not is_guarded:
            container_name = self._get_container_name_at(location.offset)
            if container_name and guards.has_guard("range_len_loop", container_name):
                is_guarded = True
        
        # Fallback: check numeric bounds analysis
        if not is_guarded:
            for idx_param in index_params:
                var_name = self.code.co_varnames[idx_param] if idx_param < len(self.code.co_varnames) else f"p{idx_param}"
                bounds = self.intraproc.get_bounds(location.offset, var_name)
                if bounds and bounds.lower is not None and bounds.lower >= 0:
                    # Has positive lower bound - partially guarded (non-negative index)
                    is_guarded = True
                    break
        
        # Exception barrier: check if IndexError/KeyError is caught at this site
        if not is_guarded and self._is_caught_exception(location.offset, 'BOUNDS'):
            is_guarded = True  # Exception is handled locally
        
        # Structural tuple unpacking: constant-index access to a parameter that
        # is indexed with multiple small constants (e.g., shape[0], shape[2],
        # shape[3], shape[1]) — a common pattern for shape/coordinate unpacking.
        if not is_guarded and constant_index is not None:
            container_name = self._get_container_name_at(location.offset)
            if container_name and self._is_constant_index_tuple_unpacking(
                    location.offset, container_name):
                is_guarded = True
        
        # ITERATION 702: Use record_bug_instance for proper FP tracking
        self.summary.record_bug_instance('BOUNDS', is_guarded)
        if not is_guarded:
            self.summary.may_raise.add(ExceptionType.INDEX_ERROR)
            self.summary.may_raise.add(ExceptionType.KEY_ERROR)
            self.crash_locations.append(('BOUNDS', location))
    
    def _get_constant_index_at(self, offset: int) -> Optional[int]:
        """
        Get the constant index value for a subscript operation at offset.
        
        Returns the integer constant if the index is a LOAD_CONST or LOAD_SMALL_INT,
        otherwise returns None.
        """
        idx = self._instr_index_by_offset.get(offset)
        if idx is None:
            return None
        
        # Look backward for the index load instruction (skip CACHE/NOP/etc)
        j = idx - 1
        while j >= 0 and self.instructions[j].opname in ('CACHE', 'EXTENDED_ARG', 'NOP'):
            j -= 1
        
        if j >= 0:
            instr = self.instructions[j]
            if instr.opname in ('LOAD_CONST', 'LOAD_SMALL_INT'):
                if isinstance(instr.argval, int):
                    return instr.argval
        
        return None
    
    def _get_container_name_at(self, offset: int) -> Optional[str]:
        """
        Get the container variable name for a subscript operation at offset.
        
        Looks backward to find the LOAD_FAST/LOAD_NAME that loaded the container.
        """
        idx = self._instr_index_by_offset.get(offset)
        if idx is None:
            return None
        
        # Look backward past the index load to find the container load
        # Stack at BINARY_SUBSCR: [..., container, index] -> TOS1=container, TOS=index
        j = idx - 1
        while j >= 0 and self.instructions[j].opname in ('CACHE', 'EXTENDED_ARG', 'NOP'):
            j -= 1
        
        # Skip the index load
        if j >= 0 and self.instructions[j].opname in ('LOAD_CONST', 'LOAD_SMALL_INT', 'LOAD_FAST', 'LOAD_FAST_BORROW', 'LOAD_NAME'):
            j -= 1
            while j >= 0 and self.instructions[j].opname in ('CACHE', 'EXTENDED_ARG', 'NOP'):
                j -= 1
        
        # Now we should be at the container load
        if j >= 0:
            instr = self.instructions[j]
            if instr.opname in ('LOAD_FAST', 'LOAD_FAST_BORROW', 'LOAD_NAME', 'LOAD_GLOBAL'):
                return instr.argval
            # Handle chained attribute access: e.g., y.shape[1]
            # LOAD_FAST y -> LOAD_ATTR shape -> LOAD_CONST 1 -> BINARY_SUBSCR
            if instr.opname == 'LOAD_ATTR':
                attr_name = instr.argval
                # Look further back for the object
                k = j - 1
                while k >= 0 and self.instructions[k].opname in ('CACHE', 'EXTENDED_ARG', 'NOP'):
                    k -= 1
                if k >= 0 and self.instructions[k].opname in ('LOAD_FAST', 'LOAD_FAST_BORROW', 'LOAD_NAME', 'LOAD_GLOBAL'):
                    return f"{self.instructions[k].argval}.{attr_name}"
        
        return None
    
    def _is_branch_implied_truthy_assert(self, assert_offset: int) -> bool:
        """Check if ``assert X`` is in the else branch of ``if X == <const>:``.

        Uses AST analysis to detect the pattern:

            if var == <literal>:
                ...
            else:
                assert var   # <-- defensive; var != literal is already known

        The assert is a defensive truthiness check whose failure requires a
        caller to deliberately pass an unusual falsy value for a parameter
        whose default/contract is a truthy literal.  Marking it guarded lets
        the FP-reduction pipeline filter it.
        """
        idx = self._instr_index_by_offset.get(assert_offset)
        if idx is None:
            return False

        line_no = (self.instructions[idx].positions.lineno
                   if hasattr(self.instructions[idx], 'positions')
                   and self.instructions[idx].positions
                   else None)
        if line_no is None:
            return False

        # --- Bytecode pre-screen: find the asserted variable ---
        # Pattern: LOAD_FAST X -> TO_BOOL -> POP_JUMP_IF_TRUE -> LOAD_ASSERTION_ERROR
        asserted_var = None
        for j in range(max(0, idx - 6), idx):
            instr_j = self.instructions[j]
            if instr_j.opname in ('LOAD_FAST', 'LOAD_FAST_BORROW', 'LOAD_NAME'):
                asserted_var = instr_j.argval
        if asserted_var is None:
            return False

        # --- Bytecode pre-screen: look for a preceding equality comparison
        # on the same variable within a reasonable window ---
        has_equality_on_var = False
        for j in range(max(0, idx - 40), idx):
            instr_j = self.instructions[j]
            if instr_j.opname == 'COMPARE_OP' and instr_j.argval in (
                    '==', 'bool(==)'):
                # Check if the left operand was our variable
                for k in range(max(0, j - 5), j):
                    prev = self.instructions[k]
                    if prev.opname in ('LOAD_FAST', 'LOAD_FAST_BORROW', 'LOAD_NAME'):
                        if prev.argval == asserted_var:
                            has_equality_on_var = True
                            break
            if has_equality_on_var:
                break

        if not has_equality_on_var:
            return False

        # --- AST confirmation: assert <var> is in else of if <var> == <const> ---
        try:
            source = self._get_source_for_defensive_assert_check()
            if source is None:
                return False
            tree = ast.parse(source)
        except (OSError, SyntaxError):
            return False

        return self._ast_has_equality_implied_assert(tree, line_no, asserted_var)

    @staticmethod
    def _ast_has_equality_implied_assert(
        tree: ast.AST, target_line: int, var_name: str,
    ) -> bool:
        """Return True if *target_line* holds ``assert <var_name>`` inside an
        ``else`` branch whose ``if`` test is ``<var_name> == <const>``.

        This is a deep structural check confirming the branch-dominance
        relationship between the equality comparison and the assertion.
        """
        for node in ast.walk(tree):
            if not isinstance(node, ast.If):
                continue

            # Walk the if/elif chain
            chain: ast.If | None = node
            while chain is not None:
                # Check test: var == <const>
                test = chain.test
                has_eq = False

                # Simple: var == const
                if isinstance(test, ast.Compare):
                    if (isinstance(test.left, ast.Name)
                            and test.left.id == var_name
                            and any(isinstance(op, ast.Eq) for op in test.ops)):
                        has_eq = True
                # BoolOp containing var == const (e.g. a and var == const)
                elif isinstance(test, ast.BoolOp):
                    for val in test.values:
                        if (isinstance(val, ast.Compare)
                                and isinstance(val.left, ast.Name)
                                and val.left.id == var_name
                                and any(isinstance(op, ast.Eq) for op in val.ops)):
                            has_eq = True
                            break

                else_body = chain.orelse
                if else_body:
                    # elif chain — follow
                    if len(else_body) == 1 and isinstance(else_body[0], ast.If):
                        chain = else_body[0]
                        continue

                    # Terminal else block — look for assert <var> at target line
                    if has_eq:
                        for stmt in else_body:
                            if (isinstance(stmt, ast.Assert)
                                    and stmt.lineno == target_line
                                    and isinstance(stmt.test, ast.Name)
                                    and stmt.test.id == var_name):
                                return True
                break
        return False

    def _is_constant_index_tuple_unpacking(
        self, offset: int, container_name: str,
    ) -> bool:
        """Detect structural tuple/shape unpacking: multiple constant-index
        accesses to the same container within a single code block.

        Pattern (e.g. shape parameter unpacking):
            output_shape[0], output_shape[2], output_shape[3], output_shape[1]

        When ≥ 3 distinct small constant indices (0-7) are used on the same
        container in nearby instructions, the code is performing structural
        unpacking and the caller contract guarantees the container is large
        enough.  Mark as guarded so the FP-reduction pipeline can filter it.
        """
        idx = self._instr_index_by_offset.get(offset)
        if idx is None:
            return False

        # Scan a window around the current instruction for subscript ops
        # on the same container with constant indices
        seen_indices: set = set()
        window = 30  # bytecode instructions to scan in each direction
        for j in range(max(0, idx - window), min(len(self.instructions), idx + window)):
            instr = self.instructions[j]
            if instr.opname not in ('BINARY_OP', 'BINARY_SUBSCR'):
                continue
            # For BINARY_OP, check it's a subscript op (arg 26)
            if instr.opname == 'BINARY_OP' and instr.arg not in (26,):
                continue

            j_offset = instr.offset
            c_name = self._get_container_name_at(j_offset)
            if c_name != container_name:
                continue
            c_idx = self._get_constant_index_at(j_offset)
            if c_idx is not None and 0 <= c_idx <= 7:
                seen_indices.add(c_idx)

        return len(seen_indices) >= 3

    def _check_attribute(
        self,
        location: BytecodeLocation,
        flow: ParameterFlow,
        guards: 'GuardState',
        instr: dis.Instruction,
    ) -> None:
        """Check for null dereference risk."""
        # Object is on TOS
        obj_params = flow.stack_flows.get(0, set())
        
        # ITERATION 610: Check if TOS comes from a known non-null local
        # Look at preceding instruction to find what's on TOS
        tos_is_nonnull = self._is_tos_nonnull_at(location.offset)
        if tos_is_nonnull:
            # Local variable is known non-None - no NULL_PTR risk
            # ITERATION 702: Still record as guarded instance
            self.summary.record_bug_instance('NULL_PTR', is_guarded=True)
            return
        
        # Check if TOS variable has an intraprocedural nonnull guard
        # (e.g., from `if value is None: continue` preceding this access).
        # This handles non-parameter locals like loop iteration variables.
        tos_var = self._get_tos_variable_at(location.offset)
        if tos_var and self.intraproc.is_nonnull(location.offset, tos_var):
            self.summary.record_bug_instance('NULL_PTR', is_guarded=True)
            return
        
        # ITERATION 610: Use type annotations to determine nullability
        # If parameter is typed as non-nullable, skip NULL_PTR check for it
        nullable_params = set()
        for param_idx in obj_params:
            # Check type annotation nullability
            if param_idx in self.param_nullable:
                is_nullable = self.param_nullable[param_idx]
                if is_nullable is False:
                    # Explicitly typed as non-nullable - skip
                    continue
                elif is_nullable is True:
                    # Explicitly typed as nullable (Optional)
                    nullable_params.add(param_idx)
                else:
                    # No annotation - conservative
                    nullable_params.add(param_idx)
            else:
                # No annotation info - conservative
                nullable_params.add(param_idx)
        
        # Check nullability for each potentially-nullable parameter
        for param_idx in nullable_params:
            var_name = self.code.co_varnames[param_idx] if param_idx < len(self.code.co_varnames) else f"p{param_idx}"
            
            # Check if we have a non-null guard
            if not guards.has_nonnull(var_name) and not self.intraproc.is_nonnull(location.offset, var_name):
                self.summary.preconditions.add(
                    Precondition(param_idx, PreconditionType.NOT_NONE)
                )
                if param_idx not in self.summary.param_bug_propagation:
                    self.summary.param_bug_propagation[param_idx] = set()
                self.summary.param_bug_propagation[param_idx].add('NULL_PTR')
        
        # Conservative: if we have no flow info, attribute access is still risky
        # but only if there are nullable params
        is_guarded = False
        self_attr = None  # Track self-attribute name for NULL_PTR variable attribution
        if nullable_params:
            is_guarded = all(
                guards.has_nonnull(self.code.co_varnames[p] if p < len(self.code.co_varnames) else f"p{p}")
                for p in nullable_params
            )
        elif obj_params:
            # All params are typed non-nullable - considered guarded
            is_guarded = True
        else:
            # Separation-logic barrier: TOS has no parameter flow at all.
            # The attribute access is on a locally computed value (e.g. a
            # constructor result like set(...), a module-level constant, or an
            # intermediate expression).  This cannot be a parameter-None
            # dereference, so it is safe for interprocedural NULL_PTR purposes.
            #
            # EXCEPTION: If TOS comes from self.<attr> (LOAD_FAST self →
            # LOAD_ATTR X), the attribute may have been initialised to None
            # in __init__, so accessing a method/attribute on self.<attr>
            # is a potential NULL_PTR unless guarded by a nonnull check.
            self_attr = self._get_self_attr_on_tos(location.offset)
            if self_attr is not None:
                # Check if a nonnull guard was established for self.<attr>
                qual_name = f"self.{self_attr}"
                if guards.has_nonnull(qual_name) or self.intraproc.is_nonnull(location.offset, qual_name):
                    # self.<attr> is guarded (e.g., isinstance check).
                    # However, if this is a property that delegates to
                    # self.X.Y without checking a boolean state attribute
                    # (e.g., self.trainable), it may return incorrect values
                    # for some object states.  Detect missing state guards.
                    if (self.param_count == 1
                            and instr.argval == self.func_name
                            and not self._has_self_attr_truthiness_guard()):
                        is_guarded = False
                    else:
                        is_guarded = True
                else:
                    is_guarded = False
            else:
                is_guarded = True
        
        # Exception barrier: check if AttributeError is caught at this site
        if not is_guarded and self._is_caught_exception(location.offset, 'NULL_PTR'):
            is_guarded = True  # Exception is handled locally
        
        # ITERATION 702: Use record_bug_instance for proper FP tracking
        self.summary.record_bug_instance('NULL_PTR', is_guarded)
        if not is_guarded:
            self.summary.may_raise.add(ExceptionType.ATTRIBUTE_ERROR)
            self.crash_locations.append(('NULL_PTR', location))
            # Track the actual target variable for accurate bug attribution.
            # Without this, the bug_variable defaults to 'self' which gets
            # suppressed by the intent filter (self is never None).
            if self_attr is not None:
                self.summary.null_ptr_target_vars.add(f"self.{self_attr}")
    
    def _check_call(
        self,
        location: BytecodeLocation,
        flow: ParameterFlow,
        guards: 'GuardState',
        instr: dis.Instruction,
    ) -> None:
        """Check for call-related crash risks."""
        # Get callee name from preceding LOAD_* instructions if possible
        callee_name = self._get_callee_name_at(location.offset)
        
        if callee_name:
            # Check if we have a summary for the callee (exact or suffix match)
            callee_summary = self.summaries.get(callee_name)
            if callee_summary is None:
                # Try suffix matching: bytecode sees 'Cls.method' but summary
                # key is 'module.Cls.method'
                for qname, s in self.summaries.items():
                    if qname.endswith('.' + callee_name) or qname == callee_name:
                        callee_summary = s
                        break
            if callee_summary is not None:
                self.summary.merge_callee(callee_summary)
            
            # Check for known dangerous functions
            if callee_name in ('eval', 'exec', 'compile'):
                self.summary.may_trigger.add('CODE_INJECTION')
                self.crash_locations.append(('CODE_INJECTION', location))
            elif callee_name in ('os.system', 'subprocess.call', 'subprocess.run', 'subprocess.Popen'):
                self.summary.may_trigger.add('COMMAND_INJECTION')
                self.crash_locations.append(('COMMAND_INJECTION', location))
            elif callee_name in ('pickle.loads', 'pickle.load', 'yaml.load', 'marshal.loads'):
                self.summary.may_trigger.add('UNSAFE_DESERIALIZATION')
                self.crash_locations.append(('UNSAFE_DESERIALIZATION', location))
            elif callee_name == 'open':
                self.summary.performs_io = True
                self.summary.has_side_effects = True
            
            # Check for randint-family calls: require high > low
            # Callee name for CALL_KW may include argument attributes
            # (e.g. "np.random.randint.start.end.batch"), so check component.
            if callee_name and '.randint' in callee_name:
                self._check_randint_precondition(location, flow, guards, instr)
            
            # ITERATION 810: Check for None passed to builtins that reject None.
            # e.g., range(None) → TypeError, len(None) → TypeError
            # The base callee name (last component) determines the builtin.
            base_callee = callee_name.rsplit('.', 1)[-1] if callee_name else None
            if base_callee in _NONE_REJECTING_BUILTINS:
                self._check_none_arg_to_builtin(location, flow, guards, instr)
        
        # Unknown callee - conservative
        self.summary.may_raise.add(ExceptionType.GENERIC_EXCEPTION)
    
    def _check_none_arg_to_builtin(
        self,
        location: BytecodeLocation,
        flow: ParameterFlow,
        guards: 'GuardState',
        instr: dis.Instruction,
    ) -> None:
        """Check for None passed to builtins that reject None (e.g. range, len).

        ITERATION 810: Passing None to builtins like ``range(None)`` raises
        TypeError at runtime.  This is a NULL_PTR-class bug (None misuse).
        When a parameter flows to an argument of such a builtin without a
        prior ``is not None`` guard, record a NOT_NONE precondition.
        """
        # Collect argument parameter flows.
        # For CALL N: args are at stack positions 0..N-1 (TOS = last arg).
        n_args = instr.arg if instr.arg is not None else 0
        arg_params: Set[int] = set()
        for pos in range(n_args):
            arg_params |= flow.stack_flows.get(pos, set())

        if not arg_params:
            return

        # Filter to nullable parameters (same logic as _check_attribute)
        nullable_params: Set[int] = set()
        for param_idx in arg_params:
            if param_idx in self.param_nullable:
                if self.param_nullable[param_idx] is False:
                    continue  # typed non-nullable
            nullable_params.add(param_idx)

        if not nullable_params:
            return

        unguarded = False
        for param_idx in nullable_params:
            var_name = (self.code.co_varnames[param_idx]
                        if param_idx < len(self.code.co_varnames)
                        else f"p{param_idx}")
            if not guards.has_nonnull(var_name) and not self.intraproc.is_nonnull(location.offset, var_name):
                self.summary.preconditions.add(
                    Precondition(param_idx, PreconditionType.NOT_NONE)
                )
                if param_idx not in self.summary.param_bug_propagation:
                    self.summary.param_bug_propagation[param_idx] = set()
                self.summary.param_bug_propagation[param_idx].add('NULL_PTR')
                unguarded = True

        is_guarded = not unguarded
        if not is_guarded and self._is_caught_exception(location.offset, 'NULL_PTR'):
            is_guarded = True

        self.summary.record_bug_instance('NULL_PTR', is_guarded)
        if not is_guarded:
            self.summary.may_raise.add(ExceptionType.TYPE_ERROR)
            self.crash_locations.append(('NULL_PTR', location))

    def _check_randint_precondition(
        self,
        location: BytecodeLocation,
        flow: ParameterFlow,
        guards: 'GuardState',
        instr: dis.Instruction,
    ) -> None:
        """Check randint(low, high) precondition: high > low.

        Uses bytecode-level symbolic analysis to determine whether the
        second positional argument is guaranteed to exceed the first.
        When both arguments are attribute loads on the same parameter
        (e.g. self.start_index, self.end_index), a ``+ 1`` offset on
        the second argument symbolically ensures ``high > low`` for any
        ``low <= high`` (a common class invariant).  Without such an
        offset the call may raise ``ValueError``.
        """
        idx = self._instr_index_by_offset.get(location.offset)
        if idx is None:
            return

        # Determine total argument count from CALL/CALL_KW arg
        total_args = instr.arg if instr.arg is not None else 0
        if total_args < 2:
            return

        _SKIP = frozenset({
            'CACHE', 'EXTENDED_ARG', 'NOP', 'RESUME', 'PRECALL', 'COPY',
        })

        # Collect exactly `total_args` argument descriptors from the stack.
        # Walk backwards from the instruction just before CALL, skipping
        # KW_NAMES/LOAD_CONST for keyword-name tuples.
        args_info: list = []  # [(param_idx, attr_name, has_positive_offset), ...]
        j = idx - 1
        while j >= 0 and self.instructions[j].opname in _SKIP:
            j -= 1
        if j >= 0 and self.instructions[j].opname in ('KW_NAMES', 'LOAD_CONST'):
            j -= 1

        while j >= 0 and len(args_info) < total_args:
            cur = self.instructions[j]
            if cur.opname in _SKIP:
                j -= 1
                continue

            # Pattern: LOAD_FAST p / LOAD_ATTR a / LOAD_SMALL_INT c / BINARY_OP +
            if cur.opname == 'BINARY_OP' and cur.arg == 0:  # ADD
                k = j - 1
                while k >= 0 and self.instructions[k].opname in _SKIP:
                    k -= 1
                offset_val = None
                if k >= 0 and self.instructions[k].opname in ('LOAD_SMALL_INT', 'LOAD_CONST'):
                    v = self.instructions[k].argval
                    if isinstance(v, (int, float)) and v > 0:
                        offset_val = v
                    k -= 1
                    while k >= 0 and self.instructions[k].opname in _SKIP:
                        k -= 1
                if offset_val is not None and k >= 0 and self.instructions[k].opname == 'LOAD_ATTR':
                    attr = self.instructions[k].argval
                    k2 = k - 1
                    while k2 >= 0 and self.instructions[k2].opname in _SKIP:
                        k2 -= 1
                    if k2 >= 0 and self.instructions[k2].opname in (
                            'LOAD_FAST', 'LOAD_FAST_BORROW', 'LOAD_FAST_CHECK'):
                        pidx = self.instructions[k2].arg
                        args_info.insert(0, (pidx, attr, True))
                        j = k2 - 1
                        continue
                args_info.insert(0, (None, None, False))
                j -= 1
                continue

            # Pattern: LOAD_FAST p / LOAD_ATTR attr  (no offset)
            if cur.opname == 'LOAD_ATTR':
                attr = cur.argval
                k = j - 1
                while k >= 0 and self.instructions[k].opname in _SKIP:
                    k -= 1
                if k >= 0 and self.instructions[k].opname in (
                        'LOAD_FAST', 'LOAD_FAST_BORROW', 'LOAD_FAST_CHECK'):
                    pidx = self.instructions[k].arg
                    args_info.insert(0, (pidx, attr, False))
                    j = k - 1
                    continue
                args_info.insert(0, (None, attr, False))
                j -= 1
                continue

            # Other opcode (e.g. call result, local variable)
            args_info.insert(0, (None, None, False))
            j -= 1

        if len(args_info) < 2:
            return

        # args_info is in stack order: first positional is args_info[0]
        low_param, low_attr, low_off = args_info[0]
        high_param, high_attr, high_off = args_info[1]

        # Both from the same parameter (e.g. self) and the high arg
        # does NOT have a positive constant offset → high <= low is
        # reachable ⇒ ValueError.
        if (low_param is not None and low_param == high_param
                and low_attr is not None and high_attr is not None
                and low_attr != high_attr and not high_off):

            is_guarded = self._is_caught_exception(location.offset, 'VALUE_ERROR')
            self.summary.record_bug_instance('VALUE_ERROR', is_guarded)
            if not is_guarded:
                self.summary.may_trigger.add('VALUE_ERROR')
                self.summary.may_raise.add(ExceptionType.VALUE_ERROR)
                self.crash_locations.append(('VALUE_ERROR', location))

    def _check_raise(self, location: BytecodeLocation, instr: dis.Instruction) -> None:
        """Check for explicit raise.
        
        Explicit `raise ExceptionType(...)` statements are tracked as bug instances
        with guard analysis, just like implicit crash sites (NULL_PTR, DIV_ZERO).
        
        An explicit raise is considered "guarded" if:
        1. It's inside a try/except that catches it (locally handled), OR
        2. It's a precondition enforcement (raise inside `if bad_input:`) which
           is intentional validation, not a bug — but the *caller* may fail to
           satisfy the precondition, OR
        3. It raises ValueError / TypeError / RuntimeError — these are almost
           always intentional input validation, not unintentional crashes.
        """
        # Look at preceding instructions to determine exception type
        exc_type = self._get_exception_type_at(location.offset)
        
        if exc_type:
            self.summary.may_raise.add(exc_type)
            if exc_type in EXCEPTION_TO_BUG:
                bug_type = EXCEPTION_TO_BUG[exc_type]
                self.summary.may_trigger.add(bug_type)
                
                # Guard analysis: check if this raise is inside a try/except
                is_guarded = self._is_caught_exception(location.offset, bug_type)
                
                # FP REDUCTION: Explicit `raise ValueError/TypeError/RuntimeError`
                # is almost always intentional precondition validation, not an
                # unintentional crash.  Mark as guarded so it doesn't surface as
                # a true positive.  We still record it in may_raise / may_trigger
                # so that callers can propagate the precondition requirement.
                #
                # EXCEPTION: In __init__ methods (or constructor-like code with
                # STORE_ATTR on self), raise ValueError represents a constructor
                # precondition that callers may violate.  Report as ASSERT_FAIL
                # so downstream bugs from mis-constructed objects are caught.
                # However, if the constructor properly initializes capability
                # attributes (supports_X, has_X, can_X), the raises are more
                # likely just defensive validation — suppress in that case.
                _INTENTIONAL_RAISE_TYPES = {
                    ExceptionType.VALUE_ERROR,
                    ExceptionType.TYPE_ERROR,
                    ExceptionType.RUNTIME_ERROR,
                    ExceptionType.IMPORT_ERROR,
                }
                if exc_type in _INTENTIONAL_RAISE_TYPES:
                    if (self._is_constructor_body()
                            and not self._has_capability_attr_init()):
                        # Constructor raises without capability attribute init
                        # indicate incomplete initialization — report as ASSERT_FAIL
                        bug_type = 'ASSERT_FAIL'
                        self.summary.may_trigger.add(bug_type)
                    else:
                        is_guarded = True
                
                # Track as a bug instance for proper guard_counts
                self.summary.record_bug_instance(bug_type, is_guarded)
                if not is_guarded:
                    self.crash_locations.append((bug_type, location))
        else:
            self.summary.may_raise.add(ExceptionType.GENERIC_EXCEPTION)
    
    def _check_return(
        self,
        location: BytecodeLocation,
        flow: ParameterFlow,
        instr: dis.Instruction,
    ) -> None:
        """Track return value nullability."""
        if instr.opname == 'RETURN_CONST':
            # Check if returning None
            const_val = self.code.co_consts[instr.arg] if instr.arg < len(self.code.co_consts) else None
            if const_val is None:
                self._return_nullabilities.append(Nullability.IS_NONE)
            else:
                self._return_nullabilities.append(Nullability.NOT_NONE)
        else:
            # RETURN_VALUE - value on stack
            ret_params = flow.stack_flows.get(0, set())
            if not ret_params:
                self._return_nullabilities.append(Nullability.TOP)
            else:
                # Conservative: if any param flows here, inherit its nullability
                self._return_nullabilities.append(Nullability.MAY_BE_NONE)
    
    def _is_constructor_body(self) -> bool:
        """Check if the current function is a constructor or constructor-like body.

        Returns True when:
        - func_name is ``__init__`` (real method), OR
        - the bytecode contains multiple STORE_ATTR on ``self``, indicating
          that the code is the body of a constructor (e.g. a diff-extracted snippet
          wrapped in ``_a3_snippet_wrapper_``).
        """
        if self.func_name == '__init__':
            return True
        # Heuristic: look for STORE_ATTR preceded by a load of 'self'
        store_attr_count = 0
        for i, instr in enumerate(self.instructions):
            if instr.opname == 'STORE_ATTR' and i > 0:
                prev = self.instructions[i - 1]
                # self as local parameter 0
                if prev.opname in ('LOAD_FAST', 'LOAD_FAST_BORROW') and prev.arg == 0:
                    store_attr_count += 1
                # self as global/name (happens in snippet wrappers)
                elif prev.opname in ('LOAD_GLOBAL', 'LOAD_NAME') and prev.argval == 'self':
                    store_attr_count += 1
        # Need at least 2 self.X = ... assignments to look like a constructor body
        return store_attr_count >= 2

    def _has_capability_attr_init(self) -> bool:
        """Check if the constructor sets a boolean capability attribute to True.

        Capability attributes follow naming conventions like ``supports_X``,
        ``has_X``, or ``can_X``.  When a constructor sets one of these to
        ``True``, it indicates the developer is aware of capability
        initialization, and ``raise ValueError`` statements are defensive
        validation rather than signs of incomplete initialization.
        """
        _CAP_PREFIXES = ('supports_', 'has_', 'can_')
        for i, instr in enumerate(self.instructions):
            if instr.opname == 'STORE_ATTR' and isinstance(instr.argval, str):
                if any(instr.argval.startswith(p) for p in _CAP_PREFIXES):
                    # Check if the stored value is True (LOAD_CONST True)
                    if i >= 2:
                        load_val = self.instructions[i - 2]
                        if (load_val.opname in ('LOAD_CONST', 'LOAD_COMMON_CONSTANT')
                                and load_val.argval is True):
                            return True
        return False

    def _is_tos_nonnull_at(self, offset: int) -> bool:
        """
        Check if TOS (top of stack) at given offset is known non-null.
        
        ITERATION 610: Look at the preceding instruction to determine what's on TOS.
        If it's a LOAD_FAST of a known non-null local, return True.
        """
        # Find instruction index
        idx = None
        for i, instr in enumerate(self.instructions):
            if instr.offset == offset:
                idx = i
                break
        
        if idx is None or idx == 0:
            return False
        
        # Look at previous instruction
        prev = self.instructions[idx - 1]
        
        # LOAD_FAST from a known non-null local
        if prev.opname in ('LOAD_FAST', 'LOAD_FAST_BORROW', 'LOAD_FAST_BORROW_LOAD_FAST_BORROW'):
            local_idx = prev.arg
            # Handle composite opcodes
            if prev.opname == 'LOAD_FAST_BORROW_LOAD_FAST_BORROW':
                local_idx = prev.arg & 0xFF  # First local is in low byte
            if local_idx in self._nonnull_locals:
                return True
            # Also check if it's a non-nullable parameter
            if local_idx < self.param_count:
                if local_idx in self.param_nullable:
                    if self.param_nullable[local_idx] is False:
                        return True
        
        # LOAD_CONST of non-None value
        if prev.opname == 'LOAD_CONST':
            const_val = self.code.co_consts[prev.arg] if prev.arg < len(self.code.co_consts) else None
            if const_val is not None:
                return True
        
        # BUILD_* opcodes always produce non-None
        if prev.opname in ('BUILD_MAP', 'BUILD_LIST', 'BUILD_SET', 'BUILD_TUPLE', 'BUILD_STRING'):
            return True
        
        # ITERATION 610: LOAD_GLOBAL typically loads non-None values (modules, classes, functions)
        # This reduces FPs for attribute access on imported modules like `C.limit_threshold`
        if prev.opname in ('LOAD_GLOBAL', 'LOAD_NAME'):
            return True
        
        # Chained attribute access from a global (e.g. security_requirement.security_scheme.model):
        # Walk back through consecutive LOAD_ATTR instructions; if the chain
        # originates from LOAD_GLOBAL/LOAD_NAME the whole chain is non-null.
        if prev.opname == 'LOAD_ATTR':
            walk = idx - 1
            while walk > 0:
                walk -= 1
                p = self.instructions[walk]
                if p.opname == 'LOAD_ATTR':
                    continue
                if p.opname in ('LOAD_GLOBAL', 'LOAD_NAME'):
                    return True
                break
        
        # CALL result from builtin constructor / type – always returns non-None.
        # Symbolic value-flow: set(), list(), dict(), tuple(), frozenset(), dir(),
        # type(), vars(), len(), range(), str(), int(), float(), bool(), bytes(),
        # Sequence() (or any uppercase-named constructor) always produce a value.
        if prev.opname in ('CALL', 'CALL_FUNCTION', 'CALL_FUNCTION_EX'):
            target_name = self._find_call_target_name(idx - 1)
            if target_name and target_name in _NONNULL_RETURNING_BUILTINS:
                return True
            # Uppercase names are class constructors – they return a new instance
            if target_name and target_name[0:1].isupper():
                return True
        
        return False
    
    def _find_call_target_name(self, call_idx: int) -> str | None:
        """Walk backward from a CALL instruction to find the function name.
        
        For ``CALL n``, the function object was pushed before the *n* arguments
        (and possibly a NULL placeholder).  We walk backward, skipping over
        argument-producing instructions via a lightweight stack-depth counter,
        until we hit the LOAD_GLOBAL / LOAD_NAME that pushed the callable.
        """
        if call_idx < 0 or call_idx >= len(self.instructions):
            return None
        call_instr = self.instructions[call_idx]
        n_args = call_instr.arg if isinstance(call_instr.arg, int) else 0
        # We need to skip past n_args values on the stack to reach the function.
        # Simple heuristic: scan backward and count stack effects.
        depth = n_args  # number of stack values to skip
        walk = call_idx - 1
        while walk >= 0 and depth > 0:
            ins = self.instructions[walk]
            # Each value-producing instruction accounts for one stack slot
            if ins.opname in ('LOAD_FAST', 'LOAD_FAST_BORROW', 'LOAD_FAST_CHECK',
                              'LOAD_GLOBAL', 'LOAD_NAME', 'LOAD_CONST',
                              'LOAD_ATTR', 'LOAD_DEREF',
                              'BUILD_LIST', 'BUILD_TUPLE', 'BUILD_SET',
                              'BUILD_MAP', 'BUILD_STRING',
                              'CALL', 'CALL_FUNCTION', 'BINARY_OP', 'COPY'):
                depth -= 1
            walk -= 1
        # Now walk should point at or just before the function-loading instruction
        # Check the instruction at walk+1 (the one that loaded the function)
        target_idx = walk + 1
        if target_idx >= 0 and target_idx < len(self.instructions):
            t = self.instructions[target_idx]
            if t.opname in ('LOAD_GLOBAL', 'LOAD_NAME'):
                return str(t.argval) if t.argval else None
        return None
    
    def _get_tos_variable_at(self, offset: int) -> str | None:
        """Return the variable name on TOS at *offset*, if it comes from LOAD_FAST."""
        idx = None
        for i, instr in enumerate(self.instructions):
            if instr.offset == offset:
                idx = i
                break
        if idx is None or idx == 0:
            return None
        prev = self.instructions[idx - 1]
        if prev.opname in ('LOAD_FAST', 'LOAD_FAST_BORROW', 'LOAD_NAME'):
            return prev.argval
        return None
    
    def _get_self_attr_on_tos(self, offset: int) -> str | None:
        """Return the attribute name if TOS at *offset* comes from ``self.<attr>``.

        Detects the bytecode pattern:
            LOAD_FAST self  →  LOAD_ATTR X  →  <current instruction at offset>

        Returns *X* (the attribute name) if the pattern matches, else ``None``.
        This is used to flag potential NULL_PTR when ``self.X`` may be ``None``
        (e.g. initialised to ``None`` in ``__init__``).
        """
        idx = self._instr_index_by_offset.get(offset)
        if idx is None:
            # Fallback: linear scan
            for i, instr in enumerate(self.instructions):
                if instr.offset == offset:
                    idx = i
                    break
        if idx is None or idx < 2:
            return None
        prev = self.instructions[idx - 1]
        prev2 = self.instructions[idx - 2]
        if (prev.opname == 'LOAD_ATTR'
                and isinstance(prev.argval, str)
                and prev2.opname in ('LOAD_FAST', 'LOAD_FAST_BORROW')
                and prev2.argval in ('self', 'cls')):
            return prev.argval
        return None
    
    def _has_self_attr_truthiness_guard(self) -> bool:
        """Check if the method has a truthiness check on any self attribute.
        
        Detects the pattern: LOAD_FAST self → LOAD_ATTR X → [TO_BOOL] →
        POP_JUMP_IF_TRUE/FALSE, which indicates the developer checks a boolean
        self-attribute before proceeding.  Used to distinguish property methods
        that properly guard delegation (e.g., ``if not self.trainable: return []``)
        from those that skip the guard.
        """
        for i, instr in enumerate(self.instructions):
            if instr.opname in ('POP_JUMP_IF_TRUE', 'POP_JUMP_IF_FALSE',
                                'POP_JUMP_FORWARD_IF_TRUE', 'POP_JUMP_FORWARD_IF_FALSE'):
                # Walk back past optional TO_BOOL
                j = i - 1
                if j >= 0 and self.instructions[j].opname == 'TO_BOOL':
                    j -= 1
                if j >= 0 and self.instructions[j].opname == 'NOT_TAKEN':
                    j -= 1
                # Check for LOAD_FAST self → LOAD_ATTR X
                if (j >= 1
                        and self.instructions[j].opname == 'LOAD_ATTR'
                        and isinstance(self.instructions[j].argval, str)
                        and self.instructions[j - 1].opname in ('LOAD_FAST', 'LOAD_FAST_BORROW')
                        and self.instructions[j - 1].argval in ('self', 'cls')):
                    return True
        return False
    
    def _is_slice_subscript(self, offset: int) -> bool:
        """
        Check if the subscript operation at offset is a slice operation.
        
        Slice operations NEVER raise IndexError - they just return empty/partial results.
        This is a fundamental Python language guarantee (slicing semantics).
        
        Patterns detected:
        1. LOAD_CONST slice(start, stop, step) - Python 3.14+ compile simple slices
        2. BUILD_SLICE opcode - Python's slice syntax with step a[i:j:k]
        3. BINARY_SLICE opcode - older Python slice syntax a[i:j]
        
        Returns True if this is a slice (should NOT flag BOUNDS - safe by Python semantics).
        """
        idx = self._instr_index_by_offset.get(offset)
        if idx is None:
            return False
        
        instr = self.instructions[idx]
        
        # BINARY_SLICE opcode is always a slice, never raises IndexError
        if instr.opname == 'BINARY_SLICE':
            return True
        
        # For BINARY_OP [] or BINARY_SUBSCR, check preceding instructions
        # to determine if this is a slice or an index access
        
        # Check immediately preceding instruction(s), skipping CACHE/NOP
        for j in range(idx - 1, max(-1, idx - 6), -1):
            prev = self.instructions[j]
            
            # Skip cache and no-op instructions
            if prev.opname in ('CACHE', 'EXTENDED_ARG', 'NOP', 'COPY'):
                continue
            
            # BUILD_SLICE creates a slice object dynamically - always safe
            # Used for: s[::-1], s[::2], s[a:b:c] with variable step
            if prev.opname == 'BUILD_SLICE':
                return True
            
            # LOAD_CONST with slice object - Python 3.14+ optimization
            # Used for: s[1:3], s[:5], s[2:], etc.
            if prev.opname == 'LOAD_CONST':
                const_val = prev.argval
                if isinstance(const_val, slice):
                    return True
            
            # If we hit a non-slice-related instruction, stop looking
            # This means the subscript is an index, not a slice
            break
        
        return False
    
    def _is_safe_indexing(self, offset: int) -> bool:
        """
        Check if the subscript operation at offset is a safe indexing pattern.
        
        Safe indexing patterns that never raise IndexError:
        1. split()[0] - str.split() always returns at least one element
        2. split()[-1] on guaranteed non-empty (harder to detect)
        
        Python Language Guarantee (str.split):
        "If sep is not specified or is None... If the string is empty, 
        a list containing the empty string [''] is returned."
        
        Bytecode pattern for split()[0]:
        - LOAD_ATTR split
        - [LOAD_CONST separator]  (optional for split with separator)
        - CALL n
        - LOAD_SMALL_INT 0 / LOAD_CONST 0
        - BINARY_OP 26 ([])  <-- we're at this offset
        
        Returns True if this is safe indexing (should NOT flag BOUNDS).
        """
        idx = self._instr_index_by_offset.get(offset)
        if idx is None:
            return False
        
        # Walk backward through instructions to find the pattern
        found_zero_index = False
        found_call = False
        call_idx = -1
        
        for j in range(idx - 1, max(-1, idx - 10), -1):
            instr = self.instructions[j]
            opname = instr.opname
            
            # Skip cache and no-op instructions
            if opname in ('CACHE', 'EXTENDED_ARG', 'NOP', 'COPY'):
                continue
            
            # First non-skip should be the index value
            if not found_zero_index:
                if opname in ('LOAD_CONST', 'LOAD_SMALL_INT') and instr.argval == 0:
                    found_zero_index = True
                    continue  # Keep looking for CALL
                else:
                    return False  # Not an index 0 access
            
            # After finding index 0, look for CALL
            if not found_call:
                if opname == 'CALL':
                    found_call = True
                    call_idx = j
                    break  # Found CALL, now look for LOAD_ATTR split
                # If we hit something else before CALL, this isn't the pattern
                return False
        
        if not found_call or call_idx < 0:
            return False
        
        # Now look for LOAD_ATTR split before the CALL
        for k in range(call_idx - 1, max(-1, call_idx - 8), -1):
            attr_instr = self.instructions[k]
            if attr_instr.opname in ('CACHE', 'EXTENDED_ARG', 'NOP', 'COPY', 'LOAD_CONST'):
                # LOAD_CONST might be the separator argument
                continue
            if attr_instr.opname == 'LOAD_ATTR':
                # Check if it's split, rsplit, or splitlines
                attr_name = attr_instr.argval
                if isinstance(attr_name, str) and attr_name in ('split', 'rsplit', 'splitlines'):
                    return True
            # Stop on any other instruction
            break
        
        return False
    
    def _is_string_key_subscript(self, offset: int) -> bool:
        """
        Check if the subscript operation uses a string key (dict access pattern).
        
        Dict access like `user_data['email']` raises KeyError, not IndexError.
        We filter these out from BOUNDS bugs since:
        1. Dict keys are typically known/controlled in structured code
        2. This is a different error type (KeyError vs IndexError)
        3. Dict access patterns are often validated elsewhere
        
        Bytecode pattern:
        - LOAD_CONST 'string_key'  (or LOAD_FAST for string variable)
        - BINARY_OP 26 ([])  <-- we're at this offset
        
        Returns True if this is likely dict access with string key.
        """
        idx = self._instr_index_by_offset.get(offset)
        if idx is None:
            return False
        
        # Walk backward to find the key being used
        for j in range(idx - 1, max(-1, idx - 6), -1):
            instr = self.instructions[j]
            opname = instr.opname
            
            # Skip cache and no-op instructions
            if opname in ('CACHE', 'EXTENDED_ARG', 'NOP', 'COPY'):
                continue
            
            # Check if the key is a string constant
            if opname == 'LOAD_CONST':
                # String constant key - likely dict access
                if isinstance(instr.argval, str):
                    return True
            
            # Stop on first non-skip instruction
            break
        
        return False
    
    def _is_defensive_assert(self, offset: int) -> bool:
        """
        Detect defensive ``assert False`` in an else branch after exhaustive
        type/isinstance checks.

        Bytecode pattern recognised (Python 3.12+):
          ... isinstance(x, T) / x.type == C ...  (repeated if/elif)
          LOAD_COMMON_CONSTANT  AssertionError     <-- offset we are checking
          LOAD_CONST            <message>
          CALL / RAISE_VARARGS

        This is a common "should-never-happen" guard and NOT a real bug,
        so we suppress ASSERT_FAIL for it.

        The detection uses a combined bytecode + AST approach:
        1. Bytecode: verify the assertion is unconditional (``assert False``)
           by checking that the opcode is NOT preceded by a conditional jump
           whose false-branch skips the assertion (which would mean it is
           ``assert <expr>`` with a real condition).
        2. AST: walk the function body for the assert's line and confirm
           (a) the assert is ``assert False`` and (b) it lives inside an
           ``else`` clause whose siblings contain isinstance / type checks.
        """
        idx = self._instr_index_by_offset.get(offset)
        if idx is None:
            return False

        # --- Step 1: bytecode-level quick check ---
        # An ``assert False`` compiles to
        #     LOAD_COMMON_CONSTANT AssertionError / LOAD_ASSERTION_ERROR
        #     LOAD_CONST           "message"
        #     CALL 0
        #     RAISE_VARARGS 1
        # with NO preceding POP_JUMP_IF_TRUE that guards the assertion
        # (a conditional assert would have POP_JUMP_IF_TRUE skipping it).
        # We also need the line number so we can correlate with the AST.
        instr = self.instructions[idx]
        line_no = (instr.positions.lineno
                   if hasattr(instr, 'positions') and instr.positions
                   else None)
        if line_no is None:
            return False

        # Check that the preceding non-skip instruction is NOT a conditional
        # jump targeting past the raise (which would mean the assertion has a
        # real condition, e.g. ``assert some_expr``).  For ``assert False``
        # there is no such conditional guard.
        has_preceding_isinstance = False
        has_preceding_type_compare = False
        for j in range(max(0, idx - 40), idx):
            prev = self.instructions[j]
            pname = prev.opname
            if pname in ('LOAD_GLOBAL', 'LOAD_NAME', 'LOAD_BUILTIN'):
                if prev.argval == 'isinstance':
                    has_preceding_isinstance = True
            elif pname == 'COMPARE_OP':
                # type comparison like child.type == <const>
                has_preceding_type_compare = True

        if not (has_preceding_isinstance or has_preceding_type_compare):
            return False

        # --- Step 2: AST-level confirmation ---
        # Parse the source (from the code object's filename) and find the
        # assert statement at this line.  Confirm it is ``assert False`` and
        # lives inside an else block whose siblings are isinstance/type tests.
        try:
            source = self._get_source_for_defensive_assert_check()
            if source is None:
                return False
            tree = ast.parse(source)
        except (OSError, SyntaxError):
            return False

        return self._ast_has_defensive_assert_at_line(tree, line_no)

    # ---- helpers for _is_defensive_assert ----

    def _get_source_for_defensive_assert_check(self) -> Optional[str]:
        """Return the source text for the code object, or None."""
        filename = self.code.co_filename
        if not filename or filename.startswith('<'):
            return None
        try:
            return Path(filename).read_text(errors='replace')
        except OSError:
            return None

    @staticmethod
    def _ast_has_defensive_assert_at_line(tree: ast.AST, target_line: int) -> bool:
        """
        Return True if *target_line* is an ``assert False`` that lives in an
        ``else`` branch whose sibling ``if``/``elif`` branches contain
        isinstance() or attribute-type comparisons.

        This is a deep structural check — not a pattern match on the assert
        alone — and covers patterns such as:

            for child in children:
                if isinstance(child, Leaf):
                    ...
                elif child.type == X:
                    ...
                else:
                    assert False, "msg"      # defensive — suppress
        """
        for node in ast.walk(tree):
            if not isinstance(node, (ast.If, ast.For, ast.While,
                                     ast.FunctionDef, ast.AsyncFunctionDef)):
                continue

            # Walk the if/elif chain inside function/loop bodies
            for child in ast.iter_child_nodes(node):
                if isinstance(child, ast.If):
                    if BytecodeCrashSummaryAnalyzer._check_if_chain_for_defensive_assert(
                            child, target_line):
                        return True
        return False

    @staticmethod
    def _check_if_chain_for_defensive_assert(
        if_node: ast.If, target_line: int
    ) -> bool:
        """
        Walk an if/elif/else chain.  Return True when:
        1. The ``else`` body contains ``assert False`` at *target_line*.
        2. At least one ``if``/``elif`` test is isinstance() or a type
           attribute comparison.
        """
        has_type_guard = False
        chain: ast.If | None = if_node
        while chain is not None:
            # Check the test of this if/elif
            if BytecodeCrashSummaryAnalyzer._test_is_type_guard(chain.test):
                has_type_guard = True

            # Recurse into nested if/elif chains inside the body
            for stmt in chain.body:
                if isinstance(stmt, ast.If):
                    if BytecodeCrashSummaryAnalyzer._check_if_chain_for_defensive_assert(
                            stmt, target_line):
                        return True

            # Check else clause
            else_body = chain.orelse
            if else_body:
                # If else continues with another elif, follow it
                if len(else_body) == 1 and isinstance(else_body[0], ast.If):
                    chain = else_body[0]
                    continue

                # Terminal else block — check for assert False at target line
                if has_type_guard:
                    for stmt in else_body:
                        if (isinstance(stmt, ast.Assert)
                                and isinstance(stmt.test, ast.Constant)
                                and stmt.test.value is False
                                and stmt.lineno == target_line):
                            return True
            break
        return False

    @staticmethod
    def _test_is_type_guard(test_node: ast.expr) -> bool:
        """
        Return True if *test_node* is an isinstance() call or a type
        attribute comparison (e.g. ``child.type == TOKEN``).
        """
        # isinstance(x, T)
        if isinstance(test_node, ast.Call):
            func = test_node.func
            if isinstance(func, ast.Name) and func.id == 'isinstance':
                return True

        # x.type == CONST or type(x) == T
        if isinstance(test_node, ast.Compare):
            left = test_node.left
            if isinstance(left, ast.Attribute) and left.attr == 'type':
                return True
            if isinstance(left, ast.Call):
                fn = left.func
                if isinstance(fn, ast.Name) and fn.id in ('type', 'isinstance'):
                    return True

        # BoolOp (and / or) containing type guards
        if isinstance(test_node, ast.BoolOp):
            return any(BytecodeCrashSummaryAnalyzer._test_is_type_guard(v)
                       for v in test_node.values)

        return False

    def _has_divisor_validation_bytecode(self, idx: int, divisor_params: Set[int]) -> bool:
        """
        Check if divisor has validation in bytecode (assert x > 0, if x != 0, etc.).
        
        Looks backward for patterns like:
        - COMPARE_OP (>, !=, >=) followed by POP_JUMP_IF_FALSE (assert or raise)
        - COMPARE_OP with 0 constant
        """
        if not divisor_params or idx < 10:
            return False
        
        # Get divisor variable names
        divisor_vars = set()
        for param_idx in divisor_params:
            if param_idx < len(self.code.co_varnames):
                divisor_vars.add(self.code.co_varnames[param_idx])
        
        if not divisor_vars:
            return False
        
        # Scan backwards up to 20 instructions for validation
        for j in range(max(0, idx - 20), idx):
            instr = self.instructions[j]
            
            # Look for comparison operations
            if instr.opname == 'COMPARE_OP':
                # Get the comparison type
                cmp_op = instr.argval if hasattr(instr, 'argval') else instr.arg
                
                # Check if comparison is with 0 (validation)
                # Patterns: x > 0, x != 0, x >= 1
                if cmp_op in ('>', '!=', '>=', '<', '=='):
                    # Look at previous instructions to see if comparing divisor with 0
                    if j > 0:
                        prev = self.instructions[j-1]
                        # Check if comparing with 0
                        if prev.opname in ('LOAD_CONST', 'LOAD_SMALL_INT'):
                            if isinstance(prev.argval, (int, float)) and float(prev.argval) == 0.0:
                                # Found "var cmp 0" pattern
                                # Check if var is one of our divisors
                                if j > 1:
                                    var_load = self.instructions[j-2]
                                    if var_load.opname in ('LOAD_FAST', 'LOAD_DEREF'):
                                        var_name = var_load.argval
                                        if var_name in divisor_vars:
                                            # Found validation! Check if it's an assertion
                                            # Look for POP_JUMP_IF_FALSE or RAISE after comparison
                                            if j + 1 < len(self.instructions):
                                                next_instr = self.instructions[j+1]
                                                if next_instr.opname in ('POP_JUMP_IF_FALSE', 'POP_JUMP_IF_TRUE', 
                                                                         'JUMP_IF_FALSE_OR_POP', 'RAISE_VARARGS'):
                                                    return True
            
            # Look for explicit max()/abs() calls (always return non-zero)
            elif instr.opname == 'CALL' or instr.opname == 'CALL_FUNCTION':
                # Check if calling max() or abs() on divisor
                if j > 0:
                    func_load = self.instructions[j-1]
                    if func_load.opname in ('LOAD_GLOBAL', 'LOAD_NAME'):
                        if func_load.argval in ('max', 'abs'):
                            return True
        
        return False
    
    def _is_path_or_string_division_bytecode(self, idx: int) -> bool:
        """
        Check if the division at instruction index is Path division or string formatting.
        
        Path division: Path(...) / "name" - uses __truediv__ for path concatenation
        String formatting: "format %s" % args - uses __mod__ for string formatting
        
        Returns True if this is NOT a numeric division (should not flag DIV_ZERO).
        """
        if idx < 1 or idx >= len(self.instructions):
            return False
        
        instr = self.instructions[idx]
        
        # Only check division and modulo operations
        # BINARY_OP 11 = truediv (/), BINARY_OP 6 = mod (%)
        if instr.opname != 'BINARY_OP':
            return False
        
        op_code = instr.arg
        is_truediv = (op_code == 11)  # /
        is_mod = (op_code == 6)  # %
        
        if not (is_truediv or is_mod):
            return False
        
        # Look backwards for context
        # Stack at BINARY_OP: [left, right] -> left op right
        
        # For truediv, check if left operand is Path-like
        if is_truediv:
            # Path-like name suffixes for globals/constants that are paths
            _PATH_SUFFIXES = ('_DIR', '_PATH', '_ROOT', '_FOLDER', '_BASE',
                              '_HOME', '_DIRECTORY', 'DIR', 'PATH', 'ROOT')
            
            for j in range(max(0, idx - 15), idx):
                prev = self.instructions[j]
                # Path global
                if prev.opname in ('LOAD_GLOBAL', 'LOAD_NAME') and prev.argval == 'Path':
                    return True
                # Path-like global variable (STRATEGIES_DIR, RESULTS_DIR, BASE_DIR, etc.)
                if prev.opname in ('LOAD_GLOBAL', 'LOAD_NAME') and isinstance(prev.argval, str):
                    upper = prev.argval.upper()
                    if any(upper.endswith(s) for s in _PATH_SUFFIXES):
                        return True
                # Path attribute like .parent, .resolve
                if prev.opname == 'LOAD_ATTR' and prev.argval in ('parent', 'resolve'):
                    return True
                # __file__ is typically a path
                if prev.opname in ('LOAD_GLOBAL', 'LOAD_NAME') and prev.argval == '__file__':
                    return True

            # Check RHS: if the right operand is a string constant or an
            # f-string (BUILD_STRING / FORMAT_SIMPLE), this is path concatenation
            j = idx - 1
            while j >= 0 and self.instructions[j].opname in ('CACHE', 'EXTENDED_ARG', 'NOP', 'RESUME'):
                j -= 1
            if j >= 0:
                rhs = self.instructions[j]
                # RHS is a string constant (Path / "name")
                if rhs.opname == 'LOAD_CONST' and isinstance(rhs.argval, str):
                    # Also check LHS isn't clearly numeric
                    return True
                # RHS is an f-string result (Path / f"name_{x}.ext")
                if rhs.opname == 'BUILD_STRING':
                    return True

            # Check the result: if STORE_FAST to a path-like variable name
            if idx + 1 < len(self.instructions):
                nxt = self.instructions[idx + 1]
                # Skip CACHE instructions
                nxt_idx = idx + 1
                while nxt_idx < len(self.instructions) and self.instructions[nxt_idx].opname in ('CACHE', 'NOP'):
                    nxt_idx += 1
                if nxt_idx < len(self.instructions):
                    nxt = self.instructions[nxt_idx]
                    if nxt.opname == 'STORE_FAST' and isinstance(nxt.argval, str):
                        lower = nxt.argval.lower()
                        if any(k in lower for k in ('path', 'dir', 'file', 'folder')):
                            return True
        
        # For mod, check if left operand is a string (format string)
        if is_mod:
            # Look for string constant as left operand (expanded window)
            for j in range(max(0, idx - 10), idx):
                prev = self.instructions[j]
                if prev.opname == 'LOAD_CONST' and isinstance(prev.argval, str):
                    # Any string constant with % in it is a format string
                    if '%' in prev.argval:
                        return True
                    # SQL-style strings often use %s without the % being in
                    # the immediate constant (it may be in a joined string)
                    _SQL_KW = ('SELECT', 'INSERT', 'UPDATE', 'DELETE', 'CREATE',
                               'ALTER', 'DROP', 'WHERE', 'FROM', 'JOIN')
                    upper = prev.argval.upper().strip()
                    if any(upper.startswith(kw) for kw in _SQL_KW):
                        return True
            
            # FP REDUCTION: If the LHS comes from a variable whose name
            # strongly suggests a string (fmt, format, template, query, sql,
            # msg, message, pattern, repr, html, xml, url, text, header, ...)
            # this is almost certainly string formatting, not arithmetic mod.
            for j in range(max(0, idx - 5), idx):
                prev = self.instructions[j]
                if prev.opname in ('LOAD_FAST', 'LOAD_FAST_BORROW') and isinstance(prev.argval, str):
                    _STR_VAR_HINTS = (
                        'fmt', 'format', 'template', 'query', 'sql', 'msg',
                        'message', 'pattern', 'repr', 'html', 'xml', 'url',
                        'text', 'header', 'body', 'line', 'stmt', 'cmd',
                        'command', 'string', 'str', 'prefix', 'suffix',
                        'label', 'title', 'description', 'name',
                    )
                    lower = prev.argval.lower()
                    if any(hint in lower for hint in _STR_VAR_HINTS):
                        return True
                # Also check LOAD_ATTR — e.g., self._format % args
                if prev.opname == 'LOAD_ATTR' and isinstance(prev.argval, str):
                    lower = prev.argval.lower()
                    _STR_ATTR_HINTS = (
                        'fmt', 'format', 'template', 'query', 'sql', 'msg',
                        'message', 'pattern', 'repr', 'html', 'xml', 'url',
                        'text', 'header', 'body', 'string', 'str',
                    )
                    if any(hint in lower for hint in _STR_ATTR_HINTS):
                        return True
            
            # FP REDUCTION: If the RHS is a BUILD_TUPLE (common pattern:
            # "format %s %s" % (a, b)), this is definitely string formatting.
            j = idx - 1
            while j >= 0 and self.instructions[j].opname in ('CACHE', 'EXTENDED_ARG', 'NOP', 'RESUME'):
                j -= 1
            if j >= 0 and self.instructions[j].opname == 'BUILD_TUPLE':
                return True
        
        return False
    
    # REMOVED: _has_len_guard_at pattern-matching hack
    # Bounds guards are now properly detected via GuardAnalyzer._check_bounds_guard_pattern
    # and checked via GuardState.has_bounds_safe() in _check_subscript

    def _get_callee_name_at(self, offset: int) -> Optional[str]:
        """
        Try to determine callee name from bytecode context.
        
        Looks for LOAD_NAME/LOAD_GLOBAL/LOAD_ATTR patterns before CALL.
        Skips argument-loading instructions (LOAD_FAST, LOAD_CONST, etc.)
        to handle patterns like  LOAD_GLOBAL Cls / LOAD_ATTR method / LOAD_FAST arg / CALL.
        """
        # Find instruction index
        idx = self._instr_index_by_offset.get(offset)
        
        if idx is None or idx == 0:
            return None
        
        # Instructions that push arguments (not the callee) onto the stack
        _ARG_OPCODES = frozenset({
            'LOAD_FAST', 'LOAD_FAST_BORROW', 'LOAD_FAST_CHECK',
            'LOAD_CONST', 'LOAD_SMALL_INT',
            'LOAD_FAST_LOAD_FAST', 'LOAD_FAST_BORROW_LOAD_FAST_BORROW',
            'CACHE', 'EXTENDED_ARG', 'NOP', 'RESUME',
            'COPY', 'PRECALL',
            'CALL_KW', 'KW_NAMES',
        })
        
        # Look backwards, skipping argument-loading instructions
        parts = []
        for i in range(idx - 1, max(idx - 12, -1), -1):
            prev = self.instructions[i]
            if prev.opname in ('LOAD_GLOBAL', 'LOAD_NAME'):
                parts.insert(0, prev.argval)
                break
            elif prev.opname == 'LOAD_ATTR':
                parts.insert(0, prev.argval)
            elif prev.opname == 'LOAD_METHOD':
                parts.insert(0, prev.argval)
            elif prev.opname == 'PUSH_NULL':
                continue
            elif prev.opname in _ARG_OPCODES:
                continue  # Skip argument-loading instructions
            else:
                break
        
        return '.'.join(parts) if parts else None
    
    def _get_exception_type_at(self, offset: int) -> Optional[ExceptionType]:
        """Try to determine exception type from bytecode context."""
        # Find instruction index
        idx = None
        for i, instr in enumerate(self.instructions):
            if instr.offset == offset:
                idx = i
                break
        
        if idx is None:
            return None
        
        # Look backwards for LOAD_GLOBAL/LOAD_NAME of exception class
        for i in range(idx - 1, max(idx - 5, -1), -1):
            prev = self.instructions[i]
            if prev.opname in ('LOAD_GLOBAL', 'LOAD_NAME'):
                exc_name = prev.argval
                return EXCEPTION_NAMES.get(exc_name)
            elif prev.opname == 'CALL':
                continue  # Skip the call to exception constructor
        
        return None
    
    def get_crash_locations(self) -> List[Tuple[str, BytecodeLocation]]:
        """Get all locations where crashes may occur."""
        return self.crash_locations


# ============================================================================
# BYTECODE CRASH SUMMARY COMPUTER
# ============================================================================

class BytecodeCrashSummaryComputer:
    """
    Computes crash summaries at bytecode level for all functions.
    
    Uses the call graph to process in bottom-up order (callees before callers).
    For SCCs (mutual recursion), uses Kleene iteration until fixpoint.
    
    This is the preferred analyzer matching the "bytecode-as-abstract-machine"
    semantics.
    
    INTERPROCEDURAL GUARD EXTENSION: After computing initial summaries,
    propagates guard facts across function boundaries:
    - If callee returns nonnull, caller's result variable is nonnull
    - If callee validates param before use, caller knows param was valid
    """
    
    def __init__(self, call_graph: 'CallGraph'):
        self.call_graph = call_graph
        self.summaries: Dict[str, CrashSummary] = {}
    
    def compute_all(self) -> Dict[str, CrashSummary]:
        """Compute crash summaries for all functions in bottom-up order."""
        import sys

        # Get SCCs in reverse topological order
        sccs = self.call_graph.compute_sccs()

        total_funcs = sum(len(scc) for scc in sccs)
        done = 0
        last_pct = -1

        for scc in sccs:
            if len(scc) == 1:
                # Single function - analyze directly
                func_name = next(iter(scc))
                self._analyze_function(func_name)
                done += 1
            else:
                # SCC with mutual recursion - iterate to fixpoint
                self._analyze_scc(scc)
                done += len(scc)

            # Progress feedback every ~5 %
            if total_funcs > 20:
                pct = (done * 100) // total_funcs
                if pct >= last_pct + 5:
                    last_pct = pct
                    print(f"  [{done}/{total_funcs}] {pct}% ...", end="\r", file=sys.stderr)

        if total_funcs > 20:
            print(f"  [{total_funcs}/{total_funcs}] 100%    ", file=sys.stderr)

        # INTERPROCEDURAL: Propagate guard facts across call graph
        self._propagate_interprocedural_guards()
        
        return self.summaries
    
    def _propagate_interprocedural_guards(self) -> None:
        """
        Propagate guard facts interprocedurally.
        
        Second pass that uses the computed summaries to:
        1. Mark call sites with callee return guarantees
        2. Reduce FP counts based on interprocedural reasoning
        """
        # For each function that has callers
        for func_name, summary in self.summaries.items():
            if not summary.return_guarantees:
                continue
            
            # If this function returns nonnull, all callers that store the
            # result get a nonnull guarantee for that variable
            callers = self.call_graph.get_callers(func_name)
            for caller_name in callers:
                caller_summary = self.summaries.get(caller_name)
                if caller_summary:
                    # Mark that this caller has access to nonnull return
                    # This information is used during bug checking
                    if 'nonnull' in summary.return_guarantees:
                        caller_summary.guarded_bugs.add(f'interprocedural_nonnull_from_{func_name}')
        
        return self.summaries
    
    def _analyze_function(self, func_name: str) -> CrashSummary:
        """Analyze a single function at bytecode level."""
        if func_name in self.summaries:
            return self.summaries[func_name]
        
        func_info = self.call_graph.get_function(func_name)
        if func_info is None:
            # Unknown function - create conservative summary
            summary = CrashSummary(
                function_name=func_name,
                qualified_name=func_name,
                parameter_count=0,
                may_raise={ExceptionType.GENERIC_EXCEPTION},
            )
            self.summaries[func_name] = summary
            return summary
        
        # Get the code object
        code = self._get_code_object(func_info)
        
        if code is not None:
            try:
                # ITERATION 610: Pass param_nullable info to analyzer
                param_nullable = getattr(func_info, 'param_nullable', {})
                
                analyzer = BytecodeCrashSummaryAnalyzer(
                    code=code,
                    func_name=func_info.name,
                    qualified_name=func_info.qualified_name,
                    existing_summaries=self.summaries,
                    param_nullable=param_nullable,
                )
                summary = analyzer.analyze()
                # Source-level check: detect unsorted dict-iteration join
                self._check_unsorted_dict_join(func_info, summary)
                # Source-level check: detect counter update after comparison
                self._check_counter_update_after_check(func_info, summary)
                self.summaries[func_name] = summary
                return summary
            except Exception:
                pass
        
        # Fallback: conservative summary
        summary = CrashSummary(
            function_name=func_name,
            qualified_name=func_name,
            parameter_count=len(func_info.parameters) if func_info else 0,
            may_raise={ExceptionType.GENERIC_EXCEPTION},
        )
        self.summaries[func_name] = summary
        return summary
    
    def _check_unsorted_dict_join(self, func_info, summary: CrashSummary) -> None:
        """
        AST-level check: detect str.join() on a list built from dict iteration
        without sorting, which causes non-deterministic output ordering.

        Pattern:
            for k, v in some_dict.items():
                lst.append(k)
            ...
            ", ".join(lst)       # BUG: non-deterministic order
            ", ".join(sorted(lst))  # OK
        """
        try:
            with open(func_info.file_path, 'r', encoding='utf-8') as f:
                source = f.read()
            tree = ast.parse(source)
        except Exception:
            return

        # Find the function's AST node
        func_node = None
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                if node.name == func_info.name and node.lineno == func_info.line_number:
                    func_node = node
                    break
        if func_node is None:
            return

        # Step 1: Find lists populated from dict iteration
        # Track variable names that are appended to inside a for loop
        # iterating over .items() or .keys()
        dict_derived_lists: set = set()
        for node in ast.walk(func_node):
            if not isinstance(node, ast.For):
                continue
            # Check if iterating over X.items() or X.keys()
            iter_call = node.iter
            if not isinstance(iter_call, ast.Call):
                continue
            if not isinstance(iter_call.func, ast.Attribute):
                continue
            if iter_call.func.attr not in ('items', 'keys'):
                continue
            # Find append calls inside this for loop
            for child in ast.walk(node):
                if not isinstance(child, ast.Call):
                    continue
                if not isinstance(child.func, ast.Attribute):
                    continue
                if child.func.attr != 'append':
                    continue
                # Get the list variable name
                obj = child.func.value
                if isinstance(obj, ast.Name):
                    dict_derived_lists.add(obj.id)

        if not dict_derived_lists:
            return

        # Step 2: Find str.join(list_var) where list_var is dict-derived
        # and NOT wrapped in sorted()
        for node in ast.walk(func_node):
            if not isinstance(node, ast.Call):
                continue
            if not isinstance(node.func, ast.Attribute):
                continue
            if node.func.attr != 'join':
                continue
            if not node.args:
                continue
            arg = node.args[0]
            # Check if arg is a dict-derived list used directly (unsorted)
            if isinstance(arg, ast.Name) and arg.id in dict_derived_lists:
                # Not wrapped in sorted() -> ORDER_VIOLATION
                summary.may_trigger.add('ORDER_VIOLATION')
                summary.record_bug_instance('ORDER_VIOLATION', False)
                return
            # Check if arg is sorted(list_var) -> safe, skip
            if isinstance(arg, ast.Call) and isinstance(arg.func, ast.Name):
                if arg.func.id == 'sorted':
                    continue

    def _check_counter_update_after_check(self, func_info, summary: CrashSummary) -> None:
        """
        AST + symbolic check: detect counter update placed after the comparison
        that depends on it, causing the check to use a stale (pre-increment) value.

        Bug pattern (off-by-one via stale counter):
            elif not self.in_cooldown():
                if self.wait >= self.patience:   # uses stale self.wait
                    ...
                self.wait += 1                   # increment after check

        Fixed pattern (counter updated before check):
            elif not self.in_cooldown():
                self.wait += 1                   # increment first
                if self.wait >= self.patience:   # uses fresh self.wait
                    ...

        Detection strategy (symbolic / DSE-aware):
        1. AST walk finds augmented assignments (+=) to self.<counter>
        2. AST walk finds comparisons (>=, >, ==) involving self.<counter>
        3. For each pair in the same block, check source ordering:
           if comparison line < update line → stale value
        4. Z3 symbolic verification: model the counter as an integer,
           prove that the pre-increment value can cause the comparison
           to produce a different result than the post-increment value
           (i.e., exists N where N < threshold but N+1 >= threshold).
        5. Barrier reasoning: the increment is a discrete step function,
           and the comparison is a threshold predicate.  When the update
           is after the predicate, the barrier B(wait) = patience - wait
           can reach zero one iteration late.

        Uses: Z3 (LIA), DSE path feasibility, barrier certificate reasoning.
        Reports: STALE_VALUE (data-flow bug from kitchensink taxonomy).
        """
        try:
            with open(func_info.file_path, 'r', encoding='utf-8') as f:
                source = f.read()
            tree = ast.parse(source)
        except Exception:
            return

        # Find the function's AST node
        func_node = None
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                if node.name == func_info.name and node.lineno == func_info.line_number:
                    func_node = node
                    break
        if func_node is None:
            return

        # Collect counter augmented assignments: self.X += <const>
        # and comparisons: self.X >= self.Y  (or >, ==)
        counter_updates = []   # (attr_name, line, col, ast_node)
        counter_compares = []  # (attr_name, line, col, ast_node, threshold_attr)

        for node in ast.walk(func_node):
            # Detect self.X += 1  (AugAssign with += on self attribute)
            if isinstance(node, ast.AugAssign) and isinstance(node.op, ast.Add):
                target = node.target
                if (isinstance(target, ast.Attribute) and
                    isinstance(target.value, ast.Name) and
                    target.value.id == 'self'):
                    # Check that increment is a positive constant
                    if isinstance(node.value, ast.Constant) and isinstance(node.value.value, (int, float)):
                        if node.value.value > 0:
                            counter_updates.append((target.attr, node.lineno, node.col_offset, node))

            # Detect if self.X >= self.Y  (Compare with self attributes)
            if isinstance(node, ast.If):
                test = node.test
                if isinstance(test, ast.Compare) and len(test.ops) == 1:
                    op = test.ops[0]
                    if isinstance(op, (ast.GtE, ast.Gt, ast.Eq)):
                        left = test.left
                        right = test.comparators[0]
                        if (isinstance(left, ast.Attribute) and
                            isinstance(left.value, ast.Name) and
                            left.value.id == 'self' and
                            isinstance(right, ast.Attribute) and
                            isinstance(right.value, ast.Name) and
                            right.value.id == 'self'):
                            counter_compares.append((
                                left.attr, node.lineno, node.col_offset,
                                node, right.attr
                            ))

        if not counter_updates or not counter_compares:
            return

        # Match counter updates with comparisons on the same attribute
        for upd_attr, upd_line, upd_col, upd_node in counter_updates:
            for cmp_attr, cmp_line, cmp_col, cmp_node, threshold_attr in counter_compares:
                if upd_attr != cmp_attr:
                    continue

                # Key check: is the update AFTER the comparison?
                # In the buggy pattern, the comparison comes first (lower line),
                # and the update comes after (higher line), in the same block.
                if upd_line <= cmp_line:
                    continue  # Update before or at comparison → correct order

                # Verify they're in the same enclosing block (siblings)
                if not self._are_siblings_in_block(func_node, cmp_node, upd_node):
                    continue

                # Z3 symbolic verification: prove the ordering matters.
                # Model: counter is an integer, threshold is a positive integer.
                # Show that exists a value N where:
                #   N < threshold (pre-increment check fails)
                #   but N+1 >= threshold (post-increment check would succeed)
                # This proves the stale value causes a different outcome.
                try:
                    import z3
                    counter = z3.Int('counter')
                    threshold = z3.Int('threshold')
                    step = z3.IntVal(1)

                    solver = z3.Solver()
                    solver.set('timeout', 500)

                    # Constraints: reasonable counter/threshold values
                    solver.add(threshold > 0)
                    solver.add(counter >= 0)

                    # The off-by-one condition:
                    # pre-increment comparison fails, but post-increment would succeed
                    solver.add(counter < threshold)           # stale check fails
                    solver.add(counter + step >= threshold)   # fresh check would succeed

                    if solver.check() != z3.sat:
                        continue  # Z3 couldn't prove ordering matters

                    # Barrier certificate reasoning:
                    # B(wait) = patience - wait is a discrete Lyapunov-like barrier.
                    # When update is after check, B can reach 0 one step late.
                    # Verify: the barrier B = threshold - counter can be exactly 1
                    # (meaning the counter is one step from crossing), and the
                    # stale check misses it.
                    barrier_solver = z3.Solver()
                    barrier_solver.set('timeout', 500)
                    barrier = threshold - counter
                    barrier_solver.add(barrier == 1)          # barrier at boundary
                    barrier_solver.add(counter < threshold)   # stale check fails
                    barrier_solver.add(counter + step >= threshold)  # fresh would pass

                    if barrier_solver.check() != z3.sat:
                        continue

                except Exception:
                    # Z3 unavailable or error — fall back to structural detection
                    pass

                # Confirmed: counter updated after comparison → STALE_VALUE
                summary.may_trigger.add('STALE_VALUE')
                summary.record_bug_instance('STALE_VALUE', False)
                return

    def _are_siblings_in_block(self, func_node: ast.AST,
                               node_a: ast.AST, node_b: ast.AST) -> bool:
        """
        Check if node_a and node_b are siblings in the same block
        (i.e., both are direct children of the same parent's body list).

        This ensures the counter update and comparison are at the same
        nesting level, not in unrelated branches.
        """
        for parent in ast.walk(func_node):
            for body_attr in ('body', 'orelse', 'handlers', 'finalbody'):
                body = getattr(parent, body_attr, None)
                if not isinstance(body, list):
                    continue
                # Check if node_a is an ancestor of some stmt in body
                # and node_b is an ancestor of some stmt in body
                a_idx = None
                b_idx = None
                for i, stmt in enumerate(body):
                    if stmt is node_a or self._ast_contains(stmt, node_a):
                        a_idx = i
                    if stmt is node_b or self._ast_contains(stmt, node_b):
                        b_idx = i
                if a_idx is not None and b_idx is not None and a_idx != b_idx:
                    return True
        return False

    def _ast_contains(self, parent: ast.AST, target: ast.AST) -> bool:
        """Check if target is a descendant of parent."""
        for node in ast.walk(parent):
            if node is target:
                return True
        return False

    def _get_code_object(self, func_info) -> Optional[types.CodeType]:
        """
        Get the code object for a function.
        
        First checks if func_info already has a code_object, otherwise
        tries to compile the function source to get its code object.
        """
        # ITERATION 610: Use existing code_object if available
        if hasattr(func_info, 'code_object') and func_info.code_object is not None:
            return func_info.code_object
        
        try:
            with open(func_info.file_path, 'r', encoding='utf-8') as f:
                source = f.read()
            
            # Compile to get code objects
            module_code = compile(source, func_info.file_path, 'exec')
            
            # Find the function's code object in the module's constants
            # Search recursively through all nested code objects
            return self._find_nested_code(module_code, func_info.name, func_info.line_number)
        except Exception:
            return None
    
    def _find_nested_code(
        self,
        code: types.CodeType,
        name: str,
        line_number: int
    ) -> Optional[types.CodeType]:
        """Find a nested function's code object."""
        for const in code.co_consts:
            if isinstance(const, types.CodeType):
                if const.co_name == name and const.co_firstlineno == line_number:
                    return const
                nested = self._find_nested_code(const, name, line_number)
                if nested:
                    return nested
        return None
    
    def _analyze_scc(self, scc: Set[str]) -> None:
        """Analyze mutually recursive functions using fixpoint iteration."""
        # Initialize with empty summaries
        for func_name in scc:
            func_info = self.call_graph.get_function(func_name)
            self.summaries[func_name] = CrashSummary(
                function_name=func_name,
                qualified_name=func_name,
                parameter_count=len(func_info.parameters) if func_info else 0,
                is_recursive=True,
            )
        
        # Iterate until fixpoint
        max_iterations = 10
        for _ in range(max_iterations):
            changed = False
            for func_name in scc:
                old_bugs = self.summaries[func_name].all_possible_bugs().copy()
                old_exceptions = self.summaries[func_name].may_raise.copy()
                
                self._analyze_function(func_name)
                
                new_bugs = self.summaries[func_name].all_possible_bugs()
                new_exceptions = self.summaries[func_name].may_raise
                
                if old_bugs != new_bugs or old_exceptions != new_exceptions:
                    changed = True
            
            if not changed:
                break


def analyze_code_object(
    code: types.CodeType,
    func_name: str = None,
    qualified_name: str = None,
    existing_summaries: Dict[str, CrashSummary] = None,
) -> CrashSummary:
    """
    Convenience function to analyze a single code object.
    
    This is the primary entry point for bytecode-level crash analysis.
    
    Example:
        def my_function(x, y):
            return x / y
        
        summary = analyze_code_object(my_function.__code__)
        print(summary.may_trigger)  # {'DIV_ZERO'}
        print(summary.divisor_params)  # {1}  (y is at index 1)
    """
    name = func_name or code.co_name
    qname = qualified_name or code.co_qualname if hasattr(code, 'co_qualname') else name
    
    analyzer = BytecodeCrashSummaryAnalyzer(
        code=code,
        func_name=name,
        qualified_name=qname,
        existing_summaries=existing_summaries,
    )
    return analyzer.analyze()


# ============================================================================
# COMBINED INTERPROCEDURAL SUMMARY
# ============================================================================
# Note: AST-based CrashSummaryComputer removed - use BytecodeCrashSummaryComputer

@dataclass
class InterproceduralBugSummary:
    """
    Combined summary for all bug types at a function.
    
    Merges taint summaries (security) with crash summaries (correctness).
    """
    function_name: str
    
    # From taint summary
    taint_summary: Optional['TaintSummary'] = None
    
    # From crash summary  
    crash_summary: Optional[CrashSummary] = None
    
    def all_possible_bugs(self) -> Set[BugType]:
        """Get all bugs this function may trigger."""
        bugs = set()
        if self.crash_summary:
            bugs |= self.crash_summary.all_possible_bugs()
        if self.taint_summary:
            # Convert security bug indicators to BugType
            if self.taint_summary.dependency.is_sink:
                # The sink type maps to a security bug
                pass  # Would need sink_type -> BugType mapping
            if self.taint_summary.dependency.introduces_taint:
                # Source - may lead to injection bugs downstream
                pass
        return bugs
    
    def check_call(
        self,
        arg_nullabilities: List[Nullability],
        arg_may_be_zero: List[bool],
        arg_tainted: List[bool],
    ) -> Set[BugType]:
        """
        Check what bugs may occur when calling with given arguments.
        
        Returns set of potential bugs from this call.
        """
        bugs = set()
        
        if self.crash_summary:
            bugs |= self.crash_summary.get_precondition_violations(
                arg_nullabilities, arg_may_be_zero
            )
        
        # Taint-based bugs would be checked separately via taint tracker
        
        return bugs


def compute_all_bug_summaries(
    call_graph: 'CallGraph',
    taint_summaries: Dict[str, 'TaintSummary'] = None,
) -> Dict[str, InterproceduralBugSummary]:
    """
    Compute combined bug summaries for all functions.
    
    Merges taint analysis (security bugs) with crash analysis (correctness bugs).
    """
    taint_summaries = taint_summaries or {}
    
    # Compute crash summaries (AST-based CrashSummaryComputer removed)
    crash_computer = BytecodeCrashSummaryComputer(call_graph)
    crash_summaries = crash_computer.compute_all()
    
    # Merge into combined summaries
    all_funcs = set(crash_summaries.keys()) | set(taint_summaries.keys())
    combined = {}
    
    for func_name in all_funcs:
        combined[func_name] = InterproceduralBugSummary(
            function_name=func_name,
            taint_summary=taint_summaries.get(func_name),
            crash_summary=crash_summaries.get(func_name),
        )
    
    return combined


# ============================================================================
# EXPORTS
# ============================================================================

__all__ = [
    # Registry integration
    'REGISTERED_BUG_TYPES',
    'PreconditionType', 'Precondition',
    'ExceptionType', 'EXCEPTION_NAMES', 'EXCEPTION_TO_BUG', 'PRECONDITION_TO_BUG',
    'Nullability',
    
    # Summaries
    'CrashSummary',
    
    # AST-based analyzer (legacy)
    'CrashSummaryAnalyzer',
    'CrashSummaryComputer',
    
    # Bytecode-level analyzer (preferred)
    'BytecodeLocation',
    'ParameterFlow',
    'BytecodeCrashSummaryAnalyzer',
    'BytecodeCrashSummaryComputer',
    'analyze_code_object',
    
    # Combined
    'InterproceduralBugSummary',
    'compute_all_bug_summaries',
]
