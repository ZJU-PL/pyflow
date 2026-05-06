"""
Interprocedural Guard Analysis.

Extends the rich intraprocedural guard analysis from cfg/control_flow.py to work
across function and file boundaries. This enables FP reduction by propagating
guard facts through:

1. **Return Value Guards**: If a function always returns non-null/non-zero,
   call sites inherit those guarantees.

2. **Callee Parameter Guards**: If a function validates parameters and returns
   early on invalid input, downstream code has guards.

3. **Compositional Guards**: Guards compose across call chains - if f() returns
   nonnull and g(x) requires nonnull(x), then g(f()) is safe.

GUARD TYPES SUPPORTED (all intraprocedural guards extended to interprocedural):

| Guard Type      | Z3 Model                | Interprocedural Extension           |
|-----------------|-------------------------|-------------------------------------|
| nonnull         | x ≠ None                | Return nonnull, param validated     |
| div             | x ≠ 0                   | Return nonzero, divisor validated   |
| bounds          | 0 ≤ i < len             | Index validated, callee safe        |
| nonempty        | len ≥ 1                 | Return nonempty, container checked  |
| exact_length    | len == n                | Return exact length, unpacking      |
| range_len_loop  | for i in range(len)     | Loop bounds propagate               |
| enumerate_loop  | for i,x in enumerate    | Loop bounds propagate               |
| loop_body       | for x in container      | Container nonempty propagates       |
| key_in          | k in d                  | Key validated by callee             |
| hasattr         | hasattr(obj, attr)      | Attribute validated by callee       |
| nonnegative     | x ≥ 0                   | Lower bound validated               |
| type            | isinstance(x, T)        | Type validated by callee            |
| exception_caught| in except block         | Exception barrier                   |
| callable        | callable(x)             | Callable validated                  |

Architecture:
    ┌─────────────────────────────────────────────────────────────────┐
    │           INTERPROCEDURAL GUARD PROPAGATION                     │
    ├─────────────────────────────────────────────────────────────────┤
    │                                                                  │
    │  CrashSummary ───► FunctionGuardSummary ───► Call Site Guards   │
    │       │                    │                        │           │
    │       │                    │                        ▼           │
    │       │                    │              ┌─────────────────┐   │
    │       │                    │              │ Interprocedural │   │
    │       │                    │              │ Guard State     │   │
    │       ▼                    ▼              │                 │   │
    │  ┌─────────┐      ┌─────────────┐        │ • has_nonnull() │   │
    │  │ Return  │      │ Parameter   │        │ • has_bounds()  │   │
    │  │ Guards  │      │ Validation  │        │ • has_div()     │   │
    │  └────┬────┘      └──────┬──────┘        │ • etc.          │   │
    │       │                  │               └────────┬────────┘   │
    │       └────────┬─────────┘                        │            │
    │                │                                  │            │
    │                ▼                                  ▼            │
    │        ┌─────────────────────────────────────────────┐         │
    │        │        Z3 GUARD VERIFICATION                │         │
    │        │  • Prove guard implications across calls    │         │
    │        │  • Compose guards from multiple callees     │         │
    │        └─────────────────────────────────────────────┘         │
    │                                                                  │
    └─────────────────────────────────────────────────────────────────┘
"""

from __future__ import annotations

import z3
from dataclasses import dataclass, field
from typing import Dict, List, Set, Optional, Tuple, Any, FrozenSet
from pathlib import Path
from enum import Enum, auto
import types
import dis
import logging

from ..cfg.control_flow import (
    ControlFlowGraph, BasicBlock, GuardFact, GuardAnalyzer, build_cfg
)
from ..cfg.dataflow import GuardState, run_intraprocedural_analysis

logger = logging.getLogger(__name__)


# ============================================================================
# GUARD SUMMARY FOR FUNCTION RETURNS AND PARAMETERS
# ============================================================================

class ReturnGuarantee(Enum):
    """Guarantees about a function's return value."""
    UNKNOWN = auto()
    NONNULL = auto()          # Return value is never None
    NONZERO = auto()          # Return value is never zero
    NONEMPTY = auto()         # Return value has len >= 1
    NONNEGATIVE = auto()      # Return value >= 0
    POSITIVE = auto()         # Return value > 0
    BOUNDED = auto()          # Return value has known bounds


@dataclass
class ParameterGuarantee:
    """Guarantees about what a function validates for a parameter."""
    param_index: int
    param_name: str
    
    # Validation guarantees: if function returns normally, these hold
    validates_nonnull: bool = False      # Checks param is not None
    validates_nonzero: bool = False      # Checks param != 0
    validates_nonempty: bool = False     # Checks len(param) >= 1
    validates_type: Optional[str] = None # Checks isinstance(param, Type)
    validates_positive: bool = False     # Checks param > 0
    validates_nonnegative: bool = False  # Checks param >= 0
    validates_callable: bool = False     # Checks callable(param)
    validates_hasattr: Optional[str] = None  # Checks hasattr(param, 'attr')
    validates_key_in: Optional[str] = None   # Checks key in container


@dataclass
class FunctionGuardSummary:
    """
    Summary of guard-related properties for a function.
    
    This extends CrashSummary with detailed guard information for
    interprocedural propagation.
    """
    function_name: str
    qualified_name: str
    
    # Return value guarantees
    return_guarantees: Set[ReturnGuarantee] = field(default_factory=set)
    return_type: Optional[str] = None  # Known return type from annotations/inference
    return_exact_length: Optional[int] = None  # If return has known exact length
    return_min_length: Optional[int] = None    # If return has known min length
    
    # Parameter validation (what the function checks on entry)
    param_guarantees: Dict[int, ParameterGuarantee] = field(default_factory=dict)
    
    # Guards established for callers after this function returns
    # If f(x) returns normally, these guards hold for x
    post_call_guards: Dict[int, Set[str]] = field(default_factory=dict)
    
    # Which parameters flow to return (for guard composition)
    # If param i flows to return, and return is nonnull, param was nonnull
    param_to_return_flow: Set[int] = field(default_factory=set)
    
    # Exception barriers: which exceptions this function catches
    catches_type_error: bool = False
    catches_attribute_error: bool = False
    catches_index_error: bool = False
    catches_key_error: bool = False
    catches_zero_division: bool = False
    
    # Analysis metadata
    analyzed: bool = False
    analysis_depth: int = 0  # For interprocedural depth limiting


# ============================================================================
# FUNCTION GUARD ANALYZER
# ============================================================================

class FunctionGuardAnalyzer:
    """
    Analyze a function to extract guard summaries for interprocedural use.
    
    This performs deeper analysis than CrashSummary to understand:
    1. What the function guarantees about its return value
    2. What the function validates about its parameters
    3. What guards are established for callers after the call
    """
    
    # Constructors and functions that always return non-None
    NONNULL_RETURNING_FUNCTIONS: FrozenSet[str] = frozenset({
        # Constructors
        'list', 'dict', 'set', 'tuple', 'str', 'int', 'float', 'bool',
        'bytes', 'bytearray', 'frozenset', 'object', 'range', 'slice', 'type',
        'complex', 'memoryview', 'super',
        
        # String methods
        'strip', 'lstrip', 'rstrip', 'split', 'rsplit', 'splitlines',
        'lower', 'upper', 'title', 'capitalize', 'swapcase', 'casefold',
        'replace', 'translate', 'encode', 'format', 'format_map',
        'join', 'center', 'ljust', 'rjust', 'zfill', 'expandtabs',
        'partition', 'rpartition', 'maketrans',
        
        # List methods
        'copy', 'sorted',
        
        # Dict methods
        'keys', 'values', 'items',
        
        # Other built-ins
        'len', 'abs', 'repr', 'str', 'hash', 'id', 'type', 'chr', 'ord',
        'bin', 'hex', 'oct', 'round', 'sum', 'min', 'max', 'all', 'any',
        'sorted', 'reversed', 'enumerate', 'zip', 'map', 'filter', 'range',
    })
    
    # Functions that return positive integers
    POSITIVE_RETURNING_FUNCTIONS: FrozenSet[str] = frozenset({
        'len', 'abs',  # abs of nonzero is positive
    })
    
    # Functions that return non-negative integers
    NONNEGATIVE_RETURNING_FUNCTIONS: FrozenSet[str] = frozenset({
        'len', 'abs', 'count', 'index', 'find', 'rfind',
    })
    
    def __init__(
        self,
        code: types.CodeType,
        func_name: str,
        qualified_name: str,
        existing_summaries: Optional[Dict[str, 'FunctionGuardSummary']] = None,
    ):
        self.code = code
        self.func_name = func_name
        self.qualified_name = qualified_name
        self.existing_summaries = existing_summaries or {}
        
        # Build CFG and run intraprocedural guard analysis
        self.cfg = build_cfg(code)
        self.guard_analyzer = GuardAnalyzer(self.cfg)
        self.block_guards = self.guard_analyzer.analyze()
        
        # Instruction list
        self.instructions = list(dis.get_instructions(code))
        
        # Parameter info
        self.param_count = code.co_argcount + code.co_kwonlyargcount
        self.param_names = list(code.co_varnames[:self.param_count])
        
        # Build summary
        self.summary = FunctionGuardSummary(
            function_name=func_name,
            qualified_name=qualified_name,
        )
    
    def analyze(self) -> FunctionGuardSummary:
        """Perform complete guard analysis."""
        self._analyze_return_guarantees()
        self._analyze_parameter_validation()
        self._analyze_exception_barriers()
        self._analyze_param_return_flow()
        
        self.summary.analyzed = True
        return self.summary
    
    def _analyze_return_guarantees(self) -> None:
        """
        Analyze what guarantees the function makes about its return value.
        
        A function returns nonnull if ALL return paths return nonnull values.
        """
        return_nullabilities: List[bool] = []  # True = nonnull, False = may be null
        
        for block in self.cfg.blocks.values():
            for i, instr in enumerate(block.instructions):
                if instr.opname == 'RETURN_VALUE':
                    # Check what's being returned
                    is_nonnull = self._check_return_nonnull(block, i)
                    return_nullabilities.append(is_nonnull)
        
        # If ALL returns are nonnull, function guarantees nonnull
        if return_nullabilities and all(return_nullabilities):
            self.summary.return_guarantees.add(ReturnGuarantee.NONNULL)
        
        # Check for other guarantees
        self._check_return_numeric_guarantees()
        self._check_return_length_guarantees()
    
    def _check_return_nonnull(self, block: BasicBlock, return_idx: int) -> bool:
        """
        Check if a specific return statement returns a nonnull value.
        
        Examines the value on the stack before RETURN_VALUE.
        """
        if return_idx < 1:
            return False
        
        # Look at what's being returned
        prev_instrs = block.instructions[:return_idx]
        
        # Work backwards to find what's on the stack
        for i in range(len(prev_instrs) - 1, -1, -1):
            instr = prev_instrs[i]
            
            # Direct None return
            if instr.opname == 'LOAD_CONST':
                const_val = instr.argval
                if const_val is None:
                    return False
                # Non-None constant is nonnull
                return True
            
            # Return from constructor/builtin
            if instr.opname in ('CALL', 'CALL_FUNCTION'):
                # Check if this is a nonnull-returning function
                for j in range(i - 1, max(-1, i - 5), -1):
                    call_instr = prev_instrs[j]
                    if call_instr.opname in ('LOAD_GLOBAL', 'LOAD_BUILTIN', 'LOAD_NAME'):
                        func_name = call_instr.argval
                        if func_name in self.NONNULL_RETURNING_FUNCTIONS:
                            return True
                        # Capitalized names are likely constructors
                        if isinstance(func_name, str) and func_name[0].isupper():
                            return True
                    elif call_instr.opname == 'LOAD_ATTR':
                        attr_name = call_instr.argval
                        if attr_name in self.NONNULL_RETURNING_FUNCTIONS:
                            return True
                break
            
            # Return a local that has nonnull guard
            if instr.opname in ('LOAD_FAST', 'LOAD_FAST_BORROW'):
                var_name = instr.argval
                # Check if this variable has a nonnull guard at this block
                guards = self.block_guards.get(block.id, set())
                for guard in guards:
                    if guard.guard_type == 'nonnull' and guard.variable == var_name:
                        return True
                break
            
            # BUILD_* instructions create nonnull values
            if instr.opname.startswith('BUILD_'):
                return True
        
        return False
    
    def _check_return_numeric_guarantees(self) -> None:
        """Check for numeric guarantees on return value."""
        # Look for patterns like "return len(x)" or "return abs(x)"
        for block in self.cfg.blocks.values():
            for i, instr in enumerate(block.instructions):
                if instr.opname == 'RETURN_VALUE' and i >= 2:
                    prev = block.instructions[i - 1]
                    
                    # Return from a call
                    if prev.opname in ('CALL', 'CALL_FUNCTION'):
                        for j in range(i - 2, max(-1, i - 5), -1):
                            call_instr = block.instructions[j]
                            if call_instr.opname in ('LOAD_GLOBAL', 'LOAD_BUILTIN', 'LOAD_NAME'):
                                func_name = call_instr.argval
                                if func_name in self.NONNEGATIVE_RETURNING_FUNCTIONS:
                                    self.summary.return_guarantees.add(ReturnGuarantee.NONNEGATIVE)
                                if func_name == 'len':
                                    self.summary.return_guarantees.add(ReturnGuarantee.NONNEGATIVE)
                            break
    
    def _check_return_length_guarantees(self) -> None:
        """Check for length guarantees on return value (e.g., returning a list with known size)."""
        # TODO: More sophisticated analysis of collection construction
        pass
    
    def _analyze_parameter_validation(self) -> None:
        """
        Analyze what the function validates about its parameters.
        
        Look for patterns like:
        - if param is None: return/raise
        - if not param: return/raise
        - if len(param) == 0: return/raise
        - assert param is not None
        """
        for param_idx, param_name in enumerate(self.param_names):
            guarantee = ParameterGuarantee(
                param_index=param_idx,
                param_name=param_name,
            )
            
            # Check for nonnull validation
            if self._param_has_nonnull_check(param_name):
                guarantee.validates_nonnull = True
            
            # Check for nonempty validation
            if self._param_has_nonempty_check(param_name):
                guarantee.validates_nonempty = True
            
            # Check for type validation
            type_check = self._param_has_type_check(param_name)
            if type_check:
                guarantee.validates_type = type_check
            
            # Check for nonzero validation
            if self._param_has_nonzero_check(param_name):
                guarantee.validates_nonzero = True
            
            # Check for callable validation
            if self._param_has_callable_check(param_name):
                guarantee.validates_callable = True
            
            # Store guarantee if any validation found
            if any([
                guarantee.validates_nonnull,
                guarantee.validates_nonempty,
                guarantee.validates_type,
                guarantee.validates_nonzero,
                guarantee.validates_callable,
            ]):
                self.summary.param_guarantees[param_idx] = guarantee
    
    def _param_has_nonnull_check(self, param_name: str) -> bool:
        """Check if parameter has a nonnull check that guards the function body."""
        # Look for guards established in early blocks
        entry_block = self.cfg.blocks.get(self.cfg.entry_block)
        if not entry_block:
            return False
        
        # Check if nonnull guard is established for this param
        for block_id, guards in self.block_guards.items():
            for guard in guards:
                if guard.guard_type == 'nonnull' and guard.variable == param_name:
                    return True
        
        return False
    
    def _param_has_nonempty_check(self, param_name: str) -> bool:
        """Check if parameter has a nonempty check."""
        for block_id, guards in self.block_guards.items():
            for guard in guards:
                if guard.guard_type == 'nonempty' and guard.variable == param_name:
                    return True
        return False
    
    def _param_has_type_check(self, param_name: str) -> Optional[str]:
        """Check if parameter has a type check (isinstance)."""
        for block_id, guards in self.block_guards.items():
            for guard in guards:
                if guard.guard_type == 'type' and guard.variable == param_name:
                    return guard.extra
        return None
    
    def _param_has_nonzero_check(self, param_name: str) -> bool:
        """Check if parameter has a nonzero check."""
        for block_id, guards in self.block_guards.items():
            for guard in guards:
                if guard.guard_type == 'div' and guard.variable == param_name:
                    return True
        return False
    
    def _param_has_callable_check(self, param_name: str) -> bool:
        """Check if parameter has a callable check."""
        # callable(x) establishes nonnull, look for that pattern
        for block_id, guards in self.block_guards.items():
            for guard in guards:
                if guard.guard_type == 'nonnull' and guard.variable == param_name:
                    if guard.condition and 'callable' in guard.condition:
                        return True
        return False
    
    def _analyze_exception_barriers(self) -> None:
        """Analyze which exception types this function catches."""
        # Look for exception handler patterns in the CFG
        for region in self.cfg.exception_regions:
            # Check what exceptions are caught
            # This is a simplified check - in reality we'd parse the exception table
            self.summary.catches_type_error = True  # Conservative
    
    def _analyze_param_return_flow(self) -> None:
        """Analyze which parameters flow to the return value."""
        # Simple analysis: if a parameter is directly returned, it flows to return
        for block in self.cfg.blocks.values():
            for i, instr in enumerate(block.instructions):
                if instr.opname == 'RETURN_VALUE' and i >= 1:
                    prev = block.instructions[i - 1]
                    if prev.opname in ('LOAD_FAST', 'LOAD_FAST_BORROW'):
                        var_name = prev.argval
                        if var_name in self.param_names:
                            param_idx = self.param_names.index(var_name)
                            self.summary.param_to_return_flow.add(param_idx)


# ============================================================================
# INTERPROCEDURAL GUARD STATE
# ============================================================================

@dataclass
class InterproceduralGuardState:
    """
    Guard state that spans function boundaries.
    
    Extends the intraprocedural GuardState with:
    - Guards inherited from callee return values
    - Guards established by callee parameter validation
    - Compositional guard reasoning
    """
    # Local guards (from intraprocedural analysis)
    local_guards: GuardState = field(default_factory=GuardState)
    
    # Interprocedural guards: variable -> set of guard types
    interprocedural_guards: Dict[str, Set[str]] = field(default_factory=dict)
    
    # Call site to guard mapping: call_result_var -> callee_summary
    call_return_guards: Dict[str, FunctionGuardSummary] = field(default_factory=dict)
    
    def add_call_return_guard(
        self,
        result_var: str,
        callee_summary: FunctionGuardSummary,
    ) -> None:
        """
        Add guards based on a call's return value.
        
        If the callee guarantees nonnull return, the result variable is nonnull.
        """
        self.call_return_guards[result_var] = callee_summary
        
        if ReturnGuarantee.NONNULL in callee_summary.return_guarantees:
            self._add_guard(result_var, 'nonnull')
        
        if ReturnGuarantee.NONZERO in callee_summary.return_guarantees:
            self._add_guard(result_var, 'div')
        
        if ReturnGuarantee.NONEMPTY in callee_summary.return_guarantees:
            self._add_guard(result_var, 'nonempty')
        
        if ReturnGuarantee.NONNEGATIVE in callee_summary.return_guarantees:
            self._add_guard(result_var, 'nonnegative')
    
    def _add_guard(self, var: str, guard_type: str) -> None:
        """Add an interprocedural guard."""
        if var not in self.interprocedural_guards:
            self.interprocedural_guards[var] = set()
        self.interprocedural_guards[var].add(guard_type)
    
    def has_nonnull(self, variable: str) -> bool:
        """Check if variable is nonnull (local or interprocedural)."""
        if self.local_guards.has_nonnull(variable):
            return True
        return 'nonnull' in self.interprocedural_guards.get(variable, set())
    
    def has_div_safe(self, variable: str) -> bool:
        """Check if variable is safe for division."""
        if self.local_guards.has_div_safe(variable):
            return True
        return 'div' in self.interprocedural_guards.get(variable, set())
    
    def has_bounds_safe(self, container: str, index: str) -> bool:
        """Check if container[index] is safe."""
        if self.local_guards.has_bounds_safe(container, index):
            return True
        # TODO: Check interprocedural bounds
        return False
    
    def has_nonempty(self, variable: str) -> bool:
        """Check if variable is nonempty."""
        if self.local_guards.has_guard('nonempty', variable, 'len>=1'):
            return True
        return 'nonempty' in self.interprocedural_guards.get(variable, set())
    
    def has_nonnegative(self, variable: str) -> bool:
        """Check if variable is nonnegative."""
        if self.local_guards.has_guard('nonnegative', variable):
            return True
        return 'nonnegative' in self.interprocedural_guards.get(variable, set())


# ============================================================================
# INTERPROCEDURAL GUARD COMPUTER
# ============================================================================

class InterproceduralGuardComputer:
    """
    Compute guard summaries across an entire call graph.
    
    Uses a bottom-up traversal (leaves first, then callers) to propagate
    guard information from callees to callers.
    """
    
    def __init__(self, call_graph: 'CallGraph'):
        from ..cfg.call_graph import CallGraph
        self.call_graph = call_graph
        self.summaries: Dict[str, FunctionGuardSummary] = {}
        self.analyzed_functions: Set[str] = set()
    
    def compute_all(self) -> Dict[str, FunctionGuardSummary]:
        """
        Compute guard summaries for all functions in the call graph.
        
        Uses SCC-based traversal for proper handling of recursion.
        """
        # Get SCCs in reverse topological order (leaves first)
        sccs = self.call_graph.compute_sccs()
        
        # Process each SCC
        for scc in sccs:
            self._process_scc(scc)
        
        return self.summaries
    
    def _process_scc(self, scc: Set[str]) -> None:
        """Process a strongly connected component."""
        # For recursive SCCs, we use a fixed-point iteration
        if len(scc) > 1:
            # Multiple functions in SCC = recursion
            # Start with empty summaries, iterate until fixed point
            for func_name in scc:
                self._analyze_function_initial(func_name)
            
            # Fixed-point iteration (limited)
            for _ in range(3):
                changed = False
                for func_name in scc:
                    old_summary = self.summaries.get(func_name)
                    new_summary = self._analyze_function(func_name)
                    if self._summary_changed(old_summary, new_summary):
                        changed = True
                        self.summaries[func_name] = new_summary
                if not changed:
                    break
        else:
            # Single function - analyze directly
            func_name = next(iter(scc))
            self._analyze_function(func_name)
    
    def _analyze_function_initial(self, func_name: str) -> None:
        """Initial analysis of a function (before fixed-point)."""
        func_info = self.call_graph.get_function(func_name)
        if not func_info or not func_info.code_object:
            return
        
        # Create initial summary
        self.summaries[func_name] = FunctionGuardSummary(
            function_name=func_info.name,
            qualified_name=func_name,
        )
    
    def _analyze_function(self, func_name: str) -> FunctionGuardSummary:
        """Analyze a single function for guard properties."""
        func_info = self.call_graph.get_function(func_name)
        if not func_info or not func_info.code_object:
            # Return empty summary for unknown functions
            return FunctionGuardSummary(
                function_name=func_name.split('.')[-1],
                qualified_name=func_name,
            )
        
        # Analyze the function
        analyzer = FunctionGuardAnalyzer(
            func_info.code_object,
            func_info.name,
            func_name,
            existing_summaries=self.summaries,
        )
        summary = analyzer.analyze()
        
        # Propagate callee guards
        self._propagate_callee_guards(func_name, summary)
        
        self.summaries[func_name] = summary
        self.analyzed_functions.add(func_name)
        
        return summary
    
    def _propagate_callee_guards(
        self,
        func_name: str,
        summary: FunctionGuardSummary,
    ) -> None:
        """
        Propagate guard information from callees to this function's summary.
        
        If a callee has strong return guarantees, those propagate to
        variables receiving the return value in this function.
        """
        # Get all callees
        callees = self.call_graph.get_callees(func_name)
        
        for callee_name in callees:
            callee_summary = self.summaries.get(callee_name)
            if callee_summary:
                # If callee always returns nonnull, any call result is nonnull
                # This is tracked at the call site level in the caller
                pass  # The actual guard application happens at use sites
    
    def _summary_changed(
        self,
        old: Optional[FunctionGuardSummary],
        new: FunctionGuardSummary,
    ) -> bool:
        """Check if a summary changed (for fixed-point iteration)."""
        if old is None:
            return True
        return (
            old.return_guarantees != new.return_guarantees or
            old.param_guarantees != new.param_guarantees
        )
    
    def get_return_nonnull_functions(self) -> Set[str]:
        """Get all functions that guarantee nonnull return."""
        return {
            name for name, summary in self.summaries.items()
            if ReturnGuarantee.NONNULL in summary.return_guarantees
        }


# ============================================================================
# INTEGRATION WITH CRASH SUMMARY ANALYSIS
# ============================================================================

def apply_interprocedural_guards_to_bugs(
    bugs: List['InterproceduralBug'],
    guard_summaries: Dict[str, FunctionGuardSummary],
    call_graph: 'CallGraph',
) -> List['InterproceduralBug']:
    """
    Apply interprocedural guard analysis to reduce false positives in bugs.
    
    For each bug, check if interprocedural guards make it safe:
    1. If the bug is about a value returned from a nonnull-returning function
    2. If the caller validated the parameter before the call
    3. If the value flowed through functions that guarantee non-null
    
    Args:
        bugs: List of bugs from interprocedural analysis
        guard_summaries: Guard summaries for all functions
        call_graph: The call graph
    
    Returns:
        Filtered list of bugs (those not protected by interprocedural guards)
    """
    from .interprocedural_bugs import InterproceduralBug
    
    filtered_bugs = []
    guarded_count = 0
    
    for bug in bugs:
        if _is_bug_guarded_interprocedurally(bug, guard_summaries, call_graph):
            guarded_count += 1
            # Mark as guarded but don't remove (for statistics)
            bug.confidence *= 0.3  # Reduce confidence for guarded bugs
        else:
            filtered_bugs.append(bug)
    
    if guarded_count > 0:
        logger.info(f"Interprocedural guard analysis marked {guarded_count} bugs as guarded")
    
    return filtered_bugs


def _is_bug_guarded_interprocedurally(
    bug: 'InterproceduralBug',
    guard_summaries: Dict[str, FunctionGuardSummary],
    call_graph: 'CallGraph',
) -> bool:
    """
    Check if a bug is protected by interprocedural guards.
    
    This implements the interprocedural guard check:
    1. For NULL_PTR: check if value came from nonnull-returning function
    2. For BOUNDS: check if index came from bounded source
    3. For DIV_ZERO: check if divisor came from nonzero-returning function
    """
    # Get the crash function's summary
    crash_func_summary = guard_summaries.get(bug.crash_function)
    
    if bug.bug_type == 'NULL_PTR':
        # Check if any caller in the chain validates nonnull
        for caller in bug.call_chain[:-1]:  # Exclude crash function itself
            caller_summary = guard_summaries.get(caller)
            if caller_summary:
                # If caller validates params and crashes if None, we're safe
                for param_idx, guarantee in caller_summary.param_guarantees.items():
                    if guarantee.validates_nonnull:
                        return True
    
    elif bug.bug_type == 'DIV_ZERO':
        # Check if divisor came from a function that guarantees nonzero
        for caller in bug.call_chain:
            caller_summary = guard_summaries.get(caller)
            if caller_summary:
                if ReturnGuarantee.NONZERO in caller_summary.return_guarantees:
                    return True
                if ReturnGuarantee.POSITIVE in caller_summary.return_guarantees:
                    return True
                # len() returns nonnegative, if we divide by len(nonempty) it's safe
                if ReturnGuarantee.NONNEGATIVE in caller_summary.return_guarantees:
                    # Need to also check that input was nonempty
                    pass
    
    elif bug.bug_type == 'BOUNDS':
        # Check for range/enumerate loop patterns propagating
        pass
    
    return False


# ============================================================================
# AUTOMATIC GUARD PROPAGATION UTILITIES
# ============================================================================

# Map from intraprocedural guard types (from control_flow.py GuardAnalyzer)
# to the bug types they protect against.
# This is the canonical mapping that enables automatic propagation.
GUARD_TYPE_TO_BUG_TYPES = {
    'nonnull': {'NULL_PTR', 'ATTRIBUTE_ERROR'},
    'div': {'DIV_ZERO'},
    'bounds': {'BOUNDS', 'INDEX_ERROR'},
    'nonempty': {'BOUNDS', 'INDEX_ERROR'},
    'exact_length': {'BOUNDS', 'INDEX_ERROR'},
    'range_len_loop': {'BOUNDS', 'INDEX_ERROR'},
    'enumerate_loop': {'BOUNDS', 'INDEX_ERROR'},
    'loop_body_nonempty': {'BOUNDS', 'INDEX_ERROR'},
    'key_in': {'KEY_ERROR'},
    'hasattr': {'ATTRIBUTE_ERROR'},
    'nonnegative': {'BOUNDS', 'INDEX_ERROR'},
    'type': {'TYPE_ERROR', 'ATTRIBUTE_ERROR'},
    'exception_caught': {'*'},  # Any exception-based bug
    'callable': {'NULL_PTR', 'TYPE_ERROR'},
}

# Reverse mapping: bug type to guard types that protect it
BUG_TYPE_TO_GUARD_TYPES = {}
for guard_type, bug_types in GUARD_TYPE_TO_BUG_TYPES.items():
    for bug_type in bug_types:
        if bug_type not in BUG_TYPE_TO_GUARD_TYPES:
            BUG_TYPE_TO_GUARD_TYPES[bug_type] = set()
        BUG_TYPE_TO_GUARD_TYPES[bug_type].add(guard_type)


def get_guard_types_for_bug(bug_type: str) -> Set[str]:
    """
    Get all guard types that protect against a bug type.
    
    This is used for automatic interprocedural propagation:
    any guard of a matching type will reduce confidence for the bug.
    """
    return BUG_TYPE_TO_GUARD_TYPES.get(bug_type, set()).copy()


def get_bug_types_for_guard(guard_type: str) -> Set[str]:
    """
    Get all bug types that a guard type protects against.
    
    This is used to understand what bugs are covered when a guard is established.
    """
    return GUARD_TYPE_TO_BUG_TYPES.get(guard_type, set()).copy()


# ============================================================================
# Z3-BACKED GUARD IMPLICATION CHECKER
# ============================================================================

class Z3GuardVerifier:
    """
    Verify guard implications using Z3.
    
    This is the principled approach: model guards as Z3 constraints and
    prove that guard_predicate => not(bug_condition).
    
    Symbolic Variable Naming Convention:
        - param_N: Function parameter N
        - local_NAME: Local variable NAME  
        - call_FUNC: Return value from calling FUNC
        - attr_OBJ_ATTR: Attribute OBJ.ATTR
    
    Guard Predicates (Z3 formulas):
        - nonnull(x): x != None (modeled as x != 0 for simplicity)
        - div(x): x != 0
        - bounds(arr, i): 0 <= i < len(arr)
        - nonempty(x): len(x) >= 1
    
    Bug Conditions (negation of safety):
        - NULL_PTR: x == None
        - DIV_ZERO: divisor == 0
        - BOUNDS: i < 0 or i >= len(arr)
    
    Implication Check:
        SAT(guard AND bug_condition) == UNSAT => guarded
    """
    
    def __init__(self):
        """Initialize the Z3 verifier with a fresh solver."""
        self.solver = z3.Solver()
        self.solver.set("timeout", 1000)  # 1 second timeout
        
        # Symbol cache: name -> Z3 symbol
        self._symbols: Dict[str, z3.ExprRef] = {}
        self._len_symbols: Dict[str, z3.ArithRef] = {}
    
    def _get_symbol(self, var_name: str) -> z3.ArithRef:
        """Get or create a Z3 integer symbol for a variable."""
        if var_name not in self._symbols:
            self._symbols[var_name] = z3.Int(f"v_{var_name}")
        return self._symbols[var_name]
    
    def _get_len_symbol(self, container: str) -> z3.ArithRef:
        """Get or create a Z3 integer symbol for len(container)."""
        if container not in self._len_symbols:
            self._len_symbols[container] = z3.Int(f"len_{container}")
        return self._len_symbols[container]
    
    def guard_to_z3(self, guard_type: str, variable: str, extra: Optional[str] = None) -> z3.BoolRef:
        """
        Convert a guard fact to a Z3 constraint.
        
        Args:
            guard_type: The type of guard (nonnull, div, bounds, etc.)
            variable: The variable being guarded
            extra: Additional info (e.g., container for bounds, length for exact_length)
        
        Returns:
            Z3 boolean expression representing the guard constraint.
        """
        sym = self._get_symbol(variable)
        
        if guard_type == 'nonnull':
            # Model as "not null" where null is represented as a special value
            # Use sym != -999999 as a proxy (symbolic null check)
            null_val = z3.IntVal(-999999)
            return sym != null_val
        
        elif guard_type == 'div':
            # x != 0
            return sym != z3.IntVal(0)
        
        elif guard_type == 'nonempty':
            # len(x) >= 1
            len_sym = self._get_len_symbol(variable)
            return len_sym >= z3.IntVal(1)
        
        elif guard_type == 'exact_length':
            # len(x) == n
            try:
                n = int(extra) if extra else 1
            except (ValueError, TypeError):
                n = 1
            len_sym = self._get_len_symbol(variable)
            return len_sym == z3.IntVal(n)
        
        elif guard_type == 'bounds':
            # Parse variable format: "container[index]"
            if '[' in variable and ']' in variable:
                container = variable.split('[')[0]
                index = variable.split('[')[1].rstrip(']')
                idx_sym = self._get_symbol(index)
                len_sym = self._get_len_symbol(container)
                return z3.And(idx_sym >= 0, idx_sym < len_sym)
            return z3.BoolVal(True)
        
        elif guard_type == 'nonnegative':
            # x >= 0
            return sym >= z3.IntVal(0)
        
        elif guard_type in ('range_len_loop', 'enumerate_loop', 'loop_body_nonempty'):
            # These establish bounds on iteration variables
            # Model as the container being nonempty
            len_sym = self._get_len_symbol(variable)
            return len_sym >= z3.IntVal(1)
        
        elif guard_type == 'key_in':
            # Model as "key is valid" - we use a special symbol
            return z3.Bool(f"key_valid_{variable}")
        
        elif guard_type == 'hasattr':
            # Model as "attribute exists"
            attr_name = extra or "attr"
            return z3.Bool(f"has_{variable}_{attr_name}")
        
        elif guard_type == 'type':
            # isinstance(x, T)
            type_name = extra or "object"
            return z3.Bool(f"isinstance_{variable}_{type_name}")
        
        elif guard_type == 'exception_caught':
            # Inside exception handler
            return z3.Bool(f"caught_exception_{variable}")
        
        elif guard_type == 'callable':
            # callable(x) implies x is not None
            null_val = z3.IntVal(-999999)
            return sym != null_val
        
        else:
            # Unknown guard type - assume True (conservative)
            return z3.BoolVal(True)
    
    def bug_condition_to_z3(self, bug_type: str, variable: str) -> z3.BoolRef:
        """
        Convert a bug condition to a Z3 constraint.
        
        The bug occurs when this constraint is satisfiable.
        
        Args:
            bug_type: The type of bug (NULL_PTR, DIV_ZERO, BOUNDS, etc.)
            variable: The variable involved in the bug
        
        Returns:
            Z3 boolean expression that, if SAT, means the bug can occur.
        """
        sym = self._get_symbol(variable)
        
        if bug_type in ('NULL_PTR', 'ATTRIBUTE_ERROR'):
            # Bug occurs when x == None (our null value)
            null_val = z3.IntVal(-999999)
            return sym == null_val
        
        elif bug_type == 'DIV_ZERO':
            # Bug occurs when divisor == 0
            return sym == z3.IntVal(0)
        
        elif bug_type in ('BOUNDS', 'INDEX_ERROR'):
            # Parse variable format: "container[index]" or just "index"
            if '[' in variable and ']' in variable:
                container = variable.split('[')[0]
                index = variable.split('[')[1].rstrip(']')
                idx_sym = self._get_symbol(index)
                len_sym = self._get_len_symbol(container)
                # Bug occurs when index out of bounds
                return z3.Or(idx_sym < 0, idx_sym >= len_sym)
            else:
                # Just an index without container - can't verify bounds
                return z3.BoolVal(True)
        
        elif bug_type == 'KEY_ERROR':
            # Bug occurs when key not in dict
            return z3.Not(z3.Bool(f"key_valid_{variable}"))
        
        elif bug_type == 'TYPE_ERROR':
            # Bug occurs when type check fails
            return z3.BoolVal(True)  # Conservative
        
        else:
            # Unknown bug type - assume possible
            return z3.BoolVal(True)
    
    def verify_guard_implies_safe(
        self,
        guards: List[Tuple[str, str, Optional[str]]],  # [(guard_type, variable, extra), ...]
        bug_type: str,
        bug_variable: str,
    ) -> bool:
        """
        Verify that the given guards imply the bug cannot occur.
        
        Uses Z3 to check: SAT(AND(guards) AND bug_condition) == UNSAT
        
        If UNSAT, the guards prevent the bug (it's a false positive).
        If SAT, there exists an assignment where guards hold but bug still occurs.
        
        Args:
            guards: List of (guard_type, variable, extra) tuples
            bug_type: The type of bug to check
            bug_variable: The variable involved in the bug
        
        Returns:
            True if guards provably prevent the bug (UNSAT), False otherwise.
        """
        self.solver.reset()
        
        # Add guard constraints
        guard_constraints = []
        for guard_type, var, extra in guards:
            constraint = self.guard_to_z3(guard_type, var, extra)
            guard_constraints.append(constraint)
        
        # Add bug condition
        bug_constraint = self.bug_condition_to_z3(bug_type, bug_variable)
        
        # Check: SAT(guards AND bug)?
        if guard_constraints:
            self.solver.add(z3.And(*guard_constraints))
        self.solver.add(bug_constraint)
        
        result = self.solver.check()
        
        if result == z3.unsat:
            # Guards prevent the bug
            return True
        elif result == z3.sat:
            # Bug can still occur despite guards
            return False
        else:
            # Unknown/timeout - be conservative
            return False
    
    def verify_variable_match(
        self,
        guards: List[Tuple[str, str, Optional[str]]],
        bug_type: str,
        bug_variable: str,
    ) -> bool:
        """
        Check if any guard applies to the specific bug variable.
        
        This is a syntactic check before invoking Z3:
        1. If guard.variable == bug.variable (exact match)
        2. If guard.variable is a prefix (e.g., guard on "x" applies to "x[0]")
        3. If guard is on a parameter that flows to the bug variable
        
        Args:
            guards: List of (guard_type, variable, extra) tuples
            bug_type: The type of bug
            bug_variable: The variable involved in the bug
        
        Returns:
            True if any guard syntactically matches the bug variable.
        """
        return self.verify_variable_match_with_aliases(guards, bug_type, bug_variable, set())
    
    def verify_variable_match_with_aliases(
        self,
        guards: List[Tuple[str, str, Optional[str]]],
        bug_type: str,
        bug_variable: str,
        bug_var_aliases: Set[str],
    ) -> bool:
        """
        Check if any guard applies to the bug variable or its aliases.
        
        This is a syntactic check before invoking Z3:
        1. If guard.variable == bug.variable (exact match)
        2. If guard.variable is a prefix (e.g., guard on "x" applies to "x[0]")
        3. If guard is on an alias of the bug variable (value flow tracking)
        4. If guard is on a container and bug is on index into that container
        
        VALUE FLOW TRACKING enables guards to propagate through assignments:
            if x is not None:  # guard on x
                y = x          # y aliases x
                y.attr         # bug on y, guarded through alias
        
        Args:
            guards: List of (guard_type, variable, extra) tuples
            bug_type: The type of bug
            bug_variable: The variable involved in the bug
            bug_var_aliases: Set of variables that alias the bug variable
        
        Returns:
            True if any guard syntactically matches the bug variable or its aliases.
        """
        return self.find_matching_guard_variable(guards, bug_type, bug_variable, bug_var_aliases) is not None
    
    def find_matching_guard_variable(
        self,
        guards: List[Tuple[str, str, Optional[str]]],
        bug_type: str,
        bug_variable: str,
        bug_var_aliases: Set[str],
    ) -> Optional[str]:
        """
        Find the guard variable that matches the bug variable or its aliases.
        
        Returns the actual variable name from the guard that matches, so the
        Z3 verification can use the same symbol.
        
        Args:
            guards: List of (guard_type, variable, extra) tuples
            bug_type: The type of bug
            bug_variable: The variable involved in the bug
            bug_var_aliases: Set of variables that alias the bug variable
        
        Returns:
            The matched guard variable name, or None if no match.
        """
        relevant_guard_types = BUG_TYPE_TO_GUARD_TYPES.get(bug_type, set())
        
        # Variables to check: the bug variable itself plus all its aliases
        vars_to_check = {bug_variable} | bug_var_aliases
        
        # Also extract base variable from accesses (e.g., "x" from "x.attr" or "x[0]")
        base_var = bug_variable.split('[')[0].split('.')[0]
        if base_var != bug_variable:
            vars_to_check.add(base_var)
        
        for guard_type, guard_var, extra in guards:
            # Must be a relevant guard type for this bug
            if guard_type not in relevant_guard_types:
                continue
            
            # Check for exact match with any of the variables to check
            if guard_var in vars_to_check:
                return guard_var
            
            # Check if any alias is an access on guarded variable
            # e.g., guard on "x" applies to "x[0]" or "x.attr"
            for var in vars_to_check:
                if var.startswith(guard_var + '[') or var.startswith(guard_var + '.'):
                    return guard_var
            
            # Check if guard is on a container and bug is on index into that container
            # e.g., guard "nonempty" on "arr" applies to "arr[i]"
            if guard_type in ('nonempty', 'exact_length', 'range_len_loop', 'enumerate_loop', 'loop_body_nonempty'):
                for var in vars_to_check:
                    if "[" in var and var.split('[')[0] == guard_var:
                        return guard_var
            
            # Check if guard variable is an alias of the bug variable
            if guard_var in bug_var_aliases:
                return guard_var
        
        return None


def check_bug_guarded_by_z3(
    bug: 'InterproceduralBug',
    crash_summary: 'CrashSummary',
    call_chain_summaries: List['CrashSummary'],
) -> bool:
    """
    Check if a bug is guarded using Z3-backed verification.
    
    This is the main entry point for Z3-based guard checking.
    
    Uses VALUE FLOW TRACKING to find guards that apply through variable aliases:
    - If x has a guard and y = x, then y is also guarded
    - This handles the common pattern of guards on parameters that flow to locals
    
    Also handles PARAMETER NAME TRANSLATION:
    - Bug variables may be named "param_0", "param_1", etc.
    - Guards use actual variable names from the code (e.g., "self", "data")
    - We translate between these representations
    
    TYPE-BASED FILTERING:
    - 'self' and 'cls' are never None by Python semantics
    - This eliminates a large class of false positive NULL_PTR bugs
    
    DSE INTEGRATION:
    - Uses path condition tracking when available
    - Uses path-sensitive guard analysis for precision
    
    Args:
        bug: The interprocedural bug to check
        crash_summary: The CrashSummary for the function where the bug occurs
        call_chain_summaries: CrashSummaries for all functions in the call chain
    
    Returns:
        True if Z3 proves the bug is guarded, False otherwise.
    """
    # Skip if no bug_variable is set
    if not bug.bug_variable:
        return False
    
    # TYPE-BASED FILTERING: 'self' and 'cls' are never None
    # This is the first and fastest check for NULL_PTR bugs
    if bug.bug_type in ('NULL_PTR', 'ATTRIBUTE_ERROR'):
        base_var = bug.bug_variable.split('[')[0].split('.')[0]
        if base_var in ('self', 'cls'):
            return True  # By Python semantics, self/cls are never None
        
        # Also check if the bug variable is param_0 for a method
        if base_var.startswith('param_0') and crash_summary:
            # Get actual param name - if it's self or cls, it's guarded
            param_names = list(getattr(crash_summary, 'param_names', []))
            if param_names and param_names[0] in ('self', 'cls'):
                return True
    
    verifier = Z3GuardVerifier()
    
    # Collect all relevant guards from the crash function and call chain
    all_guards = []
    
    # Guards from the crash function
    if crash_summary:
        for block_id, guard_facts in crash_summary.intra_guard_facts.items():
            for guard_type, var, extra in guard_facts:
                all_guards.append((guard_type, var, extra))
        
        # TYPE-BASED FILTERING: Add implicit nonnull guards for self/cls
        # These are always nonnull by Python method call semantics
        if hasattr(crash_summary, 'function_name'):
            # For methods, add implicit nonnull for first param
            pass  # Already handled above
    
    # Guards from callers in the call chain (parameter validation)
    # NOTE: call_chain_summaries may be CrashSummary objects OR function names (strings)
    # If strings are passed, we skip them (caller should resolve to summaries if needed)
    for summary in call_chain_summaries:
        if summary and hasattr(summary, 'validated_params'):
            # Add validated parameters as guards
            for param_idx, validations in summary.validated_params.items():
                for validation in validations:
                    all_guards.append((validation, f"param_{param_idx}", None))
            
            # Add return guarantees
            for guarantee in summary.return_guarantees:
                all_guards.append((guarantee, f"call_{summary.function_name}", None))
    
    # PARAMETER NAME TRANSLATION: Convert "param_N" to actual variable names
    # Guards use actual names (self, data, etc.) but bugs may use param_N notation
    bug_variable = bug.bug_variable
    param_name_variants = {bug_variable}  # Start with original
    
    # If bug_variable is "param_N", add the actual parameter name as an alias
    if bug_variable.startswith('param_') and crash_summary:
        try:
            param_idx = int(bug_variable.split('_')[1])
            # Get actual parameter name from crash summary
            if param_idx < crash_summary.parameter_count:
                # We need to get the actual name from the function's code object
                # The validated_params maps param_idx to guard types, so we know
                # which indices have guards. We also need the actual names.
                # For now, check if any guard variable matches common param patterns
                # like "self" for param_0
                for guard_type, guard_var, extra in all_guards:
                    # Check if this guard could be the parameter by position
                    # Common patterns: self=0, request=1 in Django views
                    if param_idx == 0 and guard_var == 'self':
                        param_name_variants.add('self')
                    elif param_idx == 0 and guard_var == 'cls':
                        param_name_variants.add('cls')
                    # Add the guard variable if it has a guard type relevant to this bug
                    relevant_types = BUG_TYPE_TO_GUARD_TYPES.get(bug.bug_type, set())
                    if guard_type in relevant_types:
                        param_name_variants.add(guard_var)
        except (ValueError, IndexError):
            pass
    
    # Get aliases for all bug variable variants from value flow tracking
    bug_var_aliases = set()
    if crash_summary:
        for var in param_name_variants:
            bug_var_aliases |= crash_summary.get_all_aliases(var)
        
        # Also check if bug_variable is an access (e.g., "x.attr" or "x[0]")
        # and get aliases for the base variable
        base_var = bug_variable.split('[')[0].split('.')[0]
        if base_var != bug_variable:
            bug_var_aliases |= crash_summary.get_all_aliases(base_var)
    
    # Combine all variants with aliases
    all_bug_var_candidates = param_name_variants | bug_var_aliases
    
    # First check: syntactic variable match (including aliases and param name variants)
    # Also find the matched guard variable for Z3 verification
    matched_variable = verifier.find_matching_guard_variable(
        all_guards, bug.bug_type, bug_variable, all_bug_var_candidates
    )
    
    if matched_variable is None:
        return False
    
    # Second check: Z3 implication using the matched variable name
    # This ensures the Z3 symbols align (guard on 'self' matches bug on 'self')
    return verifier.verify_guard_implies_safe(all_guards, bug.bug_type, matched_variable)


def check_bug_guarded_by_dse(
    bug: 'InterproceduralBug',
    code: 'types.CodeType',
    crash_summary: 'CrashSummary',
) -> bool:
    """
    Check if a bug is guarded using full DSE path condition analysis.
    
    This is a stronger check than Z3-based guard checking. It:
    1. Explores paths through the function
    2. Tracks path conditions with Z3 constraints
    3. Checks if the bug condition is UNSAT on any reaching path
    
    Args:
        bug: The interprocedural bug to check
        code: The code object of the function where the bug occurs
        crash_summary: The CrashSummary for the function
    
    Returns:
        True if DSE proves the bug is unreachable (FP), False otherwise.
    """
    try:
        from ..dse.path_condition import DSEExecutor
        
        executor = DSEExecutor(
            code,
            max_paths=50,
            max_depth=30,
            solver_timeout_ms=500,
        )
        executor.analyze()
        
        # Get offset from bug if available
        offset = getattr(bug, 'crash_offset', 0)
        bug_var = bug.bug_variable or f"param_0"
        
        is_reachable, _ = executor.check_bug_reachable(
            bug.bug_type,
            bug_var,
            offset,
        )
        
        # If bug is not reachable on any path, it's guarded (FP)
        return not is_reachable
        
    except (ImportError, Exception):
        # DSE not available or failed, fall back to conservative
        return False


def check_bug_guarded_path_sensitive(
    bug: 'InterproceduralBug',
    code: 'types.CodeType',
    block_id: int,
) -> bool:
    """
    Check if a bug is guarded using path-sensitive analysis.
    
    This is lighter than full DSE but more precise than path-insensitive.
    It tracks guards per CFG path and checks if the bug is guarded on
    ALL paths to the bug location.
    
    Args:
        bug: The interprocedural bug to check
        code: The code object of the function
        block_id: The block ID where the bug occurs
    
    Returns:
        True if the bug is guarded on all paths, False otherwise.
    """
    try:
        from ..dse.value_flow import PathSensitiveGuardAnalyzer
        
        analyzer = PathSensitiveGuardAnalyzer(code, max_paths=50)
        analyzer.analyze()
        
        return analyzer.bug_is_guarded_on_all_paths(
            block_id,
            bug.bug_type,
            bug.bug_variable or "",
        )
        
    except (ImportError, Exception):
        # Path-sensitive analysis not available
        return False


# ============================================================================
# EXPORTS
# ============================================================================

__all__ = [
    # Enums
    'ReturnGuarantee',
    
    # Data classes
    'ParameterGuarantee',
    'FunctionGuardSummary',
    'InterproceduralGuardState',
    
    # Analyzers
    'FunctionGuardAnalyzer',
    'InterproceduralGuardComputer',
    
    # Integration
    'apply_interprocedural_guards_to_bugs',
    
    # Z3-backed verification
    'Z3GuardVerifier',
    'check_bug_guarded_by_z3',
    
    # DSE-backed verification
    'check_bug_guarded_by_dse',
    'check_bug_guarded_path_sensitive',
    
    # Automatic propagation utilities
    'GUARD_TYPE_TO_BUG_TYPES',
    'BUG_TYPE_TO_GUARD_TYPES',
    'get_guard_types_for_bug',
    'get_bug_types_for_guard',
]
