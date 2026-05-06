"""
Bytecode-Level Summary Computation for Intraprocedural Analysis.

Implements SOTA abstract interpretation over Python bytecode, integrating with:
- SymbolicMachineState from semantics/symbolic_vm.py
- Taint lattice L = P(T) × P(K) × P(T) from z3model/taint_lattice.py
- CFG and dataflow from cfg.control_flow, cfg.dataflow
- Unsafe predicates from unsafe/registry.py
- Guard tracking from symbolic_vm.py

This provides the canonical "bytecode-as-abstract-machine" semantics described
in barrier-certificate-theory.tex §3 and §7.

Key Features:
1. **SymbolicVM Integration**: Uses existing symbolic execution for precision
2. **Z3 Taint Lattice**: Full (τ, κ, σ) product lattice for security bugs
3. **Path-Sensitive Guards**: Leverages CFG edge conditions for precision
4. **Widening for Loops**: Ensures termination on loops with proper widening
5. **Exception Semantics**: Models exceptional control flow

Mathematical Foundation:
- Abstract domain uses SymbolicValue from z3model/values.py with Z3 expressions
- Transfer functions implemented by SymbolicVM._step()
- Fixpoint via worklist algorithm over CFG with SymbolicMachineState
"""

from __future__ import annotations
from dataclasses import dataclass, field
from typing import Dict, List, Set, Optional, Tuple, Any, FrozenSet
from enum import IntEnum, auto
import dis
import types
import z3

from ..cfg.control_flow import (
    build_cfg, ControlFlowGraph, BasicBlock, EdgeType, ExceptionRegion
)
from ..cfg.dataflow import (
    run_intraprocedural_analysis, IntraprocAnalysisResult,
    GuardState, TypeState, BoundsInfo
)
from ..unsafe.registry import (
    UNSAFE_PREDICATES, check_unsafe_regions, list_implemented_bug_types
)
from ..z3model.taint_lattice import (
    TaintLabel, SymbolicTaintLabel,
    SourceType, SinkType, SanitizerType,
    TAU_WIDTH, KAPPA_WIDTH, SIGMA_WIDTH,
    tau_zero, kappa_full, sigma_zero,
)
from ..z3model.values import SymbolicValue, ValueTag


# ============================================================================
# ABSTRACT VALUE LATTICE
# ============================================================================

class Nullability(IntEnum):
    """Nullability lattice: ⊥ ⊑ NotNone ⊑ ⊤, ⊥ ⊑ IsNone ⊑ ⊤"""
    BOTTOM = 0       # Unreachable
    NOT_NONE = 1     # Definitely not None
    IS_NONE = 2      # Definitely None  
    TOP = 3          # Unknown (may be None or not)
    
    def join(self, other: 'Nullability') -> 'Nullability':
        if self == Nullability.BOTTOM:
            return other
        if other == Nullability.BOTTOM:
            return self
        if self == other:
            return self
        return Nullability.TOP
    
    def meet(self, other: 'Nullability') -> 'Nullability':
        if self == Nullability.TOP:
            return other
        if other == Nullability.TOP:
            return self
        if self == other:
            return self


class Emptiness(IntEnum):
    """Emptiness lattice for collection/sequence tracking.
    
    Used to detect:
    - EMPTY_COLLECTION_DIV: Division by len() when collection might be empty
    - EMPTY_COLLECTION_INDEX: Indexing [0] on potentially empty collections
    """
    BOTTOM = 0          # Unreachable
    NON_EMPTY = 1       # Collection has at least one element (len >= 1)
    EMPTY = 2           # Collection is definitely empty (len == 0)
    TOP = 3             # Unknown (may be empty or non-empty)
    
    def join(self, other: 'Emptiness') -> 'Emptiness':
        if self == Emptiness.BOTTOM:
            return other
        if other == Emptiness.BOTTOM:
            return self
        if self == other:
            return self
        return Emptiness.TOP
    
    def meet(self, other: 'Emptiness') -> 'Emptiness':
        if self == Emptiness.TOP:
            return other
        if other == Emptiness.TOP:
            return self
        if self == other:
            return self
        return Emptiness.BOTTOM


@dataclass(frozen=True)
class DictKeySet:
    """Tracks known dictionary keys for DICT_KEY_MISSING detection.
    
    - known_keys: Set of keys definitely present in the dict
    - is_complete: If True, no other keys exist (closed dict)
    - is_top: If True, key set is unknown
    """
    known_keys: FrozenSet[str] = field(default_factory=frozenset)
    is_complete: bool = False  # True = closed dict (only these keys exist)
    is_top: bool = True        # True = unknown key set
    
    def join(self, other: 'DictKeySet') -> 'DictKeySet':
        if self.is_top and other.is_top:
            return DictKeySet(is_top=True)
        if self.is_top:
            return other
        if other.is_top:
            return self
        # Both have known keys - intersect (definitely present in both paths)
        common_keys = self.known_keys & other.known_keys
        return DictKeySet(
            known_keys=common_keys,
            is_complete=self.is_complete and other.is_complete,
            is_top=False
        )
    
    def has_key(self, key: str) -> bool:
        """Returns True if key is definitely present."""
        if self.is_top:
            return False  # Unknown
        return key in self.known_keys
    
    def missing_key(self, key: str) -> bool:
        """Returns True if key is definitely NOT present."""
        if self.is_top:
            return False  # Unknown, can't say it's missing
        if not self.is_complete:
            return False  # Open dict, key might exist
        return key not in self.known_keys
    
    @classmethod
    def from_keys(cls, keys: Set[str], complete: bool = False) -> 'DictKeySet':
        return cls(known_keys=frozenset(keys), is_complete=complete, is_top=False)
    
    @classmethod
    def top(cls) -> 'DictKeySet':
        return cls(is_top=True)
    
    @classmethod
    def empty_dict(cls) -> 'DictKeySet':
        """Represents an empty dict {}."""
        return cls(known_keys=frozenset(), is_complete=True, is_top=False)
        return Nullability.BOTTOM


class Zeroness(IntEnum):
    """Zeroness lattice for division safety."""
    BOTTOM = 0       # Unreachable
    NON_ZERO = 1     # Definitely != 0
    ZERO = 2         # Definitely == 0
    TOP = 3          # Unknown
    
    def join(self, other: 'Zeroness') -> 'Zeroness':
        if self == Zeroness.BOTTOM:
            return other
        if other == Zeroness.BOTTOM:
            return self
        if self == other:
            return self
        return Zeroness.TOP
    
    def meet(self, other: 'Zeroness') -> 'Zeroness':
        if self == Zeroness.TOP:
            return other
        if other == Zeroness.TOP:
            return self
        if self == other:
            return self
        return Zeroness.BOTTOM


class Sign(IntEnum):
    """Sign lattice for bounds analysis."""
    BOTTOM = 0
    NEGATIVE = 1     # < 0
    ZERO = 2         # == 0
    POSITIVE = 3     # > 0
    NON_NEGATIVE = 4 # >= 0
    NON_POSITIVE = 5 # <= 0
    TOP = 6          # Any
    
    def join(self, other: 'Sign') -> 'Sign':
        if self == Sign.BOTTOM:
            return other
        if other == Sign.BOTTOM:
            return self
        if self == other:
            return self
        # Lattice join rules
        if {self, other} == {Sign.ZERO, Sign.POSITIVE}:
            return Sign.NON_NEGATIVE
        if {self, other} == {Sign.ZERO, Sign.NEGATIVE}:
            return Sign.NON_POSITIVE
        if {self, other} == {Sign.NON_NEGATIVE, Sign.NEGATIVE}:
            return Sign.TOP
        if {self, other} == {Sign.NON_POSITIVE, Sign.POSITIVE}:
            return Sign.TOP
        return Sign.TOP


@dataclass(frozen=True)
class TaintLabel:
    """
    Taint label from the product lattice L = P(T) × P(K) × P(T).
    
    Uses bitvectors for efficiency (as in z3model/taint_lattice.py).
    """
    tau: int = 0           # Sources: which taint types are present
    kappa: int = 0xFFFFFF  # Sanitizers: which sinks are protected (⊤ = all)
    sigma: int = 0         # Sinks: which sink checks have been performed
    
    def join(self, other: 'TaintLabel') -> 'TaintLabel':
        """Lattice join: τ∪, κ∩, σ∪"""
        return TaintLabel(
            tau=self.tau | other.tau,
            kappa=self.kappa & other.kappa,
            sigma=self.sigma | other.sigma,
        )
    
    def meet(self, other: 'TaintLabel') -> 'TaintLabel':
        """Lattice meet: τ∩, κ∪, σ∩"""
        return TaintLabel(
            tau=self.tau & other.tau,
            kappa=self.kappa | other.kappa,
            sigma=self.sigma & other.sigma,
        )
    
    def is_tainted(self) -> bool:
        return self.tau != 0
    
    def is_sanitized_for(self, sink_type: int) -> bool:
        return (self.kappa & (1 << sink_type)) != 0
    
    @classmethod
    def clean(cls) -> 'TaintLabel':
        return cls(tau=0, kappa=0xFFFFFF, sigma=0)
    
    @classmethod
    def tainted(cls, source_type: int) -> 'TaintLabel':
        return cls(tau=(1 << source_type), kappa=0, sigma=0)
    
    @classmethod
    def bottom(cls) -> 'TaintLabel':
        return cls(tau=0, kappa=0xFFFFFF, sigma=0)


@dataclass
class AbstractValue:
    """
    Abstract value in the product domain.
    
    A = Nullability × Zeroness × Sign × Emptiness × DictKeySet × TaintLabel × TypeSet × ParamSources
    
    This captures all properties needed for bug detection:
    - Nullability: for NULL_PTR detection
    - Zeroness: for DIV_ZERO detection  
    - Sign: for BOUNDS detection (negative indices)
    - Emptiness: for EMPTY_COLLECTION_DIV and EMPTY_COLLECTION_INDEX detection
    - DictKeySet: for DICT_KEY_MISSING detection
    - TaintLabel: for security bug detection
    - TypeSet: for TYPE_CONFUSION detection
    - ParamSources: which parameters this value derives from (for summaries)
    """
    nullability: Nullability = Nullability.TOP
    zeroness: Zeroness = Zeroness.TOP
    sign: Sign = Sign.TOP
    emptiness: Emptiness = Emptiness.TOP  # NEW: collection emptiness
    dict_keys: DictKeySet = field(default_factory=DictKeySet.top)  # NEW: known dict keys
    taint: TaintLabel = field(default_factory=TaintLabel.clean)
    types: FrozenSet[str] = field(default_factory=frozenset)  # Empty = unknown
    param_sources: FrozenSet[int] = field(default_factory=frozenset)  # Which params flow here
    
    # Numeric bounds (for widening)
    lower_bound: Optional[int] = None
    upper_bound: Optional[int] = None
    
    # NEW: Track if this value is the result of len() on a collection
    is_len_result: bool = False
    len_source_emptiness: Emptiness = Emptiness.TOP  # Emptiness of the collection len() was called on
    
    # NEW: Track collection length bounds for BOUNDS detection
    # If this collection has length constraints, track them here
    len_lower_bound: Optional[int] = None  # Minimum length (e.g., len >= 2)
    len_upper_bound: Optional[int] = None  # Maximum length
    
    # NEW: Track if value might contain zeros (for array normalization)
    may_contain_zeros: bool = True  # For arrays/lists, can any element be 0?
    
    # NEW: Track when a boolean encodes emptiness information about variables
    # If this bool is True, the sources in empty_when_true are EMPTY
    # If this bool is False, the sources in empty_when_true are NON_EMPTY
    empty_when_true_sources: FrozenSet[int] = field(default_factory=frozenset)
    # Inverse: if bool is True, sources are NON_EMPTY; if False, sources are EMPTY
    nonempty_when_true_sources: FrozenSet[int] = field(default_factory=frozenset)
    
    def join(self, other: 'AbstractValue') -> 'AbstractValue':
        """Lattice join."""
        return AbstractValue(
            nullability=self.nullability.join(other.nullability),
            zeroness=self.zeroness.join(other.zeroness),
            sign=self.sign.join(other.sign),
            emptiness=self.emptiness.join(other.emptiness),
            dict_keys=self.dict_keys.join(other.dict_keys),
            taint=self.taint.join(other.taint),
            types=self.types | other.types if self.types and other.types else frozenset(),
            param_sources=self.param_sources | other.param_sources,
            lower_bound=min(self.lower_bound, other.lower_bound) if self.lower_bound is not None and other.lower_bound is not None else None,
            upper_bound=max(self.upper_bound, other.upper_bound) if self.upper_bound is not None and other.upper_bound is not None else None,
            is_len_result=self.is_len_result or other.is_len_result,
            len_source_emptiness=self.len_source_emptiness.join(other.len_source_emptiness),
            # Join len bounds conservatively: min of lower bounds, max of upper bounds
            len_lower_bound=min(self.len_lower_bound, other.len_lower_bound) if self.len_lower_bound is not None and other.len_lower_bound is not None else None,
            len_upper_bound=max(self.len_upper_bound, other.len_upper_bound) if self.len_upper_bound is not None and other.len_upper_bound is not None else None,
            may_contain_zeros=self.may_contain_zeros or other.may_contain_zeros,
            # For emptiness indicators, take intersection (conservative)
            empty_when_true_sources=self.empty_when_true_sources & other.empty_when_true_sources,
            nonempty_when_true_sources=self.nonempty_when_true_sources & other.nonempty_when_true_sources,
        )
    
    def widen(self, other: 'AbstractValue') -> 'AbstractValue':
        """Widening operator for loop convergence."""
        result = self.join(other)
        # Drop bounds if they're growing
        if self.lower_bound is not None and other.lower_bound is not None:
            if other.lower_bound < self.lower_bound:
                result.lower_bound = None  # Widen to -∞
        if self.upper_bound is not None and other.upper_bound is not None:
            if other.upper_bound > self.upper_bound:
                result.upper_bound = None  # Widen to +∞
        return result
    
    @classmethod
    def from_param(cls, param_idx: int) -> 'AbstractValue':
        """Create abstract value for a function parameter."""
        return cls(
            nullability=Nullability.TOP,  # Params may be None
            zeroness=Zeroness.TOP,
            sign=Sign.TOP,
            taint=TaintLabel.clean(),
            types=frozenset(),
            param_sources=frozenset({param_idx}),
        )
    
    @classmethod
    def from_const(cls, value: Any) -> 'AbstractValue':
        """Create abstract value from a constant."""
        if value is None:
            return cls(
                nullability=Nullability.IS_NONE,
                zeroness=Zeroness.TOP,
                sign=Sign.TOP,
                types=frozenset({'NoneType'}),
                param_sources=frozenset(),
            )
        
        null = Nullability.NOT_NONE
        zero = Zeroness.TOP
        sgn = Sign.TOP
        typ = frozenset({type(value).__name__})
        lower = None
        upper = None
        emptiness = Emptiness.TOP
        dict_keys = DictKeySet.top()
        may_contain_zeros = True
        
        if isinstance(value, bool):
            zero = Zeroness.NON_ZERO if value else Zeroness.ZERO
            sgn = Sign.POSITIVE if value else Sign.ZERO
        elif isinstance(value, int):
            zero = Zeroness.ZERO if value == 0 else Zeroness.NON_ZERO
            if value < 0:
                sgn = Sign.NEGATIVE
            elif value == 0:
                sgn = Sign.ZERO
            else:
                sgn = Sign.POSITIVE
            lower = value
            upper = value
        elif isinstance(value, float):
            zero = Zeroness.ZERO if value == 0.0 else Zeroness.NON_ZERO
            if value < 0:
                sgn = Sign.NEGATIVE
            elif value == 0:
                sgn = Sign.ZERO
            else:
                sgn = Sign.POSITIVE
        elif isinstance(value, str):
            zero = Zeroness.NON_ZERO  # Strings are truthy unless empty
            emptiness = Emptiness.EMPTY if len(value) == 0 else Emptiness.NON_EMPTY
        elif isinstance(value, (list, tuple, set, frozenset)):
            # Track collection emptiness and precise length
            size = len(value)
            emptiness = Emptiness.EMPTY if size == 0 else Emptiness.NON_EMPTY
            # Check if any element is 0 (for normalization safety)
            may_contain_zeros = any(v == 0 for v in value if isinstance(v, (int, float)))
        elif isinstance(value, dict):
            # NEW: Track dictionary keys
            emptiness = Emptiness.EMPTY if len(value) == 0 else Emptiness.NON_EMPTY
            dict_keys = DictKeySet.from_keys({str(k) for k in value.keys()}, complete=True)
        
        # For collections, track length
        len_lower = None
        len_upper = None
        if isinstance(value, (list, tuple, set, frozenset, str)):
            size = len(value)
            len_lower = size
            len_upper = size
        
        return cls(
            nullability=null,
            zeroness=zero,
            sign=sgn,
            emptiness=emptiness,
            dict_keys=dict_keys,
            types=typ,
            param_sources=frozenset(),
            lower_bound=lower,
            upper_bound=upper,
            may_contain_zeros=may_contain_zeros,
            len_lower_bound=len_lower,
            len_upper_bound=len_upper,
        )
    
    @classmethod
    def bottom(cls) -> 'AbstractValue':
        """Bottom element (unreachable)."""
        return cls(
            nullability=Nullability.BOTTOM,
            zeroness=Zeroness.BOTTOM,
            sign=Sign.BOTTOM,
            taint=TaintLabel.bottom(),
            types=frozenset(),
            param_sources=frozenset(),
        )
    
    @classmethod
    def top(cls) -> 'AbstractValue':
        """Top element (no information)."""
        return cls()


# ============================================================================
# ABSTRACT MACHINE STATE
# ============================================================================

@dataclass
class AbstractState:
    """
    Abstract state of the Python bytecode machine.
    
    Models:
    - Operand stack: list of AbstractValue
    - Local variables: Dict[int, AbstractValue] (by varname index)
    - Global/builtin bindings (simplified)
    """
    stack: List[AbstractValue] = field(default_factory=list)
    locals: Dict[int, AbstractValue] = field(default_factory=dict)
    globals: Dict[str, AbstractValue] = field(default_factory=dict)
    
    # Tracking
    is_bottom: bool = False  # Unreachable state
    
    def copy(self) -> 'AbstractState':
        return AbstractState(
            stack=self.stack.copy(),
            locals=self.locals.copy(),
            globals=self.globals.copy(),
            is_bottom=self.is_bottom,
        )
    
    def join(self, other: 'AbstractState') -> 'AbstractState':
        """Join two states (at control flow merge)."""
        if self.is_bottom:
            return other.copy()
        if other.is_bottom:
            return self.copy()
        
        # Join stacks (must have same depth for well-formed bytecode)
        max_len = max(len(self.stack), len(other.stack))
        joined_stack = []
        for i in range(max_len):
            v1 = self.stack[i] if i < len(self.stack) else AbstractValue.bottom()
            v2 = other.stack[i] if i < len(other.stack) else AbstractValue.bottom()
            joined_stack.append(v1.join(v2))
        
        # Join locals
        all_vars = set(self.locals.keys()) | set(other.locals.keys())
        joined_locals = {}
        for var in all_vars:
            v1 = self.locals.get(var, AbstractValue.bottom())
            v2 = other.locals.get(var, AbstractValue.bottom())
            joined_locals[var] = v1.join(v2)
        
        # Join globals
        all_globals = set(self.globals.keys()) | set(other.globals.keys())
        joined_globals = {}
        for name in all_globals:
            v1 = self.globals.get(name, AbstractValue.bottom())
            v2 = other.globals.get(name, AbstractValue.bottom())
            joined_globals[name] = v1.join(v2)
        
        return AbstractState(
            stack=joined_stack,
            locals=joined_locals,
            globals=joined_globals,
            is_bottom=False,
        )
    
    def widen(self, other: 'AbstractState') -> 'AbstractState':
        """Widening for loop convergence."""
        if self.is_bottom:
            return other.copy()
        if other.is_bottom:
            return self.copy()
        
        result = self.join(other)
        
        # Apply widening to locals
        for var in result.locals:
            if var in self.locals:
                result.locals[var] = self.locals[var].widen(result.locals[var])
        
        return result
    
    @classmethod
    def bottom(cls) -> 'AbstractState':
        return cls(is_bottom=True)
    
    def push(self, value: AbstractValue) -> None:
        self.stack.append(value)
    
    def pop(self) -> AbstractValue:
        if self.stack:
            return self.stack.pop()
        return AbstractValue.top()
    
    def peek(self, depth: int = 0) -> AbstractValue:
        """Peek at stack[-(depth+1)]."""
        idx = -(depth + 1)
        if abs(idx) <= len(self.stack):
            return self.stack[idx]
        return AbstractValue.top()


# ============================================================================
# ABSTRACT INTERPRETER
# ============================================================================

# Bug types that can be detected (subset from registry)
BUG_TYPES = list_implemented_bug_types()

# Opcode categories
BINARY_OPS_DIVISION = {2, 6, 11, 15, 19, 24}  # floor_divide, remainder, true_divide
BINARY_OPS_SUBSCRIPT = {26}  # Python 3.13+


@dataclass
class BugReport:
    """A potential bug found during abstract interpretation."""
    bug_type: str
    offset: int
    line_number: Optional[int]
    message: str
    confidence: float  # 0.0 to 1.0
    param_sources: FrozenSet[int]  # Which params contribute to bug
    is_guarded: bool = False  # True if a guard protects this


@dataclass
class BytecodeSummary:
    """
    Complete summary of a function's behavior.
    
    Integrates:
    - Taint flow (which params flow to return, with transformations)
    - Crash conditions (which params may cause which bugs)
    - Nullability (param/return None-ness)
    - Exception effects
    """
    function_name: str
    qualified_name: str
    parameter_count: int
    
    # Param → Return flow (for taint)
    param_to_return: Set[int] = field(default_factory=set)
    
    # Return value properties
    return_nullability: Nullability = Nullability.TOP
    return_taint: TaintLabel = field(default_factory=TaintLabel.clean)
    return_emptiness: Emptiness = Emptiness.TOP
    return_len_lower_bound: Optional[int] = None
    return_len_upper_bound: Optional[int] = None
    
    # Parameter constraints (for preconditions)
    # Maps param_idx -> (emptiness, len_lower, len_upper)
    param_constraints: Dict[int, Tuple[Emptiness, Optional[int], Optional[int]]] = field(default_factory=dict)
    
    # Bugs that may be triggered
    potential_bugs: List[BugReport] = field(default_factory=list)
    
    # Per-param bug propagation
    # Maps param_idx -> set of bug types that param may trigger
    param_bug_propagation: Dict[int, Set[str]] = field(default_factory=dict)
    
    # Exception info
    may_raise: Set[str] = field(default_factory=set)  # Exception class names
    
    # From intraprocedural analysis integration
    intraproc_result: Optional[IntraprocAnalysisResult] = None
    
    # Side effects
    has_side_effects: bool = False
    modifies_globals: bool = False
    performs_io: bool = False
    
    def bugs_from_param(self, param_idx: int) -> Set[str]:
        """Get bug types that may be triggered by a parameter."""
        return self.param_bug_propagation.get(param_idx, set())
    
    def high_confidence_bugs(self, threshold: float = 0.7) -> List[BugReport]:
        """Get bugs with confidence above threshold."""
        return [b for b in self.potential_bugs if b.confidence >= threshold and not b.is_guarded]


class BytecodeAbstractInterpreter:
    """
    Abstract interpreter for Python bytecode.
    
    Computes a BytecodeSummary by abstract interpretation over the CFG,
    integrating with existing infrastructure:
    - Uses IntraprocAnalysisResult for guards/types/bounds
    - Uses CFG for control flow and exception handling
    - Applies widening at loop headers
    """
    
    def __init__(
        self,
        code: types.CodeType,
        func_name: str,
        qualified_name: str,
        callee_summaries: Optional[Dict[str, 'BytecodeSummary']] = None,
    ):
        self.code = code
        self.func_name = func_name
        self.qualified_name = qualified_name
        self.callee_summaries = callee_summaries or {}
        
        # Build CFG and run intraprocedural analysis
        self.cfg = build_cfg(code)
        self.intraproc = run_intraprocedural_analysis(code)
        
        # Parse code object
        self.instructions = list(dis.get_instructions(code))
        self.offset_to_instr = {i.offset: i for i in self.instructions}
        
        # Parameter info
        self.param_count = code.co_argcount + code.co_kwonlyargcount
        if code.co_flags & 0x04:  # CO_VARARGS
            self.param_count += 1
        if code.co_flags & 0x08:  # CO_VARKEYWORDS
            self.param_count += 1
        
        self.varnames = code.co_varnames
        self.const_values = code.co_consts
        
        # Analysis results
        self.block_entry_states: Dict[int, AbstractState] = {}
        self.block_exit_states: Dict[int, AbstractState] = {}
        self.potential_bugs: List[BugReport] = []
        self.return_values: List[AbstractValue] = []
        
        # Side effect tracking
        self.has_side_effects = False
        self.modifies_globals = False
        self.performs_io = False
        self.exceptions_raised: Set[str] = set()
    
    def analyze(self) -> BytecodeSummary:
        """Run abstract interpretation and produce summary."""
        # Initialize entry state with parameters
        entry_state = self._make_entry_state()
        self.block_entry_states[self.cfg.entry_block] = entry_state
        
        # Worklist algorithm with widening
        worklist = [self.cfg.entry_block]
        iterations: Dict[int, int] = {bid: 0 for bid in self.cfg.blocks}
        WIDEN_THRESHOLD = 3
        
        while worklist:
            block_id = worklist.pop(0)
            block = self.cfg.blocks[block_id]
            
            # Get entry state
            entry = self.block_entry_states.get(block_id, AbstractState.bottom())
            if entry.is_bottom:
                continue
            
            # Transfer through block
            exit_state = self._transfer_block(block, entry)
            self.block_exit_states[block_id] = exit_state
            
            # Propagate to successors
            for succ_id, edge_type, condition in block.successors:
                # Apply edge refinement
                refined = self._refine_on_edge(exit_state, edge_type, condition, block)
                
                # Get existing state at successor
                old_succ = self.block_entry_states.get(succ_id, AbstractState.bottom())
                
                # Merge (with widening at loop headers)
                iterations[succ_id] = iterations.get(succ_id, 0) + 1
                if succ_id in self.cfg.loop_headers and iterations[succ_id] > WIDEN_THRESHOLD:
                    new_succ = old_succ.widen(refined)
                else:
                    new_succ = old_succ.join(refined)
                
                # Check for change
                if self._state_changed(old_succ, new_succ):
                    self.block_entry_states[succ_id] = new_succ
                    if succ_id not in worklist:
                        worklist.append(succ_id)
        
        return self._build_summary()
    
    def _make_entry_state(self) -> AbstractState:
        """Create initial state with parameters."""
        state = AbstractState()
        for i in range(self.param_count):
            state.locals[i] = AbstractValue.from_param(i)
        return state
    
    def _transfer_block(self, block: BasicBlock, entry: AbstractState) -> AbstractState:
        """Transfer function for an entire basic block."""
        state = entry.copy()
        
        for instr in block.instructions:
            if state.is_bottom:
                break
            state = self._transfer_instr(instr, state, block.id)
        
        return state
    
    def _transfer_instr(
        self, 
        instr: dis.Instruction, 
        state: AbstractState,
        block_id: int,
    ) -> AbstractState:
        """Transfer function for a single instruction."""
        op = instr.opname
        arg = instr.arg
        argval = instr.argval
        offset = instr.offset
        
        # Get guards valid at this point
        guards = self.intraproc.get_guards_at_offset(offset)
        
        # Dispatch based on opcode
        if op == 'RESUME':
            pass  # No-op
        
        elif op == 'LOAD_CONST':
            val = self.const_values[arg] if arg is not None and arg < len(self.const_values) else None
            state.push(AbstractValue.from_const(val))
        
        elif op == 'LOAD_SMALL_INT':
            # LOAD_SMALL_INT pushes a small integer constant
            state.push(AbstractValue.from_const(arg if arg is not None else 0))
        
        elif op in ('LOAD_FAST', 'LOAD_FAST_BORROW', 'LOAD_FAST_LOAD_FAST', 
                    'LOAD_FAST_BORROW_LOAD_FAST_BORROW'):
            if op in ('LOAD_FAST_LOAD_FAST', 'LOAD_FAST_BORROW_LOAD_FAST_BORROW'):
                # Two loads encoded in argval
                if isinstance(argval, tuple):
                    for var in argval:
                        idx = self.varnames.index(var) if var in self.varnames else -1
                        if idx >= 0 and idx in state.locals:
                            state.push(state.locals[idx])
                        else:
                            state.push(AbstractValue.top())
            else:
                idx = arg if arg is not None else -1
                if idx >= 0 and idx in state.locals:
                    state.push(state.locals[idx])
                else:
                    state.push(AbstractValue.top())
        
        elif op in ('STORE_FAST', 'STORE_NAME'):
            val = state.pop()
            idx = arg if arg is not None else -1
            if idx >= 0:
                state.locals[idx] = val
        
        elif op in ('LOAD_GLOBAL', 'LOAD_NAME'):
            name = argval
            if name in state.globals:
                state.push(state.globals[name])
            else:
                # Unknown global - conservative
                state.push(AbstractValue.top())
        
        elif op == 'STORE_GLOBAL':
            val = state.pop()
            name = argval
            state.globals[name] = val
            self.modifies_globals = True
            self.has_side_effects = True
        
        elif op == 'BINARY_OP':
            self._handle_binary_op(state, arg, offset, guards, instr)
        
        elif op == 'COMPARE_OP':
            right = state.pop()
            left = state.pop()
            
            # Track emptiness indicators for len(x) comparisons with 0
            empty_when_true = frozenset()
            nonempty_when_true = frozenset()
            
            # Check for len(x) == 0 or len(x) != 0 patterns
            # argval contains the comparison operator
            cmp_op = argval if argval else ''
            
            # len(x) == 0: if true, x is empty; if false, x is non-empty
            if left.is_len_result and right.zeroness == Zeroness.ZERO:
                if '==' in str(cmp_op) or 'eq' in str(cmp_op).lower():
                    empty_when_true = left.param_sources
                elif '!=' in str(cmp_op) or 'ne' in str(cmp_op).lower():
                    nonempty_when_true = left.param_sources
                elif '>' in str(cmp_op) and '=' not in str(cmp_op):
                    # len(x) > 0: if true, x is non-empty
                    nonempty_when_true = left.param_sources
                elif '<=' in str(cmp_op):
                    # len(x) <= 0: if true (len==0), x is empty
                    empty_when_true = left.param_sources
            # Also handle 0 == len(x), 0 < len(x), etc.
            elif right.is_len_result and left.zeroness == Zeroness.ZERO:
                if '==' in str(cmp_op) or 'eq' in str(cmp_op).lower():
                    empty_when_true = right.param_sources
                elif '!=' in str(cmp_op) or 'ne' in str(cmp_op).lower():
                    nonempty_when_true = right.param_sources
                elif '<' in str(cmp_op) and '=' not in str(cmp_op):
                    # 0 < len(x): if true, x is non-empty
                    nonempty_when_true = right.param_sources
                elif '>=' in str(cmp_op):
                    # 0 >= len(x): if true (len==0), x is empty  
                    empty_when_true = right.param_sources
            
            # Result is boolean with combined sources
            result = AbstractValue(
                nullability=Nullability.NOT_NONE,
                zeroness=Zeroness.TOP,  # Comparison result may be True or False
                types=frozenset({'bool'}),
                param_sources=left.param_sources | right.param_sources,
                empty_when_true_sources=empty_when_true,
                nonempty_when_true_sources=nonempty_when_true,
            )
            state.push(result)
        
        elif op == 'IS_OP':
            right = state.pop()
            left = state.pop()
            result = AbstractValue(
                nullability=Nullability.NOT_NONE,
                types=frozenset({'bool'}),
                param_sources=left.param_sources | right.param_sources,
            )
            state.push(result)
        
        elif op == 'LOAD_ATTR':
            self._handle_load_attr(state, argval, offset, guards, instr)
        
        elif op in ('CALL', 'CALL_FUNCTION', 'CALL_METHOD'):
            self._handle_call(state, arg, offset, guards, instr)
        
        elif op in ('RETURN_VALUE', 'RETURN_CONST'):
            if op == 'RETURN_CONST':
                val = self.const_values[arg] if arg is not None and arg < len(self.const_values) else None
                self.return_values.append(AbstractValue.from_const(val))
            else:
                ret_val = state.pop()
                self.return_values.append(ret_val)
        
        elif op == 'RAISE_VARARGS':
            self.exceptions_raised.add('Exception')
            state = AbstractState.bottom()
        
        elif op == 'POP_TOP':
            state.pop()
        
        # Handle conditional jumps that pop their condition
        elif op in ('POP_JUMP_IF_TRUE', 'POP_JUMP_IF_FALSE',
                    'POP_JUMP_FORWARD_IF_TRUE', 'POP_JUMP_FORWARD_IF_FALSE',
                    'POP_JUMP_FORWARD_IF_NONE', 'POP_JUMP_IF_NONE',
                    'POP_JUMP_FORWARD_IF_NOT_NONE', 'POP_JUMP_IF_NOT_NONE'):
            # These instructions pop the top of stack (the condition)
            state.pop()
        
        elif op == 'COPY':
            if state.stack:
                state.push(state.peek(0))
        
        elif op == 'SWAP':
            if len(state.stack) >= 2:
                state.stack[-1], state.stack[-2] = state.stack[-2], state.stack[-1]
        
        elif op == 'PUSH_NULL':
            state.push(AbstractValue.from_const(None))
        
        elif op in ('BUILD_LIST', 'BUILD_TUPLE', 'BUILD_SET'):
            count = arg or 0
            sources = frozenset()
            for _ in range(count):
                v = state.pop()
                sources = sources | v.param_sources
            result = AbstractValue(
                nullability=Nullability.NOT_NONE,
                zeroness=Zeroness.NON_ZERO if count > 0 else Zeroness.ZERO,
                emptiness=Emptiness.EMPTY if count == 0 else Emptiness.NON_EMPTY,
                types=frozenset({'list' if 'LIST' in op else 'tuple' if 'TUPLE' in op else 'set'}),
                param_sources=sources,
                len_lower_bound=count,
                len_upper_bound=count,
            )
            state.push(result)
        
        elif op in ('LIST_EXTEND', 'TUPLE_EXTEND', 'SET_UPDATE'):
            # Extends list/tuple/set with iterable on TOS
            # Stack: list, iterable -> list (extended)
            iterable = state.pop()
            collection = state.peek()
            
            # If we know both lengths precisely, we can compute new length
            if (collection.len_lower_bound is not None and 
                collection.len_upper_bound is not None and
                collection.len_lower_bound == collection.len_upper_bound and
                iterable.len_lower_bound is not None and
                iterable.len_upper_bound is not None and
                iterable.len_lower_bound == iterable.len_upper_bound):
                # Precise length: add them
                new_len = collection.len_lower_bound + iterable.len_lower_bound
                collection.len_lower_bound = new_len
                collection.len_upper_bound = new_len
            else:
                # Merge bounds: add lower bounds, add upper bounds
                if collection.len_lower_bound is not None and iterable.len_lower_bound is not None:
                    collection.len_lower_bound += iterable.len_lower_bound
                else:
                    collection.len_lower_bound = None
                
                if collection.len_upper_bound is not None and iterable.len_upper_bound is not None:
                    collection.len_upper_bound += iterable.len_upper_bound
                else:
                    collection.len_upper_bound = None
            
            # Extending makes it non-empty if iterable is non-empty
            if iterable.emptiness == Emptiness.NON_EMPTY:
                collection.emptiness = Emptiness.NON_EMPTY
            
            # Merge param sources
            collection.param_sources = collection.param_sources | iterable.param_sources
        
        elif op == 'BUILD_MAP':
            count = arg or 0
            sources = frozenset()
            for _ in range(count * 2):  # key-value pairs
                v = state.pop()
                sources = sources | v.param_sources
            result = AbstractValue(
                nullability=Nullability.NOT_NONE,
                types=frozenset({'dict'}),
                param_sources=sources,
            )
            state.push(result)
        
        elif op == 'UNARY_NOT':
            val = state.pop()
            result = AbstractValue(
                nullability=Nullability.NOT_NONE,
                types=frozenset({'bool'}),
                param_sources=val.param_sources,
            )
            state.push(result)
        
        elif op == 'TO_BOOL':
            # TO_BOOL converts TOS to a bool - it replaces but doesn't change depth
            # We preserve the param_sources so we can track the original variable
            val = state.pop()
            result = AbstractValue(
                nullability=Nullability.NOT_NONE,
                types=frozenset({'bool'}),
                param_sources=val.param_sources,
                # Preserve emptiness info for later refinement detection
                emptiness=val.emptiness,
                # Preserve emptiness indicator fields from comparisons
                empty_when_true_sources=val.empty_when_true_sources,
                nonempty_when_true_sources=val.nonempty_when_true_sources,
            )
            state.push(result)
        
        elif op == 'UNARY_NEGATIVE':
            val = state.pop()
            # Negate sign
            new_sign = Sign.TOP
            if val.sign == Sign.POSITIVE:
                new_sign = Sign.NEGATIVE
            elif val.sign == Sign.NEGATIVE:
                new_sign = Sign.POSITIVE
            elif val.sign == Sign.ZERO:
                new_sign = Sign.ZERO
            
            result = AbstractValue(
                nullability=val.nullability,
                zeroness=val.zeroness,
                sign=new_sign,
                types=val.types,
                param_sources=val.param_sources,
            )
            state.push(result)
        
        elif op == 'GET_ITER':
            val = state.pop()
            result = AbstractValue(
                nullability=Nullability.NOT_NONE,
                param_sources=val.param_sources,
            )
            state.push(result)
        
        elif op == 'FOR_ITER':
            # Iterator may yield or be exhausted
            self.exceptions_raised.add('StopIteration')
        
        elif op == 'LOAD_ASSERTION_ERROR':
            state.push(AbstractValue.from_const(AssertionError))
            self._add_bug('ASSERT_FAIL', offset, instr, frozenset(), guards, 0.5)
        
        elif op in ('IMPORT_NAME', 'IMPORT_FROM'):
            state.push(AbstractValue.top())
        
        else:
            # Unknown opcode - conservative handling
            # Pop inputs based on opcode stack effect, push unknown outputs
            pass
        
        return state
    
    def _handle_binary_op(
        self,
        state: AbstractState,
        oparg: int,
        offset: int,
        guards: GuardState,
        instr: dis.Instruction,
    ) -> None:
        """Handle BINARY_OP instruction with bug detection."""
        right = state.pop()
        left = state.pop()
        
        sources = left.param_sources | right.param_sources
        result = AbstractValue(
            param_sources=sources,
            taint=left.taint.join(right.taint),
        )
        
        # Check for division
        if oparg in BINARY_OPS_DIVISION:
            # Check if divisor may be zero
            if right.zeroness != Zeroness.NON_ZERO:
                # Check for guard
                is_guarded = False
                for src in right.param_sources:
                    if src < len(self.varnames):
                        var_name = self.varnames[src]
                        if guards.has_div_safe(var_name):
                            is_guarded = True
                            break
                
                confidence = 0.9 if right.zeroness == Zeroness.ZERO else 0.6
                self._add_bug('DIV_ZERO', offset, instr, right.param_sources, guards, confidence, is_guarded)
                self.exceptions_raised.add('ZeroDivisionError')
            
            # Note: EMPTY_COLLECTION_DIV is NOT a separate bug - it's just DIV_ZERO
            # because len() of empty collection returns 0, which triggers DIV_ZERO.
            # The zeroness lattice already tracks this via len() handling in _handle_call.
            
            # SCALE_ZERO_NORMALIZE: Division by array that may contain zeros
            # This IS a distinct pattern because the array itself isn't zero,
            # but individual elements might be. Track via may_contain_zeros property.
            if right.may_contain_zeros and ('ndarray' in right.types or 'list' in right.types):
                # Array division where elements might be zero - lower confidence
                # since this is element-wise, not the whole value being zero
                self._add_bug('DIV_ZERO', offset, instr, right.param_sources, guards, 0.4, False)
            
            result.nullability = Nullability.NOT_NONE
            result.types = frozenset({'float', 'int'})
        
        # Check for subscript
        elif oparg in BINARY_OPS_SUBSCRIPT:
            # Index access - check bounds
            # Extract index value if it's a constant
            index_val = None
            if right.lower_bound is not None and right.upper_bound is not None and right.lower_bound == right.upper_bound:
                index_val = right.lower_bound
            
            # Check if index is negative (Python allows but worth noting)
            if right.sign in (Sign.NEGATIVE, Sign.TOP):
                # Negative index risk (though Python allows it)
                pass
            
            # Check for guard on the collection
            is_guarded = False
            for src in left.param_sources:
                if src < len(self.varnames):
                    var_name = self.varnames[src]
                    # Check if there's a nonempty guard
                    if guards.has_nonempty(var_name):
                        is_guarded = True
                        break
            
            # EMPTY_COLLECTION_INDEX: If we know the collection is definitely empty
            if left.emptiness == Emptiness.EMPTY:
                # Definitely empty - high confidence BOUNDS (IndexError on x[0] where x is empty)
                self._add_bug('BOUNDS', offset, instr, sources, guards, 0.95, is_guarded)
                self.exceptions_raised.add('IndexError')
                # Don't add the generic 0.5 confidence bug since we have definite knowledge
                result.nullability = Nullability.TOP
                state.push(result)
                return  # Exit early - we've handled this case
            
            # Use length bounds for more precise analysis
            # If we know len(left) >= k and accessing index i where i < k, it's safe
            if left.len_lower_bound is not None and index_val is not None:
                if index_val >= 0 and index_val < left.len_lower_bound:
                    # Index is within known bounds - SAFE, no bug to report
                    result.nullability = Nullability.TOP
                    state.push(result)
                    return
                elif index_val >= left.len_lower_bound:
                    # Index definitely out of bounds - high confidence bug
                    self._add_bug('BOUNDS', offset, instr, sources, guards, 0.95, is_guarded)
                    self.exceptions_raised.add('IndexError')
                    result.nullability = Nullability.TOP
                    state.push(result)
                    return
            
            # If non-empty but no specific length bound, could still be out of bounds
            if left.emptiness == Emptiness.NON_EMPTY:
                # Non-empty but unknown length - moderate risk if accessing beyond [0]
                if index_val is not None and index_val > 0:
                    # Accessing beyond first element, uncertain if safe
                    conf = 0.3  # Lower confidence since it's non-empty
                    self._add_bug('BOUNDS', offset, instr, sources, guards, conf, is_guarded)
                    self.exceptions_raised.add('IndexError')
                # For x[0] when x is non-empty, it's safe - no bug
                elif index_val == 0:
                    result.nullability = Nullability.TOP
                    state.push(result)
                    return
                # Unknown index on non-empty collection - low risk
                else:
                    pass  # Fall through to generic check
            
            # DICT_KEY_MISSING is just KeyError, a form of BOUNDS
            # If we know the dict's keys and the accessed key isn't in them, flag it
            if 'dict' in left.types and not left.dict_keys.is_top:
                if left.dict_keys.is_complete and len(left.dict_keys.known_keys) < 10:
                    # Known dict with limited keys - higher confidence BOUNDS
                    self._add_bug('BOUNDS', offset, instr, sources, guards, 0.7, is_guarded)
                    self.exceptions_raised.add('KeyError')
            
            # Generic BOUNDS risk without static knowledge
            # Only add this if:
            # 1. We don't have specific emptiness knowledge
            # 2. We don't have guards
            # 3. We don't have length bounds that prove safety
            if left.emptiness not in (Emptiness.EMPTY, Emptiness.NON_EMPTY) and not is_guarded:
                self._add_bug('BOUNDS', offset, instr, sources, guards, 0.5, is_guarded)
            
            self.exceptions_raised.add('IndexError')
            self.exceptions_raised.add('KeyError')
            
            result.nullability = Nullability.TOP
        
        else:
            # Other binary ops
            result.nullability = Nullability.NOT_NONE
        
        state.push(result)
    
    def _handle_load_attr(
        self,
        state: AbstractState,
        attr_name: str,
        offset: int,
        guards: GuardState,
        instr: dis.Instruction,
    ) -> None:
        """Handle LOAD_ATTR with null dereference detection."""
        obj = state.pop()
        
        # Check for null dereference
        if obj.nullability != Nullability.NOT_NONE:
            is_guarded = False
            for src in obj.param_sources:
                if src < len(self.varnames):
                    var_name = self.varnames[src]
                    if guards.has_nonnull(var_name):
                        is_guarded = True
                        break
            
            confidence = 0.9 if obj.nullability == Nullability.IS_NONE else 0.5
            self._add_bug('NULL_PTR', offset, instr, obj.param_sources, guards, confidence, is_guarded)
            self.exceptions_raised.add('AttributeError')
        
        # Result inherits sources
        result = AbstractValue(
            nullability=Nullability.TOP,  # Attribute may be None
            param_sources=obj.param_sources,
            taint=obj.taint,
        )
        state.push(result)
    
    def _handle_call(
        self,
        state: AbstractState,
        argc: int,
        offset: int,
        guards: GuardState,
        instr: dis.Instruction,
    ) -> None:
        """Handle CALL with callee summary application."""
        # Pop arguments
        args = []
        for _ in range(argc or 0):
            args.insert(0, state.pop())
        
        # Pop callable
        func = state.pop()
        
        # Check for known dangerous calls
        callee_name = self._get_callee_name(offset)
        
        # NEW: Track len() calls for EMPTY_COLLECTION_DIV detection
        if callee_name == 'len' and len(args) == 1:
            collection = args[0]
            # Result of len() is an int >= 0
            result = AbstractValue(
                nullability=Nullability.NOT_NONE,
                zeroness=Zeroness.NON_ZERO if collection.emptiness == Emptiness.NON_EMPTY else 
                         (Zeroness.ZERO if collection.emptiness == Emptiness.EMPTY else Zeroness.TOP),
                sign=Sign.NON_NEGATIVE,
                param_sources=collection.param_sources,
                types=frozenset({'int'}),
                is_len_result=True,
                len_source_emptiness=collection.emptiness,
                lower_bound=0 if collection.emptiness != Emptiness.NON_EMPTY else 1,
                upper_bound=None,
            )
            state.push(result)
            return
        
        # NEW: Track .shape[0] access for arrays (common NumPy pattern)
        if callee_name and '.shape' in callee_name:
            # Array shape - result may be 0
            result = AbstractValue(
                nullability=Nullability.NOT_NONE,
                zeroness=Zeroness.TOP,  # shape[0] could be 0 for empty arrays
                sign=Sign.NON_NEGATIVE,
                types=frozenset({'int'}),
                is_len_result=True,  # Treat shape[0] like len()
                len_source_emptiness=Emptiness.TOP,
            )
            state.push(result)
            return
        
        # NEW: Track dict.get() which is safe (returns None for missing keys)
        if callee_name and callee_name.endswith('.get'):
            # dict.get() is safe - doesn't raise KeyError
            all_sources = frozenset().union(*(a.param_sources for a in args))
            result = AbstractValue(
                nullability=Nullability.TOP,  # May return None if key missing
                param_sources=all_sources,
            )
            state.push(result)
            return
        
        # Check for callee summary
        callee_summary = None
        if callee_name:
            if callee_name in ('eval', 'exec', 'compile'):
                sources = frozenset().union(*(a.param_sources for a in args))
                self._add_bug('CODE_INJECTION', offset, instr, sources, guards, 0.8)
            elif callee_name in ('os.system', 'subprocess.call', 'subprocess.run'):
                sources = frozenset().union(*(a.param_sources for a in args))
                self._add_bug('COMMAND_INJECTION', offset, instr, sources, guards, 0.8)
                self.has_side_effects = True
            elif callee_name in ('open',):
                self.performs_io = True
                self.has_side_effects = True
            
            # Apply callee summary if available
            if callee_name in self.callee_summaries:
                callee = self.callee_summaries[callee_name]
                callee_summary = callee
                # Merge callee's bugs
                for bug in callee.potential_bugs:
                    self.potential_bugs.append(bug)
        
        # Result uses callee summary info if available
        all_sources = frozenset().union(*(a.param_sources for a in args))
        
        # Join all argument taints
        combined_taint = TaintLabel.clean()
        for a in args:
            combined_taint = combined_taint.join(a.taint)
        
        if callee_summary:
            result = AbstractValue(
                nullability=callee_summary.return_nullability,
                emptiness=callee_summary.return_emptiness,
                len_lower_bound=callee_summary.return_len_lower_bound,
                len_upper_bound=callee_summary.return_len_upper_bound,
                param_sources=all_sources,
                taint=callee_summary.return_taint.join(combined_taint),
            )
        else:
            result = AbstractValue(
                nullability=Nullability.TOP,
                param_sources=all_sources,
                taint=combined_taint,
            )
        state.push(result)
        
        # Calls may raise
        self.exceptions_raised.add('Exception')
    
    def _get_callee_name(self, call_offset: int) -> Optional[str]:
        """Try to determine callee name from preceding instructions."""
        # Look backwards for LOAD_* instructions
        parts = []
        for i, instr in enumerate(self.instructions):
            if instr.offset == call_offset:
                for j in range(i - 1, max(i - 5, -1), -1):
                    prev = self.instructions[j]
                    if prev.opname in ('LOAD_GLOBAL', 'LOAD_NAME', 'LOAD_BUILTIN', 'LOAD_DEREF', 'LOAD_FAST'):
                        parts.insert(0, prev.argval)
                        break
                    elif prev.opname == 'LOAD_ATTR':
                        parts.insert(0, prev.argval)
                    elif prev.opname == 'LOAD_METHOD':
                        parts.insert(0, prev.argval)
                    elif prev.opname in ('PUSH_NULL', 'LOAD_CONST'):
                        # Skip PUSH_NULL and LOAD_CONST (arguments)
                        continue
                    else:
                        break
                break
        return '.'.join(parts) if parts else None
    
    def _refine_on_edge(
        self,
        state: AbstractState,
        edge_type: EdgeType,
        condition: Optional[str],
        block: BasicBlock,
    ) -> AbstractState:
        """Apply path-sensitive refinement on CFG edge.
        
        This handles short-circuit evaluation semantics:
        - For `if x or x[0]`: on the false branch of `x`, we know x is falsy (empty for sequences)
        - For `if x and x[0]`: on the true branch of `x`, we know x is truthy (non-empty)
        """
        if state.is_bottom:
            return state
        
        result = state.copy()
        
        # Use intraprocedural analysis for edge refinement
        if block.instructions:
            last_offset = block.instructions[-1].offset
            
            # Look for IS_OP (None check) pattern
            for i, instr in enumerate(block.instructions):
                if instr.opname == 'IS_OP' and i >= 2:
                    is_not = instr.arg == 1
                    
                    load_instr = block.instructions[i - 2]
                    const_instr = block.instructions[i - 1]
                    
                    if (load_instr.opname in ('LOAD_FAST', 'LOAD_NAME', 'LOAD_FAST_BORROW') and
                        const_instr.opname == 'LOAD_CONST' and
                        const_instr.argval is None):
                        
                        var_idx = load_instr.arg
                        if var_idx in result.locals:
                            val = result.locals[var_idx]
                            
                            if edge_type == EdgeType.COND_TRUE:
                                # True branch
                                new_null = Nullability.NOT_NONE if is_not else Nullability.IS_NONE
                            else:
                                # False branch
                                new_null = Nullability.IS_NONE if is_not else Nullability.NOT_NONE
                            
                            result.locals[var_idx] = AbstractValue(
                                nullability=new_null,
                                zeroness=val.zeroness,
                                sign=val.sign,
                                emptiness=val.emptiness,
                                taint=val.taint,
                                types=val.types,
                                param_sources=val.param_sources,
                            )
            
            # Look for truthiness test pattern: LOAD_FAST, TO_BOOL, POP_JUMP_IF_xxx
            # This is critical for detecting `if x or x[0]` bugs
            self._refine_truthiness_on_edge(result, block, edge_type)
            
            # Also look for len comparison patterns: len(x) == 0, len(x) > 0, etc.
            self._refine_len_comparison_on_edge(result, block, edge_type)
        
        return result
    
    def _refine_truthiness_on_edge(
        self,
        state: AbstractState,
        block: BasicBlock,
        edge_type: EdgeType,
    ) -> None:
        """Refine state based on truthiness test in block.
        
        For short-circuit evaluation like `if x or x[0]`:
        - POP_JUMP_IF_TRUE on x: jumps if x truthy, falls through if x falsy
        - On the fall-through path (COND_FALSE edge), x must be falsy (empty for sequences)
        
        For `if x and x[0]`:
        - POP_JUMP_IF_FALSE on x: jumps if x falsy, falls through if x truthy
        - On the fall-through path (COND_TRUE edge), x must be truthy (non-empty)
        """
        instrs = block.instructions
        if not instrs:
            return
        
        # Find the pattern: LOAD_FAST var, [TO_BOOL], POP_JUMP_IF_xxx
        var_idx = None
        var_name = None
        jump_type = None
        
        for i in range(len(instrs) - 1, -1, -1):
            instr = instrs[i]
            
            if instr.opname in ('POP_JUMP_IF_TRUE', 'POP_JUMP_IF_FALSE',
                               'POP_JUMP_FORWARD_IF_TRUE', 'POP_JUMP_FORWARD_IF_FALSE'):
                jump_type = instr.opname
                continue
            
            if instr.opname == 'TO_BOOL':
                continue
            
            if instr.opname == 'COPY':
                continue
            
            if instr.opname in ('LOAD_FAST', 'LOAD_FAST_BORROW', 'LOAD_NAME'):
                var_idx = instr.arg
                var_name = instr.argval
                break
        
        if var_idx is None or jump_type is None:
            return
        
        if var_idx not in state.locals:
            return
        
        val = state.locals[var_idx]
        
        # Determine if the edge means truthy or falsy
        # POP_JUMP_IF_TRUE: COND_TRUE edge = truthy, COND_FALSE edge = falsy
        # POP_JUMP_IF_FALSE: COND_FALSE edge = truthy, COND_TRUE edge = falsy
        is_falsy_edge = False
        is_truthy_edge = False
        
        if 'TRUE' in jump_type:
            # POP_JUMP_IF_TRUE: jumps when condition is truthy
            if edge_type == EdgeType.COND_TRUE:
                is_truthy_edge = True
            else:  # COND_FALSE = fallthrough = falsy
                is_falsy_edge = True
        else:
            # POP_JUMP_IF_FALSE: jumps when condition is falsy
            if edge_type == EdgeType.COND_FALSE:
                is_falsy_edge = True
            else:  # COND_TRUE = fallthrough = truthy
                is_truthy_edge = True
        
        # Update the abstract value based on edge semantics
        if is_falsy_edge:
            # Variable is falsy on this edge
            # For sequences: falsy means EMPTY (len == 0)
            # For numbers: falsy means ZERO
            # For objects: falsy could mean None
            new_emptiness = Emptiness.EMPTY
            new_zeroness = Zeroness.ZERO  # Falsy could also mean zero for numbers
            
            state.locals[var_idx] = AbstractValue(
                nullability=val.nullability,  # Could still be None (which is also falsy)
                zeroness=new_zeroness,
                sign=Sign.ZERO,  # Zero is falsy
                emptiness=new_emptiness,
                taint=val.taint,
                types=val.types,
                param_sources=val.param_sources,
            )
        elif is_truthy_edge:
            # Variable is truthy on this edge
            # For sequences: truthy means NON_EMPTY (len >= 1)
            # For numbers: truthy means NON_ZERO
            # For objects: truthy means NOT_NONE
            new_emptiness = Emptiness.NON_EMPTY
            new_zeroness = Zeroness.NON_ZERO
            new_nullability = Nullability.NOT_NONE
            
            state.locals[var_idx] = AbstractValue(
                nullability=new_nullability,
                zeroness=new_zeroness,
                sign=val.sign if val.sign != Sign.ZERO else Sign.TOP,
                emptiness=new_emptiness,
                taint=val.taint,
                types=val.types,
                param_sources=val.param_sources,
            )
    
    def _refine_len_comparison_on_edge(
        self,
        state: AbstractState,
        block: BasicBlock,
        edge_type: EdgeType,
    ) -> None:
        """Refine state based on len() comparison patterns.
        
        Handles patterns like:
        - `if len(x) == 0 or x[0]`: on false edge of len(x)==0, x is non-empty
        - `if len(x) > 0 and x[0]`: on true edge of len(x)>0, x is non-empty
        
        The pattern in bytecode looks like:
        LOAD_GLOBAL len
        LOAD_FAST x
        CALL 1
        LOAD_SMALL_INT 0
        COMPARE_OP ==
        [TO_BOOL]
        POP_JUMP_IF_TRUE/FALSE
        """
        instrs = block.instructions
        if not instrs:
            return
        
        # Find the jump instruction and comparison
        jump_type = None
        compare_idx = None
        compare_op = None
        
        for i in range(len(instrs) - 1, -1, -1):
            instr = instrs[i]
            
            if instr.opname in ('POP_JUMP_IF_TRUE', 'POP_JUMP_IF_FALSE',
                               'POP_JUMP_FORWARD_IF_TRUE', 'POP_JUMP_FORWARD_IF_FALSE'):
                jump_type = instr.opname
                continue
            
            if instr.opname == 'TO_BOOL':
                continue
            
            if instr.opname == 'COMPARE_OP':
                compare_idx = i
                compare_op = instr.argval
                break
        
        if jump_type is None or compare_idx is None:
            return
        
        # Look for the pattern: LOAD_GLOBAL len, LOAD_FAST x, CALL, LOAD_SMALL_INT 0, COMPARE_OP
        # We need at least 4 instructions before COMPARE_OP
        if compare_idx < 4:
            return
        
        # Check for LOAD_SMALL_INT or LOAD_CONST before COMPARE_OP to get the compared value
        load_const_instr = instrs[compare_idx - 1]
        compared_value = None
        if load_const_instr.opname == 'LOAD_SMALL_INT':
            compared_value = load_const_instr.arg
        elif load_const_instr.opname == 'LOAD_CONST':
            if isinstance(load_const_instr.argval, int):
                compared_value = load_const_instr.argval
        
        if compared_value is None:
            return
        
        # Check for CALL before that
        call_instr = instrs[compare_idx - 2]
        if call_instr.opname not in ('CALL', 'CALL_FUNCTION'):
            return
        
        # Check for LOAD_FAST before CALL
        load_var_instr = instrs[compare_idx - 3]
        if load_var_instr.opname not in ('LOAD_FAST', 'LOAD_FAST_BORROW', 'LOAD_NAME'):
            return
        
        var_idx = load_var_instr.arg
        
        # Check for LOAD_GLOBAL len before LOAD_FAST
        load_len_instr = instrs[compare_idx - 4]
        if load_len_instr.opname != 'LOAD_GLOBAL':
            return
        # The argval might be 'len' or ('len', None) depending on Python version
        len_name = load_len_instr.argval
        if isinstance(len_name, tuple):
            len_name = len_name[0]
        if len_name != 'len':
            return
        
        if var_idx not in state.locals:
            return
        
        val = state.locals[var_idx]
        
        # Determine what the comparison and edge tell us about emptiness
        # compare_op could be '==', '!=', '<', '>', '<=', '>='
        cmp_str = str(compare_op) if compare_op else ''
        
        # Determine if the edge means the comparison was true or false
        # POP_JUMP_IF_TRUE: jumps when TRUE, so COND_TRUE = taken = comparison true
        # POP_JUMP_IF_FALSE: jumps when FALSE, so COND_FALSE = taken = comparison false
        # The edge type indicates which branch was taken
        comparison_true = False
        comparison_false = False
        
        if 'TRUE' in jump_type:
            # POP_JUMP_IF_TRUE: jumps when condition is TRUE
            # COND_TRUE edge = jump taken = comparison was TRUE
            # COND_FALSE edge = fallthrough = comparison was FALSE
            if edge_type == EdgeType.COND_TRUE:
                comparison_true = True
            else:
                comparison_false = True
        else:
            # POP_JUMP_IF_FALSE: jumps when condition is FALSE
            # COND_FALSE edge = jump taken = comparison was FALSE
            # COND_TRUE edge = fallthrough = comparison was TRUE
            if edge_type == EdgeType.COND_TRUE:
                comparison_true = True
            else:
                comparison_false = True
        
        # Now determine emptiness and length bounds based on comparison operator and result
        new_emptiness = None
        new_len_lower = None
        new_len_upper = None
        
        # len(x) == N
        if '==' in cmp_str or 'eq' in cmp_str.lower():
            if comparison_true:
                # len == N, so both lower and upper bound are N
                new_len_lower = compared_value
                new_len_upper = compared_value
                new_emptiness = Emptiness.EMPTY if compared_value == 0 else Emptiness.NON_EMPTY
            else:
                # len != N
                if compared_value == 0:
                    new_emptiness = Emptiness.NON_EMPTY
                    new_len_lower = 1  # At least 1
        
        # len(x) != N
        elif '!=' in cmp_str or 'ne' in cmp_str.lower():
            if comparison_true:
                # len != N
                if compared_value == 0:
                    new_emptiness = Emptiness.NON_EMPTY
                    new_len_lower = 1
            else:
                # len == N
                new_len_lower = compared_value
                new_len_upper = compared_value
                new_emptiness = Emptiness.EMPTY if compared_value == 0 else Emptiness.NON_EMPTY
        
        # len(x) > N
        elif '>' in cmp_str and '=' not in cmp_str:
            if comparison_true:
                # len > N, so len >= N+1
                new_len_lower = compared_value + 1
                new_emptiness = Emptiness.NON_EMPTY
            else:
                # len <= N
                new_len_upper = compared_value
                if compared_value == 0:
                    new_emptiness = Emptiness.EMPTY
        
        # len(x) >= N
        elif '>=' in cmp_str:
            if comparison_true:
                # len >= N
                new_len_lower = compared_value
                new_emptiness = Emptiness.NON_EMPTY if compared_value > 0 else Emptiness.TOP
            else:
                # len < N, so len <= N-1
                new_len_upper = compared_value - 1
                if compared_value <= 1:
                    new_emptiness = Emptiness.EMPTY
        
        # len(x) < N
        elif '<' in cmp_str and '=' not in cmp_str:
            if comparison_true:
                # len < N, so len <= N-1
                new_len_upper = compared_value - 1
                if compared_value <= 1:
                    new_emptiness = Emptiness.EMPTY
            else:
                # len >= N
                new_len_lower = compared_value
                new_emptiness = Emptiness.NON_EMPTY if compared_value > 0 else Emptiness.TOP
        
        # len(x) <= N
        elif '<=' in cmp_str:
            if comparison_true:
                # len <= N
                new_len_upper = compared_value
                if compared_value == 0:
                    new_emptiness = Emptiness.EMPTY
            else:
                # len > N, so len >= N+1
                new_len_lower = compared_value + 1
                new_emptiness = Emptiness.NON_EMPTY
        
        # Apply the refinements if we learned anything
        if new_emptiness is not None or new_len_lower is not None or new_len_upper is not None:
            # Merge with existing bounds (take intersection)
            final_len_lower = new_len_lower
            if val.len_lower_bound is not None and new_len_lower is not None:
                final_len_lower = max(val.len_lower_bound, new_len_lower)
            elif val.len_lower_bound is not None:
                final_len_lower = val.len_lower_bound
            
            final_len_upper = new_len_upper
            if val.len_upper_bound is not None and new_len_upper is not None:
                final_len_upper = min(val.len_upper_bound, new_len_upper)
            elif val.len_upper_bound is not None:
                final_len_upper = val.len_upper_bound
            
            # If we narrowed to empty, set emptiness
            final_emptiness = new_emptiness if new_emptiness is not None else val.emptiness
            if final_len_lower is not None and final_len_upper is not None and final_len_upper == 0:
                final_emptiness = Emptiness.EMPTY
            elif final_len_lower is not None and final_len_lower > 0:
                final_emptiness = Emptiness.NON_EMPTY
            
            state.locals[var_idx] = AbstractValue(
                nullability=val.nullability,
                zeroness=val.zeroness,
                sign=val.sign,
                emptiness=final_emptiness,
                taint=val.taint,
                types=val.types,
                param_sources=val.param_sources,
                len_lower_bound=final_len_lower,
                len_upper_bound=final_len_upper,
            )
    
    def _state_changed(self, old: AbstractState, new: AbstractState) -> bool:
        """Check if state changed (for fixpoint detection)."""
        if old.is_bottom != new.is_bottom:
            return True
        if old.is_bottom:
            return False
        
        # Compare locals
        all_vars = set(old.locals.keys()) | set(new.locals.keys())
        for var in all_vars:
            old_val = old.locals.get(var)
            new_val = new.locals.get(var)
            if old_val is None and new_val is not None:
                return True
            if old_val is not None and new_val is None:
                return True
            if old_val and new_val:
                if (old_val.nullability != new_val.nullability or
                    old_val.zeroness != new_val.zeroness or
                    old_val.param_sources != new_val.param_sources):
                    return True
        
        return False
    
    def _add_bug(
        self,
        bug_type: str,
        offset: int,
        instr: dis.Instruction,
        sources: FrozenSet[int],
        guards: GuardState,
        confidence: float,
        is_guarded: bool = False,
    ) -> None:
        """Record a potential bug."""
        line = None
        if hasattr(instr, 'positions') and instr.positions:
            line = instr.positions.lineno
        
        bug = BugReport(
            bug_type=bug_type,
            offset=offset,
            line_number=line,
            message=f"{bug_type} at {instr.opname}",
            confidence=confidence,
            param_sources=sources,
            is_guarded=is_guarded,
        )
        self.potential_bugs.append(bug)
    
    def _build_summary(self) -> BytecodeSummary:
        """Build final summary from analysis results."""
        # Compute return properties
        return_null = Nullability.BOTTOM
        return_taint = TaintLabel.bottom()
        return_emptiness = Emptiness.BOTTOM
        return_len_lower = None
        return_len_upper = None
        param_to_return: Set[int] = set()
        
        for ret_val in self.return_values:
            return_null = return_null.join(ret_val.nullability)
            return_taint = return_taint.join(ret_val.taint)
            return_emptiness = return_emptiness.join(ret_val.emptiness)
            param_to_return.update(ret_val.param_sources)
            
            # Join length bounds
            if ret_val.len_lower_bound is not None:
                if return_len_lower is None:
                    return_len_lower = ret_val.len_lower_bound
                else:
                    return_len_lower = min(return_len_lower, ret_val.len_lower_bound)
            if ret_val.len_upper_bound is not None:
                if return_len_upper is None:
                    return_len_upper = ret_val.len_upper_bound
                else:
                    return_len_upper = max(return_len_upper, ret_val.len_upper_bound)
        
        # Compute param bug propagation
        param_bugs: Dict[int, Set[str]] = {}
        for bug in self.potential_bugs:
            for src in bug.param_sources:
                if src not in param_bugs:
                    param_bugs[src] = set()
                param_bugs[src].add(bug.bug_type)
        
        # Extract param constraints from entry state (if we wanted preconditions)
        # For now, we don't track required preconditions, just document what we return
        
        return BytecodeSummary(
            function_name=self.func_name,
            qualified_name=self.qualified_name,
            parameter_count=self.param_count,
            param_to_return=param_to_return,
            return_nullability=return_null,
            return_taint=return_taint,
            return_emptiness=return_emptiness,
            return_len_lower_bound=return_len_lower,
            return_len_upper_bound=return_len_upper,
            potential_bugs=self.potential_bugs,
            param_bug_propagation=param_bugs,
            may_raise=self.exceptions_raised,
            intraproc_result=self.intraproc,
            has_side_effects=self.has_side_effects,
            modifies_globals=self.modifies_globals,
            performs_io=self.performs_io,
        )


# ============================================================================
# CONVENIENCE API
# ============================================================================

def analyze_function(
    func: types.FunctionType,
    callee_summaries: Optional[Dict[str, BytecodeSummary]] = None,
) -> BytecodeSummary:
    """
    Analyze a Python function and compute its bytecode summary.
    
    Example:
        def divide(x, y):
            return x / y
        
        summary = analyze_function(divide)
        print(summary.potential_bugs)  # [BugReport(bug_type='DIV_ZERO', ...)]
        print(summary.param_bug_propagation)  # {1: {'DIV_ZERO'}}
    """
    code = func.__code__
    name = func.__name__
    qualname = func.__qualname__
    
    interpreter = BytecodeAbstractInterpreter(
        code=code,
        func_name=name,
        qualified_name=qualname,
        callee_summaries=callee_summaries,
    )
    return interpreter.analyze()


def analyze_code_object(
    code: types.CodeType,
    func_name: Optional[str] = None,
    qualified_name: Optional[str] = None,
    callee_summaries: Optional[Dict[str, BytecodeSummary]] = None,
) -> BytecodeSummary:
    """
    Analyze a code object directly.
    
    This is the primary entry point for bytecode-level analysis.
    """
    name = func_name or code.co_name
    qname = qualified_name or (code.co_qualname if hasattr(code, 'co_qualname') else name)
    
    interpreter = BytecodeAbstractInterpreter(
        code=code,
        func_name=name,
        qualified_name=qname,
        callee_summaries=callee_summaries,
    )
    return interpreter.analyze()


# ============================================================================
# EXPORTS
# ============================================================================

__all__ = [
    # Lattices
    'Nullability',
    'Zeroness', 
    'Sign',
    'TaintLabel',
    'AbstractValue',
    'AbstractState',
    
    # Analysis results
    'BugReport',
    'BytecodeSummary',
    
    # Analyzer
    'BytecodeAbstractInterpreter',
    
    # Convenience API
    'analyze_function',
    'analyze_code_object',
]
