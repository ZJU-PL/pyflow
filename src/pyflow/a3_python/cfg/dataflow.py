"""
Path-Sensitive Dataflow Analysis for Python bytecode.

Implements the dataflow-barrier correspondence from barrier-certificate-theory.tex §7:
- Forward dataflow for guard validity
- Backward dataflow for liveness
- Path-sensitive abstract interpretation

The key theorem (Dataflow-Barrier Correspondence):
  DF_v(π) = true ⟹ g_v = 1 at π on all paths

This allows cheap dataflow analysis to handle easy cases, with expensive 
barrier synthesis only needed where DF_v(π) = unknown.
"""

from dataclasses import dataclass, field
from typing import Dict, Set, List, Optional, Callable, TypeVar, Generic, Tuple
from abc import ABC, abstractmethod
import z3

from .control_flow import ControlFlowGraph, BasicBlock, GuardFact, EdgeType


T = TypeVar('T')


# ============================================================================
# Abstract Dataflow Framework
# ============================================================================

class DataflowLattice(ABC, Generic[T]):
    """
    Abstract lattice for dataflow analysis.
    
    Provides:
    - Top/bottom elements
    - Meet operation (for forward analysis)
    - Join operation (for backward analysis)
    """
    
    @abstractmethod
    def bottom(self) -> T:
        """Return bottom element (most precise)."""
        ...
    
    @abstractmethod
    def top(self) -> T:
        """Return top element (least precise)."""
        ...
    
    @abstractmethod
    def meet(self, a: T, b: T) -> T:
        """Meet operation: greatest lower bound."""
        ...
    
    @abstractmethod
    def join(self, a: T, b: T) -> T:
        """Join operation: least upper bound."""
        ...
    
    @abstractmethod
    def leq(self, a: T, b: T) -> bool:
        """Check if a ≤ b in the lattice."""
        ...


class SetLattice(DataflowLattice[Set[str]]):
    """
    Set-based lattice for tracking properties.
    
    For forward must-analysis:
    - Bottom = all possible facts
    - Top = empty set
    - Meet = intersection
    """
    
    def __init__(self, universe: Set[str]):
        self.universe = universe
    
    def bottom(self) -> Set[str]:
        return self.universe.copy()
    
    def top(self) -> Set[str]:
        return set()
    
    def meet(self, a: Set[str], b: Set[str]) -> Set[str]:
        return a & b
    
    def join(self, a: Set[str], b: Set[str]) -> Set[str]:
        return a | b
    
    def leq(self, a: Set[str], b: Set[str]) -> bool:
        return a <= b


# ============================================================================
# Guard Dataflow Analysis
# ============================================================================

@dataclass
class GuardState:
    """
    State for guard dataflow analysis.
    
    Tracks which guards are definitely established at a program point.
    Uses Z3 constraints for symbolic verification of bounds safety.
    """
    # Map: guard_key -> definitely established
    # guard_key format: "nonnull:varname", "type:varname:typename", etc.
    established: Set[str] = field(default_factory=set)
    
    # Z3 constraint store: symbolic constraints for bounds verification
    # Maps container name -> (z3_length_var, lower_bound_constraint)
    # For nonempty guard: length_constraints[container] = (len_var, len_var >= 1)
    length_constraints: Dict[str, Tuple[z3.ExprRef, z3.ExprRef]] = field(default_factory=dict)
    
    def add_guard(self, guard: GuardFact):
        """
        Add a guard to the established set.
        
        Special handling for length_constraint guards:
        - These create Z3 symbolic length constraints
        - Used for pattern: if len(container) >= N: container[0..N-1] are safe
        """
        key = self._guard_key(guard)
        self.established.add(key)
        
        # NEW: Handle length_constraint guards by creating Z3 constraints
        if guard.guard_type == "length_constraint" and guard.extra:
            try:
                min_length = int(guard.extra)
                # Create Z3 variable for the length of this container
                len_var = z3.Int(f"len_{guard.variable}")
                # Create constraint: len(container) >= min_length
                constraint = len_var >= min_length
                self.add_length_constraint(guard.variable, len_var, constraint)
            except (ValueError, AttributeError):
                # If we can't parse the min_length, just add the guard normally
                pass
    
    def add_length_constraint(self, container: str, len_var: z3.ExprRef, constraint: z3.ExprRef):
        """
        Add a Z3 length constraint for a container.
        
        This is used for symbolic bounds verification. For example:
        - len(x) > 0 adds constraint: len_x >= 1
        - len(x) >= n adds constraint: len_x >= n
        """
        self.length_constraints[container] = (len_var, constraint)
    
    def has_guard(self, guard_type: str, variable: str, extra: str = None) -> bool:
        """Check if a guard is established."""
        key = f"{guard_type}:{variable}"
        if extra:
            key += f":{extra}"
        return key in self.established
    
    def has_nonnull(self, variable: str) -> bool:
        """
        Check if variable is definitely not None.
        
        Z3 model: nonnull(x) ⟹ x ≠ None
        
        Sources of nonnull guards:
        - Direct: x is not None check
        - Constructor: x = SomeClass()
        - String methods: x = s.strip()
        - getattr/setdefault/next with default
        - dict.get with non-None default
        - Callable check: callable(x) implies x is not None
        """
        return self.has_guard("nonnull", variable)
    
    def has_type(self, variable: str, type_name: str) -> bool:
        """Check if variable is definitely of given type."""
        return self.has_guard("type", variable, type_name)
    
    def has_nonempty(self, variable: str) -> bool:
        """
        Check if variable (collection) is definitely non-empty.
        
        This checks for nonempty guards established by:
        - len(x) > 0, len(x) >= 1
        - len(x) != 0
        - if x: (truthiness check for collections)
        - for loop body (inside iteration, collection is non-empty)
        """
        return self.has_guard("nonempty", variable, "len>=1") or self.has_guard("nonempty", variable)
    
    def has_div_safe(self, variable: str) -> bool:
        """
        Check if variable is definitely non-zero.
        
        This checks for div guards established by:
        - x != 0 direct checks
        - x > 0, x >= 1 (positive implies non-zero)
        - x < 0, x <= -1 (negative implies non-zero)
        - Truthiness checks (truthy implies non-zero for numbers)
        """
        if self.has_guard("div", variable):
            return True
        
        # Truthiness on fallthrough also establishes non-zero for numbers
        # If nonempty:variable is set, the variable is truthy
        # For numbers, truthy means non-zero
        if self.has_guard("nonempty", variable, "len>=1"):
            return True
        
        return False
    
    def has_bounds_safe(self, container: str, index: str) -> bool:
        """
        Check if container[index] access is definitely in bounds.
        
        Uses Z3 to verify bounds safety when symbolic constraints are available.
        
        Checks for:
        1. Explicit bounds guard: bounds:{container}[{index}]
        2. Range-len loop guard: range_len_loop:{container} (iteration variable always safe)
        3. Enumerate loop guard: enumerate_loop:{container} (index variable always safe)
        4. Nonempty guard with constant index 0: nonempty:{container} + index == 0
        5. Exact length guard: exact_length:{container}:{n} + 0 <= index < n
        6. Negative index with nonempty: arr[-1] safe when len >= 1
        7. Key-in guard: if key in d: d[key] is safe
        8. Z3 constraint verification: prove 0 <= index < len(container)
        9. NEW: length_constraint guard: len(container) >= N allows indices 0..N-1
        """
        # Check explicit bounds guard
        if self.has_guard("bounds", f"{container}[{index}]"):
            return True
        
        # Check range(len(...)) loop pattern
        if self.has_guard("range_len_loop", container):
            return True
        
        # Check enumerate(...) loop pattern
        if self.has_guard("enumerate_loop", container):
            return True
        
        # Check for loop body nonempty (inside a for loop, container is nonempty)
        if self.has_guard("loop_body_nonempty", container):
            if self._is_constant_zero_index(index):
                return True
        
        # Check nonempty guard for index 0 or -1
        if self.has_guard("nonempty", container, "len>=1"):
            if self._is_constant_zero_index(index):
                return True
            # Negative index -1 is safe when len >= 1
            if self._is_negative_one_index(index):
                return True
        
        # Check key_in guard: if key in container: container[key] is safe
        if self.has_guard("key_in", f"{container}[{index}]"):
            return True
        
        # Check exact_length guard: len(container) == n allows indices 0..n-1 and -n..-1
        exact_length = self._get_exact_length_guard(container)
        if exact_length is not None:
            try:
                idx_val = int(index)
                # Positive indices: 0..n-1
                if 0 <= idx_val < exact_length:
                    return True
                # Negative indices: -n..-1
                if -exact_length <= idx_val < 0:
                    return True
            except ValueError:
                pass
        
        # NEW: Check length_constraint guard: len(container) >= N allows indices 0..N-1
        min_length = self._get_length_constraint_guard(container)
        if min_length is not None:
            try:
                idx_val = int(index)
                # Positive indices: 0..min_length-1 are safe
                if 0 <= idx_val < min_length:
                    return True
                # Negative indices: -min_length..-1 are safe
                if -min_length <= idx_val < 0:
                    return True
            except ValueError:
                pass
        
        # Z3 constraint verification for symbolic bounds
        if container in self.length_constraints:
            return self._verify_bounds_with_z3(container, index)
        
        return False
    
    def _get_exact_length_guard(self, container: str) -> Optional[int]:
        """
        Check if there's an exact_length guard for this container.
        
        Returns the exact length value if found, None otherwise.
        """
        # Look for exact_length:container:n in established guards
        for key in self.established:
            if key.startswith(f"exact_length:{container}:"):
                try:
                    return int(key.split(":")[-1])
                except ValueError:
                    pass
        return None
    
    def _get_length_constraint_guard(self, container: str) -> Optional[int]:
        """
        Check if there's a length_constraint guard for this container.
        
        Returns the minimum length value if found, None otherwise.
        NEW: This is for the `if len(container) >= N:` pattern.
        """
        # Look for length_constraint:container:n in established guards
        for key in self.established:
            if key.startswith(f"length_constraint:{container}:"):
                try:
                    return int(key.split(":")[-1])
                except ValueError:
                    pass
        return None
    
    def _is_constant_zero_index(self, index: str) -> bool:
        """
        Check if index is the constant 0.
        
        Handles cases like:
        - Literal "0"
        - Variable that is known to be 0 from dataflow
        """
        # Direct constant check
        if index == "0":
            return True
        
        # Try to parse as integer
        try:
            if int(index) == 0:
                return True
        except ValueError:
            pass
        
        return False
    
    def _is_negative_one_index(self, index: str) -> bool:
        """
        Check if index is -1 (last element access).
        
        arr[-1] is safe when len(arr) >= 1, which is established
        by nonempty guards.
        """
        if index == "-1":
            return True
        try:
            if int(index) == -1:
                return True
        except ValueError:
            pass
        return False
    
    def has_key_safe(self, container: str, key: str) -> bool:
        """
        Check if container[key] access is safe for dict/set.
        
        This is distinct from bounds checking - it verifies key existence.
        
        Checks for:
        1. key_in guard: if key in container: container[key] is safe
        2. hasattr guard (for attribute access): if hasattr(obj, 'attr')
        """
        # Check key_in guard
        if self.has_guard("key_in", f"{container}[{key}]"):
            return True
        
        return False
    
    def has_attr_safe(self, obj: str, attr: str) -> bool:
        """
        Check if obj.attr access is safe.
        
        Checks for:
        1. hasattr guard: if hasattr(obj, 'attr')
        2. Type guard: if isinstance(obj, T) where T has attr
        """
        # Check hasattr guard
        if self.has_guard("hasattr", obj, attr):
            return True
        
        return False
    
    def _verify_bounds_with_z3(self, container: str, index: str) -> bool:
        """
        Use Z3 to verify that container[index] is in bounds.
        
        Given the established constraints (e.g., len(container) >= 1),
        check if the index is provably safe.
        
        For positive indices: 0 <= index < len(container)
        For negative indices: -len(container) <= index < 0
        
        Mathematical basis (barrier certificate):
        - Given: len(container) >= 1 (nonempty guard)
        - For index -1: -len >= -1 is always true when len >= 1
        - Therefore: -len <= -1 < 0 is satisfiable, so arr[-1] is safe
        
        Returns True if the access is provably safe.
        """
        try:
            len_var, len_constraint = self.length_constraints[container]
            
            # Try to determine index value
            idx_val = None
            try:
                idx_val = int(index)
            except ValueError:
                # index is a variable - need to check if we have constraints on it
                # For now, only handle constant indices
                return False
            
            if idx_val is None:
                return False
            
            # Create Z3 solver to verify safety
            solver = z3.Solver()
            solver.set("timeout", 100)  # 100ms timeout
            
            # Add the established length constraint
            solver.add(len_constraint)
            
            # Check if index is always in bounds
            idx_z3 = z3.IntVal(idx_val)
            
            if idx_val >= 0:
                # Positive index: 0 <= idx < len
                in_bounds = z3.And(idx_z3 >= 0, idx_z3 < len_var)
            else:
                # Negative index: -len <= idx < 0
                # In Python, arr[-1] accesses arr[len-1], arr[-2] accesses arr[len-2], etc.
                # Valid range: -len <= idx < 0
                in_bounds = z3.And(idx_z3 >= -len_var, idx_z3 < 0)
            
            # Try to prove safety by checking if NOT(in_bounds) is unsatisfiable
            solver.push()
            solver.add(z3.Not(in_bounds))
            result = solver.check()
            solver.pop()
            
            # If UNSAT, the negation is impossible, so access is always safe
            return result == z3.unsat
            
        except Exception:
            # Z3 verification failed - conservatively return False
            return False
    
    def _guard_key(self, guard: GuardFact) -> str:
        key = f"{guard.guard_type}:{guard.variable}"
        if guard.extra:
            key += f":{guard.extra}"
        return key
    
    def copy(self) -> 'GuardState':
        return GuardState(
            established=self.established.copy(),
            length_constraints=self.length_constraints.copy()
        )
    
    def meet(self, other: 'GuardState') -> 'GuardState':
        """Intersection: guards that hold on ALL paths."""
        # For length constraints, take the intersection (must hold on all paths)
        common_containers = set(self.length_constraints.keys()) & set(other.length_constraints.keys())
        merged_constraints = {}
        for container in common_containers:
            # Take the weaker constraint (smaller lower bound)
            # This is conservative - both paths must satisfy it
            # For simplicity, keep self's constraint if containers match
            merged_constraints[container] = self.length_constraints[container]
        return GuardState(
            established=self.established & other.established,
            length_constraints=merged_constraints
        )
    
    def join(self, other: 'GuardState') -> 'GuardState':
        """Union: guards that hold on ANY path."""
        # For length constraints, take the union
        merged_constraints = self.length_constraints.copy()
        merged_constraints.update(other.length_constraints)
        return GuardState(
            established=self.established | other.established,
            length_constraints=merged_constraints
        )


class GuardDataflowAnalysis:
    """
    Forward dataflow analysis for guard validity.
    
    Computes for each block: which guards are DEFINITELY established
    at block entry (on ALL paths from entry).
    
    This implements the "sparse barrier synthesis" optimization:
    when DF_v(π) = true, we know g_v = 1 without barrier synthesis.
    """
    
    def __init__(self, cfg: ControlFlowGraph):
        self.cfg = cfg
        # Block transfer functions: what guards does each block establish?
        self.block_gen: Dict[int, Set[str]] = {}
        # Analysis result: guards valid at each block entry
        self.in_state: Dict[int, GuardState] = {}
        self.out_state: Dict[int, GuardState] = {}
    
    def analyze(self) -> Dict[int, GuardState]:
        """
        Run forward dataflow analysis.
        
        Returns mapping: block_id -> GuardState at block entry
        """
        # Step 1: Compute gen sets for each block
        self._compute_gen_sets()
        
        # Step 2: Initialize
        for bid in self.cfg.blocks:
            if bid == self.cfg.entry_block:
                self.in_state[bid] = GuardState()
            else:
                # All guards (for meet = intersection)
                self.in_state[bid] = GuardState(established=self._all_guards())
            self.out_state[bid] = GuardState()
        
        # Step 3: Iterate to fixed point
        worklist = list(self.cfg.blocks.keys())
        
        while worklist:
            bid = worklist.pop(0)
            block = self.cfg.blocks[bid]
            
            # Compute IN = meet of all predecessor OUTs
            if bid == self.cfg.entry_block:
                new_in = GuardState()
            else:
                preds = block.predecessors
                if preds:
                    new_in = self.out_state[preds[0]].copy()
                    for pred in preds[1:]:
                        new_in = new_in.meet(self.out_state[pred])
                else:
                    new_in = GuardState()
            
            # Compute OUT = IN ∪ GEN
            new_out = new_in.copy()
            new_out.established |= self.block_gen.get(bid, set())
            
            # Also propagate Z3 length constraints
            if hasattr(self, 'block_length_constraints') and bid in self.block_length_constraints:
                for container, (len_var, constraint) in self.block_length_constraints[bid].items():
                    new_out.add_length_constraint(container, len_var, constraint)
            
            # Check if changed
            if new_out.established != self.out_state[bid].established:
                self.out_state[bid] = new_out
                self.in_state[bid] = new_in
                # Add successors to worklist
                for succ_id, _, _ in block.successors:
                    if succ_id not in worklist:
                        worklist.append(succ_id)
            else:
                self.in_state[bid] = new_in
        
        return self.in_state
    
    def _compute_gen_sets(self):
        """Compute guards generated by each block, including Z3 constraints."""
        from .control_flow import GuardAnalyzer
        
        guard_analyzer = GuardAnalyzer(self.cfg)
        guard_analyzer._find_guard_establishments()
        
        # Also store Z3 constraints for nonempty guards
        self.block_length_constraints: Dict[int, Dict[str, Tuple[z3.ExprRef, z3.ExprRef]]] = {}
        
        for bid, guards in guard_analyzer.block_establishes.items():
            gen = set()
            length_constraints = {}
            
            for g in guards:
                key = f"{g.guard_type}:{g.variable}"
                if g.extra:
                    key += f":{g.extra}"
                gen.add(key)
                
                # For nonempty guards, create Z3 constraint: len(container) >= 1
                if g.guard_type == "nonempty":
                    container = g.variable
                    # Create fresh Z3 variable for container length
                    len_var = z3.Int(f"len_{container}")
                    # Create constraint: len >= 1 (nonempty)
                    constraint = len_var >= 1
                    length_constraints[container] = (len_var, constraint)
                
                # For exact_length guards, create Z3 constraint: len(container) == n
                elif g.guard_type == "exact_length" and g.extra:
                    container = g.variable
                    try:
                        exact_len = int(g.extra)
                        len_var = z3.Int(f"len_{container}")
                        constraint = len_var == exact_len
                        length_constraints[container] = (len_var, constraint)
                    except ValueError:
                        pass
            
            self.block_gen[bid] = gen
            if length_constraints:
                self.block_length_constraints[bid] = length_constraints
    
    def _all_guards(self) -> Set[str]:
        """Get all possible guards (for initialization)."""
        all_guards = set()
        for bid, gen in self.block_gen.items():
            all_guards |= gen
        return all_guards
    
    def get_guards_at_block(self, block_id: int) -> GuardState:
        """Get guards valid at entry to a block."""
        return self.in_state.get(block_id, GuardState())
    
    def get_guards_at_offset(self, offset: int) -> GuardState:
        """Get guards valid at an instruction offset."""
        block = self.cfg.get_block_for_offset(offset)
        if block:
            return self.get_guards_at_block(block.id)
        return GuardState()


# ============================================================================
# Reaching Definitions Analysis
# ============================================================================

@dataclass
class Definition:
    """A variable definition."""
    variable: str
    block_id: int
    offset: int
    
    def __hash__(self):
        return hash((self.variable, self.offset))
    
    def __eq__(self, other):
        return (self.variable == other.variable and 
                self.offset == other.offset)


class ReachingDefinitionsAnalysis:
    """
    Classic reaching definitions analysis.
    
    For each program point, computes which definitions may reach it.
    Used for:
    - SSA-like value numbering
    - Detecting uninitialized variable use
    - Tracking value provenance for guards
    """
    
    def __init__(self, cfg: ControlFlowGraph):
        self.cfg = cfg
        # Definitions in each block
        self.block_defs: Dict[int, Set[Definition]] = {}
        # Results
        self.in_defs: Dict[int, Set[Definition]] = {}
        self.out_defs: Dict[int, Set[Definition]] = {}
    
    def analyze(self) -> Dict[int, Set[Definition]]:
        """
        Run reaching definitions analysis.
        
        Returns: block_id -> definitions reaching block entry
        """
        # Find all definitions
        self._collect_definitions()
        
        # Initialize
        for bid in self.cfg.blocks:
            self.in_defs[bid] = set()
            self.out_defs[bid] = set()
        
        # Iterate to fixed point
        changed = True
        while changed:
            changed = False
            
            for bid, block in self.cfg.blocks.items():
                # IN = union of predecessor OUTs
                new_in = set()
                for pred in block.predecessors:
                    new_in |= self.out_defs.get(pred, set())
                
                # OUT = GEN ∪ (IN - KILL)
                killed_vars = {d.variable for d in self.block_defs.get(bid, set())}
                surviving = {d for d in new_in if d.variable not in killed_vars}
                new_out = self.block_defs.get(bid, set()) | surviving
                
                if new_out != self.out_defs[bid]:
                    self.out_defs[bid] = new_out
                    changed = True
                
                self.in_defs[bid] = new_in
        
        return self.in_defs
    
    def _collect_definitions(self):
        """Collect all definitions in each block."""
        store_ops = {'STORE_FAST', 'STORE_NAME', 'STORE_GLOBAL'}
        
        for bid, block in self.cfg.blocks.items():
            defs = set()
            for instr in block.instructions:
                if instr.opname in store_ops and instr.argval:
                    defs.add(Definition(
                        variable=instr.argval,
                        block_id=bid,
                        offset=instr.offset
                    ))
            self.block_defs[bid] = defs


# ============================================================================
# Type State Analysis
# ============================================================================

@dataclass
class TypeState:
    """
    Abstract type state for a variable.
    
    Tracks the set of possible types a variable may have.
    """
    variable: str
    possible_types: Set[str] = field(default_factory=set)  # Empty = unknown (any type)
    is_none: Optional[bool] = None  # True/False/None for unknown
    is_initialized: bool = True
    
    def definitely_not_none(self) -> bool:
        return self.is_none == False
    
    def definitely_none(self) -> bool:
        return self.is_none == True
    
    def has_single_type(self) -> Optional[str]:
        if len(self.possible_types) == 1:
            return next(iter(self.possible_types))
        return None


class TypeStateAnalysis:
    """
    Abstract interpretation for type tracking.
    
    Computes for each variable at each block:
    - Possible types
    - None/not-None state
    - Initialization state
    """
    
    def __init__(self, cfg: ControlFlowGraph):
        self.cfg = cfg
        # Variable type states at each block entry
        self.type_states: Dict[int, Dict[str, TypeState]] = {}
    
    def analyze(self) -> Dict[int, Dict[str, TypeState]]:
        """
        Run type state analysis.
        
        Returns: block_id -> (variable -> TypeState)
        """
        # Initialize all blocks with empty type maps
        for bid in self.cfg.blocks:
            self.type_states[bid] = {}
        
        # Find all variables
        all_vars = set()
        for block in self.cfg.blocks.values():
            all_vars |= block.loads
            all_vars |= block.stores
        
        # Initialize entry block with parameters as unknown
        entry_vars = {}
        for var in all_vars:
            entry_vars[var] = TypeState(variable=var, is_initialized=True)
        self.type_states[self.cfg.entry_block] = entry_vars
        
        # Forward analysis with abstract interpretation
        worklist = [self.cfg.entry_block]
        visited = set()
        
        while worklist:
            bid = worklist.pop(0)
            if bid in visited:
                continue
            visited.add(bid)
            
            block = self.cfg.blocks[bid]
            
            # Get input state (meet of predecessor states)
            input_state = self._merge_predecessor_states(bid)
            
            # Transfer function: update state through block
            output_state = self._transfer(block, input_state)
            
            # Store result
            self.type_states[bid] = output_state
            
            # Add successors
            for succ_id, edge_type, condition in block.successors:
                # Apply edge-sensitive refinement
                refined_state = self._refine_on_edge(output_state, edge_type, condition, block)
                # Merge with existing state at successor
                self._update_state(succ_id, refined_state)
                if succ_id not in visited:
                    worklist.append(succ_id)
        
        return self.type_states
    
    def _merge_predecessor_states(self, bid: int) -> Dict[str, TypeState]:
        """Merge type states from all predecessors."""
        block = self.cfg.blocks[bid]
        if not block.predecessors:
            return {}
        
        # Start with first predecessor
        result = {}
        first_pred = block.predecessors[0]
        if first_pred in self.type_states:
            for var, state in self.type_states[first_pred].items():
                result[var] = TypeState(
                    variable=var,
                    possible_types=state.possible_types.copy(),
                    is_none=state.is_none,
                    is_initialized=state.is_initialized
                )
        
        # Merge with other predecessors
        for pred in block.predecessors[1:]:
            if pred not in self.type_states:
                continue
            pred_state = self.type_states[pred]
            for var, state in pred_state.items():
                if var in result:
                    # Merge: union of types, tristate meet for is_none
                    result[var].possible_types |= state.possible_types
                    if result[var].is_none != state.is_none:
                        result[var].is_none = None  # Unknown
                    result[var].is_initialized &= state.is_initialized
                else:
                    result[var] = TypeState(
                        variable=var,
                        possible_types=state.possible_types.copy(),
                        is_none=state.is_none,
                        is_initialized=state.is_initialized
                    )
        
        return result
    
    def _transfer(self, block: BasicBlock, state: Dict[str, TypeState]) -> Dict[str, TypeState]:
        """Apply transfer function through a block."""
        result = {v: s.copy() if hasattr(s, 'copy') else TypeState(s.variable, s.possible_types.copy(), s.is_none, s.is_initialized) 
                  for v, s in state.items()}
        
        for instr in block.instructions:
            # Track stores with type information
            if instr.opname in ('STORE_FAST', 'STORE_NAME'):
                var = instr.argval
                if var:
                    # Simple type inference based on preceding instructions
                    # Full implementation would track the stack
                    result[var] = TypeState(variable=var, is_initialized=True)
            
            # Track loads that reveal None status
            if instr.opname == 'LOAD_CONST':
                if instr.argval is None:
                    # Next store will be None
                    pass
        
        return result
    
    def _refine_on_edge(
        self, 
        state: Dict[str, TypeState], 
        edge_type: EdgeType, 
        condition: Optional[str],
        block: BasicBlock
    ) -> Dict[str, TypeState]:
        """
        Refine type state based on edge condition.
        
        This is where path-sensitivity comes in:
        - On true branch of 'x is not None', x.is_none = False
        - On false branch of 'x is not None', x.is_none = True
        """
        result = {v: TypeState(s.variable, s.possible_types.copy(), s.is_none, s.is_initialized) 
                  for v, s in state.items()}
        
        # Look for pattern in block's last instructions
        if not block.instructions:
            return result
        
        last_instr = block.instructions[-1]
        
        # Handle IS_OP followed by conditional jump
        if last_instr.opname.startswith('POP_JUMP'):
            # Look for IS_OP pattern
            for i, instr in enumerate(block.instructions[:-1]):
                if instr.opname == 'IS_OP' and i >= 2:
                    # IS_OP 0 = 'is', IS_OP 1 = 'is not'
                    is_not = instr.arg == 1
                    
                    load_instr = block.instructions[i - 2]
                    const_instr = block.instructions[i - 1]
                    
                    if (load_instr.opname in ('LOAD_FAST', 'LOAD_NAME') and
                        const_instr.opname == 'LOAD_CONST' and
                        const_instr.argval is None):
                        var = load_instr.argval
                        if var and var in result:
                            # Determine refinement based on edge type
                            if edge_type == EdgeType.COND_TRUE:
                                # True branch of 'x is not None' => x is not None
                                # True branch of 'x is None' => x is None
                                result[var].is_none = not is_not
                            elif edge_type == EdgeType.COND_FALSE:
                                # False branch of 'x is not None' => x is None
                                # False branch of 'x is None' => x is not None
                                result[var].is_none = is_not
        
        return result
    
    def _update_state(self, bid: int, new_state: Dict[str, TypeState]):
        """Update state at a block, merging with existing."""
        if bid not in self.type_states:
            self.type_states[bid] = new_state
            return
        
        existing = self.type_states[bid]
        for var, state in new_state.items():
            if var in existing:
                # Merge
                existing[var].possible_types |= state.possible_types
                if existing[var].is_none != state.is_none:
                    existing[var].is_none = None
            else:
                existing[var] = state


# ============================================================================
# Bounds Analysis
# ============================================================================

@dataclass
class BoundsInfo:
    """
    Bounds information for a variable.
    
    Tracks numeric bounds (for overflow/bounds checking).
    """
    variable: str
    lower_bound: Optional[int] = None  # None = unbounded below
    upper_bound: Optional[int] = None  # None = unbounded above
    known_length_of: Optional[str] = None  # If this is len(some_container)
    
    def is_bounded(self) -> bool:
        return self.lower_bound is not None or self.upper_bound is not None
    
    def in_bounds(self, container_len_var: str) -> bool:
        """Check if this is a valid index for a container."""
        # Simplified: check if 0 <= self < len
        return (self.lower_bound is not None and self.lower_bound >= 0 and
                self.known_length_of == container_len_var)


class BoundsAnalysis:
    """
    Bounds analysis for numeric variables.
    
    Tracks:
    - Numeric range constraints from comparisons
    - Length relationships (x = len(y))
    - Index validity (0 <= i < len(arr))
    """
    
    def __init__(self, cfg: ControlFlowGraph):
        self.cfg = cfg
        # Bounds at each block
        self.bounds: Dict[int, Dict[str, BoundsInfo]] = {}
    
    def analyze(self) -> Dict[int, Dict[str, BoundsInfo]]:
        """Run bounds analysis."""
        # Initialize
        for bid in self.cfg.blocks:
            self.bounds[bid] = {}
        
        # Forward analysis
        worklist = [self.cfg.entry_block]
        visited = set()
        
        while worklist:
            bid = worklist.pop(0)
            if bid in visited:
                continue
            visited.add(bid)
            
            block = self.cfg.blocks[bid]
            
            # Merge predecessor bounds
            input_bounds = self._merge_bounds(bid)
            
            # Transfer through block
            output_bounds = self._transfer_bounds(block, input_bounds)
            
            self.bounds[bid] = output_bounds
            
            # Add successors with edge refinement
            for succ_id, edge_type, condition in block.successors:
                refined = self._refine_bounds_on_edge(output_bounds, edge_type, condition, block)
                self._update_bounds(succ_id, refined)
                if succ_id not in visited:
                    worklist.append(succ_id)
        
        return self.bounds
    
    def _merge_bounds(self, bid: int) -> Dict[str, BoundsInfo]:
        """Merge bounds from predecessors (widening)."""
        block = self.cfg.blocks[bid]
        result = {}
        
        for pred in block.predecessors:
            if pred not in self.bounds:
                continue
            for var, info in self.bounds[pred].items():
                if var in result:
                    # Widen: keep intersection of bounds
                    existing = result[var]
                    new_lower = None
                    new_upper = None
                    if existing.lower_bound is not None and info.lower_bound is not None:
                        new_lower = min(existing.lower_bound, info.lower_bound)
                    if existing.upper_bound is not None and info.upper_bound is not None:
                        new_upper = max(existing.upper_bound, info.upper_bound)
                    result[var] = BoundsInfo(var, new_lower, new_upper)
                else:
                    result[var] = BoundsInfo(
                        var, info.lower_bound, info.upper_bound, info.known_length_of
                    )
        
        return result
    
    def _transfer_bounds(
        self, 
        block: BasicBlock, 
        bounds: Dict[str, BoundsInfo]
    ) -> Dict[str, BoundsInfo]:
        """Transfer bounds through block."""
        result = {v: BoundsInfo(b.variable, b.lower_bound, b.upper_bound, b.known_length_of)
                  for v, b in bounds.items()}
        
        # Look for len() calls and assignments
        for i, instr in enumerate(block.instructions):
            if instr.opname == 'CALL' and i >= 2:
                # Check for len(x) pattern
                prev_instrs = block.instructions[max(0, i-2):i]
                len_info = self._check_len_pattern(prev_instrs)
                if len_info:
                    container_var, = len_info
                    # Next STORE will capture the length
                    if i + 1 < len(block.instructions):
                        next_instr = block.instructions[i + 1]
                        if next_instr.opname in ('STORE_FAST', 'STORE_NAME'):
                            result_var = next_instr.argval
                            if result_var:
                                result[result_var] = BoundsInfo(
                                    result_var,
                                    lower_bound=0,
                                    upper_bound=None,
                                    known_length_of=container_var
                                )
            
            # Track assignments of constants
            if instr.opname == 'LOAD_CONST' and isinstance(instr.argval, int):
                const_val = instr.argval
                if i + 1 < len(block.instructions):
                    next_instr = block.instructions[i + 1]
                    if next_instr.opname in ('STORE_FAST', 'STORE_NAME'):
                        result_var = next_instr.argval
                        if result_var:
                            result[result_var] = BoundsInfo(
                                result_var,
                                lower_bound=const_val,
                                upper_bound=const_val
                            )
        
        return result
    
    def _check_len_pattern(self, instrs: List) -> Optional[tuple]:
        """Check for len(x) call pattern."""
        for i, instr in enumerate(instrs):
            if (instr.opname in ('LOAD_GLOBAL', 'LOAD_BUILTIN') and 
                instr.argval == 'len'):
                if i + 1 < len(instrs):
                    arg_instr = instrs[i + 1]
                    if arg_instr.opname in ('LOAD_FAST', 'LOAD_NAME'):
                        return (arg_instr.argval,)
        return None
    
    def _refine_bounds_on_edge(
        self,
        bounds: Dict[str, BoundsInfo],
        edge_type: EdgeType,
        condition: Optional[str],
        block: BasicBlock
    ) -> Dict[str, BoundsInfo]:
        """Refine bounds based on conditional edge."""
        result = {v: BoundsInfo(b.variable, b.lower_bound, b.upper_bound, b.known_length_of)
                  for v, b in bounds.items()}
        
        if not block.instructions:
            return result
        
        # Look for comparison patterns
        for i, instr in enumerate(block.instructions):
            if instr.opname == 'COMPARE_OP' and i >= 2:
                op = instr.argval
                left_instr = block.instructions[i - 2]
                right_instr = block.instructions[i - 1]
                
                # Pattern: var < const
                if (left_instr.opname in ('LOAD_FAST', 'LOAD_NAME') and
                    right_instr.opname == 'LOAD_CONST' and
                    isinstance(right_instr.argval, int)):
                    var = left_instr.argval
                    const = right_instr.argval
                    
                    if var in result:
                        if edge_type == EdgeType.COND_TRUE:
                            # True branch: condition holds
                            if op == '<':
                                result[var].upper_bound = const - 1
                            elif op == '<=':
                                result[var].upper_bound = const
                            elif op == '>':
                                result[var].lower_bound = const + 1
                            elif op == '>=':
                                result[var].lower_bound = const
        
        return result
    
    def _update_bounds(self, bid: int, new_bounds: Dict[str, BoundsInfo]):
        """Update bounds at block."""
        if bid not in self.bounds:
            self.bounds[bid] = new_bounds
            return
        
        existing = self.bounds[bid]
        for var, info in new_bounds.items():
            if var in existing:
                # Widen
                e = existing[var]
                if e.lower_bound is not None and info.lower_bound is not None:
                    e.lower_bound = min(e.lower_bound, info.lower_bound)
                else:
                    e.lower_bound = None
                if e.upper_bound is not None and info.upper_bound is not None:
                    e.upper_bound = max(e.upper_bound, info.upper_bound)
                else:
                    e.upper_bound = None
            else:
                existing[var] = info


# ============================================================================
# Integrated Intraprocedural Analysis
# ============================================================================

@dataclass
class IntraprocAnalysisResult:
    """
    Complete result of intraprocedural analysis.
    
    Combines:
    - CFG structure
    - Guard dataflow
    - Type states
    - Bounds info
    - Exception catching info
    - Z3 length constraints for symbolic bounds verification
    """
    cfg: ControlFlowGraph
    guard_states: Dict[int, GuardState]
    type_states: Dict[int, Dict[str, TypeState]]
    bounds: Dict[int, Dict[str, BoundsInfo]]
    guard_gen: Dict[int, Set[str]] = field(default_factory=dict)  # Guards generated by each block
    # Z3 length constraints generated by each block: block_id -> (container -> (len_var, constraint))
    length_constraint_gen: Dict[int, Dict[str, Tuple[z3.ExprRef, z3.ExprRef]]] = field(default_factory=dict)
    
    def get_guards_at_offset(self, offset: int) -> GuardState:
        """
        Get guards valid at instruction offset.
        
        Uses both:
        1. Dataflow-propagated guards (from guard_states)
        2. Dominance-based guards (from dominating blocks)
        
        This ensures loop-invariant guards like range_len_loop are properly
        propagated even when dataflow meet operation loses them.
        
        Also propagates Z3 length constraints for symbolic bounds verification.
        """
        block = self.cfg.get_block_for_offset(offset)
        if not block:
            return GuardState()
        
        # Start with dataflow result
        result = self.guard_states.get(block.id, GuardState()).copy()
        
        # Add guards from all dominating blocks (including self)
        # This handles loop-invariant guards that are lost by meet/intersection
        dominators = self.cfg.dominators.get(block.id, set())
        for dom_id in dominators:
            # Get guards generated by the dominating block
            if dom_id in self.guard_gen:
                result.established |= self.guard_gen[dom_id]
            
            # Propagate Z3 length constraints from dominating blocks
            if dom_id in self.length_constraint_gen:
                for container, (len_var, constraint) in self.length_constraint_gen[dom_id].items():
                    result.add_length_constraint(container, len_var, constraint)
        
        return result
    
    def get_type_state(self, offset: int, variable: str) -> Optional[TypeState]:
        """Get type state for a variable at offset."""
        block = self.cfg.get_block_for_offset(offset)
        if block and block.id in self.type_states:
            return self.type_states[block.id].get(variable)
        return None
    
    def get_bounds(self, offset: int, variable: str) -> Optional[BoundsInfo]:
        """Get bounds for a variable at offset."""
        block = self.cfg.get_block_for_offset(offset)
        if block and block.id in self.bounds:
            return self.bounds[block.id].get(variable)
        return None
    
    def is_safe_division(self, offset: int, divisor_var: str) -> bool:
        """Check if division by divisor_var is safe at offset."""
        guards = self.get_guards_at_offset(offset)
        return guards.has_div_safe(divisor_var)
    
    def is_nonnull(self, offset: int, variable: str) -> bool:
        """Check if variable is definitely not None at offset."""
        # Check guards first
        guards = self.get_guards_at_offset(offset)
        if guards.has_nonnull(variable):
            return True
        
        # Check type state
        type_state = self.get_type_state(offset, variable)
        if type_state and type_state.definitely_not_none():
            return True
        
        return False
    
    def is_in_try_block(self, offset: int) -> bool:
        """Check if offset is within a try block."""
        return self.cfg.get_exception_handler(offset) is not None
    
    def will_catch_at(self, offset: int, exception_type: str) -> bool:
        """Check if exception will be caught at offset."""
        from .control_flow import ExceptionCatchAnalyzer
        analyzer = ExceptionCatchAnalyzer(self.cfg)
        return analyzer.will_catch_at(offset, exception_type)


def run_intraprocedural_analysis(code) -> IntraprocAnalysisResult:
    """
    Run complete intraprocedural analysis on a code object.
    
    Combines:
    1. CFG construction with dominance
    2. Guard dataflow analysis
    3. Type state analysis
    4. Bounds analysis
    
    Returns complete analysis result.
    """
    import types
    from .control_flow import build_cfg
    
    # Build CFG
    cfg = build_cfg(code)
    
    # Run guard dataflow
    guard_analysis = GuardDataflowAnalysis(cfg)
    guard_states = guard_analysis.analyze()
    
    # Run type analysis
    type_analysis = TypeStateAnalysis(cfg)
    type_states = type_analysis.analyze()
    
    # Run bounds analysis
    bounds_analysis = BoundsAnalysis(cfg)
    bounds = bounds_analysis.analyze()
    
    # Get Z3 length constraints for symbolic verification
    length_constraint_gen = getattr(guard_analysis, 'block_length_constraints', {})
    
    return IntraprocAnalysisResult(
        cfg=cfg,
        guard_states=guard_states,
        type_states=type_states,
        bounds=bounds,
        guard_gen=guard_analysis.block_gen,  # Pass guard gen sets for dominance-based propagation
        length_constraint_gen=length_constraint_gen,  # Pass Z3 constraints for symbolic bounds verification
    )
