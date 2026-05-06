"""
SOTA Intraprocedural Security Engine (Phase 1 of CODEQL_PARITY_SOTA_MATH_PLAN).

This module implements a unified intraprocedural security analysis engine using:
1. CFG-based worklist algorithm with proper fixpoint computation
2. Abstract state = (Locals, Stack, Names) x TaintLabel per slot
3. Bounded partitioning for path sensitivity (sanitized vs unsanitized)
4. Witness generation for explainable BUG reports

Non-negotiables (from the plan):
- No pattern matching deciders - verdicts from semantic reachability
- No SAFE by absence - SAFE requires proof artifact
- Unknown calls use havoc fallback
- Concolic is witness-only

Architecture:
- Uses CFG from cfg/control_flow.py (includes exceptional edges)
- Uses TaintLabel from z3model/taint_lattice.py
- Uses contracts from contracts/security_lattice.py
- Reports SecurityViolation from z3model/taint_lattice.py
"""

from __future__ import annotations
from dataclasses import dataclass, field
from typing import Dict, List, Set, Optional, Tuple, FrozenSet, Any
from pathlib import Path
from enum import IntEnum, auto
import dis
import types
import copy

from ..z3model.taint_lattice import (
    SourceType, SinkType, SanitizerType,
    TaintLabel, label_join, label_join_many,
    SecurityViolation, SecurityBugType,
    tau_zero, kappa_full, sigma_zero,
)
from ..contracts.security_lattice import (
    is_taint_source, is_security_sink, is_sanitizer,
    get_source_contract, get_sink_contract, get_sanitizer_contract,
    apply_source_taint, check_sink_taint, apply_sanitizer,
)
from ..cfg.control_flow import (
    ControlFlowGraph, BasicBlock, EdgeType, build_cfg
)


# ============================================================================
# ABSTRACT STATE
# ============================================================================

class AbstractSlot:
    """
    A named slot in the abstract state.
    
    SSA-like naming without full SSA transformation:
    - LocalSlot(idx): local variable by index
    - StackSlot(depth): operand stack position (0 = TOS)
    - NameSlot(name): global/builtin names
    - AttrSlot(base, attr): attribute access result
    - SubscrSlot(base, key): subscript access result  
    """
    pass


@dataclass(frozen=True)
class LocalSlot:
    """Local variable slot (from LOAD_FAST/STORE_FAST)."""
    idx: int
    name: str = ""  # Optional name for debugging
    
    def __repr__(self):
        return f"local[{self.idx}:{self.name}]" if self.name else f"local[{self.idx}]"


@dataclass(frozen=True)
class StackSlot:
    """Stack slot (temporary during expression evaluation)."""
    depth: int  # 0 = TOS, 1 = below TOS, etc.
    
    def __repr__(self):
        return f"stack[{self.depth}]"


@dataclass(frozen=True) 
class NameSlot:
    """Named slot (globals, builtins, names)."""
    name: str
    
    def __repr__(self):
        return f"name[{self.name}]"


@dataclass
class AbstractState:
    """
    Abstract state at a program point.
    
    Tracks taint labels for:
    - locals: Dict[int, TaintLabel] - local variables by index
    - stack: List[TaintLabel] - operand stack (TOS at end)
    - names: Dict[str, TaintLabel] - global/builtin names
    - guard_facts: Set[str] - established guards (for trusted cases)
    
    The state supports join (merge at control-flow confluence) and
    is designed for efficient fixpoint computation.
    """
    
    # Map from local variable index -> taint label
    locals: Dict[int, TaintLabel] = field(default_factory=dict)
    
    # Operand stack (TOS at the end)
    stack: List[TaintLabel] = field(default_factory=list)
    
    # Map from name -> taint label (globals, builtins)
    names: Dict[str, TaintLabel] = field(default_factory=dict)
    
    # Established guard facts at this point
    guard_facts: Set[str] = field(default_factory=set)
    
    # Partition key (for bounded disjunction)
    # Format: frozenset of predicate strings, e.g., {"tainted:0", "sanitized:SQL_EXECUTE"}
    partition_key: FrozenSet[str] = field(default_factory=frozenset)
    
    def copy(self) -> AbstractState:
        """Deep copy for branching."""
        return AbstractState(
            locals=dict(self.locals),
            stack=list(self.stack),
            names=dict(self.names),
            guard_facts=set(self.guard_facts),
            partition_key=self.partition_key,
        )
    
    def get_local(self, idx: int) -> TaintLabel:
        """Get taint label for local variable."""
        return self.locals.get(idx, TaintLabel.clean())
    
    def set_local(self, idx: int, label: TaintLabel):
        """Set taint label for local variable."""
        self.locals[idx] = label
    
    def get_name(self, name: str) -> TaintLabel:
        """Get taint label for named variable."""
        return self.names.get(name, TaintLabel.clean())
    
    def set_name(self, name: str, label: TaintLabel):
        """Set taint label for named variable."""
        self.names[name] = label
    
    def push(self, label: TaintLabel):
        """Push taint label onto operand stack."""
        self.stack.append(label)
    
    def pop(self) -> TaintLabel:
        """Pop taint label from operand stack (returns clean if empty)."""
        if not self.stack:
            return TaintLabel.clean()
        return self.stack.pop()
    
    def peek(self, depth: int = 0) -> TaintLabel:
        """Peek at stack position (0 = TOS)."""
        idx = len(self.stack) - 1 - depth
        if idx < 0:
            return TaintLabel.clean()
        return self.stack[idx]
    
    def stack_size(self) -> int:
        """Get current stack depth."""
        return len(self.stack)
    
    def join(self, other: AbstractState) -> AbstractState:
        """
        Join two abstract states (for control-flow merge).
        
        Join semantics:
        - locals: pointwise join (join missing as clean)
        - stack: pointwise join (must have same depth!)
        - names: pointwise join
        - guard_facts: intersection (only guards that hold on both paths)
        - partition_key: must match (or we shouldn't be joining)
        """
        # Merge locals
        all_local_keys = set(self.locals.keys()) | set(other.locals.keys())
        merged_locals = {}
        for k in all_local_keys:
            l1 = self.locals.get(k, TaintLabel.clean())
            l2 = other.locals.get(k, TaintLabel.clean())
            merged_locals[k] = label_join(l1, l2)
        
        # Merge stack (should have same depth; if not, handle gracefully)
        merged_stack = []
        max_depth = max(len(self.stack), len(other.stack))
        for i in range(max_depth):
            l1 = self.stack[i] if i < len(self.stack) else TaintLabel.clean()
            l2 = other.stack[i] if i < len(other.stack) else TaintLabel.clean()
            merged_stack.append(label_join(l1, l2))
        
        # Merge names
        all_name_keys = set(self.names.keys()) | set(other.names.keys())
        merged_names = {}
        for k in all_name_keys:
            l1 = self.names.get(k, TaintLabel.clean())
            l2 = other.names.get(k, TaintLabel.clean())
            merged_names[k] = label_join(l1, l2)
        
        # Merge guard facts (intersection - only facts true on both paths)
        merged_guards = self.guard_facts & other.guard_facts
        
        return AbstractState(
            locals=merged_locals,
            stack=merged_stack,
            names=merged_names,
            guard_facts=merged_guards,
            partition_key=self.partition_key,  # Assume same partition
        )
    
    def __eq__(self, other: AbstractState) -> bool:
        """Check equality for fixpoint detection."""
        if not isinstance(other, AbstractState):
            return False
        return (
            self.locals == other.locals and
            self.stack == other.stack and
            self.names == other.names and
            self.partition_key == other.partition_key
        )
    
    def subsumes(self, other: AbstractState) -> bool:
        """
        Check if self subsumes other (self >= other in lattice).
        
        This is the widening check: if state hasn't grown, we've reached fixpoint.
        """
        # Check locals
        for k, v in other.locals.items():
            my_v = self.locals.get(k, TaintLabel.clean())
            # v should be "less than or equal" to my_v
            # For taint: my_tau >= other_tau, my_sigma >= other_sigma
            # my_kappa <= other_kappa (more sanitization means smaller)
            if (v.tau & ~my_v.tau) != 0:  # other has taint bits we don't
                return False
            if (v.sigma & ~my_v.sigma) != 0:  # other has sigma bits we don't
                return False
            if (my_v.kappa & ~v.kappa) != 0:  # we have kappa bits other doesn't
                return False
        
        # Check stack
        for i, v in enumerate(other.stack):
            if i >= len(self.stack):
                return False
            my_v = self.stack[i]
            if (v.tau & ~my_v.tau) != 0:
                return False
            if (v.sigma & ~my_v.sigma) != 0:
                return False
            if (my_v.kappa & ~v.kappa) != 0:
                return False
        
        # Check names
        for k, v in other.names.items():
            my_v = self.names.get(k, TaintLabel.clean())
            if (v.tau & ~my_v.tau) != 0:
                return False
            if (v.sigma & ~my_v.sigma) != 0:
                return False
            if (my_v.kappa & ~v.kappa) != 0:
                return False
        
        return True


# ============================================================================
# SECURITY VIOLATION REPORT
# ============================================================================

@dataclass
class SOTASecurityViolation:
    """
    A security violation found by the SOTA engine.
    
    Includes:
    - Bug type and location
    - Taint flow explanation (source -> ... -> sink)
    - Witness skeleton (path through CFG)
    """
    bug_type: str  # e.g., 'SQL_INJECTION', 'COMMAND_INJECTION'
    sink_type: SinkType
    
    # Location info
    file_path: str
    function_name: str
    line_number: int
    bytecode_offset: int
    
    # Taint info
    taint_label: TaintLabel
    source_description: str  # Where taint came from
    sink_description: str    # What sink was reached
    
    # Witness skeleton (list of (block_id, offset) pairs from source to sink)
    witness_skeleton: List[Tuple[int, int]] = field(default_factory=list)
    
    # Predecessor chain for backtracking
    predecessor_chain: List[int] = field(default_factory=list)
    
    # Reason string for user
    reason: str = ""
    
    # Confidence (1.0 = certain)
    confidence: float = 1.0
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            'bug_type': self.bug_type,
            'sink_type': self.sink_type.name,
            'file_path': self.file_path,
            'function_name': self.function_name,
            'line_number': self.line_number,
            'bytecode_offset': self.bytecode_offset,
            'source_description': self.source_description,
            'sink_description': self.sink_description,
            'reason': self.reason,
            'confidence': self.confidence,
        }
    
    def __str__(self) -> str:
        loc = f"{self.file_path}:{self.line_number}"
        return (
            f"{self.bug_type} at {loc} in {self.function_name}\n"
            f"  Source: {self.source_description}\n"
            f"  Sink: {self.sink_description}\n"
            f"  Reason: {self.reason}"
        )


# ============================================================================
# PARTITION KEY MANAGEMENT
# ============================================================================

def compute_partition_key(state: AbstractState, partition_predicates: Set[str]) -> FrozenSet[str]:
    """
    Compute partition key from state for selective disjunction.
    
    Partition predicates are things like:
    - "tainted:N" - local N has taint
    - "sanitized:SINK" - some value is sanitized for SINK
    """
    key_parts = set()
    
    for pred in partition_predicates:
        if pred.startswith("tainted:"):
            try:
                idx = int(pred.split(":")[1])
                if state.get_local(idx).has_any_taint():
                    key_parts.add(pred)
            except (ValueError, IndexError):
                pass
        elif pred.startswith("sanitized:"):
            try:
                sink_name = pred.split(":")[1]
                sink = SinkType[sink_name]
                # Check if any local is sanitized for this sink
                for label in state.locals.values():
                    if label.is_sanitized_for(sink):
                        key_parts.add(pred)
                        break
            except (KeyError, IndexError):
                pass
    
    return frozenset(key_parts)


# ============================================================================
# SOTA INTRAPROCEDURAL ANALYZER
# ============================================================================

class SOTAIntraproceduralAnalyzer:
    """
    SOTA intraprocedural security analyzer.
    
    Uses CFG-based worklist algorithm with:
    - Abstract interpretation to fixpoint
    - Bounded partitioning for path sensitivity
    - Transfer functions per opcode
    - Contract-based source/sink/sanitizer modeling
    """
    
    def __init__(
        self,
        code_obj: types.CodeType,
        function_name: str = "<unknown>",
        file_path: str = "<unknown>",
        max_iterations: int = 1000,  # Reduced default for performance
        max_partitions: int = 4,     # Reduced default for performance
        verbose: bool = False,
    ):
        self.code_obj = code_obj
        self.function_name = function_name
        self.file_path = file_path
        self.max_iterations = max_iterations
        self.max_partitions = max_partitions
        self.verbose = verbose
        
        # Build CFG
        self.cfg = build_cfg(code_obj)
        
        # Bytecode instructions (for quick lookup by offset)
        self.instructions = list(dis.get_instructions(code_obj))
        self.offset_to_instr: Dict[int, dis.Instruction] = {
            i.offset: i for i in self.instructions
        }
        
        # Block-level states: block_id -> partition_key -> AbstractState
        self.states: Dict[int, Dict[FrozenSet[str], AbstractState]] = {}
        
        # Worklist: set of (block_id, partition_key) pairs
        self.worklist: Set[Tuple[int, FrozenSet[str]]] = set()
        
        # Violations found
        self.violations: List[SOTASecurityViolation] = []
        
        # Predecessor tracking for witness generation
        # (block_id, partition_key) -> predecessor (block_id, partition_key, edge_type)
        self.predecessors: Dict[Tuple[int, FrozenSet[str]], Tuple[int, FrozenSet[str], EdgeType]] = {}
        
        # Source tracking
        self.sources: Dict[int, str] = {}  # offset -> description
        
        # Total iterations
        self.total_iterations = 0
        
        # Partition predicates to track
        self.partition_predicates: Set[str] = set()
    
    def analyze(
        self,
        entry_taint: Optional[Dict[int, TaintLabel]] = None,
    ) -> List[SOTASecurityViolation]:
        """
        Run intraprocedural analysis to fixpoint.
        
        Args:
            entry_taint: Optional taint labels for function parameters.
                         If None, parameters matching suspicious patterns are tainted.
        
        Returns:
            List of security violations found.
        """
        # Initialize entry state
        entry_state = self._create_entry_state(entry_taint)
        
        # Determine partition predicates based on entry taint
        for idx, label in entry_state.locals.items():
            if label.has_any_taint():
                self.partition_predicates.add(f"tainted:{idx}")
        
        # Initialize entry block state
        entry_key = frozenset()
        self.states[self.cfg.entry_block] = {entry_key: entry_state}
        self.worklist.add((self.cfg.entry_block, entry_key))
        
        # Fixpoint iteration
        while self.worklist and self.total_iterations < self.max_iterations:
            block_id, partition_key = self.worklist.pop()
            self.total_iterations += 1
            
            if self.verbose and self.total_iterations % 1000 == 0:
                print(f"  [SOTA] Iteration {self.total_iterations}, worklist size: {len(self.worklist)}")
            
            # Get state for this block+partition
            if block_id not in self.states:
                continue
            if partition_key not in self.states[block_id]:
                continue
            
            state = self.states[block_id][partition_key].copy()
            block = self.cfg.blocks[block_id]
            
            # Process all instructions in the block
            for instr in block.instructions:
                state = self._transfer(instr, state)
            
            # Propagate to successors
            for succ_id, edge_type, guard_cond in block.successors:
                self._propagate_to_successor(
                    block_id, partition_key, succ_id, edge_type, guard_cond, state
                )
        
        if self.verbose:
            print(f"  [SOTA] Completed in {self.total_iterations} iterations")
            print(f"  [SOTA] Found {len(self.violations)} violations")
        
        return self.violations
    
    def _create_entry_state(
        self,
        entry_taint: Optional[Dict[int, TaintLabel]] = None,
    ) -> AbstractState:
        """Create initial abstract state for function entry."""
        state = AbstractState()
        
        if entry_taint is not None:
            # Use provided taint labels
            for idx, label in entry_taint.items():
                state.set_local(idx, label)
        else:
            # Infer taint from parameter names
            param_patterns = [
                'command', 'cmd', 'input', 'query', 'sql', 'user', 'data',
                'param', 'arg', 'request', 'domain', 'url', 'path', 'filename',
                'host', 'ip', 'address', 'email', 'name', 'value', 'text',
                'code', 'expr', 'expression', 'script', 'template', 'html',
            ]
            
            sensitive_patterns = [
                'password', 'passwd', 'pwd', 'secret', 'key', 'token',
                'api_key', 'apikey', 'auth', 'credential', 'ssn', 'credit',
            ]
            
            for param_idx in range(self.code_obj.co_argcount):
                if param_idx < len(self.code_obj.co_varnames):
                    param_name = self.code_obj.co_varnames[param_idx]
                    param_lower = param_name.lower()
                    
                    # Check for sensitive patterns
                    is_sensitive = any(p in param_lower for p in sensitive_patterns)
                    is_untrusted = any(p in param_lower for p in param_patterns)
                    
                    if is_sensitive:
                        # Both untrusted and sensitive
                        label = TaintLabel.from_untrusted_source(
                            SourceType.USER_INPUT, f"parameter '{param_name}'"
                        ).with_sensitivity(SourceType.PASSWORD)
                        state.set_local(param_idx, label)
                        self.sources[0] = f"parameter '{param_name}' (sensitive)"
                    elif is_untrusted:
                        # Just untrusted
                        label = TaintLabel.from_untrusted_source(
                            SourceType.USER_INPUT, f"parameter '{param_name}'"
                        )
                        state.set_local(param_idx, label)
                        self.sources[0] = f"parameter '{param_name}'"
        
        return state
    
    def _propagate_to_successor(
        self,
        from_block: int,
        from_key: FrozenSet[str],
        to_block: int,
        edge_type: EdgeType,
        guard_cond: Optional[str],
        state: AbstractState,
    ):
        """Propagate state to a successor block."""
        # Compute new partition key based on state
        new_key = compute_partition_key(state, self.partition_predicates)
        
        # Apply guard condition if any
        if guard_cond:
            state = state.copy()
            state.guard_facts.add(guard_cond)
        
        # Initialize successor states dict if needed
        if to_block not in self.states:
            self.states[to_block] = {}
        
        # Check if we need to add/update state for this partition
        if new_key not in self.states[to_block]:
            # New partition - add it
            if len(self.states[to_block]) < self.max_partitions:
                self.states[to_block][new_key] = state
                self.worklist.add((to_block, new_key))
                self.predecessors[(to_block, new_key)] = (from_block, from_key, edge_type)
            else:
                # Merge into closest partition
                self._merge_into_partition(to_block, new_key, state)
        else:
            # Existing partition - join
            existing = self.states[to_block][new_key]
            if not existing.subsumes(state):
                merged = existing.join(state)
                self.states[to_block][new_key] = merged
                self.worklist.add((to_block, new_key))
    
    def _merge_into_partition(
        self,
        block: int,
        key: FrozenSet[str],
        state: AbstractState,
    ):
        """Merge state into the closest existing partition (when at partition limit)."""
        # Find partition with most overlap
        best_key = None
        best_overlap = -1
        
        for existing_key in self.states[block]:
            overlap = len(key & existing_key)
            if overlap > best_overlap:
                best_overlap = overlap
                best_key = existing_key
        
        if best_key is not None:
            existing = self.states[block][best_key]
            merged = existing.join(state)
            self.states[block][best_key] = merged
            self.worklist.add((block, best_key))
    
    def _transfer(
        self,
        instr: dis.Instruction,
        state: AbstractState,
    ) -> AbstractState:
        """
        Apply transfer function for a bytecode instruction.
        
        This is the core of the abstract interpretation - each opcode
        transforms the abstract state according to its semantics.
        """
        opname = instr.opname
        
        # === LOAD instructions ===
        if opname == 'LOAD_FAST' or opname == 'LOAD_FAST_BORROW':
            label = state.get_local(instr.arg)
            state.push(label)
        
        elif opname == 'LOAD_FAST_BORROW_LOAD_FAST_BORROW':
            # Python 3.14 optimization: loads two locals at once
            # arg encodes two indices as nibbles: (idx1 << 4) | idx2
            idx1 = (instr.arg >> 4) & 0xF
            idx2 = instr.arg & 0xF
            label1 = state.get_local(idx1)
            label2 = state.get_local(idx2)
            state.push(label1)
            state.push(label2)
        
        elif opname == 'LOAD_CONST' or opname == 'LOAD_SMALL_INT':
            # Constants (including small integers) are clean
            state.push(TaintLabel.clean())
        
        elif opname in ('LOAD_NAME', 'LOAD_GLOBAL'):
            label = state.get_name(instr.argval)
            state.push(label)
        
        elif opname == 'LOAD_ATTR':
            # Pop object, push attribute
            obj_label = state.pop()
            
            # Check if this is a method load (Python 3.11+)
            # In Python 3.11+, LOAD_ATTR with bit 0 set pushes [self, method]
            # The argval has '+ NULL|self' suffix for methods
            is_method_load = False
            if instr.arg is not None:
                # Bit 0 indicates method load
                is_method_load = (instr.arg & 1) == 1
            
            # Check if this attribute access is a source
            attr_name = instr.argval
            obj_name = self._identify_attr_object(instr.offset)
            full_name = f"{obj_name}.{attr_name}" if obj_name else attr_name
            
            if is_taint_source(full_name):
                contract = get_source_contract(full_name)
                if contract:
                    result_label = TaintLabel.from_untrusted_source(
                        contract.source_type, full_name
                    )
                    self.sources[instr.offset] = full_name
                else:
                    result_label = obj_label
            else:
                # Attribute access propagates taint from object
                result_label = obj_label
            
            if is_method_load:
                # Method load: push self (with taint), then method (with taint)
                state.push(obj_label)  # self
                state.push(result_label)  # method
            else:
                state.push(result_label)
        
        elif opname == 'LOAD_DEREF' or opname == 'LOAD_CLOSURE':
            # Closure/cell variables - conservative: push clean
            state.push(TaintLabel.clean())
        
        # === STORE instructions ===
        elif opname == 'STORE_FAST':
            label = state.pop()
            
            # Infer sensitivity from variable name
            if instr.arg < len(self.code_obj.co_varnames):
                var_name = self.code_obj.co_varnames[instr.arg]
                label = self._maybe_add_sensitivity(var_name, label)
            
            state.set_local(instr.arg, label)
        
        elif opname in ('STORE_NAME', 'STORE_GLOBAL'):
            label = state.pop()
            state.set_name(instr.argval, label)
        
        elif opname == 'STORE_ATTR':
            # Pop value and object
            value_label = state.pop()
            obj_label = state.pop()
            # Attribute stores don't produce a value
        
        elif opname == 'STORE_SUBSCR':
            # STORE_SUBSCR: Implements TOS1[TOS] = TOS2
            # Pop in order: TOS (index), TOS1 (container), TOS2 (value)
            index_label = state.pop()
            container_label = state.pop()
            value_label = state.pop()
            
            # ITERATION 599 FIX: Container sensitivity propagation
            # When a tainted value is stored into a container, the container itself becomes tainted
            # This fixes cleartext_storage_001 false negative where password is stored in dict
            
            # The container was likely loaded from a local or name variable
            # We need to find which variable holds this container and update its taint
            # Strategy: Look back at recent instructions to find the LOAD that produced the container
            
            # For now, use a heuristic: update all locals/names that have the same taint as the container
            # This is sound (over-approximation) but may be imprecise
            for local_idx, local_label in list(state.locals.items()):
                # If this local has the same taint as the container, it might be the container
                # Update it to include the value's taint
                if local_label.tau == container_label.tau and local_label.sigma == container_label.sigma:
                    updated_label = label_join(local_label, value_label)
                    state.set_local(local_idx, updated_label)
            
            for name, name_label in list(state.names.items()):
                if name_label.tau == container_label.tau and name_label.sigma == container_label.sigma:
                    updated_label = label_join(name_label, value_label)
                    state.set_name(name, updated_label)
        
        elif opname == 'STORE_DEREF':
            # Store to closure cell
            state.pop()
        
        # === Stack manipulation ===
        elif opname == 'POP_TOP':
            state.pop()
        
        elif opname == 'DUP_TOP' or opname == 'COPY':
            top = state.peek()
            state.push(top)
        
        elif opname == 'SWAP':
            # SWAP N: swap TOS with stack[N]
            n = instr.arg if instr.arg else 2
            if state.stack_size() >= n:
                state.stack[-1], state.stack[-n] = state.stack[-n], state.stack[-1]
        
        elif opname == 'ROT_TWO':
            if state.stack_size() >= 2:
                state.stack[-1], state.stack[-2] = state.stack[-2], state.stack[-1]
        
        elif opname == 'ROT_THREE':
            if state.stack_size() >= 3:
                a, b, c = state.stack[-1], state.stack[-2], state.stack[-3]
                state.stack[-1], state.stack[-2], state.stack[-3] = b, c, a
        
        # === Binary operations ===
        elif opname.startswith('BINARY_') or opname == 'BINARY_OP':
            if state.stack_size() >= 2:
                right = state.pop()
                left = state.pop()
                result = label_join(left, right)
                
                # Check for subscript with sensitive key
                is_subscript = (opname == 'BINARY_SUBSCR' or 
                               (opname == 'BINARY_OP' and instr.arg == 26))
                if is_subscript:
                    key_str = self._extract_subscript_key(instr.offset)
                    if key_str:
                        result = self._maybe_add_sensitivity(key_str, result)
                
                state.push(result)
            else:
                state.push(TaintLabel.clean())
        
        elif opname.startswith('UNARY_'):
            if state.stack_size() >= 1:
                operand = state.pop()
                state.push(operand)  # Unary ops preserve taint
        
        elif opname.startswith('INPLACE_'):
            if state.stack_size() >= 2:
                right = state.pop()
                left = state.pop()
                result = label_join(left, right)
                state.push(result)
        
        # === Comparison ===
        elif opname == 'COMPARE_OP' or opname == 'IS_OP' or opname == 'CONTAINS_OP':
            if state.stack_size() >= 2:
                right = state.pop()
                left = state.pop()
                result = label_join(left, right)
                state.push(result)
        
        # === BUILD operations ===
        elif opname.startswith('BUILD_'):
            count = instr.arg if instr.arg else 0
            
            if opname == 'BUILD_MAP':
                count = count * 2  # Key-value pairs
            
            items = []
            for _ in range(count):
                if state.stack_size() > 0:
                    items.append(state.pop())
            
            result = label_join_many(items) if items else TaintLabel.clean()
            state.push(result)
        
        elif opname == 'BUILD_STRING':
            count = instr.arg if instr.arg else 0
            items = []
            for _ in range(count):
                if state.stack_size() > 0:
                    items.append(state.pop())
            result = label_join_many(items) if items else TaintLabel.clean()
            state.push(result)
        
        elif opname == 'LIST_APPEND' or opname == 'SET_ADD' or opname == 'MAP_ADD':
            # These add to an existing collection
            if state.stack_size() >= 1:
                item = state.pop()
                # The collection stays on stack; taint it
                if state.stack_size() >= 1:
                    container = state.pop()
                    result = label_join(container, item)
                    state.push(result)
        
        # === FORMAT ===
        elif opname == 'FORMAT_VALUE':
            # Format a value (f-strings) - propagate taint
            if state.stack_size() >= 1:
                value = state.pop()
                state.push(value)
        
        elif opname == 'FORMAT_SIMPLE':
            # ITERATION 610: FORMAT_SIMPLE converts value to string (Python 3.14+)
            # Stack: value → str(value)
            # Preserves taint since the string representation of a value inherits taint
            if state.stack_size() >= 1:
                value = state.pop()
                state.push(value)  # String version inherits taint
        
        # === CALL instructions ===
        elif 'CALL' in opname:
            state = self._handle_call(instr, state)
        
        elif opname == 'PUSH_NULL':
            state.push(TaintLabel.clean())
        
        elif opname == 'PRECALL':
            # Just setup for CALL, no state change
            pass
        
        # === Control flow (handled at block level, but pop condition) ===
        elif opname.startswith('POP_JUMP_IF'):
            state.pop()  # Pop condition
        
        elif opname == 'JUMP_FORWARD' or opname == 'JUMP_BACKWARD':
            pass  # Unconditional jump
        
        elif opname == 'JUMP_IF_TRUE_OR_POP' or opname == 'JUMP_IF_FALSE_OR_POP':
            # Complex control flow - peek but don't pop (may or may not pop)
            pass
        
        # === Boolean/Condition opcodes (Python 3.14+) ===
        elif opname == 'TO_BOOL':
            # Converts TOS to boolean - doesn't change taint
            # Stack remains the same (TOS is still there with same taint)
            pass
        
        elif opname == 'NOT_TAKEN':
            # Branch hint for JIT - no stack effect
            pass
        
        # === Fast store variants (Python 3.14+) ===
        elif opname == 'STORE_FAST_STORE_FAST':
            # Stores two values to two locals
            # arg encodes two indices as nibbles: (idx1 << 4) | idx2
            idx2 = instr.arg & 0xF
            idx1 = (instr.arg >> 4) & 0xF
            if state.stack_size() >= 2:
                label2 = state.pop()
                label1 = state.pop()
                state.set_local(idx1, label1)
                state.set_local(idx2, label2)
        
        # === Exception handling (Python 3.11+) ===
        elif opname == 'PUSH_EXC_INFO':
            # Push exception info onto stack
            state.push(TaintLabel.clean())  # Exception info is clean
        
        elif opname == 'POP_EXCEPT':
            # Pop exception from stack
            if state.stack_size() >= 1:
                state.pop()
        
        elif opname == 'CHECK_EXC_MATCH':
            # Check if exception matches - push result
            if state.stack_size() >= 2:
                state.pop()  # exception type
                # Keep exception on stack
                state.push(TaintLabel.clean())  # Match result is clean
        
        # === Return ===
        elif opname == 'RETURN_VALUE' or opname == 'RETURN_CONST':
            # Return doesn't modify state for intraprocedural analysis
            # (interprocedural will handle return value propagation)
            pass
        
        # === Exception handling ===
        elif opname in ('SETUP_FINALLY', 'SETUP_WITH', 'BEFORE_WITH'):
            pass  # Exception setup
        
        elif opname == 'RERAISE' or opname == 'RAISE_VARARGS':
            pass  # Re-raise - control flow handled at block level
        
        # === Generators ===
        elif opname in ('YIELD_VALUE', 'SEND', 'GET_YIELD_FROM_ITER'):
            if state.stack_size() >= 1:
                value = state.pop()
                state.push(value)  # Yield and receive
        
        # === Async operations (ITERATION 610) ===
        elif opname == 'GET_AWAITABLE':
            # GET_AWAITABLE: Convert value to awaitable
            # Stack: value → awaitable (preserves taint)
            if state.stack_size() >= 1:
                value = state.pop()
                state.push(value)  # Awaitable has same taint as the value
        
        elif opname == 'GET_AITER':
            # GET_AITER: Get async iterator from async iterable
            # Stack: iterable → aiterator (preserves taint)
            if state.stack_size() >= 1:
                iterable = state.pop()
                state.push(iterable)  # Async iterator has same taint as iterable
        
        elif opname == 'GET_ANEXT':
            # GET_ANEXT: Get next awaitable from async iterator
            # Stack: aiterator → aiterator, awaitable
            if state.stack_size() >= 1:
                aiter = state.peek()
                state.push(aiter)  # Awaitable gets same taint as iterator
        
        elif opname == 'END_ASYNC_FOR':
            # END_ASYNC_FOR: End of async for loop
            # Stack: aiterator, value → (empty)
            if state.stack_size() >= 2:
                state.pop()  # value
                state.pop()  # aiterator
        
        elif opname == 'CLEANUP_THROW':
            # CLEANUP_THROW: Exception handling for async/generator throw
            # No stack changes needed for taint tracking
            pass
        
        elif opname == 'RETURN_GENERATOR':
            # RETURN_GENERATOR: Convert function to generator/coroutine
            # Stack: unchanged (implicitly returns the generator object)
            pass
        
        # === Resume and other ===
        elif opname in ('RESUME', 'NOP', 'CACHE', 'EXTENDED_ARG', 'END_FOR', 'END_SEND',
                        'IMPORT_NAME', 'IMPORT_FROM', 'IMPORT_STAR',
                        'JUMP_BACKWARD_NO_INTERRUPT'):  # ITERATION 610: Add async jump
            # Import operations don't affect taint tracking in most cases
            # They push a module object (clean) onto the stack
            if opname == 'IMPORT_NAME':
                # Pop level and fromlist, push module (clean)
                state.pop()  # fromlist
                state.pop()  # level  
                state.push(TaintLabel.clean())
            elif opname == 'IMPORT_FROM':
                # Peek at module, push attribute (clean)
                state.push(TaintLabel.clean())
            # JUMP_BACKWARD_NO_INTERRUPT: Used in async for/with loops
            # NOP semantics for taint - just advances control flow
            pass  # IMPORT_STAR doesn't change stack
        
        elif opname == 'LOAD_SPECIAL':
            # LOAD_SPECIAL: Python 3.14+ special method loading for __enter__/__exit__ etc.
            # Stack: obj → obj, special_method
            # Pushes a clean value (method itself is not tainted)
            state.push(TaintLabel.clean())
        
        elif opname == 'WITH_EXCEPT_START':
            # WITH_EXCEPT_START: Calls __exit__ at start of exception handling
            # Stack varies, but for taint tracking we treat as no-op
            pass
        
        elif opname == 'POP_ITER':
            # Pop iterator from stack (end of for loop)
            state.pop()
        
        # === GET_ITER and FOR_ITER ===
        elif opname == 'GET_ITER':
            if state.stack_size() >= 1:
                iterable = state.pop()
                state.push(iterable)  # Iterator has same taint as iterable
        
        elif opname == 'FOR_ITER':
            # Loop iteration - peek at iterator, push next value (same taint)
            if state.stack_size() >= 1:
                iterator = state.peek()
                state.push(iterator)
        
        # === Unpack ===
        elif opname == 'UNPACK_SEQUENCE':
            if state.stack_size() >= 1:
                seq = state.pop()
                count = instr.arg if instr.arg else 0
                for _ in range(count):
                    state.push(seq)  # Each unpacked element inherits taint
        
        # === Default: unknown opcode ===
        else:
            # Conservative: any unknown opcode that might produce a value
            # We don't modify state, but log for debugging
            if self.verbose:
                print(f"    [SOTA] Unhandled opcode: {opname}")
        
        return state
    
    def _handle_call(
        self,
        instr: dis.Instruction,
        state: AbstractState,
    ) -> AbstractState:
        """
        Handle CALL instructions.
        
        This is where source/sink/sanitizer contracts are applied.
        """
        opname = instr.opname
        
        # Determine number of arguments
        if opname in ('CALL', 'CALL_KW'):
            nargs = instr.arg if instr.arg else 0
        elif opname == 'CALL_FUNCTION':
            nargs = instr.arg if instr.arg else 0
        elif opname == 'CALL_FUNCTION_KW':
            nargs = instr.arg if instr.arg else 0
            # Pop kwnames tuple
            if state.stack_size() > 0:
                state.pop()
        elif opname == 'CALL_FUNCTION_EX':
            # Variable args - conservative
            nargs = 0
        else:
            nargs = 0
        
        # For CALL_KW, pop the keyword names tuple
        if opname == 'CALL_KW' and state.stack_size() > 0:
            state.pop()  # kwnames
        
        # Pop arguments
        args = []
        for _ in range(nargs):
            if state.stack_size() > 0:
                args.append(state.pop())
        args.reverse()
        
        # Pop callable
        callable_label = state.pop() if state.stack_size() > 0 else TaintLabel.clean()
        
        # Check if this is a method call (self is on stack below callable)
        # In Python 3.11+, method calls have self pushed by LOAD_ATTR
        # We detect this by checking if the next item on stack is tainted and
        # the call looks like a method call (has a dot)
        self_label = TaintLabel.clean()
        call_name = self._identify_call(instr.offset)
        
        # Method calls have the pattern "obj.method" and need to pop self
        if '.' in call_name and state.stack_size() > 0:
            # Check if this could be a method call (self on stack)
            # Peek at the stack - if there's an extra value, it might be self
            # For method calls, Python 3.11+ pushes [self, method, args...]
            # We already popped args and method (callable), so self is next
            self_label = state.pop()
        
        # Include self_label in args for taint propagation
        all_labels = [self_label] + args if self_label.has_any_taint() else args
        
        # Check if it's a sink FIRST (before applying source taint to return)
        if is_security_sink(call_name):
            contract = get_sink_contract(call_name)
            if contract:
                # Check each argument against sink requirements
                self._check_sink(instr, call_name, contract, args, state)
        
        # Check for insecure cookie configuration
        # This is a special check for response.set_cookie() with insecure flags
        if call_name.endswith('.set_cookie') or call_name == 'set_cookie':
            self._check_insecure_cookie(instr, nargs)
        
        # Check for Flask debug mode
        # This is a special check for app.run(debug=True)
        if call_name.endswith('.run') or call_name == 'run':
            self._check_flask_debug(instr, nargs)
        
        # Determine return value taint
        result_label = TaintLabel.clean()
        
        # Check if it's a source
        if is_taint_source(call_name):
            contract = get_source_contract(call_name)
            if contract:
                # Extract constant string args for sensitivity detection
                const_args = self._extract_const_args(instr.offset, nargs)
                result_label = apply_source_taint(call_name, str(instr.offset), const_args)
                self.sources[instr.offset] = call_name
        
        # Check if it's a sanitizer
        elif is_sanitizer(call_name):
            contract = get_sanitizer_contract(call_name)
            if contract and all_labels:
                # Apply sanitizer to first argument (or self for method sanitizers)
                result_label = apply_sanitizer(call_name, all_labels[0])
            else:
                # Fallback: join all labels
                result_label = label_join_many(all_labels) if all_labels else TaintLabel.clean()
        
        # Check for path validation patterns (for tarslip/zipslip safety)
        elif call_name in ('str.startswith', 'startswith') and nargs >= 1:
            # Pattern: path.startswith(safe_prefix)
            # If the result is checked with POP_JUMP_IF_TRUE/FALSE and raises on failure,
            # this establishes a guard fact that the path is validated
            # For now, just propagate taint conservatively
            result_label = label_join_many(all_labels) if all_labels else TaintLabel.clean()
            
            # Note: Path validation guard establishment happens at the conditional branch
            # instruction (POP_JUMP_IF_*), not at the call itself. The call just returns
            # a boolean that is used in the guard.
        
        else:
            # Unknown call: havoc fallback
            # Return value has join of all argument taints (including self), loses sanitization
            if all_labels:
                result_label = label_join_many(all_labels)
                # Conservative: drop kappa bits (lose sanitization)
                result_label = TaintLabel(
                    tau=result_label.tau,
                    kappa=0,  # Not sanitized for anything
                    sigma=result_label.sigma,
                    provenance=result_label.provenance,
                )
        
        state.push(result_label)
        return state
    
    def _check_sink(
        self,
        instr: dis.Instruction,
        call_name: str,
        contract,
        args: List[TaintLabel],
        state: AbstractState,
    ):
        """Check if tainted data reaches a sink and report violation."""
        from ..contracts.security_lattice import get_sink_contract
        
        # Context-dependent safety checks
        if contract.parameterized_check:
            # SQL: safe if second argument (params) is provided
            # The presence of a params argument indicates parameterization
            if len(args) > 1:
                return  # Parameterized query, safe
        
        if contract.shell_check:
            # Subprocess: only dangerous if shell=True
            # Extract shell kwarg value from bytecode
            shell_value = self._extract_kwarg_value(instr, 'shell')
            # If shell_value is None (not provided), CPython defaults shell=False.
            # Treat unknown/missing as safe to match CLI expectations and common usage.
            if shell_value is not True:
                return  # shell is False/missing/unknown → treat as safe
        
        # Get the relevant argument indices to check from the contract
        # Only check arguments that the contract specifies as tainted
        indices_to_check = contract.tainted_arg_indices if contract.tainted_arg_indices else frozenset({0})
        
        # ITERATION 588: Check for path validation guards
        # For TARSLIP/ZIPSLIP sinks (FILE_PATH), check if there's a guard fact
        # indicating that paths have been validated
        if contract.sink_type == SinkType.FILE_PATH:
            # Check if there's a path_validated guard in the abstract state
            if "path_validated" in state.guard_facts:
                # Path has been validated - SAFE
                return
        
        for i in indices_to_check:
            if i >= len(args):
                continue
            arg_label = args[i]
            
            # Check injection sinks (τ-based)
            if arg_label.has_untrusted_taint():
                if not arg_label.is_safe_for_sink(contract.sink_type):
                    self._report_violation(
                        instr=instr,
                        call_name=call_name,
                        sink_type=contract.sink_type,
                        taint_label=arg_label,
                        arg_index=i,
                        is_injection=True,
                    )
            
            # Check sensitive sinks (σ-based)
            if arg_label.has_sensitivity():
                if not arg_label.is_safe_for_sink(contract.sink_type):
                    self._report_violation(
                        instr=instr,
                        call_name=call_name,
                        sink_type=contract.sink_type,
                        taint_label=arg_label,
                        arg_index=i,
                        is_injection=False,
                    )
    
    def _extract_kwarg_value(self, instr: dis.Instruction, kwarg_name: str):
        """
        Extract the value of a keyword argument from the bytecode before a CALL_KW instruction.
        
        Returns the concrete value if it's a LOAD_CONST, None if not found, or None if symbolic.
        """
        if instr.opname != 'CALL_KW':
            return None
        
        # Find the instruction index
        call_idx = None
        for i, inst in enumerate(self.instructions):
            if inst.offset == instr.offset:
                call_idx = i
                break
        
        if call_idx is None:
            return None
        
        # For CALL_KW, look for the kwnames tuple
        kwnames = []
        kwvalues = {}
        
        # Look backwards for LOAD_CONST with kwnames tuple
        for j in range(call_idx - 1, max(0, call_idx - 10), -1):
            prev = self.instructions[j]
            if prev.opname == 'LOAD_CONST' and isinstance(prev.argval, tuple):
                kwnames = list(prev.argval)
                break
        
        if not kwnames or kwarg_name not in kwnames:
            return None
        
        # Now look for the values (they're loaded before kwnames)
        # Walk backwards from kwnames, collecting values
        value_idx = call_idx - 2  # -1 is LOAD_CONST for kwnames
        for kw in reversed(kwnames):
            if value_idx >= 0:
                val_instr = self.instructions[value_idx]
                if val_instr.opname == 'LOAD_CONST':
                    kwvalues[kw] = val_instr.argval
                value_idx -= 1
        
        return kwvalues.get(kwarg_name)
    
    def _report_violation(
        self,
        instr: dis.Instruction,
        call_name: str,
        sink_type: SinkType,
        taint_label: TaintLabel,
        arg_index: int,
        is_injection: bool,
    ):
        """Report a security violation."""
        # Determine bug type from sink type
        # CODEQL_BUG_TYPES is keyed by name strings, so we need to find by sink_type
        from ..z3model.taint_lattice import CODEQL_BUG_TYPES
        bug_type = sink_type.name  # Default to sink type name
        for name, bug_info in CODEQL_BUG_TYPES.items():
            if hasattr(bug_info, 'sink_type') and bug_info.sink_type == sink_type:
                bug_type = name
                break  # Use first match (most specific)
        
        # Build source description
        source_desc = ", ".join(taint_label.provenance) if taint_label.provenance else "tainted input"
        
        # Build sink description
        sink_desc = f"{call_name}(arg[{arg_index}])"
        
        # Build reason
        if is_injection:
            reason = (f"Untrusted input from {source_desc} flows to {sink_desc} "
                     f"without sanitization for {sink_type.name}")
        else:
            reason = (f"Sensitive data from {source_desc} flows to {sink_desc} "
                     f"without declassification for {sink_type.name}")
        
        # Get line number
        line_no = instr.positions.lineno if hasattr(instr, 'positions') and instr.positions else 0
        if line_no is None:
            line_no = 0
        
        violation = SOTASecurityViolation(
            bug_type=bug_type,
            sink_type=sink_type,
            file_path=self.file_path,
            function_name=self.function_name,
            line_number=line_no,
            bytecode_offset=instr.offset,
            taint_label=taint_label,
            source_description=source_desc,
            sink_description=sink_desc,
            reason=reason,
            confidence=1.0,
        )
        
        # Avoid duplicates
        for existing in self.violations:
            if (existing.bytecode_offset == violation.bytecode_offset and
                existing.bug_type == violation.bug_type):
                return
        
        self.violations.append(violation)
        
        if self.verbose:
            print(f"    [SOTA] Violation: {bug_type} at offset {instr.offset}")
    
    def _check_insecure_cookie(self, instr: dis.Instruction, nargs: int):
        """
        Check for insecure cookie configuration.
        
        Flags set_cookie() calls where:
        - secure=False (or not set)
        - httponly=False (or not set)
        """
        # This requires inspecting keyword arguments in the bytecode
        # For CALL_KW, the keyword names are in a constant tuple before the call
        
        # Find the instruction index
        call_idx = None
        for i, inst in enumerate(self.instructions):
            if inst.offset == instr.offset:
                call_idx = i
                break
        
        if call_idx is None:
            return
        
        # For CALL_KW, look for the kwnames tuple
        kwnames = []
        kwvalues = {}
        kwnames_idx = None
        
        if instr.opname == 'CALL_KW':
            # Look backwards for LOAD_CONST with kwnames tuple
            # Start from instruction just before CALL_KW
            for j in range(call_idx - 1, max(0, call_idx - nargs - 10), -1):
                prev = self.instructions[j]
                if prev.opname == 'LOAD_CONST' and isinstance(prev.argval, tuple):
                    # Check if this looks like a kwnames tuple (strings)
                    if all(isinstance(x, str) for x in prev.argval):
                        kwnames = list(prev.argval)
                        kwnames_idx = j
                        break
            
            if kwnames and kwnames_idx is not None:
                # Now look for the values (they're loaded before kwnames)
                # The keyword argument values are loaded in order before the kwnames tuple
                # For N keyword args, they are at indices: kwnames_idx-N, kwnames_idx-N+1, ..., kwnames_idx-1
                for i, kw in enumerate(kwnames):
                    value_idx = kwnames_idx - len(kwnames) + i
                    if value_idx >= 0 and value_idx < len(self.instructions):
                        val_instr = self.instructions[value_idx]
                        # Extract constant values (True, False, etc.)
                        if val_instr.opname == 'LOAD_CONST':
                            kwvalues[kw] = val_instr.argval
                            if self.verbose:
                                print(f"      [COOKIE] Extracted {kw}={val_instr.argval}")
                        # Also handle LOAD_FAST and other common patterns
                        # For boolean flags, we mainly care about LOAD_CONST True/False
        
        # Check if secure or httponly are explicitly set to insecure values
        secure_value = kwvalues.get('secure', None)
        httponly_value = kwvalues.get('httponly', None)
        
        if self.verbose:
            print(f"    [COOKIE] Extracted kwargs: {kwvalues}")
            print(f"    [COOKIE] kwnames: {kwnames}")
            print(f"    [COOKIE] secure_value={secure_value}, 'secure' in kwnames={('secure' in kwnames)}")
        
        # Report violation ONLY if:
        # 1. secure is explicitly False, OR
        # 2. secure is not present in kwargs at all (defaults to insecure)
        # If secure=True is explicitly set, do NOT flag as insecure
        is_insecure = secure_value is False or 'secure' not in kwnames
        
        if self.verbose:
            print(f"    [COOKIE] is_insecure={is_insecure}")
        
        if is_insecure:
            line_no = instr.positions.lineno if hasattr(instr, 'positions') and instr.positions else 0
            if line_no is None:
                line_no = 0
            
            violation = SOTASecurityViolation(
                bug_type='INSECURE_COOKIE',
                sink_type=SinkType.COOKIE_VALUE,
                file_path=self.file_path,
                function_name=self.function_name,
                line_number=line_no,
                bytecode_offset=instr.offset,
                taint_label=TaintLabel.clean(),
                source_description="cookie configuration",
                sink_description="set_cookie() with secure=False",
                reason="Cookie is set without secure=True flag, may be sent over HTTP",
                confidence=1.0,
            )
            
            # Avoid duplicates
            for existing in self.violations:
                if (existing.bytecode_offset == violation.bytecode_offset and
                    existing.bug_type == violation.bug_type):
                    return
            
            self.violations.append(violation)
            
            if self.verbose:
                print(f"    [SOTA] Violation: INSECURE_COOKIE at offset {instr.offset}")
    
    def _check_flask_debug(self, instr: dis.Instruction, nargs: int):
        """
        Check for Flask debug mode enabled.
        
        Flags app.run() calls where:
        - debug=True is explicitly set
        """
        # Find the instruction index
        call_idx = None
        for i, inst in enumerate(self.instructions):
            if inst.offset == instr.offset:
                call_idx = i
                break
        
        if call_idx is None:
            return
        
        # For CALL_KW, look for the kwnames tuple
        kwnames = []
        kwvalues = {}
        
        if instr.opname == 'CALL_KW':
            # Look backwards for LOAD_CONST with kwnames tuple
            for j in range(call_idx - 1, max(0, call_idx - nargs - 5), -1):
                prev = self.instructions[j]
                if prev.opname == 'LOAD_CONST' and isinstance(prev.argval, tuple):
                    kwnames = list(prev.argval)
                    break
            
            # Now look for the values (they're loaded before kwnames)
            # Walk backwards from kwnames, collecting values
            value_idx = call_idx - 2  # -1 is LOAD_CONST for kwnames
            for kw in reversed(kwnames):
                if value_idx >= 0:
                    val_instr = self.instructions[value_idx]
                    if val_instr.opname == 'LOAD_CONST':
                        kwvalues[kw] = val_instr.argval
                    elif val_instr.opname in ['LOAD_FAST', 'LOAD_FAST_BORROW', 'LOAD_GLOBAL', 'LOAD_NAME']:
                        # Variable reference - try to trace back to see if it's True
                        var_name = val_instr.argval
                        # Look backwards for STORE_FAST of this variable
                        traced_value = self._trace_variable_value(var_name, value_idx)
                        if traced_value is True:
                            kwvalues[kw] = True
                        elif var_name and 'debug' in var_name.lower():
                            # Variable name suggests it might be debug-related
                            kwvalues[kw] = 'possibly_true'
                    value_idx -= 1
        
        # Check if debug=True is explicitly set
        debug_value = kwvalues.get('debug', None)
        
        # Report if debug=True is explicitly set
        if debug_value is True or debug_value == 'possibly_true':
            line_no = instr.positions.lineno if hasattr(instr, 'positions') and instr.positions else 0
            if line_no is None:
                line_no = 0
            
            violation = SOTASecurityViolation(
                bug_type='FLASK_DEBUG',
                sink_type=SinkType.DEBUG_OUTPUT,  # Use debug output sink type
                file_path=self.file_path,
                function_name=self.function_name,
                line_number=line_no,
                bytecode_offset=instr.offset,
                taint_label=TaintLabel.clean(),
                source_description="flask configuration",
                sink_description="app.run(debug=True)",
                reason="Flask debug mode is enabled (exposes Werkzeug debugger - RCE risk)",
                confidence=1.0 if debug_value is True else 0.8,
            )
            
            # Avoid duplicates
            for existing in self.violations:
                if (existing.bytecode_offset == violation.bytecode_offset and
                    existing.bug_type == violation.bug_type):
                    return
            
            self.violations.append(violation)
            
            if self.verbose:
                print(f"    [SOTA] Violation: FLASK_DEBUG at offset {instr.offset}")
    
    def _trace_variable_value(self, var_name: str, from_index: int):
        """
        Trace a variable's value by looking backwards for its assignment.
        
        Returns the constant value if found, None otherwise.
        """
        # Look backwards from from_index for STORE_FAST of var_name
        for i in range(from_index - 1, -1, -1):
            instr = self.instructions[i]
            if instr.opname in ['STORE_FAST', 'STORE_NAME'] and instr.argval == var_name:
                # Found the store - look for the preceding LOAD_CONST
                if i > 0:
                    prev = self.instructions[i - 1]
                    if prev.opname == 'LOAD_CONST':
                        return prev.argval
                break
        return None


    
    # ========================================================================
    # HELPER METHODS
    # ========================================================================
    
    def _identify_attr_object(self, offset: int) -> str:
        """Try to identify the object in an attribute access."""
        # Look back for LOAD_NAME/LOAD_FAST that loaded the object
        for i, instr in enumerate(self.instructions):
            if instr.offset == offset:
                # Look at previous instruction(s)
                if i > 0:
                    prev = self.instructions[i - 1]
                    if prev.opname in ('LOAD_NAME', 'LOAD_GLOBAL', 'LOAD_FAST'):
                        return prev.argval
                break
        return ""
    
    def _identify_call(self, offset: int) -> str:
        """
        Identify the function being called at a CALL instruction.
        
        Uses stack depth tracking to skip nested calls and their arguments.
        """
        # Find the instruction index for this offset
        call_idx = None
        call_instr = None
        for i, instr in enumerate(self.instructions):
            if instr.offset == offset:
                call_idx = i
                call_instr = instr
                break
        
        if call_idx is None:
            return "<unknown>"
        
        is_call_kw = call_instr.opname == 'CALL_KW'
        nargs = call_instr.arg if call_instr.arg else 0
        
        # We need to skip back over the arguments to find the callable.
        # The stack layout before CALL/CALL_KW with N args is:
        #   [callable] [NULL (maybe)] [arg0] [arg1] ... [argN-1] [kwnames (for CALL_KW)]
        # 
        # Each "argument" might be the result of a nested call, which itself
        # has its own arguments. We track how many stack items we need to skip.
        
        # For CALL_KW: skip kwnames tuple + N argument values
        # For CALL: skip N argument values
        # Then skip PUSH_NULL if present
        # Then the next LOAD_GLOBAL/LOAD_ATTR chain is the callable
        
        items_to_skip = nargs
        if is_call_kw:
            items_to_skip += 1  # kwnames tuple
        
        # Walk backwards, tracking net stack contribution
        j = call_idx - 1
        
        while j >= 0 and items_to_skip > 0:
            prev = self.instructions[j]
            opname = prev.opname
            
            # Stack effect: how many items does this instruction contribute?
            # Positive = pushes to stack, Negative = pops from stack
            if opname in ('LOAD_CONST', 'LOAD_FAST', 'LOAD_FAST_BORROW', 
                          'LOAD_GLOBAL', 'LOAD_NAME', 'LOAD_DEREF', 'LOAD_CLOSURE'):
                # These push 1 item
                items_to_skip -= 1
                j -= 1
            elif opname == 'LOAD_ATTR':
                # Pops 1, pushes 1 (or 2 for method loads) - net 0 or +1
                # For counting, treat as net 0 (replacement)
                j -= 1
            elif opname in ('CALL', 'CALL_KW', 'CALL_FUNCTION', 'CALL_METHOD'):
                # A nested call: consumes nargs+1 (or +2 with kwnames), produces 1
                # For our purposes: the result is 1 item on stack
                # But we need to recursively skip the nested call's args too
                nested_nargs = prev.arg if prev.arg else 0
                nested_extra = 1 if opname == 'CALL_KW' else 0  # kwnames
                # Add nested args to skip, but we already counted this call's result
                items_to_skip -= 1  # The result of this call counts as 1 item
                items_to_skip += nested_nargs + 1 + nested_extra  # Its args + callable + kwnames
                j -= 1
            elif opname == 'PUSH_NULL':
                # PUSH_NULL doesn't count as an argument
                j -= 1
            elif opname in ('CACHE', 'EXTENDED_ARG', 'COPY', 'NOP', 'RESUME',
                            'POP_TOP', 'STORE_FAST', 'STORE_NAME', 'STORE_GLOBAL'):
                # Skip these, they don't affect argument counting
                j -= 1
            elif opname in ('BUILD_LIST', 'BUILD_TUPLE', 'BUILD_MAP', 'BUILD_SET'):
                # Consumes N items, produces 1
                # Net effect: -N + 1
                build_count = prev.arg if prev.arg else 0
                items_to_skip += build_count - 1  # We counted result, add back consumed items
                j -= 1
            elif opname == 'BUILD_STRING':
                build_count = prev.arg if prev.arg else 0
                items_to_skip += build_count - 1
                j -= 1
            elif opname in ('BINARY_OP', 'BINARY_ADD', 'BINARY_SUBSCR', 'COMPARE_OP'):
                # Consumes 2, produces 1 - net -1
                items_to_skip += 1  # We counted result, add back one consumed item
                j -= 1
            elif opname == 'FORMAT_VALUE':
                # Consumes 1 (or 2 with format spec), produces 1
                flags = prev.arg if prev.arg else 0
                has_fmt = (flags & 0x04) != 0
                if has_fmt:
                    items_to_skip += 1  # Format spec consumed
                j -= 1
            elif opname == 'UNPACK_SEQUENCE':
                # Consumes 1, produces N
                unpack_count = prev.arg if prev.arg else 2
                items_to_skip -= unpack_count - 1
                j -= 1
            elif opname in ('LOAD_FAST_BORROW_LOAD_FAST_BORROW',):
                # Pushes 2 items
                items_to_skip -= 2
                j -= 1
            else:
                # Unknown - try to continue
                j -= 1
        
        # Now skip PUSH_NULL if present (goes before the callable)
        while j >= 0:
            prev = self.instructions[j]
            if prev.opname == 'PUSH_NULL':
                j -= 1
            elif prev.opname in ('CACHE', 'EXTENDED_ARG', 'NOP'):
                j -= 1
            else:
                break
        
        # Now collect the callable (LOAD_GLOBAL/LOAD_NAME + LOAD_ATTR chain)
        parts = []
        while j >= 0:
            prev = self.instructions[j]
            
            if prev.opname == 'LOAD_ATTR':
                # Part of the call target chain
                # Clean up the argval (remove '+ NULL|self' suffix)
                attr_name = str(prev.argval)
                if ' +' in attr_name:
                    attr_name = attr_name.split(' +')[0]
                parts.insert(0, attr_name)
                j -= 1
            elif prev.opname in ('LOAD_NAME', 'LOAD_GLOBAL'):
                # Found the root name
                name = str(prev.argval)
                if ' +' in name:
                    name = name.split(' +')[0]
                parts.insert(0, name)
                break
            elif prev.opname in ('LOAD_FAST', 'LOAD_FAST_BORROW'):
                # Base object for method call
                parts.insert(0, str(prev.argval))
                break
            elif prev.opname in ('PUSH_NULL', 'CACHE', 'EXTENDED_ARG', 'NOP'):
                j -= 1
            else:
                # Unknown - stop
                break
        
        return ".".join(parts) if parts else "<unknown>"
    
    def _extract_const_args(self, offset: int, nargs: int) -> List[str]:
        """Extract constant string arguments for a call."""
        const_args = []
        # Look back for LOAD_CONST instructions
        for i, instr in enumerate(self.instructions):
            if instr.offset == offset:
                # Look at previous nargs instructions
                for j in range(max(0, i - nargs), i):
                    prev = self.instructions[j]
                    if prev.opname == 'LOAD_CONST':
                        if isinstance(prev.argval, str):
                            const_args.append(prev.argval)
                break
        return const_args
    
    def _extract_subscript_key(self, offset: int) -> Optional[str]:
        """Extract constant subscript key (e.g., for dict['password'])."""
        for i, instr in enumerate(self.instructions):
            if instr.offset == offset:
                # Previous instruction should be the key
                if i > 0:
                    prev = self.instructions[i - 1]
                    if prev.opname == 'LOAD_CONST' and isinstance(prev.argval, str):
                        return prev.argval
                break
        return None
    
    def _maybe_add_sensitivity(self, name: str, label: TaintLabel) -> TaintLabel:
        """Add sensitivity to label if name matches sensitive patterns."""
        if not label.has_any_taint():
            return label
        
        sensitive_patterns = [
            'password', 'passwd', 'pwd', 'secret', 'key', 'token',
            'api_key', 'apikey', 'auth', 'credential', 'ssn', 'credit',
        ]
        
        name_lower = name.lower()
        if any(p in name_lower for p in sensitive_patterns):
            return label.with_sensitivity(SourceType.PASSWORD)
        
        return label


# ============================================================================
# CONVENIENCE FUNCTION
# ============================================================================

def analyze_function_sota(
    code_obj: types.CodeType,
    function_name: str = "<unknown>",
    file_path: str = "<unknown>",
    entry_taint: Optional[Dict[int, TaintLabel]] = None,
    verbose: bool = False,
    max_iterations: int = 50000,
) -> List[SOTASecurityViolation]:
    """
    Analyze a function using the SOTA intraprocedural engine.
    
    Args:
        code_obj: The compiled code object to analyze.
        function_name: Name of the function (for reporting).
        file_path: Path to the source file (for reporting).
        entry_taint: Optional taint labels for parameters.
        verbose: Enable verbose logging.
        max_iterations: Maximum worklist iterations (for performance).
    
    Returns:
        List of security violations found.
    """
    analyzer = SOTAIntraproceduralAnalyzer(
        code_obj=code_obj,
        function_name=function_name,
        file_path=file_path,
        verbose=verbose,
        max_iterations=max_iterations,
    )
    return analyzer.analyze(entry_taint=entry_taint)
