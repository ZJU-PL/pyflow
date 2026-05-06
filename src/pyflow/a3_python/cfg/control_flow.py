"""
Control Flow Graph for Python bytecode, including exceptional edges.

Implements the CFG extraction described in barrier-certificate-theory.tex §6.3:
- Normal edges: JUMP, JUMP_IF_*, fallthrough, RETURN_VALUE
- Exceptional edges: any instruction that may raise can transfer to a handler

The CFG provides:
1. Basic block structure
2. Dominance analysis for guard inference
3. Exception handler regions (for WillCatchAt predicates)
4. Loop detection for ranking function synthesis
"""

from dataclasses import dataclass, field
from typing import Dict, List, Set, Optional, Tuple
import dis
import types
from enum import Enum, auto


class EdgeType(Enum):
    """Type of CFG edge."""
    FALLTHROUGH = auto()      # Normal sequential execution
    JUMP = auto()             # Unconditional jump
    COND_TRUE = auto()        # Conditional branch (true case)
    COND_FALSE = auto()       # Conditional branch (false case)
    EXCEPTION = auto()        # Exception raised → handler
    RETURN = auto()           # Function return
    YIELD = auto()            # Generator yield
    RAISE = auto()            # Explicit raise (to exception handler or exit)


@dataclass
class BasicBlock:
    """
    A basic block in the CFG.
    
    Single entry, single exit under normal control flow.
    May have multiple exception edges.
    """
    id: int
    start_offset: int
    end_offset: int  # Exclusive
    instructions: List[dis.Instruction]
    
    # Successor edges: (target_block_id, edge_type, guard_condition)
    # guard_condition is the condition that must hold for this edge (for COND_TRUE/COND_FALSE)
    successors: List[Tuple[int, EdgeType, Optional[str]]] = field(default_factory=list)
    
    # Predecessor block IDs
    predecessors: List[int] = field(default_factory=list)
    
    # Exception handler target (if any instruction in this block can raise)
    exception_handler: Optional[int] = None
    
    # Variables loaded/stored in this block
    loads: Set[str] = field(default_factory=set)
    stores: Set[str] = field(default_factory=set)
    
    # Guard checks performed in this block
    # Each entry: (var_name, guard_type, check_offset)
    guard_checks: List[Tuple[str, str, int]] = field(default_factory=list)
    
    @property
    def is_entry(self) -> bool:
        """Is this the entry block?"""
        return self.start_offset == 0
    
    @property
    def is_exit(self) -> bool:
        """Is this an exit block (returns or raises unhandled)?"""
        if not self.instructions:
            return False
        last_instr = self.instructions[-1]
        return last_instr.opname in ('RETURN_VALUE', 'RETURN_CONST')
    
    @property
    def may_raise(self) -> bool:
        """Does this block contain any instruction that may raise?"""
        # Most operations in Python can potentially raise
        # We're conservative: only RESUME, NOP, and some other pure ops are safe
        safe_ops = {'RESUME', 'NOP', 'CACHE', 'POP_TOP', 'COPY', 'SWAP', 
                    'EXTENDED_ARG', 'PUSH_NULL', 'END_FOR', 'END_SEND'}
        for instr in self.instructions:
            if instr.opname not in safe_ops:
                return True
        return False


@dataclass  
class ExceptionRegion:
    """
    An exception handler region in the bytecode.
    
    Corresponds to a try/except/finally block.
    """
    start_offset: int        # First instruction covered
    end_offset: int          # Last instruction covered (exclusive)
    handler_offset: int      # Handler entry point
    depth: int               # Nesting depth
    exception_types: List[str] = field(default_factory=list)  # Types caught (empty = catch-all)
    
    def contains_offset(self, offset: int) -> bool:
        """Check if an instruction offset is within this region."""
        return self.start_offset <= offset < self.end_offset


@dataclass
class ControlFlowGraph:
    """
    Complete CFG for a Python function/module.
    
    Provides:
    - Basic block structure
    - Dominance tree
    - Exception handler regions
    - Loop headers and back edges
    """
    code: types.CodeType
    blocks: Dict[int, BasicBlock]  # block_id -> BasicBlock
    entry_block: int
    exit_blocks: List[int]
    
    # Exception regions from exception table
    exception_regions: List[ExceptionRegion] = field(default_factory=list)
    
    # Dominance info (populated by compute_dominance)
    dominators: Dict[int, Set[int]] = field(default_factory=dict)  # block -> set of dominators
    immediate_dominator: Dict[int, int] = field(default_factory=dict)  # block -> idom
    
    # Post-dominance info (for control dependence)
    post_dominators: Dict[int, Set[int]] = field(default_factory=dict)
    
    # Loop info
    loop_headers: Set[int] = field(default_factory=set)  # block IDs that are loop headers
    back_edges: List[Tuple[int, int]] = field(default_factory=list)  # (from_block, to_block)
    
    # Offset to block mapping
    offset_to_block: Dict[int, int] = field(default_factory=dict)  # instruction offset -> block_id
    
    def get_block_for_offset(self, offset: int) -> Optional[BasicBlock]:
        """Get the basic block containing a given instruction offset."""
        block_id = self.offset_to_block.get(offset)
        if block_id is not None:
            return self.blocks.get(block_id)
        return None
    
    def get_exception_handler(self, offset: int) -> Optional[ExceptionRegion]:
        """Get the innermost exception handler covering an offset."""
        best = None
        for region in self.exception_regions:
            if region.contains_offset(offset):
                if best is None or region.depth > best.depth:
                    best = region
        return best
    
    def is_dominated_by(self, block: int, dominator: int) -> bool:
        """Check if 'dominator' dominates 'block'."""
        return dominator in self.dominators.get(block, set())
    
    def dominates_all_paths_to(self, check_block: int, use_block: int) -> bool:
        """
        Check if check_block dominates all paths to use_block.
        
        This is used for guard inference: if a type/None check in check_block
        dominates use_block, then the guard is established at use_block.
        """
        return self.is_dominated_by(use_block, check_block)


def build_cfg(code: types.CodeType) -> ControlFlowGraph:
    """
    Build a control flow graph from a code object.
    
    Algorithm:
    1. Parse exception table to identify protected regions
    2. Find basic block boundaries (leaders)
    3. Build blocks and edges
    4. Compute dominance
    5. Detect loops
    
    Returns:
        Complete CFG with all analysis results
    """
    instructions = list(dis.get_instructions(code))
    if not instructions:
        # Empty code object
        empty_block = BasicBlock(0, 0, 0, [])
        return ControlFlowGraph(
            code=code,
            blocks={0: empty_block},
            entry_block=0,
            exit_blocks=[0]
        )
    
    # Step 1: Parse exception table
    exception_regions = _parse_exception_regions(code)
    
    # Step 2: Find block leaders
    leaders = _find_leaders(instructions, exception_regions)
    
    # Step 3: Build basic blocks
    blocks, offset_to_block = _build_blocks(instructions, leaders)
    
    # Step 4: Connect edges
    _connect_edges(blocks, offset_to_block, exception_regions)
    
    # Step 5: Analyze variable accesses
    _analyze_variables(blocks)
    
    # Create CFG
    entry_block = 0  # First block is always entry
    exit_blocks = [bid for bid, blk in blocks.items() if blk.is_exit]
    
    cfg = ControlFlowGraph(
        code=code,
        blocks=blocks,
        entry_block=entry_block,
        exit_blocks=exit_blocks,
        exception_regions=exception_regions,
        offset_to_block=offset_to_block
    )
    
    # Step 6: Compute dominance
    _compute_dominance(cfg)
    
    # Step 7: Detect loops
    _detect_loops(cfg)
    
    return cfg


def _parse_exception_regions(code: types.CodeType) -> List[ExceptionRegion]:
    """Parse Python 3.11+ exception table into ExceptionRegion objects."""
    regions = []
    
    import sys
    if sys.version_info >= (3, 11):
        try:
            from dis import _parse_exception_table
            for start, end, target, depth, lasti in _parse_exception_table(code):
                region = ExceptionRegion(
                    start_offset=start,
                    end_offset=end,
                    handler_offset=target,
                    depth=depth
                )
                regions.append(region)
        except Exception:
            pass
    
    return regions


def _find_leaders(
    instructions: List[dis.Instruction],
    exception_regions: List[ExceptionRegion]
) -> Set[int]:
    """
    Find basic block leaders (first instruction of each block).
    
    A leader is:
    - First instruction of the function
    - Target of any jump
    - Instruction following a jump/branch
    - Handler entry point
    """
    leaders = {0}  # First instruction is always a leader
    
    # Add exception handler targets as leaders
    for region in exception_regions:
        leaders.add(region.handler_offset)
    
    for i, instr in enumerate(instructions):
        # Check for jump instructions
        if instr.opname in (
            'JUMP_FORWARD',
            'JUMP_BACKWARD',
            'JUMP_BACKWARD_NO_INTERRUPT',
            'JUMP',
            'POP_JUMP_IF_TRUE',
            'POP_JUMP_IF_FALSE',
            'POP_JUMP_IF_NONE',
            'POP_JUMP_IF_NOT_NONE',
            'POP_JUMP_FORWARD_IF_TRUE',
            'POP_JUMP_FORWARD_IF_FALSE',
            'POP_JUMP_FORWARD_IF_NONE',
            'POP_JUMP_FORWARD_IF_NOT_NONE',
            'POP_JUMP_BACKWARD_IF_TRUE',
            'POP_JUMP_BACKWARD_IF_FALSE',
            'POP_JUMP_BACKWARD_IF_NONE',
            'POP_JUMP_BACKWARD_IF_NOT_NONE',
            'FOR_ITER',
            'SEND',
        ):
            # Jump target is a leader
            if instr.argval is not None:
                leaders.add(instr.argval)
            # Instruction after jump is a leader (for conditional jumps)
            if i + 1 < len(instructions):
                leaders.add(instructions[i + 1].offset)
        
        # Return/raise end a block
        if instr.opname in ('RETURN_VALUE', 'RETURN_CONST', 'RAISE_VARARGS', 'RERAISE'):
            if i + 1 < len(instructions):
                leaders.add(instructions[i + 1].offset)
    
    return leaders


def _build_blocks(
    instructions: List[dis.Instruction],
    leaders: Set[int]
) -> Tuple[Dict[int, BasicBlock], Dict[int, int]]:
    """Build basic blocks from instructions and leaders."""
    blocks = {}
    offset_to_block = {}
    
    sorted_leaders = sorted(leaders)
    
    for i, leader_offset in enumerate(sorted_leaders):
        # Find end of this block
        if i + 1 < len(sorted_leaders):
            end_offset = sorted_leaders[i + 1]
        else:
            # Last block extends to end
            end_offset = instructions[-1].offset + 2
        
        # Collect instructions in this block
        block_instrs = [
            instr for instr in instructions
            if leader_offset <= instr.offset < end_offset
        ]
        
        block = BasicBlock(
            id=i,
            start_offset=leader_offset,
            end_offset=end_offset,
            instructions=block_instrs
        )
        blocks[i] = block
        
        # Map offsets to block
        for instr in block_instrs:
            offset_to_block[instr.offset] = i
    
    return blocks, offset_to_block


def _connect_edges(
    blocks: Dict[int, BasicBlock],
    offset_to_block: Dict[int, int],
    exception_regions: List[ExceptionRegion]
):
    """Connect blocks with normal and exceptional edges."""
    
    for block in blocks.values():
        if not block.instructions:
            continue
        
        last_instr = block.instructions[-1]
        
        # Determine successor edges based on last instruction
        if last_instr.opname in ('RETURN_VALUE', 'RETURN_CONST'):
            # No successors (exit block)
            pass
        
        elif last_instr.opname in ('JUMP_FORWARD', 'JUMP_BACKWARD', 'JUMP_BACKWARD_NO_INTERRUPT', 'JUMP'):
            # Unconditional jump
            target = last_instr.argval
            if target in offset_to_block:
                target_block = offset_to_block[target]
                block.successors.append((target_block, EdgeType.JUMP, None))
                blocks[target_block].predecessors.append(block.id)
        
        elif last_instr.opname.startswith('POP_JUMP'):
            # Conditional jump
            target = last_instr.argval
            if target in offset_to_block:
                target_block = offset_to_block[target]
                
                # Determine true/false based on opname
                if 'IF_TRUE' in last_instr.opname or 'IF_NOT_NONE' in last_instr.opname:
                    block.successors.append((target_block, EdgeType.COND_TRUE, None))
                else:
                    block.successors.append((target_block, EdgeType.COND_FALSE, None))
                blocks[target_block].predecessors.append(block.id)
            
            # Fallthrough edge
            fallthrough_offset = block.end_offset
            if fallthrough_offset in offset_to_block:
                ft_block = offset_to_block[fallthrough_offset]
                if 'IF_TRUE' in last_instr.opname or 'IF_NOT_NONE' in last_instr.opname:
                    block.successors.append((ft_block, EdgeType.COND_FALSE, None))
                else:
                    block.successors.append((ft_block, EdgeType.COND_TRUE, None))
                blocks[ft_block].predecessors.append(block.id)
        
        elif last_instr.opname == 'FOR_ITER':
            # For loop: jump target on exhaustion, fallthrough on next item
            target = last_instr.argval
            if target in offset_to_block:
                target_block = offset_to_block[target]
                block.successors.append((target_block, EdgeType.COND_FALSE, "iterator_exhausted"))
                blocks[target_block].predecessors.append(block.id)
            
            fallthrough_offset = block.end_offset
            if fallthrough_offset in offset_to_block:
                ft_block = offset_to_block[fallthrough_offset]
                block.successors.append((ft_block, EdgeType.COND_TRUE, "iterator_has_next"))
                blocks[ft_block].predecessors.append(block.id)
        
        elif last_instr.opname in ('RAISE_VARARGS', 'RERAISE'):
            # Explicit raise - handled by exception edges
            pass
        
        else:
            # Normal fallthrough
            fallthrough_offset = block.end_offset
            if fallthrough_offset in offset_to_block:
                ft_block = offset_to_block[fallthrough_offset]
                block.successors.append((ft_block, EdgeType.FALLTHROUGH, None))
                blocks[ft_block].predecessors.append(block.id)
        
        # Exception edges: find innermost handler for any raising instruction
        for instr in block.instructions:
            for region in exception_regions:
                if region.contains_offset(instr.offset):
                    handler_offset = region.handler_offset
                    if handler_offset in offset_to_block:
                        handler_block = offset_to_block[handler_offset]
                        # Add exception edge if not already present
                        exc_edge = (handler_block, EdgeType.EXCEPTION, None)
                        if exc_edge not in block.successors:
                            block.successors.append(exc_edge)
                            if block.id not in blocks[handler_block].predecessors:
                                blocks[handler_block].predecessors.append(block.id)
                        block.exception_handler = handler_block
                    break  # Only innermost handler matters


def _analyze_variables(blocks: Dict[int, BasicBlock]):
    """Analyze variable loads and stores in each block."""
    
    load_ops = {'LOAD_FAST', 'LOAD_NAME', 'LOAD_GLOBAL', 'LOAD_DEREF', 'LOAD_CLASSDEREF'}
    store_ops = {'STORE_FAST', 'STORE_NAME', 'STORE_GLOBAL', 'STORE_DEREF'}
    
    for block in blocks.values():
        for instr in block.instructions:
            if instr.opname in load_ops:
                if instr.argval and isinstance(instr.argval, str):
                    block.loads.add(instr.argval)
            elif instr.opname in store_ops:
                if instr.argval and isinstance(instr.argval, str):
                    block.stores.add(instr.argval)


def _compute_dominance(cfg: ControlFlowGraph):
    """
    Compute dominance tree using iterative dataflow.
    
    Algorithm: standard iterative dominance computation
    - dom[entry] = {entry}
    - dom[n] = {n} ∪ (∩ dom[p] for p in predecessors of n)
    """
    blocks = cfg.blocks
    entry = cfg.entry_block
    
    # Initialize: dom[entry] = {entry}, dom[n] = all blocks for n != entry
    all_blocks = set(blocks.keys())
    cfg.dominators = {}
    cfg.dominators[entry] = {entry}
    
    for bid in blocks:
        if bid != entry:
            cfg.dominators[bid] = all_blocks.copy()
    
    # Iterate until fixed point
    changed = True
    while changed:
        changed = False
        for bid in blocks:
            if bid == entry:
                continue
            
            block = blocks[bid]
            if not block.predecessors:
                continue
            
            # New dom set = intersection of predecessor doms, plus self
            pred_doms = [cfg.dominators[p] for p in block.predecessors if p in cfg.dominators]
            if pred_doms:
                new_dom = pred_doms[0].copy()
                for pd in pred_doms[1:]:
                    new_dom &= pd
                new_dom.add(bid)
                
                if new_dom != cfg.dominators[bid]:
                    cfg.dominators[bid] = new_dom
                    changed = True
    
    # Compute immediate dominators
    for bid in blocks:
        if bid == entry:
            continue
        
        doms = cfg.dominators.get(bid, set())
        strict_doms = doms - {bid}
        
        # idom is the unique dominator that doesn't dominate any other strict dominator
        for candidate in strict_doms:
            is_idom = True
            for other in strict_doms:
                if other != candidate and candidate in cfg.dominators.get(other, set()):
                    is_idom = False
                    break
            if is_idom:
                cfg.immediate_dominator[bid] = candidate
                break


def _detect_loops(cfg: ControlFlowGraph):
    """
    Detect loops by finding back edges and loop headers.
    
    A back edge is an edge n → h where h dominates n.
    The target h is a loop header.
    """
    for block in cfg.blocks.values():
        for succ_id, edge_type, _ in block.successors:
            # Check if this is a back edge
            if cfg.is_dominated_by(block.id, succ_id):
                cfg.back_edges.append((block.id, succ_id))
                cfg.loop_headers.add(succ_id)


# ============================================================================
# Guard Analysis
# ============================================================================

@dataclass
class GuardFact:
    """
    A guard fact established at a program point.
    
    Corresponds to guard variables in barrier-certificate-theory.tex §7:
    - g_nonnull(v): v is not None
    - g_type(v, T): isinstance(v, T)
    - g_bounds(seq, i): 0 <= i < len(seq)
    - g_div(d): d != 0
    - g_catch(E): exception E will be caught
    """
    guard_type: str  # "nonnull", "type", "bounds", "div", "catch"
    variable: str
    extra: Optional[str] = None  # type for g_type, exception class for g_catch
    established_at: int = 0  # block ID where guard was established
    condition: Optional[str] = None  # The condition that established this guard
    
    def __hash__(self):
        return hash((self.guard_type, self.variable, self.extra))
    
    def __eq__(self, other):
        if not isinstance(other, GuardFact):
            return False
        return (self.guard_type == other.guard_type and 
                self.variable == other.variable and
                self.extra == other.extra)


class GuardAnalyzer:
    """
    Analyze guard establishment and propagation.
    
    Uses dominance information to determine which guards are
    established at each program point.
    """
    
    def __init__(self, cfg: ControlFlowGraph):
        self.cfg = cfg
        # Maps block_id -> set of GuardFacts established by that block
        self.block_establishes: Dict[int, Set[GuardFact]] = {}
        # Maps block_id -> set of GuardFacts valid at entry to that block
        self.block_guards: Dict[int, Set[GuardFact]] = {}
        
    def analyze(self) -> Dict[int, Set[GuardFact]]:
        """
        Perform guard analysis.
        
        Returns mapping from block_id to guards valid at that block.
        """
        # Step 1: Identify guard-establishing patterns in each block
        self._find_guard_establishments()
        
        # Step 2: Propagate guards using dominance
        self._propagate_guards()
        
        return self.block_guards
    
    def _find_guard_establishments(self):
        """Find guard checks in each block."""
        
        for block in self.cfg.blocks.values():
            guards = set()
            
            for i, instr in enumerate(block.instructions):
                # Pattern: x = SomeClass() or x = func() - constructor/call result is typically non-None
                # CALL followed by STORE_FAST establishes nonnull for simple constructors
                if instr.opname == 'STORE_FAST' and i >= 1:
                    prev = block.instructions[i - 1]
                    if prev.opname in ('CALL', 'CALL_FUNCTION'):
                        var_name = instr.argval
                        if var_name:
                            # Check if this is likely a constructor call (heuristic: capitalized function name)
                            # Look back to find what was called
                            is_constructor = False
                            for j in range(i - 2, max(-1, i - 6), -1):
                                if j >= 0:
                                    load_instr = block.instructions[j]
                                    if load_instr.opname in ('LOAD_GLOBAL', 'LOAD_NAME', 'LOAD_ATTR'):
                                        func_name = load_instr.argval
                                        if func_name and isinstance(func_name, str):
                                            # Constructors are typically capitalized
                                            if func_name[0].isupper():
                                                is_constructor = True
                                            # Also handle known non-None returning builtins
                                            elif func_name in ('list', 'dict', 'set', 'tuple', 'str', 'int', 'float', 'bool', 'bytes', 'bytearray', 'frozenset', 'object', 'range', 'slice', 'type'):
                                                is_constructor = True
                                        break
                            if is_constructor:
                                guards.add(GuardFact(
                                    guard_type="nonnull",
                                    variable=var_name,
                                    established_at=block.id,
                                    condition=f"constructor assignment => {var_name} is not None"
                                ))
                
                # Pattern: isinstance(v, T) followed by conditional jump
                # LOAD_GLOBAL isinstance
                # LOAD_FAST v
                # LOAD_GLOBAL T
                # CALL 2
                # POP_JUMP_IF_FALSE/TRUE
                if instr.opname == 'CALL' and i >= 2:
                    # Look back for isinstance pattern
                    prev_instrs = block.instructions[max(0, i-4):i]
                    isinstance_guard = self._check_isinstance_pattern(prev_instrs, block)
                    if isinstance_guard:
                        guards.add(isinstance_guard)
                
                # Pattern: if v is not None / if v is None
                # LOAD_FAST v
                # LOAD_CONST None
                # IS_OP 0/1
                # POP_JUMP_IF_FALSE/TRUE
                if instr.opname == 'IS_OP' and i >= 2:
                    none_guard = self._check_none_pattern(block.instructions[:i+2], block)
                    if none_guard:
                        guards.add(none_guard)

                # Pattern (Python 3.14+ specialized): if v is not None / if v is None
                # LOAD_FAST(_BORROW) v
                # POP_JUMP_IF_NONE / POP_JUMP_IF_NOT_NONE
                if instr.opname in (
                    'POP_JUMP_IF_NONE',
                    'POP_JUMP_IF_NOT_NONE',
                    'POP_JUMP_FORWARD_IF_NONE',
                    'POP_JUMP_FORWARD_IF_NOT_NONE',
                ):
                    guard_var = None
                    if i >= 1 and block.instructions[i - 1].opname in ('LOAD_FAST', 'LOAD_FAST_BORROW', 'LOAD_NAME'):
                        guard_var = block.instructions[i - 1].argval
                    # Pattern: LOAD_FAST self → LOAD_ATTR X → POP_JUMP_IF_NONE
                    # Establishes nonnull guard for "self.X"
                    elif (i >= 2
                          and block.instructions[i - 1].opname == 'LOAD_ATTR'
                          and block.instructions[i - 2].opname in ('LOAD_FAST', 'LOAD_FAST_BORROW')
                          and block.instructions[i - 2].argval in ('self', 'cls')):
                        attr_name = block.instructions[i - 1].argval
                        if isinstance(attr_name, str):
                            guard_var = f"self.{attr_name}"
                    if guard_var:
                        # POP_JUMP_IF_NONE: fallthrough implies nonnull
                        # POP_JUMP_IF_NOT_NONE: jump-taken implies nonnull
                        cond = (
                            f"{guard_var} is not None"
                            if instr.opname.endswith('_IF_NONE')
                            else f"{guard_var} is not None (jump-taken)"
                        )
                        guards.add(
                            GuardFact(
                                guard_type="nonnull",
                                variable=guard_var,
                                established_at=block.id,
                                condition=cond,
                            )
                        )
                
                # Pattern: x = y or default (or-default pattern)
                # LOAD_FAST y, COPY, TO_BOOL, POP_JUMP_IF_TRUE, POP_TOP, LOAD_CONST default, STORE_FAST x
                # If default is truthy/non-None, x is nonnull
                # If default is non-zero, x is nonzero (for div safety)
                if instr.opname == 'STORE_FAST' and i >= 4:
                    or_guards = self._check_or_default_pattern(block.instructions[:i+1], block, instr)
                    for g in or_guards:
                        guards.add(g)
                
                # Pattern: if v (truthiness check)
                # LOAD_FAST v
                # POP_JUMP_IF_FALSE
                if instr.opname in ('POP_JUMP_IF_FALSE', 'POP_JUMP_FORWARD_IF_FALSE'):
                    if i >= 1 and block.instructions[i-1].opname in ('LOAD_FAST', 'LOAD_FAST_BORROW', 'LOAD_NAME'):
                        var_name = block.instructions[i-1].argval
                        if var_name:
                            # Truthiness check establishes nonnull on true branch
                            guard = GuardFact(
                                guard_type="nonnull",
                                variable=var_name,
                                established_at=block.id,
                                condition=f"truthiness check on {var_name}"
                            )
                            guards.add(guard)
                
                # Pattern: NOT_TAKEN after truthiness check establishes nonempty AND nonnull
                # This handles patterns like: not data or data[0]
                # When we're in the fallthrough block (NOT_TAKEN), we know the
                # condition was False, so for `not data`, data is truthy/nonempty
                if instr.opname == 'NOT_TAKEN' and i == 0:
                    truthiness_guard = self._check_truthiness_fallthrough_pattern(block)
                    if truthiness_guard:
                        guards.add(truthiness_guard)
                    
                    # Truthiness also implies nonnull (None is falsy)
                    nonnull_guard = self._check_truthiness_nonnull_guard(block)
                    if nonnull_guard:
                        guards.add(nonnull_guard)
                    
                    # Also check for len(x) != n pattern on fallthrough
                    len_ne_guard = self._check_len_ne_fallthrough_pattern(block)
                    if len_ne_guard:
                        guards.add(len_ne_guard)
                
                # Pattern: comparisons that establish x != 0 (for DIV_ZERO)
                # Includes: x != 0, x > 0, x >= 1, x < 0, x <= -1, etc.
                if instr.opname == 'COMPARE_OP' and instr.argval in ('!=', '<', '<=', '>', '>=') and i >= 2:
                    div_guard = self._check_div_guard_pattern(block.instructions[:i+1], block)
                    if div_guard:
                        guards.add(div_guard)
                    
                    # Also check for len(x) != 0 pattern (non-empty check)
                    nonempty_guard = self._check_nonempty_guard_pattern(block.instructions[:i+1], block)
                    if nonempty_guard:
                        guards.add(nonempty_guard)
                
                # Pattern: i < len(container) or len(container) > i  (bounds check)
                # This establishes bounds guard for container[i]
                if instr.opname == 'COMPARE_OP' and instr.argval in ('<', '<=', '>', '>=') and i >= 2:
                    bounds_guard = self._check_bounds_guard_pattern(block.instructions[:i+1], block)
                    if bounds_guard:
                        guards.add(bounds_guard)
                    
                    # Also check for len(x) > 0 pattern (non-empty check)
                    nonempty_guard = self._check_nonempty_guard_pattern(block.instructions[:i+1], block)
                    if nonempty_guard:
                        guards.add(nonempty_guard)
                
                # Pattern: len(x) == n for exact length check
                if instr.opname == 'COMPARE_OP' and instr.argval == '==' and i >= 2:
                    exact_len_guard = self._check_nonempty_guard_pattern(block.instructions[:i+1], block)
                    if exact_len_guard:
                        guards.add(exact_len_guard)
                
                # Pattern: x = d.get(key, default) where default is non-None
                # LOAD_FAST d, LOAD_ATTR get, LOAD_* key, LOAD_CONST default, CALL, STORE_FAST x
                if instr.opname == 'STORE_FAST' and i >= 3:
                    dict_get_guards = self._check_dict_get_pattern(block.instructions[:i+1], block, instr)
                    for g in dict_get_guards:
                        guards.add(g)
                
                # Pattern: assert x is not None
                # LOAD_FAST x, LOAD_CONST None, IS_OP 1, POP_JUMP_IF_TRUE, LOAD_ASSERTION_ERROR, RAISE
                if instr.opname == 'RAISE_VARARGS' and i >= 2:
                    assert_guard = self._check_assert_nonnull_pattern(block.instructions[:i+1], block)
                    if assert_guard:
                        guards.add(assert_guard)
                    
                    # Pattern: assert len(x) > 0 (non-empty assertion)
                    # LOAD_GLOBAL len, LOAD_FAST x, CALL, LOAD_CONST 0, COMPARE_OP >, POP_JUMP_IF_TRUE, ..., RAISE_VARARGS
                    assert_len_guard = self._check_assert_len_pattern(block.instructions[:i+1], block)
                    if assert_len_guard:
                        guards.add(assert_len_guard)
                    
                    # Pattern: assert KEY in dict (membership assertion)
                    # LOAD_FAST key, LOAD_FAST dict, CONTAINS_OP 0, POP_JUMP_IF_TRUE, ..., RAISE_VARARGS  
                    assert_contains_guard = self._check_assert_contains_pattern(block.instructions[:i+1], block)
                    if assert_contains_guard:
                        guards.add(assert_contains_guard)
                    
                    # Pattern: assert x != 0 (non-zero assertion)
                    assert_nonzero_guard = self._check_assert_nonzero_pattern(block.instructions[:i+1], block)
                    if assert_nonzero_guard:
                        guards.add(assert_nonzero_guard)
                
                # Pattern: a, b, c = iterable (unpacking establishes exact length)
                # UNPACK_SEQUENCE n followed by STORE_FAST * n
                if instr.opname == 'UNPACK_SEQUENCE':
                    unpack_guard = self._check_unpack_pattern(block.instructions[:i+1], block, instr)
                    if unpack_guard:
                        guards.add(unpack_guard)
                
                # Pattern: i = min(i, len(arr)-1) or i = max(0, i) (bounds clamping)
                if instr.opname == 'STORE_FAST' and i >= 3:
                    clamp_guards = self._check_minmax_clamp_pattern(block.instructions[:i+1], block, instr)
                    for g in clamp_guards:
                        guards.add(g)
                
                # Pattern: if hasattr(obj, 'attr'): obj.attr
                # LOAD_GLOBAL hasattr, LOAD_FAST obj, LOAD_CONST 'attr', CALL, POP_JUMP_IF_FALSE
                if instr.opname == 'CALL' and i >= 3:
                    hasattr_guard = self._check_hasattr_pattern(block.instructions[:i+1], block)
                    if hasattr_guard:
                        guards.add(hasattr_guard)
                
                # Pattern: if callable(x): x(...)
                # LOAD_GLOBAL callable, LOAD_FAST x, CALL, POP_JUMP_IF_FALSE
                if instr.opname == 'CALL' and i >= 2:
                    callable_guard = self._check_callable_pattern(block.instructions[:i+1], block)
                    if callable_guard:
                        guards.add(callable_guard)
                
                # Pattern: if key in d: d[key]
                # LOAD_FAST key, LOAD_FAST d, CONTAINS_OP 0, POP_JUMP_IF_FALSE
                if instr.opname == 'CONTAINS_OP' and i >= 2:
                    contains_guard = self._check_contains_pattern(block.instructions[:i+1], block, instr)
                    if contains_guard:
                        guards.add(contains_guard)
                
                # Pattern: if not x: raise ValueError (raise-before-access guards rest of function)
                # LOAD_FAST x, POP_JUMP_IF_TRUE skip_raise, LOAD_GLOBAL ValueError, RAISE_VARARGS
                # After this, x is guaranteed truthy/non-None
                if instr.opname == 'RAISE_VARARGS' and i >= 1:
                    raise_guard = self._check_raise_if_not_pattern(block.instructions[:i+1], block)
                    if raise_guard:
                        guards.add(raise_guard)
                
                # Pattern: x = a if cond else default (conditional expression)
                # Result is nonnull if both branches are nonnull
                if instr.opname == 'STORE_FAST' and i >= 2:
                    ternary_guards = self._check_ternary_pattern(block.instructions[:i+1], block, instr)
                    for g in ternary_guards:
                        guards.add(g)
                
                # Pattern: x = s.strip() / s.split() / etc. (string methods returning non-None)
                if instr.opname == 'STORE_FAST' and i >= 2:
                    str_method_guard = self._check_string_method_pattern(block.instructions[:i+1], block, instr)
                    if str_method_guard:
                        guards.add(str_method_guard)
                
                # Pattern: x = getattr(obj, 'attr', default) where default is non-None
                # LOAD_GLOBAL getattr, LOAD_FAST obj, LOAD_CONST 'attr', LOAD_CONST default, CALL, STORE_FAST x
                if instr.opname == 'STORE_FAST' and i >= 4:
                    getattr_guards = self._check_getattr_pattern(block.instructions[:i+1], block, instr)
                    for g in getattr_guards:
                        guards.add(g)
                
                # Pattern: x = d.setdefault(key, default) where default is non-None
                # LOAD_FAST d, LOAD_ATTR setdefault, LOAD_* key, LOAD_CONST default, CALL, STORE_FAST x
                if instr.opname == 'STORE_FAST' and i >= 4:
                    setdefault_guards = self._check_setdefault_pattern(block.instructions[:i+1], block, instr)
                    for g in setdefault_guards:
                        guards.add(g)
                
                # Pattern: x = next(iter, default) where default is non-None
                # LOAD_GLOBAL next, LOAD_FAST iter, LOAD_CONST default, CALL, STORE_FAST x
                if instr.opname == 'STORE_FAST' and i >= 3:
                    next_guards = self._check_next_default_pattern(block.instructions[:i+1], block, instr)
                    for g in next_guards:
                        guards.add(g)
                
                # Pattern: if (x := func()) is not None (walrus operator with None check)
                # CALL, COPY, STORE_FAST x, LOAD_CONST None, IS_OP 1, POP_JUMP_IF_FALSE
                if instr.opname == 'STORE_FAST' and i >= 1:
                    walrus_guard = self._check_walrus_pattern(block.instructions[:i+1], block, instr)
                    if walrus_guard:
                        guards.add(walrus_guard)
                
                # Pattern: for i in range(len(container)): container[i]
                # The loop iteration variable is bounded by len(container)
                if instr.opname == 'GET_ITER':
                    range_bounds = self._check_range_len_pattern(block.instructions[:i+1], block)
                    for g in range_bounds:
                        guards.add(g)
                    
                    # Also check for enumerate(container) pattern
                    enumerate_bounds = self._check_enumerate_pattern(block.instructions[:i+1], block)
                    for g in enumerate_bounds:
                        guards.add(g)
                    
                    # Check for simple iteration: for item in container
                    # This establishes that container is nonempty during iteration
                    loop_nonempty = self._check_loop_body_nonempty(block.instructions[:i+1], block)
                    for g in loop_nonempty:
                        guards.add(g)
            
            # Check if this block is a jump target of a len() != n pattern
            # This establishes exact_length when we know the != was False
            len_ne_guard = self._check_len_ne_fallthrough_pattern(block)
            if len_ne_guard:
                guards.add(len_ne_guard)
            
            # Check if this block is after an exception handler
            # (try/except barrier: code after except block has caught the exception)
            exc_barrier_guards = self._check_exception_barrier_pattern(block)
            for g in exc_barrier_guards:
                guards.add(g)
            
            self.block_establishes[block.id] = guards
    
    def _check_isinstance_pattern(
        self, 
        prev_instrs: List[dis.Instruction],
        block: BasicBlock
    ) -> Optional[GuardFact]:
        """Check for isinstance call pattern.
        
        Handles both simple variables and self-attribute access:
        - isinstance(var, Type)  → guard on 'var'
        - isinstance(self.attr, Type)  → nonnull guard on 'self.attr'
        """
        # Look for: LOAD_GLOBAL 'isinstance', LOAD_* var, LOAD_* type
        for i, instr in enumerate(prev_instrs):
            if (instr.opname in ('LOAD_GLOBAL', 'LOAD_BUILTIN') and 
                instr.argval == 'isinstance'):
                # Next should be variable load
                if i + 1 < len(prev_instrs):
                    var_instr = prev_instrs[i + 1]
                    if var_instr.opname in ('LOAD_FAST', 'LOAD_FAST_BORROW', 'LOAD_NAME'):
                        var_name = var_instr.argval
                        # Check for self.attr pattern: LOAD_FAST self → LOAD_ATTR attr → LOAD_GLOBAL Type
                        if (i + 3 < len(prev_instrs)
                                and prev_instrs[i + 2].opname == 'LOAD_ATTR'
                                and var_name in ('self', 'cls')
                                and isinstance(prev_instrs[i + 2].argval, str)
                                and prev_instrs[i + 3].opname in ('LOAD_GLOBAL', 'LOAD_NAME')):
                            attr_name = prev_instrs[i + 2].argval
                            type_name = prev_instrs[i + 3].argval
                            qual_var = f"{var_name}.{attr_name}"
                            # Use guard_type="nonnull" without extra so that
                            # has_nonnull(qual_var) matches (key = "nonnull:self.attr").
                            return GuardFact(
                                guard_type="nonnull",
                                variable=qual_var,
                                established_at=block.id,
                                condition=f"isinstance({qual_var}, {type_name})"
                            )
                        # Simple variable: LOAD_FAST var, LOAD_GLOBAL Type
                        if i + 2 < len(prev_instrs):
                            type_instr = prev_instrs[i + 2]
                            if type_instr.opname in ('LOAD_GLOBAL', 'LOAD_NAME'):
                                type_name = type_instr.argval
                                return GuardFact(
                                    guard_type="type",
                                    variable=var_name,
                                    extra=type_name,
                                    established_at=block.id,
                                    condition=f"isinstance({var_name}, {type_name})"
                                )
        return None
    
    def _check_none_pattern(
        self,
        instrs: List[dis.Instruction],
        block: BasicBlock
    ) -> Optional[GuardFact]:
        """Check for 'is None' / 'is not None' pattern."""
        for i, instr in enumerate(instrs):
            if instr.opname == 'IS_OP':
                # IS_OP 0 = 'is', IS_OP 1 = 'is not'
                is_not = instr.arg == 1
                
                # Look back for LOAD_* v, LOAD_CONST None
                if i >= 2:
                    load_instr = instrs[i - 2]
                    const_instr = instrs[i - 1]
                    
                    if (const_instr.opname == 'LOAD_CONST' and 
                        const_instr.argval is None):
                        var_name = None
                        if load_instr.opname in ('LOAD_FAST', 'LOAD_FAST_BORROW', 'LOAD_NAME'):
                            var_name = load_instr.argval
                        # Pattern: LOAD_FAST self → LOAD_ATTR X → LOAD_CONST None → IS_OP
                        elif (load_instr.opname == 'LOAD_ATTR'
                              and i >= 3
                              and instrs[i - 3].opname in ('LOAD_FAST', 'LOAD_FAST_BORROW')
                              and instrs[i - 3].argval in ('self', 'cls')
                              and isinstance(load_instr.argval, str)):
                            var_name = f"self.{load_instr.argval}"
                        if var_name:
                            # 'is not None' establishes nonnull on true branch
                            # 'is None' establishes nonnull on false branch
                            return GuardFact(
                                guard_type="nonnull",
                                variable=var_name,
                                established_at=block.id,
                                condition=f"{var_name} is not None" if is_not else f"{var_name} is None (false branch)"
                            )
        return None
    
    def _check_div_guard_pattern(
        self,
        instrs: List[dis.Instruction],
        block: BasicBlock
    ) -> Optional[GuardFact]:
        """
        Check for division guard patterns that establish x != 0.
        
        Patterns detected:
        1. x != 0 or 0 != x - direct non-zero check
        2. x > 0 or x >= 1 - positive implies non-zero
        3. x < 0 or x <= -1 - negative implies non-zero
        4. 0 < x or 0 > x - reversed comparisons
        
        Mathematical basis:
        - x > 0 => x >= 1 (for integers) => x != 0
        - x < 0 => x <= -1 (for integers) => x != 0
        - These are Z3-verifiable implications
        """
        for i, instr in enumerate(instrs):
            if instr.opname == 'COMPARE_OP' and i >= 2:
                left = instrs[i - 2]
                right = instrs[i - 1]
                compare_op = instr.argval
                
                # Get variable and constant from comparison operands
                var_name = None
                const_val = None
                var_is_left = False
                
                if left.opname in ('LOAD_FAST', 'LOAD_FAST_BORROW', 'LOAD_NAME'):
                    if right.opname in ('LOAD_CONST', 'LOAD_SMALL_INT') and isinstance(right.argval, (int, float)):
                        var_name = left.argval
                        const_val = right.argval
                        var_is_left = True
                elif right.opname in ('LOAD_FAST', 'LOAD_FAST_BORROW', 'LOAD_NAME'):
                    if left.opname in ('LOAD_CONST', 'LOAD_SMALL_INT') and isinstance(left.argval, (int, float)):
                        var_name = right.argval
                        const_val = left.argval
                        var_is_left = False
                
                if var_name is None or const_val is None:
                    continue
                
                # Check if comparison implies non-zero
                # Normalize to var <op> const form
                effective_op = compare_op
                if not var_is_left:
                    # Flip comparison: const <op> var => var <flipped_op> const
                    flip_map = {'<': '>', '>': '<', '<=': '>=', '>=': '<=', '==': '==', '!=': '!='}
                    effective_op = flip_map.get(compare_op, compare_op)
                
                implies_nonzero = False
                condition = None
                
                # var != 0 => div safe
                if effective_op == '!=' and const_val == 0:
                    implies_nonzero = True
                    condition = f"{var_name} != 0"
                
                # var > 0 => var >= 1 => var != 0 (for positive)
                elif effective_op == '>' and const_val >= 0:
                    implies_nonzero = True
                    condition = f"{var_name} > {const_val} => nonzero"
                
                # var >= 1 => var != 0
                elif effective_op == '>=' and const_val >= 1:
                    implies_nonzero = True
                    condition = f"{var_name} >= {const_val} => nonzero"
                
                # var < 0 => var <= -1 => var != 0 (for negative)
                elif effective_op == '<' and const_val <= 0:
                    implies_nonzero = True
                    condition = f"{var_name} < {const_val} => nonzero"
                
                # var <= -1 => var != 0
                elif effective_op == '<=' and const_val <= -1:
                    implies_nonzero = True
                    condition = f"{var_name} <= {const_val} => nonzero"
                
                if implies_nonzero:
                    return GuardFact(
                        guard_type="div",
                        variable=var_name,
                        established_at=block.id,
                        condition=condition
                    )
        
        return None
    
    def _check_bounds_guard_pattern(
        self,
        instrs: List[dis.Instruction],
        block: BasicBlock
    ) -> Optional[GuardFact]:
        """
        Check for bounds guard pattern: i < len(container) or len(container) > i or len(container) >= N.
        
        Establishes guard for container[i] access.
        
        Patterns detected:
        1. LOAD_FAST i, CALL len(container), COMPARE_OP < → guards container[i]
        2. CALL len(container), LOAD_FAST i, COMPARE_OP > → guards container[i]
        3. CALL len(container), LOAD_CONST N, COMPARE_OP >= → guards container[0..N-1]
        4. LOAD_CONST N, CALL len(container), COMPARE_OP <= → guards container[0..N-1]
        
        NEW: Pattern 3 and 4 are the key fix for `if len(fields) >= 3: fields[2]`
        """
        # Find the comparison instruction
        compare_idx = None
        for i, instr in enumerate(instrs):
            if instr.opname == 'COMPARE_OP' and instr.argval in ('<', '<=', '>', '>='):
                compare_idx = i
                break
        
        if compare_idx is None or compare_idx < 4:
            return None
        
        # Look for len() call before comparison
        len_call_idx = None
        len_container = None
        for i in range(compare_idx - 1, -1, -1):
            instr = instrs[i]
            if instr.opname in ('CALL', 'CALL_FUNCTION'):
                # Check if this was a call to len()
                if i >= 2:
                    # Look for LOAD_GLOBAL/LOAD_BUILTIN 'len' before LOAD_* container
                    for j in range(max(0, i - 3), i):
                        if instrs[j].opname in ('LOAD_GLOBAL', 'LOAD_BUILTIN', 'LOAD_NAME'):
                            if instrs[j].argval == 'len':
                                # Found len() - next instruction should be container
                                if j + 1 < i:
                                    container_instr = instrs[j + 1]
                                    if container_instr.opname in ('LOAD_FAST', 'LOAD_FAST_BORROW', 'LOAD_NAME', 'LOAD_GLOBAL'):
                                        len_container = container_instr.argval
                                        len_call_idx = i
                                break
                if len_container:
                    break
        
        if not len_container or len_call_idx is None:
            return None
        
        compare_op = instrs[compare_idx].argval
        
        # Check if we're comparing len(container) with a constant
        # Pattern: len(container) >= N or N <= len(container)
        const_value = None
        const_is_left = False
        
        # Look for constant after len() call (len(x) >= N pattern)
        for i in range(len_call_idx + 1, compare_idx):
            instr = instrs[i]
            if instr.opname in ('LOAD_CONST', 'LOAD_SMALL_INT') and isinstance(instr.argval, int):
                const_value = instr.argval
                const_is_left = False
                break
        
        # Look for constant before len() call (N <= len(x) pattern)
        if const_value is None:
            len_load_idx = None
            for j in range(len_call_idx - 1, -1, -1):
                if instrs[j].opname in ('LOAD_GLOBAL', 'LOAD_BUILTIN', 'LOAD_NAME') and instrs[j].argval == 'len':
                    len_load_idx = j
                    break
            
            if len_load_idx is not None:
                for i in range(0, len_load_idx):
                    instr = instrs[i]
                    if instr.opname in ('LOAD_CONST', 'LOAD_SMALL_INT') and isinstance(instr.argval, int):
                        const_value = instr.argval
                        const_is_left = True
                        break
        
        # If we found a constant, this is a len(container) >= N pattern
        if const_value is not None and const_value >= 1:
            # Determine the minimum length guaranteed by the check
            min_length = None
            
            if const_is_left:
                # Pattern: const <= len(container) or const < len(container)
                if compare_op == '<=':
                    min_length = const_value  # len >= const
                elif compare_op == '<':
                    min_length = const_value + 1  # len > const => len >= const + 1
            else:
                # Pattern: len(container) >= const or len(container) > const
                if compare_op == '>=':
                    min_length = const_value  # len >= const
                elif compare_op == '>':
                    min_length = const_value + 1  # len > const => len >= const + 1
            
            if min_length is not None and min_length >= 1:
                # Create a length_constraint guard that will be used by GuardState
                # This will allow has_bounds_safe to verify container[0..min_length-1]
                return GuardFact(
                    guard_type="length_constraint",
                    variable=len_container,
                    extra=str(min_length),  # Store minimum length
                    established_at=block.id,
                    condition=f"len({len_container}) >= {min_length}"
                )
        
        # Otherwise, try to find index variable for pattern 1 and 2
        # Find index variable: should be loaded near comparison
        index_var = None
        
        # For i < len(c): index loaded BEFORE len() call setup
        # For len(c) > i: index loaded after len() but before comparison
        # We need to search from compare back to before the len() setup started
        # The len() call sequence is: LOAD_GLOBAL len, LOAD_FAST container, CALL
        # So index should be found before LOAD_GLOBAL len (at len_call_idx - 2 or earlier)
        len_load_idx = None
        for j in range(len_call_idx - 1, -1, -1):
            if instrs[j].opname in ('LOAD_GLOBAL', 'LOAD_BUILTIN', 'LOAD_NAME') and instrs[j].argval == 'len':
                len_load_idx = j
                break
        
        search_start = compare_idx - 1
        search_end = 0 if len_load_idx is None else len_load_idx - 1
        
        for i in range(search_start, search_end - 1, -1):
            instr = instrs[i]
            if instr.opname in ('LOAD_FAST', 'LOAD_FAST_BORROW', 'LOAD_NAME'):
                if instr.argval != len_container and instr.argval != 'len':
                    index_var = instr.argval
                    break
        
        if not index_var:
            return None
        
        # Determine if this is a valid bounds check
        # i < len(c) or i <= len(c) - 1 → safe for c[i]
        # len(c) > i or len(c) >= i + 1 → safe for c[i]
        if compare_op in ('<', '<=', '>', '>='):
            return GuardFact(
                guard_type="bounds",
                variable=f"{len_container}[{index_var}]",
                established_at=block.id,
                condition=f"{index_var} {compare_op} len({len_container})"
            )
        
        return None
    
    def _check_range_len_pattern(
        self,
        instrs: List[dis.Instruction],
        block: BasicBlock
    ) -> List[GuardFact]:
        """
        Check for range(len(container)) iteration pattern.
        
        In: for i in range(len(container)): ...
        The loop variable i is always in bounds for container.
        
        This pattern is common and establishes bounds guards for the
        iteration variable on every container access.
        """
        guards = []
        
        # Look for pattern: LOAD_GLOBAL range, LOAD_GLOBAL len, LOAD_* container, CALL, CALL, GET_ITER
        for i, instr in enumerate(instrs):
            if instr.opname == 'GET_ITER' and i >= 4:
                # Look back for range(len(...)) pattern
                range_idx = None
                len_idx = None
                container = None
                
                for j in range(max(0, i - 10), i):
                    if instrs[j].opname in ('LOAD_GLOBAL', 'LOAD_BUILTIN', 'LOAD_NAME'):
                        if instrs[j].argval == 'range':
                            range_idx = j
                        elif instrs[j].argval == 'len':
                            len_idx = j
                    elif instrs[j].opname in ('LOAD_FAST', 'LOAD_FAST_BORROW', 'LOAD_NAME'):
                        if len_idx is not None and range_idx is not None:
                            if instrs[j].argval not in ('range', 'len'):
                                container = instrs[j].argval
                                break
                
                if range_idx is not None and len_idx is not None and container:
                    # This block establishes a bounds guard for any iteration variable
                    # accessing container. The actual variable name will be resolved
                    # by the FOR_ITER -> STORE_FAST pattern.
                    guards.append(GuardFact(
                        guard_type="range_len_loop",
                        variable=container,
                        established_at=block.id,
                        condition=f"range(len({container}))"
                    ))
        
        return guards

    def _check_enumerate_pattern(
        self,
        instrs: List[dis.Instruction],
        block: BasicBlock
    ) -> List[GuardFact]:
        """
        Check for enumerate(container) iteration pattern.
        
        In: for i, item in enumerate(container): ...
        The loop variable i is always in bounds for container.
        
        Pattern: LOAD_GLOBAL enumerate, LOAD_FAST container, CALL, GET_ITER
        """
        guards = []
        
        for i, instr in enumerate(instrs):
            if instr.opname == 'GET_ITER' and i >= 2:
                # Look back for enumerate(...) pattern
                enumerate_idx = None
                container = None
                
                for j in range(max(0, i - 6), i):
                    if instrs[j].opname in ('LOAD_GLOBAL', 'LOAD_BUILTIN', 'LOAD_NAME'):
                        if instrs[j].argval == 'enumerate':
                            enumerate_idx = j
                    elif instrs[j].opname in ('LOAD_FAST', 'LOAD_FAST_BORROW', 'LOAD_NAME'):
                        if enumerate_idx is not None:
                            if instrs[j].argval != 'enumerate':
                                container = instrs[j].argval
                                break
                
                if enumerate_idx is not None and container:
                    # enumerate(x) guarantees i is valid index for x
                    guards.append(GuardFact(
                        guard_type="enumerate_loop",
                        variable=container,
                        established_at=block.id,
                        condition=f"enumerate({container})"
                    ))
        
        return guards

    def _check_or_default_pattern(
        self,
        instrs: List[dis.Instruction],
        block: BasicBlock,
        store_instr: dis.Instruction
    ) -> List[GuardFact]:
        """
        Check for x = y or default pattern.
        
        Pattern: LOAD_FAST y, COPY, TO_BOOL, POP_JUMP_IF_TRUE, NOT_TAKEN, POP_TOP, LOAD_CONST default, STORE_FAST x
        
        If default is truthy/non-None, x is nonnull.
        If default is non-zero, x is nonzero (for div safety).
        """
        guards = []
        var_name = store_instr.argval
        if not var_name:
            return guards
        
        # Look for pattern ending in STORE_FAST
        # We need: LOAD_CONST <default> before this, and POP_JUMP_IF_TRUE before that
        has_pop_jump = False
        default_val = None
        
        for i in range(len(instrs) - 2, max(-1, len(instrs) - 10), -1):
            instr = instrs[i]
            if instr.opname in ('LOAD_CONST', 'LOAD_SMALL_INT'):
                default_val = instr.argval
            elif instr.opname in ('POP_JUMP_IF_TRUE', 'POP_JUMP_FORWARD_IF_TRUE'):
                has_pop_jump = True
                break
        
        if not has_pop_jump:
            return guards
        
        # Check if default establishes guards
        if default_val is not None:
            # If default is truthy (non-None, non-empty, non-zero), x is guarded
            if default_val is not None and default_val != 0 and default_val != '' and default_val != []:
                guards.append(GuardFact(
                    guard_type="nonnull",
                    variable=var_name,
                    established_at=block.id,
                    condition=f"{var_name} = ... or {repr(default_val)} => nonnull"
                ))
                
                # If default is numeric and non-zero, x is div-safe
                if isinstance(default_val, (int, float)) and default_val != 0:
                    guards.append(GuardFact(
                        guard_type="div",
                        variable=var_name,
                        established_at=block.id,
                        condition=f"{var_name} = ... or {default_val} => nonzero"
                    ))
        
        return guards

    def _check_loop_body_nonempty(
        self,
        instrs: List[dis.Instruction],
        block: BasicBlock
    ) -> List[GuardFact]:
        """
        Check for simple iteration pattern: for item in container.
        
        During iteration, the container is non-empty (we're inside the loop body).
        This allows safe access to container[0] inside the loop.
        
        Pattern: LOAD_FAST container, GET_ITER -> FOR_ITER body
        """
        guards = []
        
        # Look for GET_ITER preceded by LOAD_FAST (simple iteration)
        for i, instr in enumerate(instrs):
            if instr.opname == 'GET_ITER' and i >= 1:
                prev = instrs[i - 1]
                if prev.opname in ('LOAD_FAST', 'LOAD_FAST_BORROW', 'LOAD_NAME'):
                    container = prev.argval
                    if container:
                        # Inside the loop body, container is nonempty
                        guards.append(GuardFact(
                            guard_type="loop_body_nonempty",
                            variable=container,
                            established_at=block.id,
                            condition=f"for ... in {container} => {container} nonempty"
                        ))
        
        return guards

    def _check_dict_get_pattern(
        self,
        instrs: List[dis.Instruction],
        block: BasicBlock,
        store_instr: dis.Instruction
    ) -> List[GuardFact]:
        """
        Check for dict.get(key, default) pattern.
        
        Pattern: LOAD_FAST d, LOAD_ATTR get, LOAD_* key, LOAD_CONST default, CALL, STORE_FAST x
        
        If default is non-None, x is nonnull.
        If default is non-zero numeric, x is div-safe.
        """
        guards = []
        var_name = store_instr.argval
        if not var_name:
            return guards
        
        # Look for LOAD_ATTR 'get' and a default value before the CALL
        has_get_attr = False
        default_val = None
        call_idx = None
        
        for i in range(len(instrs) - 2, max(-1, len(instrs) - 12), -1):
            instr = instrs[i]
            if instr.opname in ('CALL', 'CALL_FUNCTION', 'CALL_METHOD'):
                call_idx = i
            elif instr.opname == 'LOAD_ATTR' and instr.argval == 'get':
                has_get_attr = True
            elif instr.opname in ('LOAD_CONST', 'LOAD_SMALL_INT') and call_idx is not None:
                # This might be the default argument
                if default_val is None:
                    default_val = instr.argval
        
        if not has_get_attr or call_idx is None:
            return guards
        
        # Check if default establishes guards
        if default_val is not None:
            # If default is non-None, x is nonnull
            guards.append(GuardFact(
                guard_type="nonnull",
                variable=var_name,
                established_at=block.id,
                condition=f"{var_name} = d.get(k, {repr(default_val)}) => nonnull"
            ))
            
            # If default is numeric and non-zero, x is div-safe
            if isinstance(default_val, (int, float)) and default_val != 0:
                guards.append(GuardFact(
                    guard_type="div",
                    variable=var_name,
                    established_at=block.id,
                    condition=f"{var_name} = d.get(k, {default_val}) => nonzero"
                ))
        
        return guards

    def _check_assert_nonnull_pattern(
        self,
        instrs: List[dis.Instruction],
        block: BasicBlock
    ) -> Optional[GuardFact]:
        """
        Check for assert x is not None pattern.
        
        Pattern: LOAD_FAST x, LOAD_CONST None, IS_OP 1, POP_JUMP_IF_TRUE, ..., RAISE_VARARGS
        
        After the assertion passes (no raise), x is guaranteed non-None.
        We detect this by finding the assertion pattern and establishing nonnull
        for the variable on the non-raise path.
        """
        # Look for IS_OP followed by conditional jump (assertion pattern)
        for i in range(len(instrs) - 1, -1, -1):
            instr = instrs[i]
            if instr.opname == 'IS_OP' and instr.arg == 1:  # 'is not'
                # Check if previous is LOAD_CONST None
                if i >= 2:
                    load_instr = instrs[i - 2]
                    const_instr = instrs[i - 1]
                    
                    if (load_instr.opname in ('LOAD_FAST', 'LOAD_FAST_BORROW', 'LOAD_NAME') and
                        const_instr.opname == 'LOAD_CONST' and const_instr.argval is None):
                        var_name = load_instr.argval
                        if var_name:
                            return GuardFact(
                                guard_type="nonnull",
                                variable=var_name,
                                established_at=block.id,
                                condition=f"assert {var_name} is not None"
                            )
        return None
    
    def _check_assert_len_pattern(
        self,
        instrs: List[dis.Instruction],
        block: BasicBlock
    ) -> Optional[GuardFact]:
        """
        Check for assert len(x) > 0 pattern.
        
        Pattern: LOAD_GLOBAL len, LOAD_FAST x, CALL, LOAD_CONST 0, COMPARE_OP >, POP_JUMP_IF_TRUE, ..., RAISE_VARARGS
        
        After assertion passes, x is guaranteed non-empty.
        """
        # Look for COMPARE_OP followed by POP_JUMP in assertion context
        for i in range(len(instrs) - 1, -1, -1):
            instr = instrs[i]
            if instr.opname == 'COMPARE_OP' and instr.argval in ('>', '>=', '!='):
                # Look back for len() call pattern
                if i >= 4:
                    # Check for: LOAD_GLOBAL/BUILTIN len, LOAD_FAST x, CALL, LOAD_CONST 0, COMPARE_OP
                    const_idx = i - 1
                    call_idx = i - 2
                    container_idx = i - 3
                    len_idx = i - 4
                    
                    if (const_idx >= 0 and call_idx >= 0 and container_idx >= 0 and len_idx >= 0 and
                        instrs[const_idx].opname in ('LOAD_CONST', 'LOAD_SMALL_INT') and
                        instrs[const_idx].argval == 0 and
                        instrs[call_idx].opname in ('CALL', 'CALL_FUNCTION') and
                        instrs[container_idx].opname in ('LOAD_FAST', 'LOAD_FAST_BORROW', 'LOAD_NAME') and
                        instrs[len_idx].opname in ('LOAD_GLOBAL', 'LOAD_BUILTIN', 'LOAD_NAME') and
                        instrs[len_idx].argval == 'len'):
                        
                        container = instrs[container_idx].argval
                        if container:
                            return GuardFact(
                                guard_type="nonempty",
                                variable=container,
                                established_at=block.id,
                                condition=f"assert len({container}) > 0"
                            )
        return None
    
    def _check_assert_contains_pattern(
        self,
        instrs: List[dis.Instruction],
        block: BasicBlock
    ) -> Optional[GuardFact]:
        """
        Check for assert key in dict pattern.
        
        Pattern: LOAD_FAST key, LOAD_FAST dict, CONTAINS_OP 0, POP_JUMP_IF_TRUE, ..., RAISE_VARARGS
        
        After assertion passes, key is guaranteed in dict.
        """
        for i in range(len(instrs) - 1, -1, -1):
            instr = instrs[i]
            if instr.opname == 'CONTAINS_OP' and instr.arg == 0:  # 'in'
                if i >= 2:
                    key_instr = instrs[i - 2]
                    dict_instr = instrs[i - 1]
                    
                    if (key_instr.opname in ('LOAD_FAST', 'LOAD_FAST_BORROW', 'LOAD_NAME', 'LOAD_CONST') and
                        dict_instr.opname in ('LOAD_FAST', 'LOAD_FAST_BORROW', 'LOAD_NAME')):
                        
                        key_var = key_instr.argval
                        dict_var = dict_instr.argval
                        if key_var and dict_var:
                            # If key is a constant, use its repr
                            if key_instr.opname == 'LOAD_CONST':
                                key_str = repr(key_var)
                            else:
                                key_str = str(key_var)
                            
                            return GuardFact(
                                guard_type="key_in",
                                variable=f"{dict_var}[{key_str}]",
                                established_at=block.id,
                                condition=f"assert {key_str} in {dict_var}"
                            )
        return None
    
    def _check_assert_nonzero_pattern(
        self,
        instrs: List[dis.Instruction],
        block: BasicBlock
    ) -> Optional[GuardFact]:
        """
        Check for assert x != 0 pattern.
        
        Pattern: LOAD_FAST x, LOAD_CONST 0, COMPARE_OP !=, POP_JUMP_IF_TRUE, ..., RAISE_VARARGS
        
        After assertion passes, x is guaranteed non-zero (safe for division).
        """
        for i in range(len(instrs) - 1, -1, -1):
            instr = instrs[i]
            if instr.opname == 'COMPARE_OP' and instr.argval in ('!=', '>', '>=', '<', '<='):
                if i >= 2:
                    var_instr = instrs[i - 2]
                    const_instr = instrs[i - 1]
                    
                    if (var_instr.opname in ('LOAD_FAST', 'LOAD_FAST_BORROW', 'LOAD_NAME') and
                        const_instr.opname in ('LOAD_CONST', 'LOAD_SMALL_INT') and
                        const_instr.argval == 0):
                        
                        var_name = var_instr.argval
                        compare_op = instr.argval
                        
                        # Check if comparison implies non-zero
                        if compare_op in ('!=', '>', '>=', '<', '<='):
                            # !=, >, <, >=, <= all imply non-zero when compared to 0
                            if var_name:
                                return GuardFact(
                                    guard_type="div",
                                    variable=var_name,
                                    established_at=block.id,
                                    condition=f"assert {var_name} {compare_op} 0"
                                )
        return None
    
    def _check_raise_if_not_pattern(
        self,
        instrs: List[dis.Instruction],
        block: BasicBlock
    ) -> Optional[GuardFact]:
        """
        Check for 'if not x: raise' pattern.
        
        Pattern: LOAD_FAST x, POP_JUMP_IF_TRUE skip_raise, ..., RAISE_VARARGS
        
        After this pattern (on non-raise path), x is guaranteed truthy/non-None.
        This is detected by looking for a jump-if-true that skips over a raise.
        """
        # The RAISE_VARARGS is at the end, look back for the conditional jump
        for i in range(len(instrs) - 2, -1, -1):
            instr = instrs[i]
            if instr.opname in ('POP_JUMP_IF_TRUE', 'POP_JUMP_FORWARD_IF_TRUE'):
                # Look back one more for the variable load
                if i >= 1:
                    load_instr = instrs[i - 1]
                    if load_instr.opname in ('LOAD_FAST', 'LOAD_FAST_BORROW', 'LOAD_NAME'):
                        var_name = load_instr.argval
                        if var_name:
                            # This establishes nonnull on the jump-taken path (after the raise)
                            return GuardFact(
                                guard_type="nonnull",
                                variable=var_name,
                                established_at=block.id,
                                condition=f"if not {var_name}: raise (guards rest of function)"
                            )
        return None

    def _check_unpack_pattern(
        self,
        instrs: List[dis.Instruction],
        block: BasicBlock,
        unpack_instr: dis.Instruction
    ) -> Optional[GuardFact]:
        """
        Check for unpacking pattern: a, b, c = iterable.
        
        Pattern: LOAD_FAST iterable, UNPACK_SEQUENCE n
        
        This establishes that len(iterable) == n, making indices 0..n-1 safe.
        """
        n = unpack_instr.arg  # Number of elements to unpack
        if n is None or n < 1:
            return None
        
        # Find the variable being unpacked (should be loaded just before)
        for i in range(len(instrs) - 2, max(-1, len(instrs) - 5), -1):
            instr = instrs[i]
            if instr.opname in ('LOAD_FAST', 'LOAD_FAST_BORROW', 'LOAD_NAME'):
                container = instr.argval
                if container:
                    return GuardFact(
                        guard_type="exact_length",
                        variable=container,
                        extra=str(n),
                        established_at=block.id,
                        condition=f"unpacking {container} into {n} values => len({container}) == {n}"
                    )
                break
        
        return None

    def _check_minmax_clamp_pattern(
        self,
        instrs: List[dis.Instruction],
        block: BasicBlock,
        store_instr: dis.Instruction
    ) -> List[GuardFact]:
        """
        Check for min/max bounds clamping patterns.
        
        Patterns:
        1. i = min(i, len(arr)-1) - clamps i to valid upper bound
        2. i = max(0, i) - clamps i to valid lower bound
        3. i = min(max(0, i), len(arr)-1) - full clamping
        
        After clamping, arr[i] is bounds-safe.
        """
        guards = []
        var_name = store_instr.argval
        if not var_name:
            return guards
        
        # Look for min() or max() call with len() or constant
        has_min = False
        has_max = False
        has_len = False
        container = None
        lower_bound = None
        
        for i in range(len(instrs) - 2, max(-1, len(instrs) - 15), -1):
            instr = instrs[i]
            if instr.opname in ('LOAD_GLOBAL', 'LOAD_BUILTIN', 'LOAD_NAME'):
                if instr.argval == 'min':
                    has_min = True
                elif instr.argval == 'max':
                    has_max = True
                elif instr.argval == 'len':
                    has_len = True
            elif instr.opname in ('LOAD_FAST', 'LOAD_FAST_BORROW', 'LOAD_NAME'):
                if has_len and container is None and instr.argval != var_name:
                    container = instr.argval
            elif instr.opname in ('LOAD_CONST', 'LOAD_SMALL_INT'):
                if isinstance(instr.argval, int) and instr.argval == 0:
                    lower_bound = 0
        
        # min(i, len(arr)-1) or min(i, len(arr)) establishes upper bound
        if has_min and has_len and container:
            guards.append(GuardFact(
                guard_type="bounds",
                variable=f"{container}[{var_name}]",
                established_at=block.id,
                condition=f"{var_name} = min({var_name}, len({container})-1) => bounds safe"
            ))
        
        # max(0, i) establishes lower bound (i >= 0)
        if has_max and lower_bound == 0:
            guards.append(GuardFact(
                guard_type="nonnegative",
                variable=var_name,
                established_at=block.id,
                condition=f"{var_name} = max(0, {var_name}) => {var_name} >= 0"
            ))
        
        return guards

    def _check_hasattr_pattern(
        self,
        instrs: List[dis.Instruction],
        block: BasicBlock
    ) -> Optional[GuardFact]:
        """
        Check for hasattr(obj, 'attr') pattern.
        
        Pattern: LOAD_GLOBAL hasattr, LOAD_FAST obj, LOAD_CONST 'attr', CALL
        
        After the hasattr check passes, obj.attr is safe to access.
        This establishes a 'hasattr' guard that the dataflow analysis
        can use to suppress AttributeError warnings.
        """
        # Look for hasattr call
        has_hasattr = False
        obj_var = None
        attr_name = None
        
        for i in range(len(instrs) - 1, -1, -1):
            instr = instrs[i]
            if instr.opname in ('LOAD_GLOBAL', 'LOAD_BUILTIN', 'LOAD_NAME'):
                if instr.argval == 'hasattr':
                    has_hasattr = True
            elif instr.opname in ('LOAD_FAST', 'LOAD_FAST_BORROW', 'LOAD_NAME'):
                if has_hasattr and obj_var is None:
                    obj_var = instr.argval
            elif instr.opname == 'LOAD_CONST':
                if has_hasattr and obj_var and isinstance(instr.argval, str):
                    attr_name = instr.argval
                    break
        
        if has_hasattr and obj_var and attr_name:
            return GuardFact(
                guard_type="hasattr",
                variable=obj_var,
                extra=attr_name,
                established_at=block.id,
                condition=f"hasattr({obj_var}, '{attr_name}')"
            )
        
        return None

    def _check_callable_pattern(
        self,
        instrs: List[dis.Instruction],
        block: BasicBlock
    ) -> Optional[GuardFact]:
        """
        Check for callable(x) pattern.
        
        Pattern: LOAD_GLOBAL callable, LOAD_FAST x, CALL
        
        After callable check passes, x is guaranteed to be non-None
        (None is not callable). This establishes nonnull guard.
        """
        has_callable = False
        var_name = None
        
        for i in range(len(instrs) - 1, -1, -1):
            instr = instrs[i]
            if instr.opname in ('LOAD_GLOBAL', 'LOAD_BUILTIN', 'LOAD_NAME'):
                if instr.argval == 'callable':
                    has_callable = True
            elif instr.opname in ('LOAD_FAST', 'LOAD_FAST_BORROW', 'LOAD_NAME'):
                if has_callable and var_name is None:
                    var_name = instr.argval
                    break
        
        if has_callable and var_name:
            return GuardFact(
                guard_type="nonnull",
                variable=var_name,
                established_at=block.id,
                condition=f"callable({var_name}) => {var_name} is not None"
            )
        
        return None

    def _check_contains_pattern(
        self,
        instrs: List[dis.Instruction],
        block: BasicBlock,
        contains_instr: dis.Instruction
    ) -> Optional[GuardFact]:
        """
        Check for 'key in container' pattern.
        
        Pattern: LOAD_FAST key, LOAD_FAST container, CONTAINS_OP 0
        
        After 'key in d' check passes, d[key] is safe (no KeyError).
        This establishes a 'key_in' guard for safe dict/set access.
        
        CONTAINS_OP 0 = 'in', CONTAINS_OP 1 = 'not in'
        """
        # Only handle 'in' (not 'not in')
        if contains_instr.arg != 0:
            return None
        
        # Look for the key and container
        key_var = None
        container_var = None
        
        for i in range(len(instrs) - 1, max(-1, len(instrs) - 5), -1):
            instr = instrs[i]
            if instr.opname in ('LOAD_FAST', 'LOAD_FAST_BORROW', 'LOAD_NAME'):
                if container_var is None:
                    container_var = instr.argval
                elif key_var is None:
                    key_var = instr.argval
                    break
        
        if key_var and container_var:
            return GuardFact(
                guard_type="key_in",
                variable=f"{container_var}[{key_var}]",
                extra=container_var,
                established_at=block.id,
                condition=f"{key_var} in {container_var}"
            )
        
        return None

    def _check_ternary_pattern(
        self,
        instrs: List[dis.Instruction],
        block: BasicBlock,
        store_instr: dis.Instruction
    ) -> List[GuardFact]:
        """
        Check for conditional expression: x = a if cond else default.
        
        Pattern involves POP_JUMP_IF_FALSE/TRUE and multiple value loads.
        
        If the default value is non-None, x is guaranteed nonnull.
        """
        guards = []
        var_name = store_instr.argval
        if not var_name:
            return guards
        
        # Look for pattern with conditional jump and constant default
        has_cond_jump = False
        default_val = None
        
        for i in range(len(instrs) - 2, max(-1, len(instrs) - 10), -1):
            instr = instrs[i]
            if instr.opname in ('POP_JUMP_IF_FALSE', 'POP_JUMP_IF_TRUE',
                               'POP_JUMP_FORWARD_IF_FALSE', 'POP_JUMP_FORWARD_IF_TRUE'):
                has_cond_jump = True
            elif instr.opname in ('LOAD_CONST', 'LOAD_SMALL_INT') and has_cond_jump:
                # This could be the default value in else branch
                if default_val is None:
                    default_val = instr.argval
        
        if has_cond_jump and default_val is not None:
            # If default is non-None, result is nonnull
            guards.append(GuardFact(
                guard_type="nonnull",
                variable=var_name,
                established_at=block.id,
                condition=f"{var_name} = ... if ... else {repr(default_val)} => nonnull"
            ))
            
            # If default is non-zero numeric, result is div-safe
            if isinstance(default_val, (int, float)) and default_val != 0:
                guards.append(GuardFact(
                    guard_type="div",
                    variable=var_name,
                    established_at=block.id,
                    condition=f"{var_name} = ... if ... else {default_val} => nonzero"
                ))
        
        return guards

    def _check_string_method_pattern(
        self,
        instrs: List[dis.Instruction],
        block: BasicBlock,
        store_instr: dis.Instruction
    ) -> Optional[GuardFact]:
        """
        Check for string method calls that always return non-None.
        
        Methods like str.strip(), str.split(), str.lower(), str.upper(),
        str.replace(), etc. always return a string (never None).
        
        Pattern: LOAD_FAST s, LOAD_ATTR strip, CALL, STORE_FAST x
        """
        var_name = store_instr.argval
        if not var_name:
            return None
        
        # String methods that never return None
        nonnull_str_methods = {
            'strip', 'lstrip', 'rstrip', 'split', 'rsplit', 'splitlines',
            'lower', 'upper', 'title', 'capitalize', 'swapcase', 'casefold',
            'replace', 'translate', 'encode', 'format', 'format_map',
            'join', 'center', 'ljust', 'rjust', 'zfill', 'expandtabs',
            'partition', 'rpartition', 'maketrans'
        }
        
        # Also list methods that return non-None
        nonnull_list_methods = {'copy', 'sorted'}
        
        # Dict methods
        nonnull_dict_methods = {'copy', 'keys', 'values', 'items'}
        
        all_nonnull_methods = nonnull_str_methods | nonnull_list_methods | nonnull_dict_methods
        
        # Look for LOAD_ATTR with one of these methods followed by CALL
        has_call = False
        method_name = None
        
        for i in range(len(instrs) - 2, max(-1, len(instrs) - 8), -1):
            instr = instrs[i]
            if instr.opname in ('CALL', 'CALL_FUNCTION', 'CALL_METHOD'):
                has_call = True
            elif instr.opname == 'LOAD_ATTR' and has_call:
                if instr.argval in all_nonnull_methods:
                    method_name = instr.argval
                    break
        
        if has_call and method_name:
            return GuardFact(
                guard_type="nonnull",
                variable=var_name,
                established_at=block.id,
                condition=f"{var_name} = ....{method_name}() => nonnull"
            )
        
        return None

    def _check_getattr_pattern(
        self,
        instrs: List[dis.Instruction],
        block: BasicBlock,
        store_instr: dis.Instruction
    ) -> List[GuardFact]:
        """
        Check for getattr(obj, 'attr', default) pattern.
        
        Pattern: LOAD_GLOBAL getattr, LOAD_FAST obj, LOAD_CONST 'attr', LOAD_CONST default, CALL
        
        If default is non-None, x is nonnull.
        If default is non-zero numeric, x is div-safe.
        
        Z3 model:
        - getattr(obj, attr, default) returns obj.attr if exists, else default
        - If default is non-None, result is guaranteed non-None
        """
        guards = []
        var_name = store_instr.argval
        if not var_name:
            return guards
        
        has_getattr = False
        default_val = None
        call_idx = None
        
        for i in range(len(instrs) - 2, max(-1, len(instrs) - 12), -1):
            instr = instrs[i]
            if instr.opname in ('CALL', 'CALL_FUNCTION'):
                call_idx = i
            elif instr.opname in ('LOAD_GLOBAL', 'LOAD_BUILTIN', 'LOAD_NAME'):
                if instr.argval == 'getattr':
                    has_getattr = True
            elif instr.opname in ('LOAD_CONST', 'LOAD_SMALL_INT') and call_idx is not None:
                # This might be the default argument (3rd arg)
                if default_val is None:
                    default_val = instr.argval
        
        if not has_getattr or call_idx is None:
            return guards
        
        # Check if default establishes guards
        if default_val is not None:
            guards.append(GuardFact(
                guard_type="nonnull",
                variable=var_name,
                established_at=block.id,
                condition=f"{var_name} = getattr(obj, attr, {repr(default_val)}) => nonnull"
            ))
            
            if isinstance(default_val, (int, float)) and default_val != 0:
                guards.append(GuardFact(
                    guard_type="div",
                    variable=var_name,
                    established_at=block.id,
                    condition=f"{var_name} = getattr(obj, attr, {default_val}) => nonzero"
                ))
        
        return guards

    def _check_setdefault_pattern(
        self,
        instrs: List[dis.Instruction],
        block: BasicBlock,
        store_instr: dis.Instruction
    ) -> List[GuardFact]:
        """
        Check for dict.setdefault(key, default) pattern.
        
        Pattern: LOAD_FAST d, LOAD_ATTR setdefault, LOAD_* key, LOAD_CONST default, CALL
        
        d.setdefault(key, default) returns:
        - d[key] if key exists
        - default otherwise (and sets d[key] = default)
        
        If default is non-None, result is guaranteed non-None.
        
        Z3 model:
        - result = d[key] if key in d else default
        - If default is non-None: result is non-None
        """
        guards = []
        var_name = store_instr.argval
        if not var_name:
            return guards
        
        has_setdefault = False
        default_val = None
        call_idx = None
        
        for i in range(len(instrs) - 2, max(-1, len(instrs) - 12), -1):
            instr = instrs[i]
            if instr.opname in ('CALL', 'CALL_FUNCTION', 'CALL_METHOD'):
                call_idx = i
            elif instr.opname == 'LOAD_ATTR' and instr.argval == 'setdefault':
                has_setdefault = True
            elif instr.opname in ('LOAD_CONST', 'LOAD_SMALL_INT') and call_idx is not None:
                if default_val is None:
                    default_val = instr.argval
        
        if not has_setdefault or call_idx is None:
            return guards
        
        if default_val is not None:
            guards.append(GuardFact(
                guard_type="nonnull",
                variable=var_name,
                established_at=block.id,
                condition=f"{var_name} = d.setdefault(k, {repr(default_val)}) => nonnull"
            ))
            
            if isinstance(default_val, (int, float)) and default_val != 0:
                guards.append(GuardFact(
                    guard_type="div",
                    variable=var_name,
                    established_at=block.id,
                    condition=f"{var_name} = d.setdefault(k, {default_val}) => nonzero"
                ))
        
        return guards

    def _check_next_default_pattern(
        self,
        instrs: List[dis.Instruction],
        block: BasicBlock,
        store_instr: dis.Instruction
    ) -> List[GuardFact]:
        """
        Check for next(iterator, default) pattern.
        
        Pattern: LOAD_GLOBAL next, LOAD_FAST iter, LOAD_CONST default, CALL
        
        next(iter, default) returns:
        - Next item from iterator if available
        - default if iterator is exhausted
        
        If default is non-None, result is guaranteed non-None.
        
        Z3 model:
        - result = next_item OR default (depending on iterator state)
        - If default is non-None: result is non-None
        """
        guards = []
        var_name = store_instr.argval
        if not var_name:
            return guards
        
        has_next = False
        default_val = None
        call_idx = None
        
        for i in range(len(instrs) - 2, max(-1, len(instrs) - 10), -1):
            instr = instrs[i]
            if instr.opname in ('CALL', 'CALL_FUNCTION'):
                call_idx = i
            elif instr.opname in ('LOAD_GLOBAL', 'LOAD_BUILTIN', 'LOAD_NAME'):
                if instr.argval == 'next':
                    has_next = True
            elif instr.opname in ('LOAD_CONST', 'LOAD_SMALL_INT') and call_idx is not None:
                if default_val is None:
                    default_val = instr.argval
        
        if not has_next or call_idx is None:
            return guards
        
        if default_val is not None:
            guards.append(GuardFact(
                guard_type="nonnull",
                variable=var_name,
                established_at=block.id,
                condition=f"{var_name} = next(iter, {repr(default_val)}) => nonnull"
            ))
            
            if isinstance(default_val, (int, float)) and default_val != 0:
                guards.append(GuardFact(
                    guard_type="div",
                    variable=var_name,
                    established_at=block.id,
                    condition=f"{var_name} = next(iter, {default_val}) => nonzero"
                ))
        
        return guards

    def _check_walrus_pattern(
        self,
        instrs: List[dis.Instruction],
        block: BasicBlock,
        store_instr: dis.Instruction
    ) -> Optional[GuardFact]:
        """
        Check for walrus operator with subsequent None check.
        
        Pattern: if (x := func()) is not None:
        Bytecode: CALL, COPY, STORE_FAST x, LOAD_CONST None, IS_OP 1, POP_JUMP_IF_FALSE
        
        On the true branch, x is guaranteed non-None.
        
        Z3 model:
        - Condition: x is not None
        - True branch: nonnull(x) = True
        """
        var_name = store_instr.argval
        if not var_name:
            return None
        
        # Look for COPY before STORE_FAST (walrus pattern duplicates value)
        has_copy = False
        for i in range(len(instrs) - 2, max(-1, len(instrs) - 5), -1):
            if instrs[i].opname == 'COPY':
                has_copy = True
                break
        
        if has_copy:
            # Walrus operator detected - check if there's a None check after
            # The guard will be established by the POP_JUMP_IF_NOT_NONE handler
            # For now, we establish a tentative nonnull that will be refined
            return GuardFact(
                guard_type="nonnull",
                variable=var_name,
                established_at=block.id,
                condition=f"(x := ...) walrus pattern => may be nonnull after check"
            )
        
        return None

    def _check_exception_barrier_pattern(
        self,
        block: BasicBlock
    ) -> List[GuardFact]:
        """
        Check for exception barrier pattern (try/except).
        
        Code after an exception handler that catches TypeError/AttributeError
        establishes that operations which would raise those exceptions are safe.
        
        Z3/Barrier model:
        - Exception barrier: if we reach code after except block, the exception was caught
        - For TypeError: type errors in the try block are handled
        - For AttributeError: attribute access errors are handled
        
        This is conservative - we only establish guards for blocks that are
        exception handler entry points or directly follow exception handlers.
        """
        guards = []
        
        # Check if this block is an exception handler entry
        for region in self.cfg.exception_regions:
            if block.start_offset == region.handler_offset:
                # This is an exception handler - the exception is being caught
                # Code after this point is protected from that exception type
                guards.append(GuardFact(
                    guard_type="exception_caught",
                    variable="_exception",
                    extra="handler",
                    established_at=block.id,
                    condition=f"exception handler at offset {region.handler_offset}"
                ))
        
        return guards

    def _check_nonempty_guard_pattern(
        self,
        instrs: List[dis.Instruction],
        block: BasicBlock
    ) -> Optional[GuardFact]:
        """
        Check for len(x) > 0 or len(x) >= 1 pattern (non-empty check).
        
        This pattern establishes that x[0] is a safe access (container has >= 1 element).
        
        Patterns detected:
        1. len(x) > 0   - container has at least 1 element
        2. len(x) >= 1  - container has at least 1 element  
        3. len(x) != 0  - container is not empty
        4. 0 < len(x)   - same as len(x) > 0
        5. 1 <= len(x)  - same as len(x) >= 1
        
        The guard stores Z3-verifiable constraint: len(container) >= 1.
        This allows proving that x[0] is safe via Z3 implication checking.
        """
        # Find the comparison instruction
        compare_idx = None
        compare_op = None
        for i, instr in enumerate(instrs):
            if instr.opname == 'COMPARE_OP':
                compare_idx = i
                compare_op = instr.argval
                break
        
        if compare_idx is None or compare_idx < 3:
            return None
        
        # Look for len() call in the pattern
        len_container = None
        len_call_idx = None
        
        for i in range(compare_idx - 1, -1, -1):
            instr = instrs[i]
            if instr.opname in ('CALL', 'CALL_FUNCTION'):
                # Check if this was a call to len()
                for j in range(max(0, i - 3), i):
                    if instrs[j].opname in ('LOAD_GLOBAL', 'LOAD_BUILTIN', 'LOAD_NAME'):
                        if instrs[j].argval == 'len':
                            # Found len() - next instruction should be container
                            if j + 1 < i:
                                container_instr = instrs[j + 1]
                                if container_instr.opname in ('LOAD_FAST', 'LOAD_FAST_BORROW', 'LOAD_NAME', 'LOAD_GLOBAL'):
                                    # Check for chained attr: LOAD_FAST x, LOAD_ATTR a → len(x.a)
                                    if j + 2 < i and instrs[j + 2].opname == 'LOAD_ATTR':
                                        len_container = f"{container_instr.argval}.{instrs[j + 2].argval}"
                                    else:
                                        len_container = container_instr.argval
                                    len_call_idx = i
                            break
                if len_container:
                    break
        
        if not len_container or len_call_idx is None:
            return None
        
        # Look for constant 0 or 1 in the comparison
        const_value = None
        const_is_left = False  # True if constant is on left side of comparison
        
        # Check for constant after len() call (len(x) > 0 pattern)
        for i in range(len_call_idx + 1, compare_idx):
            instr = instrs[i]
            if instr.opname == 'LOAD_CONST' and isinstance(instr.argval, int):
                const_value = instr.argval
                const_is_left = False
                break
            # Handle LOAD_SMALL_INT for Python 3.14+
            if instr.opname == 'LOAD_SMALL_INT' and isinstance(instr.argval, int):
                const_value = instr.argval
                const_is_left = False
                break
        
        # Check for constant before len() (0 < len(x) pattern)
        if const_value is None:
            for i in range(0, len_call_idx):
                instr = instrs[i]
                if instr.opname == 'LOAD_CONST' and isinstance(instr.argval, int):
                    # Check if this is loaded right before the comparison setup
                    # It should be the first operand loaded
                    const_value = instr.argval
                    const_is_left = True
                    break
                if instr.opname == 'LOAD_SMALL_INT' and isinstance(instr.argval, int):
                    const_value = instr.argval
                    const_is_left = True
                    break
        
        if const_value is None:
            return None
        
        # Determine if this is a non-empty check or an exact length check
        # Valid patterns:
        # - len(x) > 0, len(x) >= 1, len(x) != 0 -> nonempty (len >= 1)
        # - len(x) == n (for n >= 1) -> exact length (len == n)
        is_nonempty_check = False
        exact_length = None
        
        if const_is_left:
            # Pattern: const <op> len(x)
            # 0 < len(x)  -> len(x) > 0  -> len(x) >= 1
            # 1 <= len(x) -> len(x) >= 1
            # 0 != len(x) -> len(x) != 0 -> len(x) >= 1
            # n == len(x) -> len(x) == n
            if const_value == 0 and compare_op == '<':
                is_nonempty_check = True
            elif const_value == 1 and compare_op == '<=':
                is_nonempty_check = True
            elif const_value == 0 and compare_op == '!=':
                is_nonempty_check = True
            elif compare_op == '==' and const_value >= 1:
                exact_length = const_value
        else:
            # Pattern: len(x) <op> const
            # len(x) > 0  -> len(x) >= 1
            # len(x) >= 1 -> len(x) >= 1
            # len(x) != 0 -> len(x) >= 1
            # len(x) == n -> len(x) == n
            if const_value == 0 and compare_op == '>':
                is_nonempty_check = True
            elif const_value == 1 and compare_op == '>=':
                is_nonempty_check = True
            elif const_value == 0 and compare_op == '!=':
                is_nonempty_check = True
            elif compare_op == '==' and const_value >= 1:
                exact_length = const_value
        
        if exact_length is not None:
            # Create guard with exact length constraint
            # For len(x) == n, we know indices 0 to n-1 are valid
            return GuardFact(
                guard_type="exact_length",
                variable=len_container,
                extra=str(exact_length),  # Store the exact length
                established_at=block.id,
                condition=f"len({len_container}) == {exact_length}"
            )
        elif is_nonempty_check:
            # Create guard with nonempty constraint (len >= 1)
            return GuardFact(
                guard_type="nonempty",
                variable=len_container,
                extra="len>=1",  # Encodes the Z3 constraint for verification
                established_at=block.id,
                condition=f"len({len_container}) >= 1"
            )
        
        return None
    
    def _check_truthiness_fallthrough_pattern(
        self,
        block: BasicBlock
    ) -> Optional[GuardFact]:
        """
        Check for truthiness guard established by fallthrough from conditional.
        
        Handles patterns like: not data or data[0]
        When we're in the fallthrough block (starts with NOT_TAKEN), we know:
        - For POP_JUMP_IF_TRUE preceded by UNARY_NOT: the original value is truthy
        - For POP_JUMP_IF_FALSE: the original value is truthy
        
        For sequences, truthy means non-empty, so this establishes nonempty.
        """
        if not block.predecessors:
            return None
        
        # Look at the predecessor block to find the conditional pattern
        pred_id = block.predecessors[0]
        pred_block = self.cfg.blocks.get(pred_id)
        if not pred_block or not pred_block.instructions:
            return None
        
        # Find the conditional jump at the end of the predecessor
        instrs = pred_block.instructions
        
        # Look for pattern: LOAD_FAST v, TO_BOOL, [UNARY_NOT], POP_JUMP_IF_xxx
        var_name = None
        has_unary_not = False
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
            
            if instr.opname == 'UNARY_NOT':
                has_unary_not = True
                continue
            
            if instr.opname in ('LOAD_FAST', 'LOAD_FAST_BORROW', 'LOAD_NAME'):
                var_name = instr.argval
                break
        
        if not var_name or not jump_type:
            return None
        
        # Determine if the fallthrough means the variable is truthy/nonempty
        # POP_JUMP_IF_TRUE: jumps if True, fallthrough if False
        # POP_JUMP_IF_FALSE: jumps if False, fallthrough if True
        # 
        # With UNARY_NOT:
        # - `not x` is True when x is falsy, False when x is truthy
        # - POP_JUMP_IF_TRUE on `not x`: jump when x is falsy, fallthrough when x is truthy
        #
        # Without UNARY_NOT:
        # - POP_JUMP_IF_TRUE on x: jump when x is truthy, fallthrough when x is falsy
        # - POP_JUMP_IF_FALSE on x: jump when x is falsy, fallthrough when x is truthy
        
        var_is_truthy_on_fallthrough = False
        
        if has_unary_not:
            # The condition is `not x`
            if 'TRUE' in jump_type:
                # POP_JUMP_IF_TRUE on `not x`: fallthrough when `not x` is False, i.e., x is truthy
                var_is_truthy_on_fallthrough = True
            else:
                # POP_JUMP_IF_FALSE on `not x`: fallthrough when `not x` is True, i.e., x is falsy
                var_is_truthy_on_fallthrough = False
        else:
            # The condition is just x
            if 'FALSE' in jump_type:
                # POP_JUMP_IF_FALSE on x: fallthrough when x is truthy
                var_is_truthy_on_fallthrough = True
            else:
                # POP_JUMP_IF_TRUE on x: fallthrough when x is falsy
                var_is_truthy_on_fallthrough = False
        
        if var_is_truthy_on_fallthrough:
            # Variable is truthy on this path
            # This establishes BOTH nonnull (for objects) AND nonempty (for sequences)
            # We return nonempty which is the stronger condition
            # The nonnull guard is also added by the caller
            return GuardFact(
                guard_type="nonempty",
                variable=var_name,
                extra="len>=1",  # Truthy for sequences means non-empty
                established_at=block.id,
                condition=f"{var_name} is truthy (non-empty/nonnull)"
            )
        else:
            # Variable is FALSY on this path (critical for `if x or x[0]` pattern)
            # For sequences, falsy means EMPTY (len == 0)
            # This is the key insight for detecting IndexError in short-circuit evaluation:
            # In `if x or x[0]`: if x is falsy, we evaluate x[0], but x is empty -> IndexError
            return GuardFact(
                guard_type="empty",
                variable=var_name,
                extra="len==0",  # Falsy for sequences means empty
                established_at=block.id,
                condition=f"{var_name} is falsy (empty/None)"
            )
    
    def _check_truthiness_nonnull_guard(self, block: BasicBlock) -> Optional[GuardFact]:
        """
        Additional check for truthiness establishing nonnull.
        
        When we detect truthiness fallthrough, the variable is also non-None
        because None is falsy. This establishes a separate nonnull guard.
        """
        if not block.predecessors:
            return None
        
        pred_id = block.predecessors[0]
        pred_block = self.cfg.blocks.get(pred_id)
        if not pred_block or not pred_block.instructions:
            return None
        
        instrs = pred_block.instructions
        
        # Look for the same pattern as truthiness fallthrough
        var_name = None
        has_unary_not = False
        jump_type = None
        
        for i in range(len(instrs) - 1, -1, -1):
            instr = instrs[i]
            
            if instr.opname in ('POP_JUMP_IF_TRUE', 'POP_JUMP_IF_FALSE', 
                               'POP_JUMP_FORWARD_IF_TRUE', 'POP_JUMP_FORWARD_IF_FALSE'):
                jump_type = instr.opname
                continue
            
            if instr.opname in ('TO_BOOL', 'COPY'):
                continue
            
            if instr.opname == 'UNARY_NOT':
                has_unary_not = True
                continue
            
            if instr.opname in ('LOAD_FAST', 'LOAD_FAST_BORROW', 'LOAD_NAME'):
                var_name = instr.argval
                break
        
        if not var_name or not jump_type:
            return None
        
        var_is_truthy_on_fallthrough = False
        if has_unary_not:
            if 'TRUE' in jump_type:
                var_is_truthy_on_fallthrough = True
        else:
            if 'FALSE' in jump_type:
                var_is_truthy_on_fallthrough = True
        
        if var_is_truthy_on_fallthrough:
            return GuardFact(
                guard_type="nonnull",
                variable=var_name,
                established_at=block.id,
                condition=f"{var_name} is truthy => nonnull"
            )
        
        return None
    
    def _check_len_ne_fallthrough_pattern(
        self,
        block: BasicBlock
    ) -> Optional[GuardFact]:
        """
        Check for len(x) != n pattern on fallthrough.
        
        Handles patterns like:
            if len(args) != 4:
                return error
            # Here args[0..3] are safe
        
        When we're in the fallthrough block (NOT_TAKEN after POP_JUMP_IF_FALSE),
        and the predecessor had len(x) != n, we know len(x) == n.
        
        NOTE: This handles the case where NOT_TAKEN indicates fallthrough.
        The guard is established on THIS block (the fallthrough), but we also
        need to check if we're the jump target of a len() != check.
        """
        if not block.predecessors:
            return None
        
        # Look at the predecessor block
        pred_id = block.predecessors[0]
        pred_block = self.cfg.blocks.get(pred_id)
        if not pred_block or not pred_block.instructions:
            return None
        
        instrs = pred_block.instructions
        
        # Look for pattern: LOAD_GLOBAL len, LOAD_FAST x, CALL, LOAD_CONST n, COMPARE_OP !=, POP_JUMP_IF_FALSE
        # When POP_JUMP_IF_FALSE falls through, the != was True (condition True, no jump)
        # When POP_JUMP_IF_FALSE jumps, the != was False, so len(x) == n
        
        # Find the jump instruction
        jump_instr = None
        jump_target = None
        for i in range(len(instrs) - 1, -1, -1):
            if instrs[i].opname in ('POP_JUMP_IF_FALSE', 'POP_JUMP_FORWARD_IF_FALSE'):
                jump_instr = instrs[i]
                jump_target = instrs[i].argval
                break
        
        if not jump_instr:
            return None
        
        # Determine if we're the fallthrough or the jump target
        # For NOT_TAKEN blocks, we're the fallthrough (condition was True)
        # We need to check if THIS block is the JUMP TARGET (condition was False)
        is_jump_target = False
        if block.instructions and block.instructions[0].offset == jump_target:
            is_jump_target = True
        
        # Look for COMPARE_OP != before the jump
        compare_idx = None
        compare_op = None
        for i in range(len(instrs) - 1, -1, -1):
            if instrs[i].opname == 'COMPARE_OP':
                compare_idx = i
                compare_op = instrs[i].argval
                break
        
        if compare_idx is None or compare_op != '!=':
            return None
        
        # Look for len() call and constant
        container = None
        const_value = None
        
        for i in range(compare_idx - 1, -1, -1):
            instr = instrs[i]
            
            # Find the constant
            if instr.opname in ('LOAD_CONST', 'LOAD_SMALL_INT') and isinstance(instr.argval, int):
                const_value = instr.argval
            
            # Find len() call pattern
            if instr.opname in ('CALL', 'CALL_FUNCTION'):
                # Look back for LOAD_GLOBAL len, LOAD_FAST x
                for j in range(max(0, i - 4), i):
                    if instrs[j].opname in ('LOAD_GLOBAL', 'LOAD_BUILTIN', 'LOAD_NAME'):
                        if instrs[j].argval == 'len':
                            # Next instruction should be the container
                            if j + 1 < i:
                                container_instr = instrs[j + 1]
                                if container_instr.opname in ('LOAD_FAST', 'LOAD_FAST_BORROW', 'LOAD_NAME', 'LOAD_GLOBAL'):
                                    # Check for chained attr: LOAD_FAST x, LOAD_ATTR a → len(x.a)
                                    if j + 2 < i and instrs[j + 2].opname == 'LOAD_ATTR':
                                        container = f"{container_instr.argval}.{instrs[j + 2].argval}"
                                    else:
                                        container = container_instr.argval
                            break
                break
        
        if not container or const_value is None or const_value < 1:
            return None
        
        # For POP_JUMP_IF_FALSE:
        # - Fallthrough (NOT_TAKEN): condition was True (len != n is True, so len != n)
        # - Jump target: condition was False (len != n is False, so len == n)
        
        if is_jump_target:
            # We're the jump target - condition was False, so len == n
            return GuardFact(
                guard_type="exact_length",
                variable=container,
                extra=str(const_value),
                established_at=block.id,
                condition=f"len({container}) == {const_value} (from != jump target)"
            )
        
        return None

    def _propagate_guards(self):
        """
        Propagate guards using dominance.
        
        A guard is valid at block B if:
        1. The guard-establishing block dominates B, AND
        2. The guard was established on the path taken to reach B
        """
        # For each block, collect guards from all dominating blocks
        for block_id in self.cfg.blocks:
            valid_guards = set()
            
            # Get all blocks that dominate this one
            dominators = self.cfg.dominators.get(block_id, set())
            
            for dom_id in dominators:
                # Add guards established by this dominator
                established = self.block_establishes.get(dom_id, set())
                
                for guard in established:
                    # Check if this guard is on the path to block_id
                    # For now, conservatively include all dominating guards
                    # TODO: refine with edge-sensitive analysis
                    valid_guards.add(guard)
            
            self.block_guards[block_id] = valid_guards
    
    def get_guards_at_offset(self, offset: int) -> Set[GuardFact]:
        """Get guards valid at a specific instruction offset."""
        block = self.cfg.get_block_for_offset(offset)
        if block:
            return self.block_guards.get(block.id, set())
        return set()
    
    def has_guard(self, offset: int, guard_type: str, variable: str) -> bool:
        """Check if a specific guard is established at an offset."""
        guards = self.get_guards_at_offset(offset)
        for g in guards:
            if g.guard_type == guard_type and g.variable == variable:
                return True
        return False


# ============================================================================
# WillCatchAt Predicate
# ============================================================================

class ExceptionCatchAnalyzer:
    """
    Analyzes exception catching behavior.
    
    Implements the WillCatchAt(pc, exc) predicate from barrier-certificate-theory.tex §9.7.
    """
    
    def __init__(self, cfg: ControlFlowGraph):
        self.cfg = cfg
    
    def will_catch_at(self, offset: int, exception_type: str) -> bool:
        """
        Check if an exception of given type will be caught at this offset.
        
        This is an intraprocedural approximation: we check if there's a handler
        in the exception table that covers this offset.
        """
        handler = self.cfg.get_exception_handler(offset)
        if handler is None:
            return False
        
        # Check if handler catches this exception type
        # If exception_types is empty, it's a catch-all
        if not handler.exception_types:
            return True
        
        # Check if exception_type is in the caught types
        # This requires knowing the exception hierarchy
        # For now, exact match or catch-all
        return exception_type in handler.exception_types
    
    def get_handler_at(self, offset: int) -> Optional[int]:
        """Get handler offset for exceptions at this offset."""
        handler = self.cfg.get_exception_handler(offset)
        if handler:
            return handler.handler_offset
        return None
    
    def is_in_try_block(self, offset: int) -> bool:
        """Check if offset is within any try block."""
        return self.cfg.get_exception_handler(offset) is not None


# ============================================================================
# Convenience Functions
# ============================================================================

def analyze_guards(code: types.CodeType) -> Tuple[ControlFlowGraph, Dict[int, Set[GuardFact]]]:
    """
    Perform complete guard analysis on a code object.
    
    Returns:
        (cfg, guard_map) where guard_map maps block_id -> valid guards
    """
    cfg = build_cfg(code)
    analyzer = GuardAnalyzer(cfg)
    guards = analyzer.analyze()
    return cfg, guards


def print_cfg(cfg: ControlFlowGraph, show_guards: bool = True):
    """Print CFG for debugging."""
    print(f"CFG for {cfg.code.co_name}")
    print(f"Entry: block {cfg.entry_block}")
    print(f"Exits: {cfg.exit_blocks}")
    print(f"Loop headers: {cfg.loop_headers}")
    print()
    
    guard_analyzer = None
    if show_guards:
        guard_analyzer = GuardAnalyzer(cfg)
        guard_analyzer.analyze()
    
    for bid, block in sorted(cfg.blocks.items()):
        print(f"Block {bid}:")
        print(f"  Offsets: {block.start_offset} - {block.end_offset}")
        print(f"  Instructions:")
        for instr in block.instructions:
            print(f"    {instr.offset:4d}: {instr.opname} {instr.argrepr}")
        
        print(f"  Successors: {[(s, e.name) for s, e, _ in block.successors]}")
        print(f"  Predecessors: {block.predecessors}")
        
        if block.exception_handler is not None:
            print(f"  Exception handler: block {block.exception_handler}")
        
        print(f"  Loads: {block.loads}")
        print(f"  Stores: {block.stores}")
        
        # Show dominators
        doms = cfg.dominators.get(bid, set())
        print(f"  Dominated by: {sorted(doms)}")
        
        if guard_analyzer and bid in guard_analyzer.block_guards:
            guards = guard_analyzer.block_guards[bid]
            if guards:
                print(f"  Guards valid: {[str(g) for g in guards]}")
        
        print()
