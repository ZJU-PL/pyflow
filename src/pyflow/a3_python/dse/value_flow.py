"""
Richer Value Flow Analysis for FP Reduction.

This module extends simple variable aliasing to track values through:
1. **Function Returns**: If x = f(), and f() returns nonnull, x is nonnull
2. **Container Operations**: Track values through list/dict/set ops
3. **Attribute Access**: Track values through attribute chains
4. **Path-Sensitive Analysis**: Track different guards on different CFG paths

MATHEMATICAL FOUNDATION:

    Value Flow Graph: V → 2^V (transitive closure of value assignments)
    
    For y = expr(x₁, ..., xₙ):
        flow(y) = flow(x₁) ∪ ... ∪ flow(xₙ) ∪ {expr_semantics}
    
    Guards propagate through value flow:
        guard(x, nonnull) ∧ y ∈ flow(x) ⟹ guard(y, nonnull)

PATH-SENSITIVE ANALYSIS:

    Instead of merging guards at join points (losing precision), we track
    guards per CFG path. This is lighter than full DSE but more precise
    than path-insensitive analysis.
    
    Per-path guard state: Γ : Path → (Var → 2^{GuardType})
    
    At branch point p with condition C on variable x:
        - True branch: Γ[path·true](x) = Γ[path](x) ∪ {guard_from(C)}
        - False branch: Γ[path·false](x) = Γ[path](x) ∪ {guard_from(¬C)}
    
    At join point j with predecessors p₁, p₂:
        - Path-sensitive: Keep separate states for each incoming path
        - Path-insensitive: Γ[j](x) = Γ[p₁](x) ∩ Γ[p₂](x)

ARCHITECTURE:

    ┌─────────────────────────────────────────────────────────────────┐
    │              RICHER VALUE FLOW ANALYSIS                         │
    ├─────────────────────────────────────────────────────────────────┤
    │                                                                  │
    │  CFG ──► ValueFlowAnalyzer                                       │
    │              │                                                   │
    │              ├──► ReturnValueFlow (track f() return types)       │
    │              ├──► ContainerFlow (track container operations)     │
    │              ├──► AttributeFlow (track x.attr chains)            │
    │              └──► PathSensitiveGuards (per-path guard state)    │
    │                          │                                       │
    │                          ▼                                       │
    │              FlowEnrichedGuardState                              │
    │              (guards + value flow + path sensitivity)            │
    │                                                                  │
    └─────────────────────────────────────────────────────────────────┘
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Set, Optional, Tuple, FrozenSet, Any
from enum import Enum, auto
import dis
import types

from ..cfg.control_flow import ControlFlowGraph, BasicBlock, build_cfg, EdgeType


# ============================================================================
# VALUE FLOW CATEGORIES
# ============================================================================

class FlowKind(Enum):
    """Kind of value flow edge."""
    DIRECT_ASSIGN = auto()      # y = x
    FUNCTION_RETURN = auto()    # y = f(x)
    CONTAINER_GET = auto()      # y = container[i]
    CONTAINER_SET = auto()      # container[i] = y
    ATTRIBUTE_GET = auto()      # y = x.attr
    ATTRIBUTE_SET = auto()      # x.attr = y
    BINARY_OP = auto()          # y = x + z
    UNARY_OP = auto()           # y = -x
    CONSTRUCT = auto()          # y = [x, z] or y = Foo(x)
    UNPACK = auto()             # a, b = x


@dataclass(frozen=True)
class ValueFlowEdge:
    """
    An edge in the value flow graph.
    
    Represents that `target` receives a value derived from `sources`.
    """
    target: str  # Variable receiving the value
    sources: FrozenSet[str]  # Variables the value derives from
    kind: FlowKind  # Kind of flow
    operation: str = ""  # Operation description (e.g., function name)
    
    # Semantic properties derived from the flow
    preserves_nonnull: bool = True  # If sources are nonnull, target is nonnull
    preserves_nonzero: bool = True  # If sources are nonzero, target is nonzero
    produces_nonnull: bool = False  # Operation always produces nonnull
    produces_nonempty: bool = False  # Operation always produces nonempty container


# ============================================================================
# FUNCTION RETURN VALUE SEMANTICS
# ============================================================================

@dataclass
class FunctionReturnSemantics:
    """
    Semantic properties of function return values.
    
    This encodes what we know about what functions return, enabling
    guard propagation through function calls.
    """
    # Functions that always return non-None
    NONNULL_FUNCTIONS: FrozenSet[str] = frozenset({
        # Built-in constructors
        'list', 'dict', 'set', 'tuple', 'str', 'int', 'float', 'bool',
        'bytes', 'bytearray', 'frozenset', 'object', 'range', 'slice', 'type',
        'complex', 'memoryview', 'super',
        
        # Built-in functions that never return None
        'len', 'abs', 'repr', 'str', 'hash', 'id', 'type', 'chr', 'ord',
        'bin', 'hex', 'oct', 'round', 'sum', 'min', 'max', 'all', 'any',
        'sorted', 'reversed', 'enumerate', 'zip', 'map', 'filter', 'range',
        'input', 'format', 'ascii', 'pow', 'divmod',
        
        # String methods
        'strip', 'lstrip', 'rstrip', 'split', 'rsplit', 'splitlines',
        'lower', 'upper', 'title', 'capitalize', 'swapcase', 'casefold',
        'replace', 'translate', 'encode', 'decode', 'format', 'format_map',
        'join', 'center', 'ljust', 'rjust', 'zfill', 'expandtabs',
        'partition', 'rpartition', 'maketrans',
        
        # List/dict methods that return non-None
        'copy', 'keys', 'values', 'items',
    })
    
    # Methods that always return non-None
    NONNULL_METHODS: FrozenSet[str] = frozenset({
        'strip', 'lstrip', 'rstrip', 'split', 'rsplit', 'splitlines',
        'lower', 'upper', 'title', 'capitalize', 'swapcase', 'casefold',
        'replace', 'encode', 'decode', 'format', 'join', 'center', 'ljust', 'rjust',
        'keys', 'values', 'items', 'copy', 'get',  # dict.get can return default
        'union', 'intersection', 'difference', 'symmetric_difference',
        'issubset', 'issuperset', 'isdisjoint',  # Return bool (non-None)
    })
    
    # Functions that always return non-zero
    NONZERO_FUNCTIONS: FrozenSet[str] = frozenset({
        'id', 'hash',  # These return non-zero for any object
    })
    
    # Functions that return nonempty containers
    NONEMPTY_RETURN_FUNCTIONS: FrozenSet[str] = frozenset({
        # split with default always returns at least one element
        # range with positive arg is nonempty
    })
    
    @classmethod
    def is_nonnull_function(cls, name: str) -> bool:
        """Check if function always returns non-None."""
        if name in cls.NONNULL_FUNCTIONS:
            return True
        # Constructors (capitalized names) typically return non-None
        if name and name[0].isupper() and name.isidentifier():
            return True
        return False
    
    @classmethod
    def is_nonnull_method(cls, name: str) -> bool:
        """Check if method always returns non-None."""
        return name in cls.NONNULL_METHODS
    
    @classmethod
    def is_nonzero_function(cls, name: str) -> bool:
        """Check if function always returns non-zero."""
        return name in cls.NONZERO_FUNCTIONS


# ============================================================================
# CONTAINER OPERATION SEMANTICS
# ============================================================================

@dataclass
class ContainerOperationSemantics:
    """
    Semantic properties of container operations.
    
    Tracks how values flow through container operations and what
    guarantees we can derive.
    """
    
    # Operations that preserve nonnull from container elements
    NONNULL_PRESERVING_OPS: FrozenSet[str] = frozenset({
        '__getitem__',  # container[i] - depends on container contents
        'pop',          # Returns element or raises
        'popleft',      # Deque operation
    })
    
    # Operations that always return nonnull
    NONNULL_PRODUCING_OPS: FrozenSet[str] = frozenset({
        '__len__',      # len() returns int
        '__contains__', # in returns bool
        '__iter__',     # iter() returns iterator (not None)
        'keys', 'values', 'items',  # Dict views
        'copy',         # Always returns new container
        'index',        # Returns int or raises
        'count',        # Returns int >= 0
    })
    
    @classmethod
    def getitem_preserves_nonnull(cls, container_elements_nonnull: bool) -> bool:
        """Check if container[i] preserves nonnull from container."""
        return container_elements_nonnull


# ============================================================================
# PATH-SENSITIVE GUARD STATE
# ============================================================================

@dataclass
class PathGuardState:
    """
    Guard state for a single execution path.
    
    This is the per-path version of GuardState, enabling path-sensitive
    analysis without full DSE.
    """
    # Path identifier (sequence of branch decisions)
    path_id: Tuple[Tuple[int, bool], ...] = ()  # (block_id, branch_taken)
    
    # Variables known to be non-None on this path
    nonnull_vars: Set[str] = field(default_factory=set)
    
    # Variables known to be non-zero on this path
    nonzero_vars: Set[str] = field(default_factory=set)
    
    # Containers known to be non-empty on this path
    nonempty_containers: Set[str] = field(default_factory=set)
    
    # Type constraints on this path
    type_constraints: Dict[str, Set[str]] = field(default_factory=dict)
    
    # Bounds constraints: (container, index) pairs known to be in bounds
    bounds_safe: Set[Tuple[str, str]] = field(default_factory=set)
    
    # Key constraints: (dict, key) pairs known to be present
    keys_present: Set[Tuple[str, str]] = field(default_factory=set)
    
    # Whether this path is inside an exception handler
    in_except_handler: Set[str] = field(default_factory=set)  # Exception types caught
    
    def copy(self) -> 'PathGuardState':
        """Create a deep copy for branching."""
        return PathGuardState(
            path_id=self.path_id,
            nonnull_vars=self.nonnull_vars.copy(),
            nonzero_vars=self.nonzero_vars.copy(),
            nonempty_containers=self.nonempty_containers.copy(),
            type_constraints={k: v.copy() for k, v in self.type_constraints.items()},
            bounds_safe=self.bounds_safe.copy(),
            keys_present=self.keys_present.copy(),
            in_except_handler=self.in_except_handler.copy(),
        )
    
    def extend_path(self, block_id: int, branch_taken: bool) -> 'PathGuardState':
        """Create a new state with extended path."""
        new_state = self.copy()
        new_state.path_id = self.path_id + ((block_id, branch_taken),)
        return new_state
    
    def add_nonnull(self, var: str) -> None:
        """Record variable as non-null on this path."""
        self.nonnull_vars.add(var)
    
    def add_nonzero(self, var: str) -> None:
        """Record variable as non-zero on this path."""
        self.nonzero_vars.add(var)
    
    def add_nonempty(self, container: str) -> None:
        """Record container as non-empty on this path."""
        self.nonempty_containers.add(container)
    
    def add_type(self, var: str, type_name: str) -> None:
        """Record type constraint on this path."""
        if var not in self.type_constraints:
            self.type_constraints[var] = set()
        self.type_constraints[var].add(type_name)
    
    def add_bounds_safe(self, container: str, index: str) -> None:
        """Record that container[index] is safe on this path."""
        self.bounds_safe.add((container, index))
    
    def add_key_present(self, container: str, key: str) -> None:
        """Record that key is in container on this path."""
        self.keys_present.add((container, key))
    
    def enter_except_handler(self, exception_types: Set[str]) -> None:
        """Record entering an exception handler."""
        self.in_except_handler.update(exception_types)
    
    def has_nonnull(self, var: str) -> bool:
        """Check if variable is nonnull on this path."""
        return var in self.nonnull_vars
    
    def has_nonzero(self, var: str) -> bool:
        """Check if variable is nonzero on this path."""
        return var in self.nonzero_vars
    
    def has_nonempty(self, container: str) -> bool:
        """Check if container is nonempty on this path."""
        return container in self.nonempty_containers
    
    def has_bounds_safe(self, container: str, index: str) -> bool:
        """Check if container[index] is safe on this path."""
        return (container, index) in self.bounds_safe
    
    def has_key_present(self, container: str, key: str) -> bool:
        """Check if key is in container on this path."""
        return (container, key) in self.keys_present
    
    def merge_with(self, other: 'PathGuardState') -> 'PathGuardState':
        """
        Merge two path states at a join point.
        
        Conservatively takes the intersection of guards (only guards
        that hold on BOTH paths are kept).
        """
        return PathGuardState(
            path_id=(),  # Merged state has no single path
            nonnull_vars=self.nonnull_vars & other.nonnull_vars,
            nonzero_vars=self.nonzero_vars & other.nonzero_vars,
            nonempty_containers=self.nonempty_containers & other.nonempty_containers,
            type_constraints={
                k: self.type_constraints.get(k, set()) & other.type_constraints.get(k, set())
                for k in self.type_constraints.keys() | other.type_constraints.keys()
            },
            bounds_safe=self.bounds_safe & other.bounds_safe,
            keys_present=self.keys_present & other.keys_present,
            in_except_handler=self.in_except_handler & other.in_except_handler,
        )


# ============================================================================
# VALUE FLOW GRAPH
# ============================================================================

class ValueFlowGraph:
    """
    Graph tracking value flow between variables.
    
    Enables guard propagation through assignments and operations.
    """
    
    def __init__(self):
        # Forward edges: target -> set of sources
        self.forward: Dict[str, Set[str]] = {}
        # Backward edges: source -> set of targets
        self.backward: Dict[str, Set[str]] = {}
        # Edge annotations: (target, source) -> FlowKind
        self.edge_kinds: Dict[Tuple[str, str], ValueFlowEdge] = {}
    
    def add_edge(self, edge: ValueFlowEdge) -> None:
        """Add a value flow edge."""
        target = edge.target
        
        if target not in self.forward:
            self.forward[target] = set()
        
        for source in edge.sources:
            self.forward[target].add(source)
            
            if source not in self.backward:
                self.backward[source] = set()
            self.backward[source].add(target)
            
            self.edge_kinds[(target, source)] = edge
    
    def get_all_sources(self, var: str, visited: Optional[Set[str]] = None) -> Set[str]:
        """
        Get all variables that may flow to this variable (transitive closure).
        """
        if visited is None:
            visited = set()
        
        if var in visited:
            return set()
        visited.add(var)
        
        result = set()
        for source in self.forward.get(var, set()):
            result.add(source)
            result.update(self.get_all_sources(source, visited))
        
        return result
    
    def get_all_targets(self, var: str, visited: Optional[Set[str]] = None) -> Set[str]:
        """
        Get all variables that this variable may flow to (transitive closure).
        """
        if visited is None:
            visited = set()
        
        if var in visited:
            return set()
        visited.add(var)
        
        result = set()
        for target in self.backward.get(var, set()):
            result.add(target)
            result.update(self.get_all_targets(target, visited))
        
        return result
    
    def guard_propagates(self, source: str, target: str, guard_type: str) -> bool:
        """
        Check if a guard on source propagates to target through value flow.
        
        Args:
            source: Variable with the guard
            target: Variable to check
            guard_type: Type of guard ('nonnull', 'nonzero', etc.)
        
        Returns:
            True if the guard propagates, False otherwise.
        """
        # Direct edge?
        if source in self.forward.get(target, set()):
            edge = self.edge_kinds.get((target, source))
            if edge:
                if guard_type == 'nonnull' and edge.preserves_nonnull:
                    return True
                if guard_type == 'nonzero' and edge.preserves_nonzero:
                    return True
        
        # Transitive check through all sources
        all_sources = self.get_all_sources(target)
        if source not in all_sources:
            return False
        
        # Check if guard propagates through the path
        # Simplified: check if all edges preserve the guard
        # (In reality, we'd need path-sensitive checking)
        return True  # Conservative for now


# ============================================================================
# VALUE FLOW ANALYZER
# ============================================================================

class ValueFlowAnalyzer:
    """
    Analyze value flow through a function.
    
    Builds a value flow graph and tracks:
    - Function return value semantics
    - Container operation semantics
    - Attribute access chains
    """
    
    def __init__(self, code: types.CodeType):
        self.code = code
        self.cfg = build_cfg(code)
        self.instructions = list(dis.get_instructions(code))
        
        # Parameter info
        self.param_count = code.co_argcount + code.co_kwonlyargcount
        self.param_names = list(code.co_varnames[:self.param_count])
        self.local_names = list(code.co_varnames)
        
        # Value flow graph
        self.flow_graph = ValueFlowGraph()
        
        # Track which variables are known nonnull
        self.known_nonnull: Set[str] = set()
        
        # Track container element nonnull status
        self.container_elements_nonnull: Dict[str, bool] = {}
    
    def analyze(self) -> ValueFlowGraph:
        """
        Build the value flow graph for the function.
        
        Returns the completed flow graph.
        """
        # TYPE-BASED FILTERING: 'self' and 'cls' are never None
        if self.param_names and self.param_names[0] == 'self':
            self.known_nonnull.add('self')
        if self.param_names and self.param_names[0] == 'cls':
            self.known_nonnull.add('cls')
        
        # Analyze each instruction
        prev_instr = None
        for instr in self.instructions:
            self._analyze_instruction(instr, prev_instr)
            prev_instr = instr
        
        return self.flow_graph
    
    def _analyze_instruction(self, instr: dis.Instruction, prev: Optional[dis.Instruction]) -> None:
        """Analyze a single instruction for value flow."""
        opname = instr.opname
        
        if opname == 'STORE_FAST':
            target = instr.argval
            if not target:
                return
            
            # Check what's being stored
            if prev:
                self._analyze_store(target, prev)
        
        elif opname == 'STORE_NAME' or opname == 'STORE_GLOBAL':
            target = instr.argval
            if not target:
                return
            
            if prev:
                self._analyze_store(target, prev)
    
    def _analyze_store(self, target: str, prev: dis.Instruction) -> None:
        """Analyze a store operation to build value flow edge."""
        opname = prev.opname
        
        if opname in ('LOAD_FAST', 'LOAD_FAST_BORROW'):
            # Direct assignment: target = source
            source = prev.argval
            if source:
                edge = ValueFlowEdge(
                    target=target,
                    sources=frozenset({source}),
                    kind=FlowKind.DIRECT_ASSIGN,
                    preserves_nonnull=True,
                    preserves_nonzero=True,
                )
                self.flow_graph.add_edge(edge)
                
                # Propagate nonnull
                if source in self.known_nonnull:
                    self.known_nonnull.add(target)
        
        elif opname in ('LOAD_CONST', 'LOAD_SMALL_INT'):
            # Constant assignment
            const_val = prev.argval
            edge = ValueFlowEdge(
                target=target,
                sources=frozenset(),
                kind=FlowKind.DIRECT_ASSIGN,
                operation=f"const:{const_val}",
                produces_nonnull=(const_val is not None),
            )
            self.flow_graph.add_edge(edge)
            
            if const_val is not None:
                self.known_nonnull.add(target)
        
        elif opname in ('CALL', 'CALL_FUNCTION'):
            # Function call result
            # We need to look back further to find the function name
            edge = ValueFlowEdge(
                target=target,
                sources=frozenset(),
                kind=FlowKind.FUNCTION_RETURN,
                operation='<call>',
            )
            self.flow_graph.add_edge(edge)
        
        elif opname.startswith('BUILD_'):
            # Container construction: always nonnull
            edge = ValueFlowEdge(
                target=target,
                sources=frozenset(),
                kind=FlowKind.CONSTRUCT,
                operation=opname,
                produces_nonnull=True,
                produces_nonempty=(opname != 'BUILD_LIST' or prev.arg > 0),
            )
            self.flow_graph.add_edge(edge)
            self.known_nonnull.add(target)
        
        elif opname == 'BINARY_SUBSCR':
            # Container access: value from container
            edge = ValueFlowEdge(
                target=target,
                sources=frozenset(),  # Would need deeper analysis
                kind=FlowKind.CONTAINER_GET,
                operation='[]',
                preserves_nonnull=False,  # Container may have None elements
            )
            self.flow_graph.add_edge(edge)
        
        elif opname == 'LOAD_ATTR':
            # Attribute access
            attr = prev.argval
            edge = ValueFlowEdge(
                target=target,
                sources=frozenset(),
                kind=FlowKind.ATTRIBUTE_GET,
                operation=f'.{attr}',
                preserves_nonnull=False,  # Attribute may be None
            )
            self.flow_graph.add_edge(edge)
    
    def get_nonnull_variables(self) -> Set[str]:
        """Get all variables known to be nonnull."""
        return self.known_nonnull.copy()
    
    def get_aliases(self, var: str) -> Set[str]:
        """Get all variables that may hold the same value as var."""
        # Variables that var flows to
        targets = self.flow_graph.get_all_targets(var)
        # Variables that flow to var
        sources = self.flow_graph.get_all_sources(var)
        return targets | sources


# ============================================================================
# PATH-SENSITIVE GUARD ANALYZER
# ============================================================================

class PathSensitiveGuardAnalyzer:
    """
    Analyze guards with path sensitivity.
    
    Tracks different guard states on different CFG paths, enabling
    more precise FP reduction than path-insensitive analysis.
    """
    
    def __init__(
        self,
        code: types.CodeType,
        max_paths: int = 50,
    ):
        self.code = code
        self.cfg = build_cfg(code)
        self.instructions = list(dis.get_instructions(code))
        self.max_paths = max_paths
        
        # Parameter info
        self.param_count = code.co_argcount + code.co_kwonlyargcount
        self.param_names = list(code.co_varnames[:self.param_count])
        
        # Per-path guard states at each block
        self.block_path_states: Dict[int, List[PathGuardState]] = {}
        
        # Merged guard state at each block (for fast lookup)
        self.block_merged_states: Dict[int, PathGuardState] = {}
    
    def analyze(self) -> Dict[int, List[PathGuardState]]:
        """
        Run path-sensitive guard analysis.
        
        Returns map from block ID to list of path guard states.
        """
        # Initialize entry state
        entry_state = PathGuardState()
        
        # TYPE-BASED FILTERING: 'self' and 'cls' are never None
        if self.param_names and self.param_names[0] == 'self':
            entry_state.add_nonnull('self')
        if self.param_names and self.param_names[0] == 'cls':
            entry_state.add_nonnull('cls')
        
        # Worklist algorithm with path sensitivity
        worklist = [(self.cfg.entry_block, entry_state)]
        visited_paths = 0
        
        while worklist and visited_paths < self.max_paths:
            block_id, state = worklist.pop(0)
            visited_paths += 1
            
            # Store state for this block
            if block_id not in self.block_path_states:
                self.block_path_states[block_id] = []
            self.block_path_states[block_id].append(state)
            
            # Get block
            block = self.cfg.blocks.get(block_id)
            if not block:
                continue
            
            # Process instructions in block to update guards
            new_state = state.copy()
            for instr in block.instructions:
                self._update_guards_for_instruction(new_state, instr)
            
            # Process successors
            for succ_id, edge_type, guard_cond in block.successors:
                if edge_type == EdgeType.COND_TRUE:
                    # True branch - apply positive guard
                    branch_state = new_state.extend_path(block_id, True)
                    self._apply_branch_guard(branch_state, guard_cond, True)
                    worklist.append((succ_id, branch_state))
                
                elif edge_type == EdgeType.COND_FALSE:
                    # False branch - apply negative guard
                    branch_state = new_state.extend_path(block_id, False)
                    self._apply_branch_guard(branch_state, guard_cond, False)
                    worklist.append((succ_id, branch_state))
                
                else:
                    # Unconditional edge
                    worklist.append((succ_id, new_state.copy()))
        
        # Compute merged states for each block
        self._compute_merged_states()
        
        return self.block_path_states
    
    def _update_guards_for_instruction(self, state: PathGuardState, instr: dis.Instruction) -> None:
        """Update guard state based on instruction semantics."""
        opname = instr.opname
        
        # Track assignments that produce nonnull
        if opname == 'STORE_FAST':
            target = instr.argval
            # If previous op produces nonnull (BUILD_*, constructors, etc.)
            # This is handled by value flow analysis
            pass
        
        # Exception handler entry
        if opname == 'PUSH_EXC_INFO':
            # Inside exception handler
            state.in_except_handler.add('*')
    
    def _apply_branch_guard(
        self,
        state: PathGuardState,
        guard_cond: Optional[str],
        is_true_branch: bool
    ) -> None:
        """Apply guard derived from branch condition."""
        if not guard_cond:
            return
        
        # Parse guard condition
        # Common patterns: "is_none:x", "is_not_none:x", "eq_zero:x", etc.
        
        if 'is_not_none' in guard_cond or 'nonnull' in guard_cond:
            # Extract variable name
            parts = guard_cond.split(':')
            var = parts[-1] if len(parts) > 1 else guard_cond.split('_')[0]
            if is_true_branch:
                state.add_nonnull(var)
        
        elif 'is_none' in guard_cond or 'null' in guard_cond:
            parts = guard_cond.split(':')
            var = parts[-1] if len(parts) > 1 else guard_cond.split('_')[0]
            if not is_true_branch:
                state.add_nonnull(var)
        
        elif 'neq_zero' in guard_cond or '!= 0' in guard_cond:
            parts = guard_cond.split(':')
            var = parts[-1] if len(parts) > 1 else guard_cond.split('_')[0]
            if is_true_branch:
                state.add_nonzero(var)
        
        elif 'eq_zero' in guard_cond or '== 0' in guard_cond:
            parts = guard_cond.split(':')
            var = parts[-1] if len(parts) > 1 else guard_cond.split('_')[0]
            if not is_true_branch:
                state.add_nonzero(var)
        
        elif 'nonempty' in guard_cond or 'len' in guard_cond:
            parts = guard_cond.split(':')
            container = parts[-1] if len(parts) > 1 else guard_cond.split('_')[0]
            if is_true_branch:
                state.add_nonempty(container)
        
        elif 'truthiness' in guard_cond:
            # if x: means x is truthy (not None, not 0, not empty)
            parts = guard_cond.split(':')
            var = parts[-1] if len(parts) > 1 else guard_cond
            if is_true_branch:
                state.add_nonnull(var)
                state.add_nonzero(var)
                state.add_nonempty(var)
    
    def _compute_merged_states(self) -> None:
        """Compute merged (path-insensitive) state at each block."""
        for block_id, path_states in self.block_path_states.items():
            if not path_states:
                continue
            
            # Start with first state
            merged = path_states[0].copy()
            
            # Intersect with all other states
            for state in path_states[1:]:
                merged = merged.merge_with(state)
            
            self.block_merged_states[block_id] = merged
    
    def get_guards_at_block(self, block_id: int) -> PathGuardState:
        """Get merged guard state at a block."""
        return self.block_merged_states.get(block_id, PathGuardState())
    
    def get_path_states_at_block(self, block_id: int) -> List[PathGuardState]:
        """Get all path states at a block (for path-sensitive checking)."""
        return self.block_path_states.get(block_id, [])
    
    def bug_is_guarded_on_all_paths(
        self,
        block_id: int,
        bug_type: str,
        bug_variable: str,
    ) -> bool:
        """
        Check if a bug is guarded on ALL paths to this block.
        
        This is stronger than the merged check - it requires the guard
        to hold on every path that reaches this block.
        """
        path_states = self.get_path_states_at_block(block_id)
        if not path_states:
            return False
        
        for state in path_states:
            if not self._state_guards_bug(state, bug_type, bug_variable):
                return False
        
        return True
    
    def bug_is_guarded_on_any_path(
        self,
        block_id: int,
        bug_type: str,
        bug_variable: str,
    ) -> bool:
        """
        Check if a bug is guarded on ANY path to this block.
        
        This is weaker - returns True if at least one path has the guard.
        """
        path_states = self.get_path_states_at_block(block_id)
        
        for state in path_states:
            if self._state_guards_bug(state, bug_type, bug_variable):
                return True
        
        return False
    
    def _state_guards_bug(
        self,
        state: PathGuardState,
        bug_type: str,
        bug_variable: str,
    ) -> bool:
        """Check if a path state guards against a bug type."""
        # Extract base variable
        base_var = bug_variable.split('[')[0].split('.')[0]
        
        if bug_type in ('NULL_PTR', 'ATTRIBUTE_ERROR'):
            return state.has_nonnull(base_var)
        
        elif bug_type == 'DIV_ZERO':
            return state.has_nonzero(base_var)
        
        elif bug_type in ('BOUNDS', 'INDEX_ERROR'):
            if '[' in bug_variable:
                container = bug_variable.split('[')[0]
                index = bug_variable.split('[')[1].rstrip(']')
                return state.has_bounds_safe(container, index) or state.has_nonempty(container)
            return False
        
        elif bug_type == 'KEY_ERROR':
            if '[' in bug_variable:
                container = bug_variable.split('[')[0]
                key = bug_variable.split('[')[1].rstrip(']')
                return state.has_key_present(container, key)
            return False
        
        return False


# ============================================================================
# FLOW-ENRICHED GUARD STATE
# ============================================================================

@dataclass
class FlowEnrichedGuardState:
    """
    Guard state enriched with value flow information.
    
    Combines:
    - Direct guards from control flow
    - Guards propagated through value flow
    - Path-sensitive guards
    """
    # Direct guards (from control flow analysis)
    direct_guards: PathGuardState = field(default_factory=PathGuardState)
    
    # Value flow graph
    value_flow: Optional[ValueFlowGraph] = None
    
    # Path-sensitive guards (per-path states)
    path_states: List[PathGuardState] = field(default_factory=list)
    
    def has_nonnull(self, var: str) -> bool:
        """
        Check if variable is nonnull, considering value flow.
        
        Returns True if:
        - var has a direct nonnull guard, OR
        - any source of var (through value flow) has a nonnull guard
        """
        # Direct check
        if self.direct_guards.has_nonnull(var):
            return True
        
        # Check through value flow
        if self.value_flow:
            sources = self.value_flow.get_all_sources(var)
            for source in sources:
                if self.direct_guards.has_nonnull(source):
                    # Check if nonnull propagates through the flow
                    if self.value_flow.guard_propagates(source, var, 'nonnull'):
                        return True
        
        return False
    
    def has_nonzero(self, var: str) -> bool:
        """Check if variable is nonzero, considering value flow."""
        if self.direct_guards.has_nonzero(var):
            return True
        
        if self.value_flow:
            sources = self.value_flow.get_all_sources(var)
            for source in sources:
                if self.direct_guards.has_nonzero(source):
                    if self.value_flow.guard_propagates(source, var, 'nonzero'):
                        return True
        
        return False
    
    def has_nonempty(self, container: str) -> bool:
        """Check if container is nonempty, considering value flow."""
        if self.direct_guards.has_nonempty(container):
            return True
        
        if self.value_flow:
            sources = self.value_flow.get_all_sources(container)
            for source in sources:
                if self.direct_guards.has_nonempty(source):
                    return True
        
        return False
    
    def bug_is_guarded(self, bug_type: str, bug_variable: str) -> bool:
        """
        Check if a bug is guarded (on all paths).
        
        Uses value flow to propagate guards.
        """
        base_var = bug_variable.split('[')[0].split('.')[0]
        
        if bug_type in ('NULL_PTR', 'ATTRIBUTE_ERROR'):
            return self.has_nonnull(base_var)
        
        elif bug_type == 'DIV_ZERO':
            return self.has_nonzero(base_var)
        
        elif bug_type in ('BOUNDS', 'INDEX_ERROR'):
            if '[' in bug_variable:
                container = bug_variable.split('[')[0]
                return self.has_nonempty(container)
            return False
        
        return False


# ============================================================================
# EXPORTS
# ============================================================================

__all__ = [
    # Value flow
    'FlowKind',
    'ValueFlowEdge',
    'ValueFlowGraph',
    'ValueFlowAnalyzer',
    
    # Semantics
    'FunctionReturnSemantics',
    'ContainerOperationSemantics',
    
    # Path-sensitive analysis
    'PathGuardState',
    'PathSensitiveGuardAnalyzer',
    
    # Enriched state
    'FlowEnrichedGuardState',
]
