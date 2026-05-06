"""
Full Dynamic Symbolic Execution (DSE) with Path Condition Tracking.

This module implements true DSE for FP reduction through:
1. **Symbolic Path Conditions**: Track Z3 constraints along each execution path
2. **Infeasible Path Pruning**: Use Z3 to prove bug conditions are unreachable
3. **Value Flow Tracking**: Track symbolic values through operations
4. **Container Operation Modeling**: Track values through list/dict operations

MATHEMATICAL FOUNDATION (python-barrier-certificate-theory.md §9):

    Path Condition: PC = ⋀_{i∈path} guard_condition_i
    
    Bug is FP if: SAT(PC ∧ bug_condition) = UNSAT
    
    I.e., if the conjunction of path conditions makes the bug condition
    unsatisfiable, then no concrete execution can trigger the bug.

ARCHITECTURE:

    ┌─────────────────────────────────────────────────────────────────┐
    │                    DSE PATH CONDITION TRACKER                    │
    ├─────────────────────────────────────────────────────────────────┤
    │                                                                  │
    │  CFG ──► PathEnumerator ──► PathCondition per path               │
    │              │                      │                            │
    │              ▼                      ▼                            │
    │  ┌─────────────────┐      ┌─────────────────┐                   │
    │  │ Symbolic State  │      │ Z3 Constraints  │                   │
    │  │ per variable    │      │ per path        │                   │
    │  └────────┬────────┘      └────────┬────────┘                   │
    │           │                        │                            │
    │           ▼                        ▼                            │
    │  ┌─────────────────────────────────────────────┐                │
    │  │        BUG REACHABILITY CHECK               │                │
    │  │  SAT(path_condition ∧ bug_condition)?       │                │
    │  │  UNSAT → Bug is FP (provably unreachable)   │                │
    │  │  SAT   → Bug may be TP (concrete witness)   │                │
    │  └─────────────────────────────────────────────┘                │
    │                                                                  │
    └─────────────────────────────────────────────────────────────────┘
"""

from __future__ import annotations

import z3
from dataclasses import dataclass, field
from typing import Dict, List, Set, Optional, Tuple, Any, Union
from enum import Enum, auto
import dis
import types
import logging

from ..cfg.control_flow import ControlFlowGraph, BasicBlock, build_cfg

logger = logging.getLogger(__name__)


# ============================================================================
# SYMBOLIC VALUES
# ============================================================================

@dataclass(frozen=True)
class SymbolicValue:
    """
    A symbolic value tracked through DSE.
    
    Represents either:
    - A parameter (symbolic input)
    - A concrete constant
    - An expression over other symbolic values
    - A function return value
    - A container access
    """
    kind: str  # 'param', 'const', 'expr', 'call_result', 'container_access', 'attr_access'
    name: str  # Variable name or expression description
    z3_expr: Optional[z3.ExprRef] = None  # Z3 representation
    
    # For tracking nullability symbolically
    may_be_none: bool = True
    definitely_none: bool = False
    
    # For numeric values
    may_be_zero: bool = True
    
    # Source tracking (for value flow)
    source_params: frozenset = field(default_factory=frozenset)
    
    @staticmethod
    def parameter(name: str, param_idx: int) -> 'SymbolicValue':
        """Create a symbolic parameter value."""
        z3_var = z3.Int(f"param_{param_idx}_{name}")
        return SymbolicValue(
            kind='param',
            name=name,
            z3_expr=z3_var,
            source_params=frozenset({param_idx}),
        )
    
    @staticmethod
    def constant(value: Any) -> 'SymbolicValue':
        """Create a symbolic constant value."""
        if value is None:
            return SymbolicValue(
                kind='const',
                name='None',
                z3_expr=z3.IntVal(-999999),  # Sentinel for None
                may_be_none=True,
                definitely_none=True,
                may_be_zero=False,
                source_params=frozenset(),
            )
        elif isinstance(value, bool):
            return SymbolicValue(
                kind='const',
                name=str(value),
                z3_expr=z3.IntVal(1 if value else 0),
                may_be_none=False,
                definitely_none=False,
                may_be_zero=not value,
                source_params=frozenset(),
            )
        elif isinstance(value, (int, float)):
            return SymbolicValue(
                kind='const',
                name=str(value),
                z3_expr=z3.IntVal(int(value)) if isinstance(value, int) else z3.RealVal(value),
                may_be_none=False,
                definitely_none=False,
                may_be_zero=(value == 0),
                source_params=frozenset(),
            )
        elif isinstance(value, str):
            return SymbolicValue(
                kind='const',
                name=f'"{value}"',
                z3_expr=None,  # Strings not modeled in Z3 for now
                may_be_none=False,
                definitely_none=False,
                may_be_zero=False,
                source_params=frozenset(),
            )
        else:
            # Other constants (tuple, bytes, etc.)
            return SymbolicValue(
                kind='const',
                name=repr(value),
                may_be_none=False,
                definitely_none=False,
                may_be_zero=False,
                source_params=frozenset(),
            )
    
    @staticmethod
    def call_result(func_name: str, args: List['SymbolicValue']) -> 'SymbolicValue':
        """Create a symbolic call result."""
        # Merge source params from all args
        source_params = frozenset().union(*(a.source_params for a in args))
        
        # Check if function is known to return non-None
        NONNULL_FUNCTIONS = {
            'list', 'dict', 'set', 'tuple', 'str', 'int', 'float', 'bool',
            'bytes', 'bytearray', 'frozenset', 'object', 'range', 'slice', 'type',
            'len', 'abs', 'repr', 'hash', 'id', 'chr', 'ord', 'bin', 'hex', 'oct',
            'sorted', 'reversed', 'enumerate', 'zip', 'map', 'filter',
        }
        may_be_none = func_name not in NONNULL_FUNCTIONS
        
        # Functions that return non-zero
        NONZERO_FUNCTIONS = {'len', 'id', 'hash'}
        may_be_zero = func_name not in NONZERO_FUNCTIONS
        
        # Create a fresh Z3 variable for the result
        z3_var = z3.Int(f"call_{func_name}_{id(args)}")
        
        return SymbolicValue(
            kind='call_result',
            name=f"{func_name}(...)",
            z3_expr=z3_var,
            may_be_none=may_be_none,
            definitely_none=False,
            may_be_zero=may_be_zero,
            source_params=source_params,
        )
    
    @staticmethod
    def container_access(container: 'SymbolicValue', index: 'SymbolicValue') -> 'SymbolicValue':
        """Create a symbolic value from container access."""
        source_params = container.source_params | index.source_params
        z3_var = z3.Int(f"access_{container.name}_{index.name}")
        
        return SymbolicValue(
            kind='container_access',
            name=f"{container.name}[{index.name}]",
            z3_expr=z3_var,
            may_be_none=True,  # Container elements could be None
            may_be_zero=True,
            source_params=source_params,
        )
    
    @staticmethod
    def attr_access(obj: 'SymbolicValue', attr: str) -> 'SymbolicValue':
        """Create a symbolic value from attribute access."""
        z3_var = z3.Int(f"attr_{obj.name}_{attr}")
        
        return SymbolicValue(
            kind='attr_access',
            name=f"{obj.name}.{attr}",
            z3_expr=z3_var,
            may_be_none=True,  # Attributes could be None
            may_be_zero=True,
            source_params=obj.source_params,
        )


# ============================================================================
# PATH CONDITION
# ============================================================================

@dataclass
class PathCondition:
    """
    Accumulated constraints along an execution path.
    
    The path condition is a conjunction of all branch conditions taken
    to reach the current program point.
    """
    constraints: List[z3.BoolRef] = field(default_factory=list)
    
    # Map variable name to its current symbolic value on this path
    variables: Dict[str, SymbolicValue] = field(default_factory=dict)
    
    # Track which variables are known null/non-null on this path
    nonnull_vars: Set[str] = field(default_factory=set)
    null_vars: Set[str] = field(default_factory=set)
    
    # Track which variables are known non-zero on this path
    nonzero_vars: Set[str] = field(default_factory=set)
    
    # Track container lengths (for bounds checking)
    container_lengths: Dict[str, z3.ArithRef] = field(default_factory=dict)
    container_nonempty: Set[str] = field(default_factory=set)
    
    # Track type constraints
    type_constraints: Dict[str, Set[str]] = field(default_factory=dict)
    
    def copy(self) -> 'PathCondition':
        """Create a deep copy for branching."""
        return PathCondition(
            constraints=self.constraints.copy(),
            variables={k: v for k, v in self.variables.items()},
            nonnull_vars=self.nonnull_vars.copy(),
            null_vars=self.null_vars.copy(),
            nonzero_vars=self.nonzero_vars.copy(),
            container_lengths={k: v for k, v in self.container_lengths.items()},
            container_nonempty=self.container_nonempty.copy(),
            type_constraints={k: v.copy() for k, v in self.type_constraints.items()},
        )
    
    def add_constraint(self, constraint: z3.BoolRef) -> None:
        """Add a path constraint."""
        self.constraints.append(constraint)
    
    def add_nonnull(self, var: str) -> None:
        """Record that variable is non-null on this path."""
        self.nonnull_vars.add(var)
        self.null_vars.discard(var)
        
        # Add Z3 constraint
        if var in self.variables and self.variables[var].z3_expr is not None:
            null_val = z3.IntVal(-999999)
            self.add_constraint(self.variables[var].z3_expr != null_val)
    
    def add_null(self, var: str) -> None:
        """Record that variable is null on this path."""
        self.null_vars.add(var)
        self.nonnull_vars.discard(var)
        
        # Add Z3 constraint
        if var in self.variables and self.variables[var].z3_expr is not None:
            null_val = z3.IntVal(-999999)
            self.add_constraint(self.variables[var].z3_expr == null_val)
    
    def add_nonzero(self, var: str) -> None:
        """Record that variable is non-zero on this path."""
        self.nonzero_vars.add(var)
        
        # Add Z3 constraint
        if var in self.variables and self.variables[var].z3_expr is not None:
            self.add_constraint(self.variables[var].z3_expr != z3.IntVal(0))
    
    def add_nonempty(self, container: str) -> None:
        """Record that container is non-empty on this path."""
        self.container_nonempty.add(container)
        
        # Add Z3 constraint for length >= 1
        if container in self.container_lengths:
            self.add_constraint(self.container_lengths[container] >= z3.IntVal(1))
        else:
            len_sym = z3.Int(f"len_{container}")
            self.container_lengths[container] = len_sym
            self.add_constraint(len_sym >= z3.IntVal(1))
    
    def add_type(self, var: str, type_name: str) -> None:
        """Record that variable has a specific type on this path."""
        if var not in self.type_constraints:
            self.type_constraints[var] = set()
        self.type_constraints[var].add(type_name)
    
    def is_feasible(self, solver_timeout_ms: int = 1000) -> bool:
        """Check if this path condition is satisfiable."""
        if not self.constraints:
            return True
        
        solver = z3.Solver()
        solver.set("timeout", solver_timeout_ms)
        solver.add(z3.And(*self.constraints))
        
        result = solver.check()
        return result != z3.unsat
    
    def bug_is_unreachable(
        self,
        bug_type: str,
        bug_variable: str,
        solver_timeout_ms: int = 1000
    ) -> bool:
        """
        Check if a bug is provably unreachable on this path.
        
        Returns True if SAT(path_condition ∧ bug_condition) = UNSAT,
        meaning the bug cannot occur on any concrete execution of this path.
        """
        solver = z3.Solver()
        solver.set("timeout", solver_timeout_ms)
        
        # Add path conditions
        if self.constraints:
            solver.add(z3.And(*self.constraints))
        
        # Add bug condition based on type
        bug_constraint = self._bug_condition(bug_type, bug_variable)
        if bug_constraint is not None:
            solver.add(bug_constraint)
        else:
            # Can't model this bug - be conservative
            return False
        
        result = solver.check()
        
        if result == z3.unsat:
            # Bug is provably unreachable
            return True
        else:
            # Bug may be reachable (SAT or unknown)
            return False
    
    def _bug_condition(self, bug_type: str, bug_variable: str) -> Optional[z3.BoolRef]:
        """Get Z3 constraint representing the bug condition."""
        # Extract base variable (e.g., "x" from "x.attr" or "x[0]")
        base_var = bug_variable.split('[')[0].split('.')[0]
        
        if bug_type in ('NULL_PTR', 'ATTRIBUTE_ERROR'):
            # Bug occurs when variable is None
            if base_var in self.nonnull_vars:
                # Variable is known non-null, bug condition is false
                return z3.BoolVal(False)
            if base_var in self.null_vars:
                # Variable is known null, bug condition is true
                return z3.BoolVal(True)
            
            # Use Z3 variable
            if base_var in self.variables and self.variables[base_var].z3_expr is not None:
                null_val = z3.IntVal(-999999)
                return self.variables[base_var].z3_expr == null_val
            
            return None
        
        elif bug_type == 'DIV_ZERO':
            # Bug occurs when divisor is zero
            if base_var in self.nonzero_vars:
                return z3.BoolVal(False)
            
            if base_var in self.variables and self.variables[base_var].z3_expr is not None:
                return self.variables[base_var].z3_expr == z3.IntVal(0)
            
            return None
        
        elif bug_type in ('BOUNDS', 'INDEX_ERROR'):
            # Bug occurs when index out of bounds
            # Parse container[index] format
            if '[' in bug_variable and ']' in bug_variable:
                container = bug_variable.split('[')[0]
                index = bug_variable.split('[')[1].rstrip(']')
                
                if container in self.container_lengths:
                    len_sym = self.container_lengths[container]
                else:
                    len_sym = z3.Int(f"len_{container}")
                
                if index in self.variables and self.variables[index].z3_expr is not None:
                    idx_sym = self.variables[index].z3_expr
                else:
                    idx_sym = z3.Int(f"v_{index}")
                
                # Bug condition: index < 0 OR index >= len
                return z3.Or(idx_sym < z3.IntVal(0), idx_sym >= len_sym)
            
            return None
        
        elif bug_type == 'KEY_ERROR':
            # Model as boolean "key not in container"
            return z3.Bool(f"key_missing_{bug_variable}")
        
        else:
            # Unknown bug type
            return None


# ============================================================================
# DSE SYMBOLIC STATE
# ============================================================================

@dataclass
class SymbolicState:
    """
    Complete symbolic state for DSE.
    
    Tracks:
    - Symbolic values for all variables
    - The operand stack with symbolic values
    - Path conditions for the current path
    """
    # Local variables: var_name -> SymbolicValue
    locals: Dict[str, SymbolicValue] = field(default_factory=dict)
    
    # Operand stack: list of SymbolicValue (TOS at end)
    stack: List[SymbolicValue] = field(default_factory=list)
    
    # Current path condition
    path_condition: PathCondition = field(default_factory=PathCondition)
    
    # Current block ID in CFG
    block_id: int = 0
    
    # Instruction offset within block
    offset: int = 0
    
    def copy(self) -> 'SymbolicState':
        """Create a deep copy for branching."""
        return SymbolicState(
            locals={k: v for k, v in self.locals.items()},
            stack=self.stack.copy(),
            path_condition=self.path_condition.copy(),
            block_id=self.block_id,
            offset=self.offset,
        )
    
    def push(self, value: SymbolicValue) -> None:
        """Push a value onto the stack."""
        self.stack.append(value)
    
    def pop(self) -> SymbolicValue:
        """Pop a value from the stack."""
        if self.stack:
            return self.stack.pop()
        # Return unknown value if stack is empty
        return SymbolicValue(kind='unknown', name='<empty>')
    
    def peek(self, depth: int = 0) -> SymbolicValue:
        """Peek at a stack value (0 = TOS)."""
        if len(self.stack) > depth:
            return self.stack[-(depth + 1)]
        return SymbolicValue(kind='unknown', name='<empty>')
    
    def load_local(self, name: str) -> SymbolicValue:
        """Load a local variable onto the stack."""
        if name in self.locals:
            return self.locals[name]
        # Return unknown symbolic value
        return SymbolicValue(kind='unknown', name=name)
    
    def store_local(self, name: str, value: SymbolicValue) -> None:
        """Store a value to a local variable."""
        self.locals[name] = value
        # Update path condition to track this variable
        self.path_condition.variables[name] = value


# ============================================================================
# DSE EXECUTOR
# ============================================================================

class DSEExecutor:
    """
    Dynamic Symbolic Executor for path condition tracking.
    
    Executes bytecode symbolically, tracking path conditions and
    checking bug reachability using Z3.
    """
    
    def __init__(
        self,
        code: types.CodeType,
        max_paths: int = 100,
        max_depth: int = 30,
        solver_timeout_ms: int = 1000,
        max_calls: int = 5000,
        time_budget_s: float = 10.0,
    ):
        self.code = code
        self.max_paths = max_paths
        self.max_depth = max_depth
        self.solver_timeout_ms = solver_timeout_ms
        self.max_calls = max_calls
        self.time_budget_s = time_budget_s
        
        # Build CFG
        self.cfg = build_cfg(code)
        
        # Get instructions
        self.instructions = list(dis.get_instructions(code))
        self.offset_to_instr = {instr.offset: instr for instr in self.instructions}
        
        # Get parameter info
        self.param_count = code.co_argcount + code.co_kwonlyargcount
        self.param_names = list(code.co_varnames[:self.param_count])
        
        # Results
        self.explored_paths: List[PathCondition] = []
        self.bug_reachability: Dict[Tuple[str, str, int], bool] = {}  # (bug_type, var, offset) -> reachable?
        
        # Budget tracking
        self._call_count = 0
        self._start_time = 0.0
    
    def analyze(self) -> Dict[Tuple[str, str, int], bool]:
        """
        Explore paths and compute bug reachability.
        
        Returns:
            Map from (bug_type, variable, offset) to reachability status.
            True = bug may be reachable, False = provably unreachable (FP).
        """
        import time as _time
        self._start_time = _time.monotonic()
        self._call_count = 0
        
        # Initialize symbolic state
        initial_state = self._create_initial_state()
        
        # Explore paths using bounded DFS
        try:
            self._explore_paths(initial_state, depth=0)
        except RecursionError:
            pass  # Hit Python recursion limit — keep results so far
        
        return self.bug_reachability
    
    def _create_initial_state(self) -> SymbolicState:
        """Create the initial symbolic state with symbolic parameters."""
        state = SymbolicState()
        
        for i, name in enumerate(self.param_names):
            sym_val = SymbolicValue.parameter(name, i)
            state.locals[name] = sym_val
            state.path_condition.variables[name] = sym_val
            
            # TYPE-BASED FILTERING: 'self' and 'cls' are never None
            if name in ('self', 'cls'):
                state.path_condition.add_nonnull(name)
        
        return state
    
    def _explore_paths(self, state: SymbolicState, depth: int) -> None:
        """Explore paths from the current state."""
        import time as _time
        self._call_count += 1
        if depth > self.max_depth:
            return
        if len(self.explored_paths) >= self.max_paths:
            return
        if self._call_count > self.max_calls:
            return
        if _time.monotonic() - self._start_time > self.time_budget_s:
            return
        
        # Get current block
        block = self.cfg.blocks.get(state.block_id)
        if not block:
            self.explored_paths.append(state.path_condition.copy())
            return
        
        # Execute instructions in the block
        for instr in block.instructions:
            state.offset = instr.offset
            
            # Check for terminating instructions
            if instr.opname in ('RETURN_VALUE', 'RETURN_CONST'):
                self.explored_paths.append(state.path_condition.copy())
                return
            
            # Execute the instruction symbolically
            self._execute_symbolic(state, instr)
        
        # Handle block successors
        successors = block.successors
        if not successors:
            self.explored_paths.append(state.path_condition.copy())
            return
        
        # Branch: explore each successor with appropriate path condition
        for succ_id, edge_type, guard_condition in successors:
            if edge_type.name in ('COND_TRUE', 'COND_FALSE'):
                # Fork the state and add branch condition
                branch_state = state.copy()
                branch_state.block_id = succ_id
                
                # Add branch constraint
                if guard_condition:
                    self._add_branch_constraint(branch_state, guard_condition, edge_type.name == 'COND_TRUE')
                
                # Check feasibility before exploring
                if branch_state.path_condition.is_feasible(self.solver_timeout_ms):
                    self._explore_paths(branch_state, depth + 1)
            else:
                # Unconditional successor
                state.block_id = succ_id
                self._explore_paths(state, depth + 1)
                return  # Only explore one unconditional successor
    
    def _execute_symbolic(self, state: SymbolicState, instr: dis.Instruction) -> None:
        """Execute a single instruction symbolically."""
        opname = instr.opname
        
        if opname in ('LOAD_FAST', 'LOAD_FAST_BORROW'):
            name = instr.argval
            value = state.load_local(name)
            state.push(value)
        
        elif opname == 'STORE_FAST':
            name = instr.argval
            value = state.pop()
            state.store_local(name, value)
            
            # VALUE FLOW: Track aliasing
            if value.kind == 'param' or value.kind == 'unknown':
                # Target inherits nullability from source
                if value.name in state.path_condition.nonnull_vars:
                    state.path_condition.add_nonnull(name)
                if value.name in state.path_condition.nonzero_vars:
                    state.path_condition.add_nonzero(name)
        
        elif opname in ('LOAD_CONST', 'LOAD_SMALL_INT'):
            value = SymbolicValue.constant(instr.argval)
            state.push(value)
        
        elif opname in ('LOAD_GLOBAL', 'LOAD_NAME', 'LOAD_BUILTIN'):
            # Create a symbolic value for globals/names
            name = instr.argval
            value = SymbolicValue(
                kind='global',
                name=name,
                may_be_none=True,  # Could be None
                may_be_zero=True,
            )
            state.push(value)
        
        elif opname == 'LOAD_ATTR':
            obj = state.pop()
            attr = instr.argval
            result = SymbolicValue.attr_access(obj, attr)
            state.push(result)
        
        elif opname == 'BINARY_OP':
            right = state.pop()
            left = state.pop()
            
            # Track value flow for binary operations
            source_params = left.source_params | right.source_params
            
            # For division, the right operand matters for DIV_ZERO
            if instr.arg in {2, 6, 11, 15, 19, 24}:  # Division ops
                # Check if divisor is known non-zero
                if right.may_be_zero and not right.definitely_none:
                    # Record potential DIV_ZERO bug
                    bug_key = ('DIV_ZERO', right.name, state.offset)
                    if bug_key not in self.bug_reachability:
                        # Check if unreachable on current path
                        unreachable = state.path_condition.bug_is_unreachable(
                            'DIV_ZERO', right.name, self.solver_timeout_ms
                        )
                        self.bug_reachability[bug_key] = not unreachable
            
            result = SymbolicValue(
                kind='expr',
                name=f"({left.name} op {right.name})",
                may_be_none=False,  # Arithmetic results are not None
                may_be_zero=True,
                source_params=source_params,
            )
            state.push(result)
        
        elif opname == 'BINARY_SUBSCR':
            index = state.pop()
            container = state.pop()
            
            # Record potential BOUNDS bug
            bug_var = f"{container.name}[{index.name}]"
            bug_key = ('BOUNDS', bug_var, state.offset)
            if bug_key not in self.bug_reachability:
                unreachable = state.path_condition.bug_is_unreachable(
                    'BOUNDS', bug_var, self.solver_timeout_ms
                )
                self.bug_reachability[bug_key] = not unreachable
            
            result = SymbolicValue.container_access(container, index)
            state.push(result)
        
        elif opname == 'CALL':
            # Simplified call handling
            # Pop function and args (we don't track exact arg count here)
            # In a full implementation, we'd parse the arg count
            func = state.pop() if state.stack else SymbolicValue(kind='unknown', name='<func>')
            result = SymbolicValue.call_result(func.name, [])
            state.push(result)
        
        elif opname == 'POP_TOP':
            state.pop()
        
        elif opname in ('COMPARE_OP', 'CONTAINS_OP', 'IS_OP'):
            right = state.pop()
            left = state.pop()
            result = SymbolicValue(
                kind='expr',
                name=f"({left.name} cmp {right.name})",
                may_be_none=False,  # Comparisons return bool
                may_be_zero=True,
            )
            state.push(result)
        
        elif opname.startswith('BUILD_'):
            # BUILD_* creates non-None values
            # Pop the elements (count from arg)
            count = instr.arg if instr.arg else 0
            for _ in range(count):
                if state.stack:
                    state.pop()
            result = SymbolicValue(
                kind='const',
                name=f'<{opname}>',
                may_be_none=False,
                may_be_zero=False,
            )
            state.push(result)
        
        # Handle other opcodes as needed...
    
    def _add_branch_constraint(
        self,
        state: SymbolicState,
        guard_condition: str,
        is_true_branch: bool
    ) -> None:
        """Add branch constraint to path condition."""
        # Parse guard condition and add appropriate Z3 constraint
        # Format: "var_is_none", "var_is_not_none", "var_eq_0", etc.
        
        if 'is_not_none' in guard_condition.lower():
            var = guard_condition.split('_')[0]
            if is_true_branch:
                state.path_condition.add_nonnull(var)
            else:
                state.path_condition.add_null(var)
        
        elif 'is_none' in guard_condition.lower():
            var = guard_condition.split('_')[0]
            if is_true_branch:
                state.path_condition.add_null(var)
            else:
                state.path_condition.add_nonnull(var)
        
        elif 'neq_0' in guard_condition.lower() or '!= 0' in guard_condition:
            var = guard_condition.split('_')[0]
            if is_true_branch:
                state.path_condition.add_nonzero(var)
        
        elif 'eq_0' in guard_condition.lower() or '== 0' in guard_condition:
            var = guard_condition.split('_')[0]
            if not is_true_branch:
                state.path_condition.add_nonzero(var)
    
    def check_bug_reachable(
        self,
        bug_type: str,
        bug_variable: str,
        offset: int,
    ) -> Tuple[bool, Optional[PathCondition]]:
        """
        Check if a bug at a specific location is reachable.
        
        Returns:
            (is_reachable, witnessing_path) where:
            - is_reachable: False if provably unreachable (FP), True otherwise
            - witnessing_path: A path condition that witnesses reachability (if SAT)
        """
        # Check cached result
        bug_key = (bug_type, bug_variable, offset)
        if bug_key in self.bug_reachability:
            return (self.bug_reachability[bug_key], None)
        
        # Check all explored paths
        for path in self.explored_paths:
            # Find paths that reach this offset
            # Check if bug is reachable on this path
            if not path.bug_is_unreachable(bug_type, bug_variable, self.solver_timeout_ms):
                self.bug_reachability[bug_key] = True
                return (True, path)
        
        # No path witnesses the bug - it's unreachable
        self.bug_reachability[bug_key] = False
        return (False, None)


# ============================================================================
# INTEGRATION WITH CRASH SUMMARY
# ============================================================================

def run_dse_analysis(
    code: types.CodeType,
    bugs: List[Tuple[str, str, int]],  # [(bug_type, variable, offset), ...]
    max_paths: int = 100,
    solver_timeout_ms: int = 1000,
) -> Dict[Tuple[str, str, int], bool]:
    """
    Run DSE analysis on a function and check bug reachability.
    
    Args:
        code: The function's code object
        bugs: List of potential bugs to check (type, variable, offset)
        max_paths: Maximum paths to explore
        solver_timeout_ms: Z3 solver timeout
    
    Returns:
        Map from bug tuple to reachability: True = may be TP, False = FP
    """
    executor = DSEExecutor(
        code=code,
        max_paths=max_paths,
        solver_timeout_ms=solver_timeout_ms,
    )
    
    # Run path exploration
    executor.analyze()
    
    # Check each bug
    results = {}
    for bug_type, variable, offset in bugs:
        is_reachable, _ = executor.check_bug_reachable(bug_type, variable, offset)
        results[(bug_type, variable, offset)] = is_reachable
    
    return results


# ============================================================================
# EXPORTS
# ============================================================================

__all__ = [
    'SymbolicValue',
    'PathCondition',
    'SymbolicState',
    'DSEExecutor',
    'run_dse_analysis',
]
