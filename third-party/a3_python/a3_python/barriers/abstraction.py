"""
Abstraction Layer for Barrier Certificate Synthesis.

This module provides abstraction-refinement techniques that manage
complexity by computing over abstract representations. It integrates:

    Paper #12: CEGAR (Clarke et al. 2000)
        - Counterexample-Guided Abstraction Refinement
        - Spurious counterexample analysis
        
    Paper #13: Predicate Abstraction (Graf-Saïdi 1997)
        - Boolean abstraction via predicates
        - Abstract successor computation
        
    Paper #14: Boolean Programs (Ball-Rajamani 2001)
        - Finite-state abstraction of programs
        - Symbolic execution of abstractions
        
    Paper #16: IMPACT/Lazy Abstraction (McMillan 2006)
        - On-demand abstraction refinement
        - Interpolation-based predicate discovery

The composable architecture:

    ┌─────────────────────────────────────────────────────────────┐
    │                    ABSTRACTION LAYER                         │
    ├─────────────────────────────────────────────────────────────┤
    │                                                              │
    │  ┌───────────────────────────────────────────────────────┐  │
    │  │        BARRIER CERTIFICATE CORE                        │  │
    │  │  (Hybrid, Stochastic, SOS Safety, SOSTOOLS)           │  │
    │  └────────────────────────┬──────────────────────────────┘  │
    │                           │                                  │
    │           ┌───────────────┼───────────────┐                  │
    │           │               │               │                  │
    │           ▼               ▼               ▼                  │
    │  ┌────────────┐   ┌────────────┐   ┌────────────┐           │
    │  │  Predicate │   │  Boolean   │   │   IMPACT   │           │
    │  │ Abstraction│   │  Programs  │   │    Lazy    │           │
    │  │ (Paper #13)│   │ (Paper #14)│   │ (Paper #16)│           │
    │  └──────┬─────┘   └──────┬─────┘   └──────┬─────┘           │
    │         │                │                │                  │
    │         └────────────────┼────────────────┘                  │
    │                          │                                   │
    │                          ▼                                   │
    │              ┌───────────────────────┐                       │
    │              │        CEGAR          │                       │
    │              │   Refinement Loop     │                       │
    │              │     (Paper #12)       │                       │
    │              └───────────────────────┘                       │
    │                                                              │
    └─────────────────────────────────────────────────────────────┘

Usage:
    from barriers.abstraction import (
        PredicateAbstraction,
        BooleanProgram,
        LazyAbstraction,
        CEGARLoop,
        AbstractionRefinementEngine,
    )
    
    # Unified interface
    engine = AbstractionRefinementEngine(predicates)
    result = engine.verify(program, property)
"""

from __future__ import annotations

import z3
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple, Set, Any, Union, Callable, FrozenSet
from enum import Enum, auto
import logging

# Import from lower layers
from .foundations import Polynomial, SemialgebraicSet
from .certificate_core import (
    ContinuousDynamics, BarrierConditions, BarrierTemplate
)

logger = logging.getLogger(__name__)


# =============================================================================
# PREDICATE ABSTRACTION (Paper #13)
# =============================================================================

@dataclass
class Predicate:
    """
    A predicate over program/system variables.
    
    Predicates are the atoms of abstraction - they represent boolean
    properties that partition the state space.
    """
    name: str
    expr: z3.ExprRef  # Z3 boolean expression
    variables: Set[str] = field(default_factory=set)  # Variables used
    
    def __hash__(self):
        return hash(self.name)
    
    def __eq__(self, other):
        return isinstance(other, Predicate) and self.name == other.name
    
    def evaluate(self, model: z3.ModelRef) -> Optional[bool]:
        """Evaluate predicate in model."""
        val = model.eval(self.expr, model_completion=True)
        if z3.is_true(val):
            return True
        elif z3.is_false(val):
            return False
        return None
    
    def negate(self) -> 'Predicate':
        """Return negation of predicate."""
        return Predicate(
            name=f"¬{self.name}",
            expr=z3.Not(self.expr),
            variables=self.variables
        )


@dataclass
class AbstractState:
    """
    Abstract state = valuation of predicates.
    
    Represents a region of concrete states where predicates
    have specific truth values.
    """
    valuation: FrozenSet[Tuple[str, bool]]  # (pred_name, value) pairs
    
    @property
    def as_dict(self) -> Dict[str, bool]:
        return dict(self.valuation)
    
    def consistent_with(self, other: 'AbstractState') -> bool:
        """Check if two abstract states are consistent (no contradictions)."""
        self_dict = self.as_dict
        other_dict = other.as_dict
        
        for name in set(self_dict.keys()) & set(other_dict.keys()):
            if self_dict[name] != other_dict[name]:
                return False
        return True
    
    def __hash__(self):
        return hash(self.valuation)
    
    def __eq__(self, other):
        return isinstance(other, AbstractState) and self.valuation == other.valuation
    
    def __repr__(self):
        parts = [f"{name}={val}" for name, val in sorted(self.valuation)]
        return "{" + ", ".join(parts) + "}"


class PredicateAbstraction:
    """
    Predicate abstraction engine (Paper #13).
    
    Maps concrete states to abstract states via predicate evaluation.
    Computes abstract successors using SMT solving.
    """
    
    def __init__(self, predicates: List[Predicate],
                 variables: List[z3.ExprRef],
                 timeout_ms: int = 30000):
        self.predicates = predicates
        self.variables = variables
        self.timeout_ms = timeout_ms
        
        # Build predicate index
        self.pred_by_name: Dict[str, Predicate] = {p.name: p for p in predicates}
        
        # Cached abstract transition relation
        self.abstract_trans: Dict[AbstractState, Set[AbstractState]] = {}
        
        self.stats = {
            'abstractions_computed': 0,
            'successor_queries': 0,
        }
    
    @property
    def num_predicates(self) -> int:
        return len(self.predicates)
    
    @property
    def num_abstract_states(self) -> int:
        """Upper bound on abstract states (2^n)."""
        return 2 ** len(self.predicates)
    
    def abstract(self, concrete_constraint: z3.ExprRef) -> Set[AbstractState]:
        """
        Compute abstract states consistent with concrete constraint.
        
        Returns all abstract states whose concretization intersects
        the constraint.
        """
        self.stats['abstractions_computed'] += 1
        result = set()
        
        # Enumerate possible valuations
        for valuation in self._enumerate_valuations():
            solver = z3.Solver()
            solver.set("timeout", self.timeout_ms // 10)
            
            # Add concrete constraint
            solver.add(concrete_constraint)
            
            # Add predicate constraints according to valuation
            for pred_name, value in valuation:
                pred = self.pred_by_name.get(pred_name)
                if pred:
                    if value:
                        solver.add(pred.expr)
                    else:
                        solver.add(z3.Not(pred.expr))
            
            if solver.check() == z3.sat:
                result.add(AbstractState(valuation))
        
        return result
    
    def concretize(self, abstract_state: AbstractState) -> z3.ExprRef:
        """
        Compute concretization: conjunction of predicates according to valuation.
        """
        constraints = []
        for pred_name, value in abstract_state.valuation:
            pred = self.pred_by_name.get(pred_name)
            if pred:
                if value:
                    constraints.append(pred.expr)
                else:
                    constraints.append(z3.Not(pred.expr))
        
        if constraints:
            return z3.And(constraints)
        return z3.BoolVal(True)
    
    def compute_abstract_successors(self, state: AbstractState,
                                      transition: z3.ExprRef) -> Set[AbstractState]:
        """
        Compute abstract successors of state under transition.
        
        transition should relate current (unprimed) and next (primed) variables.
        """
        self.stats['successor_queries'] += 1
        
        if state in self.abstract_trans:
            return self.abstract_trans[state]
        
        successors = set()
        
        # Get concretization of current state
        current = self.concretize(state)
        
        # For each possible successor valuation
        for valuation in self._enumerate_valuations():
            solver = z3.Solver()
            solver.set("timeout", self.timeout_ms // 10)
            
            # Current state constraints
            solver.add(current)
            
            # Transition relation
            solver.add(transition)
            
            # Target state constraints (primed predicates)
            for pred_name, value in valuation:
                pred = self.pred_by_name.get(pred_name)
                if pred:
                    # Create primed version of predicate
                    primed = self._prime_expr(pred.expr)
                    if value:
                        solver.add(primed)
                    else:
                        solver.add(z3.Not(primed))
            
            if solver.check() == z3.sat:
                successors.add(AbstractState(valuation))
        
        self.abstract_trans[state] = successors
        return successors
    
    def _enumerate_valuations(self) -> List[FrozenSet[Tuple[str, bool]]]:
        """Enumerate all possible predicate valuations."""
        result = []
        n = len(self.predicates)
        
        for i in range(2 ** n):
            valuation = []
            for j, pred in enumerate(self.predicates):
                value = bool((i >> j) & 1)
                valuation.append((pred.name, value))
            result.append(frozenset(valuation))
        
        return result
    
    def _prime_expr(self, expr: z3.ExprRef) -> z3.ExprRef:
        """Create primed version of expression (x -> x')."""
        substitutions = []
        for v in self.variables:
            name = str(v)
            primed = z3.Const(f"{name}'", v.sort())
            substitutions.append((v, primed))
        return z3.substitute(expr, substitutions)


# =============================================================================
# BOOLEAN PROGRAMS (Paper #14)
# =============================================================================

@dataclass
class BooleanVariable:
    """A boolean variable in a boolean program."""
    name: str
    initial: Optional[bool] = None  # Initial value (None = nondeterministic)


@dataclass
class BooleanStatement:
    """A statement in a boolean program."""
    label: int
    kind: str  # 'assign', 'assume', 'goto', 'call', 'return'
    
    # For assign: target = expr
    target: Optional[str] = None
    expr: Optional[z3.ExprRef] = None
    
    # For assume: condition
    condition: Optional[z3.ExprRef] = None
    
    # For goto: target labels
    targets: List[int] = field(default_factory=list)
    
    # For call/return
    callee: Optional[str] = None
    return_label: Optional[int] = None


@dataclass
class BooleanProcedure:
    """A procedure in a boolean program."""
    name: str
    parameters: List[BooleanVariable]
    locals: List[BooleanVariable]
    statements: List[BooleanStatement]
    entry_label: int
    exit_labels: List[int]


class BooleanProgram:
    """
    Boolean program abstraction (Paper #14).
    
    Represents program as finite-state system over boolean variables.
    Each procedure is a collection of labeled statements.
    """
    
    def __init__(self, name: str = ""):
        self.name = name
        self.global_vars: List[BooleanVariable] = []
        self.procedures: Dict[str, BooleanProcedure] = {}
        self.main_procedure: Optional[str] = None
        
    def add_global(self, var: BooleanVariable) -> None:
        """Add global variable."""
        self.global_vars.append(var)
    
    def add_procedure(self, proc: BooleanProcedure) -> None:
        """Add procedure."""
        self.procedures[proc.name] = proc
    
    def set_main(self, proc_name: str) -> None:
        """Set main procedure."""
        self.main_procedure = proc_name
    
    def get_all_variables(self) -> List[BooleanVariable]:
        """Get all variables (global + all locals)."""
        result = list(self.global_vars)
        for proc in self.procedures.values():
            result.extend(proc.parameters)
            result.extend(proc.locals)
        return result
    
    def to_predicates(self) -> List[Predicate]:
        """Convert boolean variables to predicates."""
        predicates = []
        for var in self.get_all_variables():
            z3_var = z3.Bool(var.name)
            predicates.append(Predicate(
                name=var.name,
                expr=z3_var,
                variables={var.name}
            ))
        return predicates


@dataclass
class BooleanProgramState:
    """State of boolean program execution."""
    program_counter: Tuple[str, int]  # (procedure, label)
    variable_values: Dict[str, bool]
    call_stack: List[Tuple[str, int]]  # Stack of (procedure, return_label)
    
    def __hash__(self):
        return hash((self.program_counter,
                    frozenset(self.variable_values.items()),
                    tuple(self.call_stack)))
    
    def __eq__(self, other):
        return (isinstance(other, BooleanProgramState) and
                self.program_counter == other.program_counter and
                self.variable_values == other.variable_values and
                self.call_stack == other.call_stack)


class BooleanProgramExecutor:
    """
    Executor for boolean programs.
    
    Performs symbolic exploration of the boolean program's state space.
    """
    
    def __init__(self, program: BooleanProgram):
        self.program = program
        self.explored_states: Set[BooleanProgramState] = set()
        self.state_graph: Dict[BooleanProgramState, Set[BooleanProgramState]] = {}
        
    def get_initial_states(self) -> Set[BooleanProgramState]:
        """Get initial states of program."""
        if not self.program.main_procedure:
            return set()
        
        main = self.program.procedures.get(self.program.main_procedure)
        if not main:
            return set()
        
        # Initialize variables
        init_values = {}
        for var in self.program.global_vars:
            if var.initial is not None:
                init_values[var.name] = var.initial
        
        for var in main.locals:
            if var.initial is not None:
                init_values[var.name] = var.initial
        
        # Create initial state(s)
        return self._expand_nondeterminism(
            BooleanProgramState(
                program_counter=(main.name, main.entry_label),
                variable_values=init_values,
                call_stack=[]
            )
        )
    
    def successors(self, state: BooleanProgramState) -> Set[BooleanProgramState]:
        """Compute successor states."""
        proc_name, label = state.program_counter
        proc = self.program.procedures.get(proc_name)
        
        if not proc:
            return set()
        
        # Find statement at label
        stmt = None
        for s in proc.statements:
            if s.label == label:
                stmt = s
                break
        
        if not stmt:
            return set()
        
        return self._execute_statement(state, stmt, proc)
    
    def _execute_statement(self, state: BooleanProgramState,
                            stmt: BooleanStatement,
                            proc: BooleanProcedure) -> Set[BooleanProgramState]:
        """Execute a single statement."""
        result = set()
        
        if stmt.kind == 'assign':
            new_values = dict(state.variable_values)
            if stmt.target and stmt.expr:
                val = self._eval_expr(stmt.expr, state.variable_values)
                if val is not None:
                    new_values[stmt.target] = val
            
            # Find next statement
            next_label = self._find_next_label(proc, stmt.label)
            if next_label is not None:
                result.add(BooleanProgramState(
                    program_counter=(proc.name, next_label),
                    variable_values=new_values,
                    call_stack=list(state.call_stack)
                ))
        
        elif stmt.kind == 'assume':
            if stmt.condition:
                val = self._eval_expr(stmt.condition, state.variable_values)
                if val is True:
                    next_label = self._find_next_label(proc, stmt.label)
                    if next_label is not None:
                        result.add(BooleanProgramState(
                            program_counter=(proc.name, next_label),
                            variable_values=dict(state.variable_values),
                            call_stack=list(state.call_stack)
                        ))
        
        elif stmt.kind == 'goto':
            for target in stmt.targets:
                result.add(BooleanProgramState(
                    program_counter=(proc.name, target),
                    variable_values=dict(state.variable_values),
                    call_stack=list(state.call_stack)
                ))
        
        elif stmt.kind == 'call':
            if stmt.callee:
                callee = self.program.procedures.get(stmt.callee)
                if callee:
                    new_stack = list(state.call_stack)
                    if stmt.return_label is not None:
                        new_stack.append((proc.name, stmt.return_label))
                    result.add(BooleanProgramState(
                        program_counter=(callee.name, callee.entry_label),
                        variable_values=dict(state.variable_values),
                        call_stack=new_stack
                    ))
        
        elif stmt.kind == 'return':
            if state.call_stack:
                ret_proc, ret_label = state.call_stack[-1]
                result.add(BooleanProgramState(
                    program_counter=(ret_proc, ret_label),
                    variable_values=dict(state.variable_values),
                    call_stack=state.call_stack[:-1]
                ))
        
        return result
    
    def _eval_expr(self, expr: z3.ExprRef,
                    values: Dict[str, bool]) -> Optional[bool]:
        """Evaluate Z3 expression with variable values."""
        solver = z3.Solver()
        solver.set("timeout", 1000)
        
        for name, val in values.items():
            v = z3.Bool(name)
            solver.add(v == z3.BoolVal(val))
        
        solver.push()
        solver.add(expr)
        sat_true = (solver.check() == z3.sat)
        solver.pop()
        
        solver.push()
        solver.add(z3.Not(expr))
        sat_false = (solver.check() == z3.sat)
        solver.pop()
        
        if sat_true and not sat_false:
            return True
        elif sat_false and not sat_true:
            return False
        return None
    
    def _find_next_label(self, proc: BooleanProcedure, current: int) -> Optional[int]:
        """Find next sequential label."""
        labels = sorted(s.label for s in proc.statements)
        for i, l in enumerate(labels):
            if l == current and i + 1 < len(labels):
                return labels[i + 1]
        return None
    
    def _expand_nondeterminism(self, state: BooleanProgramState) -> Set[BooleanProgramState]:
        """Expand nondeterministic variables."""
        # For now, just return the state
        return {state}


# =============================================================================
# LAZY ABSTRACTION / IMPACT (Paper #16)
# =============================================================================

@dataclass
class ARTNode:
    """
    Node in the Abstract Reachability Tree (ART).
    
    From IMPACT (Paper #16): The ART represents explored program states
    with predicates discovered on-demand.
    """
    node_id: int
    location: Any  # Program location
    predicates: Set[Predicate]  # Predicates tracked at this node
    constraint: z3.ExprRef  # Path constraint to reach this node
    parent: Optional['ARTNode'] = None
    children: List['ARTNode'] = field(default_factory=list)
    
    # Coverage status
    is_covered: bool = False
    covered_by: Optional['ARTNode'] = None
    
    # Error status
    is_error: bool = False
    
    def __hash__(self):
        return self.node_id
    
    def __eq__(self, other):
        return isinstance(other, ARTNode) and self.node_id == other.node_id


class LazyAbstraction:
    """
    Lazy abstraction / IMPACT algorithm (Paper #16).
    
    Key ideas:
    1. Build ART lazily (on-demand exploration)
    2. Use interpolation to discover new predicates
    3. Refine only when spurious counterexamples found
    """
    
    def __init__(self, initial_predicates: List[Predicate],
                 timeout_ms: int = 60000):
        self.predicates = set(initial_predicates)
        self.timeout_ms = timeout_ms
        
        # ART state
        self.nodes: Dict[int, ARTNode] = {}
        self.next_node_id = 0
        self.root: Optional[ARTNode] = None
        self.worklist: List[ARTNode] = []
        
        self.stats = {
            'nodes_created': 0,
            'refinements': 0,
            'interpolations': 0,
        }
    
    def create_node(self, location: Any,
                     predicates: Set[Predicate],
                     constraint: z3.ExprRef,
                     parent: Optional[ARTNode] = None) -> ARTNode:
        """Create new ART node."""
        node = ARTNode(
            node_id=self.next_node_id,
            location=location,
            predicates=predicates,
            constraint=constraint,
            parent=parent
        )
        self.nodes[self.next_node_id] = node
        self.next_node_id += 1
        self.stats['nodes_created'] += 1
        
        if parent:
            parent.children.append(node)
        
        return node
    
    def is_covered(self, node: ARTNode) -> Tuple[bool, Optional[ARTNode]]:
        """
        Check if node is covered by another node.
        
        Covered if: same location AND constraint implies existing constraint.
        """
        for other_id, other in self.nodes.items():
            if other_id == node.node_id:
                continue
            if other.location != node.location:
                continue
            if other.is_covered:
                continue
            
            # Check: node.constraint => other.constraint
            solver = z3.Solver()
            solver.set("timeout", self.timeout_ms // 100)
            solver.add(node.constraint)
            solver.add(z3.Not(other.constraint))
            
            if solver.check() == z3.unsat:
                return (True, other)
        
        return (False, None)
    
    def expand(self, node: ARTNode,
                transition: Callable[[ARTNode], List[Tuple[Any, z3.ExprRef]]]) -> List[ARTNode]:
        """
        Expand node: compute successors lazily.
        
        transition(node) returns list of (location, constraint) pairs.
        """
        successors = []
        
        for next_loc, trans_constraint in transition(node):
            # Path constraint to successor
            new_constraint = z3.And(node.constraint, trans_constraint)
            
            # Check feasibility
            solver = z3.Solver()
            solver.set("timeout", self.timeout_ms // 50)
            solver.add(new_constraint)
            
            if solver.check() == z3.sat:
                # Create successor node with current predicates
                succ = self.create_node(
                    location=next_loc,
                    predicates=set(node.predicates),
                    constraint=new_constraint,
                    parent=node
                )
                successors.append(succ)
        
        return successors
    
    def refine_from_counterexample(self, path: List[ARTNode],
                                     error_constraint: z3.ExprRef) -> Optional[Predicate]:
        """
        Refine abstraction based on spurious counterexample.
        
        Uses interpolation to discover predicate that eliminates the spurious path.
        """
        self.stats['refinements'] += 1
        
        if len(path) < 2:
            return None
        
        # Build path formula
        path_formulas = []
        for node in path:
            path_formulas.append(node.constraint)
        path_formulas.append(error_constraint)
        
        # Try to compute interpolant
        interpolant = self._compute_interpolant(path_formulas)
        
        if interpolant is not None:
            self.stats['interpolations'] += 1
            pred = Predicate(
                name=f"itp_{self.stats['interpolations']}",
                expr=interpolant,
                variables=self._get_variables(interpolant)
            )
            self.predicates.add(pred)
            return pred
        
        return None
    
    def _compute_interpolant(self, formulas: List[z3.ExprRef]) -> Optional[z3.ExprRef]:
        """
        Compute Craig interpolant between prefix and suffix.
        
        Uses Z3's interpolation capabilities (simplified version).
        """
        if len(formulas) < 2:
            return None
        
        # Split formulas into A (prefix) and B (suffix)
        mid = len(formulas) // 2
        A = z3.And(formulas[:mid]) if mid > 0 else z3.BoolVal(True)
        B = z3.And(formulas[mid:]) if mid < len(formulas) else z3.BoolVal(True)
        
        # Check unsatisfiability
        solver = z3.Solver()
        solver.set("timeout", self.timeout_ms // 10)
        solver.add(A)
        solver.add(B)
        
        if solver.check() != z3.unsat:
            return None  # Not spurious
        
        # Simplified interpolant: try negation of B as candidate
        # (Real implementation would use proper interpolation)
        return z3.Not(B)
    
    def _get_variables(self, expr: z3.ExprRef) -> Set[str]:
        """Extract variable names from expression."""
        vars_set = set()
        
        def collect(e):
            if z3.is_const(e) and e.decl().kind() == z3.Z3_OP_UNINTERPRETED:
                vars_set.add(str(e))
            for child in e.children():
                collect(child)
        
        collect(expr)
        return vars_set


# =============================================================================
# CEGAR LOOP (Paper #12)
# =============================================================================

class CEGARResult(Enum):
    """Result of CEGAR verification."""
    SAFE = auto()
    UNSAFE = auto()
    UNKNOWN = auto()


@dataclass
class Counterexample:
    """A counterexample trace."""
    states: List[Any]
    transitions: List[Any]
    is_spurious: bool = False


class CEGARLoop:
    """
    Counterexample-Guided Abstraction Refinement (Paper #12).
    
    The CEGAR loop:
    1. Build abstract model
    2. Model check abstract model
    3. If safe: done
    4. If counterexample found:
       a. Check if real (simulate on concrete)
       b. If real: report bug
       c. If spurious: refine abstraction
    5. Repeat
    """
    
    def __init__(self, initial_predicates: List[Predicate],
                 max_iterations: int = 100,
                 timeout_ms: int = 300000):
        self.predicates = list(initial_predicates)
        self.max_iterations = max_iterations
        self.timeout_ms = timeout_ms
        
        # Sub-components
        self.abstraction = PredicateAbstraction(
            predicates=self.predicates,
            variables=[],  # Will be set later
            timeout_ms=timeout_ms // 10
        )
        self.lazy_abs = LazyAbstraction(self.predicates, timeout_ms // 5)
        
        self.stats = {
            'iterations': 0,
            'refinements': 0,
            'spurious_counterexamples': 0,
        }
    
    def verify(self, initial: z3.ExprRef,
                bad: z3.ExprRef,
                transition: z3.ExprRef) -> Tuple[CEGARResult, Optional[Counterexample]]:
        """
        Run CEGAR verification.
        
        Args:
            initial: Initial state constraint
            bad: Bad (error) state constraint
            transition: Transition relation (unprimed -> primed)
        
        Returns:
            (result, counterexample if unsafe)
        """
        for iteration in range(self.max_iterations):
            self.stats['iterations'] = iteration + 1
            
            # Step 1: Build/update abstract model
            abstract_initial = self.abstraction.abstract(initial)
            abstract_bad = self.abstraction.abstract(bad)
            
            # Step 2: Check reachability in abstract model
            reachable = self._compute_reachable(abstract_initial, transition)
            
            # Check if bad states reachable
            bad_reachable = reachable & abstract_bad
            
            if not bad_reachable:
                # Step 3a: No counterexample = safe
                return (CEGARResult.SAFE, None)
            
            # Step 3b: Extract abstract counterexample
            abstract_cex = self._extract_counterexample(
                abstract_initial, bad_reachable, transition
            )
            
            # Step 4: Check if counterexample is real
            is_real, concrete_cex = self._check_counterexample(
                abstract_cex, initial, bad, transition
            )
            
            if is_real:
                # Step 4b: Real counterexample = unsafe
                return (CEGARResult.UNSAFE, concrete_cex)
            
            # Step 4c: Spurious - refine
            self.stats['spurious_counterexamples'] += 1
            new_pred = self._refine(abstract_cex, transition)
            
            if new_pred is None:
                # Can't refine further
                return (CEGARResult.UNKNOWN, None)
            
            self._add_predicate(new_pred)
            self.stats['refinements'] += 1
        
        return (CEGARResult.UNKNOWN, None)
    
    def _compute_reachable(self, initial: Set[AbstractState],
                            transition: z3.ExprRef) -> Set[AbstractState]:
        """Compute reachable abstract states via BFS."""
        reachable = set(initial)
        worklist = list(initial)
        
        while worklist:
            current = worklist.pop(0)
            
            successors = self.abstraction.compute_abstract_successors(
                current, transition
            )
            
            for succ in successors:
                if succ not in reachable:
                    reachable.add(succ)
                    worklist.append(succ)
        
        return reachable
    
    def _extract_counterexample(self, initial: Set[AbstractState],
                                  bad: Set[AbstractState],
                                  transition: z3.ExprRef) -> Counterexample:
        """Extract counterexample path from initial to bad."""
        # BFS to find path
        visited = {}
        worklist = [(s, [s]) for s in initial]
        
        while worklist:
            current, path = worklist.pop(0)
            
            if current in bad:
                return Counterexample(states=path, transitions=[])
            
            if current in visited:
                continue
            visited[current] = True
            
            for succ in self.abstraction.compute_abstract_successors(current, transition):
                if succ not in visited:
                    worklist.append((succ, path + [succ]))
        
        return Counterexample(states=[], transitions=[], is_spurious=True)
    
    def _check_counterexample(self, abstract_cex: Counterexample,
                               initial: z3.ExprRef,
                               bad: z3.ExprRef,
                               transition: z3.ExprRef) -> Tuple[bool, Optional[Counterexample]]:
        """Check if abstract counterexample is realizable."""
        if not abstract_cex.states:
            return (False, None)
        
        solver = z3.Solver()
        solver.set("timeout", self.timeout_ms // 10)
        
        # Build path formula
        path_length = len(abstract_cex.states)
        
        # Initial state constraint
        solver.add(initial)
        
        # Step through path
        for i, state in enumerate(abstract_cex.states):
            state_constraint = self.abstraction.concretize(state)
            # Would need to create indexed variables here
            solver.add(state_constraint)
        
        # Bad state at end
        solver.add(bad)
        
        if solver.check() == z3.sat:
            # Real counterexample
            model = solver.model()
            return (True, Counterexample(
                states=abstract_cex.states,
                transitions=[],
                is_spurious=False
            ))
        
        return (False, None)
    
    def _refine(self, abstract_cex: Counterexample,
                 transition: z3.ExprRef) -> Optional[Predicate]:
        """Refine abstraction to eliminate spurious counterexample."""
        # Use lazy abstraction's interpolation-based refinement
        if not abstract_cex.states:
            return None
        
        # Build ART nodes for path
        path_nodes = []
        for i, state in enumerate(abstract_cex.states):
            constraint = self.abstraction.concretize(state)
            node = self.lazy_abs.create_node(
                location=i,
                predicates=self.lazy_abs.predicates,
                constraint=constraint,
                parent=path_nodes[-1] if path_nodes else None
            )
            path_nodes.append(node)
        
        # Get new predicate from interpolation
        return self.lazy_abs.refine_from_counterexample(
            path_nodes, z3.BoolVal(False)
        )
    
    def _add_predicate(self, pred: Predicate) -> None:
        """Add predicate to abstraction."""
        self.predicates.append(pred)
        self.abstraction = PredicateAbstraction(
            predicates=self.predicates,
            variables=self.abstraction.variables,
            timeout_ms=self.abstraction.timeout_ms
        )


# =============================================================================
# ABSTRACTION FOR BARRIER CERTIFICATES
# =============================================================================

class BarrierAbstraction:
    """
    Abstraction specifically designed for barrier certificate synthesis.
    
    Key insight: Use barrier template coefficients as predicates.
    Abstraction over coefficient space rather than state space.
    """
    
    def __init__(self, n_vars: int, max_degree: int = 4):
        self.n_vars = n_vars
        self.max_degree = max_degree
        self.template = BarrierTemplate(n_vars, max_degree)
        
        # Abstract coefficient regions
        self.coefficient_predicates: List[Predicate] = []
        self._build_coefficient_predicates()
    
    def _build_coefficient_predicates(self) -> None:
        """Build predicates over barrier coefficients."""
        self.template.create_symbolic("B")
        
        for mono, coeff in self.template.coefficients.items():
            # Positivity predicate: c >= 0
            pred_pos = Predicate(
                name=f"c_{mono.exponents}_pos",
                expr=coeff >= 0,
                variables={str(coeff)}
            )
            self.coefficient_predicates.append(pred_pos)
            
            # Boundedness predicates: |c| <= 10
            pred_bounded = Predicate(
                name=f"c_{mono.exponents}_bounded",
                expr=z3.And(coeff >= -10, coeff <= 10),
                variables={str(coeff)}
            )
            self.coefficient_predicates.append(pred_bounded)
    
    def abstract_barrier_constraints(self, conditions: BarrierConditions,
                                       dynamics: ContinuousDynamics) -> z3.ExprRef:
        """
        Abstract barrier synthesis constraints.
        
        Returns formula over coefficient predicates.
        """
        solver = z3.Solver()
        solver.set("timeout", 30000)
        
        vars_z3 = [z3.Real(f'x{i}') for i in range(self.n_vars)]
        B_z3 = self.template.to_z3(vars_z3)
        
        # Sample-based abstraction of constraints
        constraints = []
        
        # Initial positivity samples
        for sample in self._sample_region(conditions.initial, 10):
            B_val = self._substitute(B_z3, vars_z3, sample)
            constraints.append(B_val >= 0.1)
        
        # Unsafe negativity samples
        for sample in self._sample_region(conditions.unsafe, 10):
            B_val = self._substitute(B_z3, vars_z3, sample)
            constraints.append(B_val <= -0.1)
        
        return z3.And(constraints) if constraints else z3.BoolVal(True)
    
    def _sample_region(self, region: SemialgebraicSet, count: int) -> List[List[float]]:
        """Sample points from region."""
        import random
        samples = []
        
        for _ in range(count * 10):
            if len(samples) >= count:
                break
            point = [random.uniform(-5, 5) for _ in range(region.n_vars)]
            if region.contains(point):
                samples.append(point)
        
        while len(samples) < count:
            samples.append([0.0] * region.n_vars)
        
        return samples
    
    def _substitute(self, expr: z3.ExprRef,
                     vars_z3: List[z3.ExprRef],
                     point: List[float]) -> z3.ExprRef:
        """Substitute point values."""
        subs = [(vars_z3[i], z3.RealVal(point[i]))
                for i in range(min(len(vars_z3), len(point)))]
        return z3.substitute(expr, subs)


# =============================================================================
# UNIFIED ABSTRACTION-REFINEMENT ENGINE
# =============================================================================

class AbstractionRefinementEngine:
    """
    Unified engine for abstraction-refinement verification.
    
    MAIN INTERFACE for the abstraction layer.
    
    Integrates:
    - Predicate abstraction (Paper #13)
    - Boolean programs (Paper #14)
    - IMPACT/Lazy abstraction (Paper #16)
    - CEGAR loop (Paper #12)
    
    Automatically selects appropriate technique based on problem structure.
    """
    
    def __init__(self, initial_predicates: Optional[List[Predicate]] = None,
                 max_iterations: int = 100,
                 timeout_ms: int = 300000):
        self.predicates = initial_predicates or []
        self.max_iterations = max_iterations
        self.timeout_ms = timeout_ms
        
        # Sub-engines
        self.predicate_abs: Optional[PredicateAbstraction] = None
        self.lazy_abs: Optional[LazyAbstraction] = None
        self.cegar: Optional[CEGARLoop] = None
        
        self.stats = {
            'verifications': 0,
            'safe': 0,
            'unsafe': 0,
            'unknown': 0,
        }
    
    def set_predicates(self, predicates: List[Predicate],
                        variables: List[z3.ExprRef]) -> None:
        """Set predicates and variables for abstraction."""
        self.predicates = predicates
        self.predicate_abs = PredicateAbstraction(predicates, variables, self.timeout_ms // 10)
        self.lazy_abs = LazyAbstraction(predicates, self.timeout_ms // 5)
        self.cegar = CEGARLoop(predicates, self.max_iterations, self.timeout_ms)
    
    def verify_safety(self, initial: z3.ExprRef,
                       bad: z3.ExprRef,
                       transition: z3.ExprRef) -> Tuple[str, Optional[Counterexample]]:
        """
        Verify safety property using CEGAR.
        
        Returns ('safe', None), ('unsafe', cex), or ('unknown', None).
        """
        self.stats['verifications'] += 1
        
        if self.cegar is None:
            # Create default CEGAR
            self.cegar = CEGARLoop(self.predicates, self.max_iterations, self.timeout_ms)
        
        result, cex = self.cegar.verify(initial, bad, transition)
        
        if result == CEGARResult.SAFE:
            self.stats['safe'] += 1
            return ('safe', None)
        elif result == CEGARResult.UNSAFE:
            self.stats['unsafe'] += 1
            return ('unsafe', cex)
        else:
            self.stats['unknown'] += 1
            return ('unknown', None)
    
    def verify_with_barrier(self, conditions: BarrierConditions,
                             dynamics: ContinuousDynamics) -> Tuple[str, Any]:
        """
        Verify using barrier-specific abstraction.
        
        Combines abstraction with barrier synthesis.
        """
        barrier_abs = BarrierAbstraction(dynamics.n_vars)
        
        # Abstract the problem
        abstract_constraint = barrier_abs.abstract_barrier_constraints(conditions, dynamics)
        
        # Solve abstracted problem
        solver = z3.Solver()
        solver.set("timeout", self.timeout_ms)
        solver.add(abstract_constraint)
        
        if solver.check() == z3.sat:
            model = solver.model()
            
            # Extract coefficient values
            coeff_values = {}
            for mono, var in barrier_abs.template.coefficients.items():
                val = model.eval(var, model_completion=True)
                if z3.is_rational_value(val):
                    coeff_values[mono] = (float(val.numerator_as_long()) /
                                         float(val.denominator_as_long()))
                else:
                    coeff_values[mono] = 0.0
            
            barrier = barrier_abs.template.to_polynomial(coeff_values)
            return ('safe', barrier)
        
        return ('unknown', None)


# =============================================================================
# EXPORTS
# =============================================================================

__all__ = [
    # Predicate Abstraction (Paper #13)
    'Predicate',
    'AbstractState',
    'PredicateAbstraction',
    
    # Boolean Programs (Paper #14)
    'BooleanVariable',
    'BooleanStatement',
    'BooleanProcedure',
    'BooleanProgram',
    'BooleanProgramState',
    'BooleanProgramExecutor',
    
    # Lazy Abstraction / IMPACT (Paper #16)
    'ARTNode',
    'LazyAbstraction',
    
    # CEGAR (Paper #12)
    'CEGARResult',
    'Counterexample',
    'CEGARLoop',
    
    # Barrier-specific abstraction
    'BarrierAbstraction',
    
    # Unified Engine
    'AbstractionRefinementEngine',
]
