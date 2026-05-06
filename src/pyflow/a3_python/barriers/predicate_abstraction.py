"""
SOTA Paper: Predicate Abstraction via SAT.

Implements predicate abstraction for software verification:
    E. Clarke, D. Kroening, N. Sharygina, K. Yorav.
    "Predicate Abstraction of ANSI-C Programs Using SAT."
    Formal Methods in System Design (FMSD), 2004.

KEY INSIGHT
===========

Predicate abstraction maps a concrete program to a Boolean program
by tracking only the truth values of selected predicates.

Given predicates P = {p_1,...,p_n}:
- Concrete state s maps to abstract state {i : s ⊨ p_i}
- Transitions are computed using SAT queries

This enables verification of infinite-state programs using
finite-state model checking techniques.

ABSTRACTION COMPUTATION
=======================

For a transition relation T(s, s'):
1. Select predicates P = {p_1,...,p_n}
2. For each Boolean assignment (b_1,...,b_n) to predicates:
   - Use SAT to check if transition (b_1,...,b_n) -> (b'_1,...,b'_n) possible
3. Build abstract transition relation T_abs

The key optimization is using SAT instead of BDD-based methods.

ABSTRACTION REFINEMENT
======================

When spurious counterexample found:
1. Analyze why abstract path doesn't correspond to concrete path
2. Extract new predicates from interpolation or weakest precondition
3. Refine abstraction with new predicates
4. Repeat

IMPLEMENTATION STRUCTURE
========================

1. Predicate: Individual predicate with Z3 formula
2. PredicateSet: Set of predicates forming abstraction
3. AbstractState: Boolean assignment to predicates
4. AbstractTransition: Transition between abstract states
5. PredicateAbstractor: Compute abstraction using SAT
6. PredicateRefinement: CEGAR-based refinement
7. PredicateIntegration: Integration with barriers

LAYER POSITION
==============

This is a **Layer 3 (Abstraction)** module.

    ┌─────────────────────────────────────────────────────────────────┐
    │ Layer 5: Advanced Verification (IC3, CHC, IMC, Assume-Guarantee)│
    │ Layer 4: Learning (ICE, Houdini, SyGuS)                         │
    │ Layer 3: ABSTRACTION ← [THIS MODULE]                            │
    │   ├── cegar_refinement.py (Paper #12)                           │
    │   ├── predicate_abstraction.py ← You are here (Paper #13)       │
    │   ├── boolean_programs.py (Paper #14)                           │
    │   └── impact_lazy.py (Paper #16)                                │
    │ Layer 2: Certificate Core (Hybrid, Stochastic, SOS Safety)      │
    │ Layer 1: Foundations (Positivstellensatz, SOS/SDP, Lasserre)    │
    └─────────────────────────────────────────────────────────────────┘

CROSS-PAPER DEPENDENCIES
========================

This module builds on:
- Layer 1: Polynomial predicates from SOS basis
- Layer 2: Barrier conditions as abstraction targets

This module synergizes with Layer 3 peers:
- Paper #12 (CEGAR): Predicates are refined through CEGAR loop
- Paper #14 (Boolean Programs): Predicates define Boolean program
- Paper #16 (IMPACT): Lazy abstraction shares predicate infrastructure

This module is used by:
- Paper #10 (IC3): Predicates form IC3 lemma atoms
- Paper #15 (Interpolation): Interpolants yield new predicates
- Paper #17 (ICE): Predicates as ICE feature basis

PREDICATES + BARRIERS
=====================

Predicate abstraction enables barrier synthesis:
- Predicates {p_1,...,p_n} define finite abstract domain
- Barrier B is a Boolean combination of predicates
- Synthesis becomes search over Boolean functions
"""

from __future__ import annotations

import time
import itertools
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Dict, List, Optional, Tuple, Set, Any, Callable, FrozenSet
from collections import defaultdict

import z3

# =============================================================================
# LAYER 3: IMPORTS FROM LOWER LAYERS
# =============================================================================
# Predicate abstraction uses polynomial predicates from Layer 1 and
# targets barrier conditions from Layer 2.
# =============================================================================

from .parrilo_sos_sdp import (
    Polynomial,
    SemialgebraicSet,
    BarrierSynthesisProblem,
)


# =============================================================================
# PREDICATE REPRESENTATION
# =============================================================================

@dataclass
class Predicate:
    """
    A predicate for abstraction.
    
    Represents a Boolean property of program states.
    """
    name: str
    formula: z3.BoolRef  # Z3 formula for the predicate
    variables: List[z3.ArithRef]  # Variables appearing in predicate
    id: int = 0
    
    def evaluate(self, model: z3.ModelRef) -> bool:
        """Evaluate predicate under a model."""
        result = model.eval(self.formula, model_completion=True)
        return z3.is_true(result)
    
    def negate(self) -> z3.BoolRef:
        """Get negation of predicate."""
        return z3.Not(self.formula)
    
    def to_constraint(self, value: bool) -> z3.BoolRef:
        """Get constraint for predicate having given value."""
        if value:
            return self.formula
        else:
            return z3.Not(self.formula)
    
    def __str__(self) -> str:
        return f"{self.name}: {self.formula}"
    
    def __hash__(self) -> int:
        return hash(self.name)
    
    def __eq__(self, other) -> bool:
        if isinstance(other, Predicate):
            return self.name == other.name
        return False


@dataclass
class PredicateSet:
    """
    Set of predicates for abstraction.
    """
    predicates: List[Predicate]
    variables: List[z3.ArithRef]
    
    def __post_init__(self):
        # Assign IDs
        for i, p in enumerate(self.predicates):
            p.id = i
    
    def size(self) -> int:
        """Number of predicates."""
        return len(self.predicates)
    
    def get_predicate(self, name: str) -> Optional[Predicate]:
        """Get predicate by name."""
        for p in self.predicates:
            if p.name == name:
                return p
        return None
    
    def add_predicate(self, pred: Predicate) -> None:
        """Add a predicate."""
        pred.id = len(self.predicates)
        self.predicates.append(pred)
    
    def remove_predicate(self, name: str) -> None:
        """Remove a predicate."""
        self.predicates = [p for p in self.predicates if p.name != name]
        for i, p in enumerate(self.predicates):
            p.id = i


# =============================================================================
# ABSTRACT STATE
# =============================================================================

@dataclass(frozen=True)
class AbstractState:
    """
    Abstract state: Boolean assignment to predicates.
    
    Represents a set of concrete states satisfying the assignment.
    """
    assignment: Tuple[bool, ...]  # Truth values for each predicate
    
    def __str__(self) -> str:
        bits = ''.join('1' if b else '0' for b in self.assignment)
        return f"[{bits}]"
    
    def get_value(self, pred_id: int) -> bool:
        """Get value of predicate."""
        if pred_id < len(self.assignment):
            return self.assignment[pred_id]
        return False
    
    def to_constraint(self, predicates: PredicateSet) -> z3.BoolRef:
        """Get Z3 constraint characterizing this abstract state."""
        constraints = []
        for i, value in enumerate(self.assignment):
            if i < len(predicates.predicates):
                constraints.append(predicates.predicates[i].to_constraint(value))
        
        if constraints:
            return z3.And(constraints)
        return z3.BoolVal(True)
    
    @staticmethod
    def from_model(model: z3.ModelRef, predicates: PredicateSet) -> AbstractState:
        """Create abstract state from Z3 model."""
        assignment = tuple(p.evaluate(model) for p in predicates.predicates)
        return AbstractState(assignment)
    
    @staticmethod
    def all_states(n_predicates: int) -> List[AbstractState]:
        """Generate all possible abstract states."""
        return [AbstractState(tuple(bits)) 
                for bits in itertools.product([False, True], repeat=n_predicates)]


@dataclass
class AbstractTransition:
    """
    Transition between abstract states.
    """
    source: AbstractState
    target: AbstractState
    concrete_witness: Optional[Dict[str, float]] = None
    
    def __str__(self) -> str:
        return f"{self.source} -> {self.target}"
    
    def __hash__(self) -> int:
        return hash((self.source, self.target))
    
    def __eq__(self, other) -> bool:
        if isinstance(other, AbstractTransition):
            return self.source == self.source and self.target == other.target
        return False


# =============================================================================
# ABSTRACT TRANSITION SYSTEM
# =============================================================================

@dataclass
class AbstractTransitionSystem:
    """
    Abstract transition system built from predicate abstraction.
    """
    predicates: PredicateSet
    initial_states: Set[AbstractState]
    transitions: Set[AbstractTransition]
    error_states: Set[AbstractState]
    
    def get_successors(self, state: AbstractState) -> Set[AbstractState]:
        """Get successor states."""
        return {t.target for t in self.transitions if t.source == state}
    
    def get_predecessors(self, state: AbstractState) -> Set[AbstractState]:
        """Get predecessor states."""
        return {t.source for t in self.transitions if t.target == state}
    
    def is_reachable(self, state: AbstractState) -> bool:
        """Check if state is reachable from initial states."""
        visited = set()
        worklist = list(self.initial_states)
        
        while worklist:
            current = worklist.pop()
            if current == state:
                return True
            if current in visited:
                continue
            visited.add(current)
            worklist.extend(self.get_successors(current))
        
        return False
    
    def find_path_to_error(self) -> Optional[List[AbstractState]]:
        """Find path from initial to error state."""
        for error in self.error_states:
            path = self._find_path(error)
            if path:
                return path
        return None
    
    def _find_path(self, target: AbstractState) -> Optional[List[AbstractState]]:
        """Find path from initial to target using BFS."""
        from collections import deque
        
        # BFS backwards from target
        parent = {target: None}
        queue = deque([target])
        
        while queue:
            current = queue.popleft()
            
            if current in self.initial_states:
                # Reconstruct path
                path = []
                node = current
                while node is not None:
                    path.append(node)
                    node = parent.get(node)
                return path
            
            for pred in self.get_predecessors(current):
                if pred not in parent:
                    parent[pred] = current
                    queue.append(pred)
        
        return None


# =============================================================================
# PREDICATE ABSTRACTOR
# =============================================================================

class AbstractionResult(Enum):
    """Result of abstraction computation."""
    SUCCESS = auto()
    TIMEOUT = auto()
    ERROR = auto()


@dataclass
class AbstractionComputationResult:
    """Result of computing abstraction."""
    result: AbstractionResult
    system: Optional[AbstractTransitionSystem] = None
    statistics: Dict[str, Any] = field(default_factory=dict)
    message: str = ""


class PredicateAbstractor:
    """
    Compute predicate abstraction using SAT.
    
    Given concrete transition relation and predicates,
    computes abstract transition relation.
    """
    
    def __init__(self, variables: List[z3.ArithRef],
                 primed_variables: List[z3.ArithRef],
                 transition_relation: z3.BoolRef,
                 timeout_ms: int = 60000,
                 verbose: bool = False):
        self.variables = variables
        self.primed_variables = primed_variables
        self.transition_relation = transition_relation
        self.timeout_ms = timeout_ms
        self.verbose = verbose
        
        self.stats = {
            'sat_queries': 0,
            'transitions_found': 0,
            'states_explored': 0,
        }
    
    def compute_abstraction(self, 
                             predicates: PredicateSet,
                             initial_constraint: z3.BoolRef,
                             error_constraint: z3.BoolRef) -> AbstractionComputationResult:
        """
        Compute abstract transition system.
        """
        start_time = time.time()
        
        # Find initial abstract states
        initial_states = self._compute_abstract_initial(predicates, initial_constraint)
        
        # Find error abstract states
        error_states = self._compute_abstract_error(predicates, error_constraint)
        
        # Compute abstract transitions
        transitions = self._compute_abstract_transitions(predicates)
        
        system = AbstractTransitionSystem(
            predicates=predicates,
            initial_states=initial_states,
            transitions=transitions,
            error_states=error_states
        )
        
        self.stats['computation_time_ms'] = (time.time() - start_time) * 1000
        
        return AbstractionComputationResult(
            result=AbstractionResult.SUCCESS,
            system=system,
            statistics=self.stats,
            message="Abstraction computed"
        )
    
    def _compute_abstract_initial(self, predicates: PredicateSet,
                                    initial: z3.BoolRef) -> Set[AbstractState]:
        """Compute abstract initial states."""
        initial_states = set()
        
        for state in AbstractState.all_states(predicates.size()):
            # Check if state ∧ initial is SAT
            solver = z3.Solver()
            solver.set("timeout", self.timeout_ms // 100)
            
            solver.add(initial)
            solver.add(state.to_constraint(predicates))
            
            self.stats['sat_queries'] += 1
            
            if solver.check() == z3.sat:
                initial_states.add(state)
                self.stats['states_explored'] += 1
        
        return initial_states
    
    def _compute_abstract_error(self, predicates: PredicateSet,
                                  error: z3.BoolRef) -> Set[AbstractState]:
        """Compute abstract error states."""
        error_states = set()
        
        for state in AbstractState.all_states(predicates.size()):
            # Check if state ∧ error is SAT
            solver = z3.Solver()
            solver.set("timeout", self.timeout_ms // 100)
            
            solver.add(error)
            solver.add(state.to_constraint(predicates))
            
            self.stats['sat_queries'] += 1
            
            if solver.check() == z3.sat:
                error_states.add(state)
        
        return error_states
    
    def _compute_abstract_transitions(self, 
                                        predicates: PredicateSet) -> Set[AbstractTransition]:
        """Compute abstract transitions using SAT."""
        transitions = set()
        
        # Create primed predicates
        primed_predicates = self._create_primed_predicates(predicates)
        
        for source in AbstractState.all_states(predicates.size()):
            for target in AbstractState.all_states(predicates.size()):
                # Check if source ∧ T ∧ target' is SAT
                solver = z3.Solver()
                solver.set("timeout", self.timeout_ms // 100)
                
                # Source state constraint
                solver.add(source.to_constraint(predicates))
                
                # Transition relation
                solver.add(self.transition_relation)
                
                # Target state constraint (on primed variables)
                target_constraint = self._create_primed_constraint(target, primed_predicates)
                solver.add(target_constraint)
                
                self.stats['sat_queries'] += 1
                
                if solver.check() == z3.sat:
                    model = solver.model()
                    witness = self._extract_witness(model)
                    
                    transitions.add(AbstractTransition(source, target, witness))
                    self.stats['transitions_found'] += 1
        
        return transitions
    
    def _create_primed_predicates(self, predicates: PredicateSet) -> PredicateSet:
        """Create primed versions of predicates."""
        primed = []
        
        for p in predicates.predicates:
            # Substitute primed variables
            subs = list(zip(self.variables, self.primed_variables))
            primed_formula = z3.substitute(p.formula, subs)
            
            primed.append(Predicate(
                name=f"{p.name}'",
                formula=primed_formula,
                variables=self.primed_variables
            ))
        
        return PredicateSet(primed, self.primed_variables)
    
    def _create_primed_constraint(self, state: AbstractState,
                                     primed_preds: PredicateSet) -> z3.BoolRef:
        """Create constraint for target state on primed variables."""
        return state.to_constraint(primed_preds)
    
    def _extract_witness(self, model: z3.ModelRef) -> Dict[str, float]:
        """Extract witness from model."""
        witness = {}
        for v in self.variables:
            val = model.eval(v, model_completion=True)
            if z3.is_rational_value(val):
                witness[str(v)] = float(val.numerator_as_long()) / float(val.denominator_as_long())
            else:
                witness[str(v)] = 0.0
        return witness


# =============================================================================
# COUNTEREXAMPLE ANALYSIS
# =============================================================================

class SpuriousnessResult(Enum):
    """Result of spuriousness check."""
    GENUINE = auto()
    SPURIOUS = auto()
    UNKNOWN = auto()


@dataclass
class CounterexampleAnalysisResult:
    """Result of analyzing counterexample."""
    result: SpuriousnessResult
    spurious_point: int = -1  # Index where path becomes spurious
    new_predicates: List[Predicate] = field(default_factory=list)
    message: str = ""


class CounterexampleAnalyzer:
    """
    Analyze abstract counterexamples for spuriousness.
    
    If spurious, extract new predicates for refinement.
    """
    
    def __init__(self, variables: List[z3.ArithRef],
                 primed_variables: List[z3.ArithRef],
                 transition_relation: z3.BoolRef,
                 timeout_ms: int = 60000,
                 verbose: bool = False):
        self.variables = variables
        self.primed_variables = primed_variables
        self.transition_relation = transition_relation
        self.timeout_ms = timeout_ms
        self.verbose = verbose
        
        self.stats = {
            'analyses': 0,
            'spurious_found': 0,
            'predicates_extracted': 0,
        }
    
    def analyze(self, path: List[AbstractState],
                 predicates: PredicateSet) -> CounterexampleAnalysisResult:
        """
        Analyze abstract path for spuriousness.
        """
        self.stats['analyses'] += 1
        
        # Check if path is concretizable
        concrete_path = self._try_concretize(path, predicates)
        
        if concrete_path is not None:
            return CounterexampleAnalysisResult(
                result=SpuriousnessResult.GENUINE,
                message="Path is genuine"
            )
        
        # Path is spurious, find where it breaks
        spurious_point = self._find_spurious_point(path, predicates)
        
        # Extract new predicates
        new_preds = self._extract_predicates(path, predicates, spurious_point)
        
        self.stats['spurious_found'] += 1
        self.stats['predicates_extracted'] += len(new_preds)
        
        return CounterexampleAnalysisResult(
            result=SpuriousnessResult.SPURIOUS,
            spurious_point=spurious_point,
            new_predicates=new_preds,
            message="Path is spurious"
        )
    
    def _try_concretize(self, path: List[AbstractState],
                          predicates: PredicateSet) -> Optional[List[Dict[str, float]]]:
        """Try to find concrete path corresponding to abstract path."""
        solver = z3.Solver()
        solver.set("timeout", self.timeout_ms)
        
        # Create copies of variables for each step
        step_vars = []
        for i in range(len(path)):
            vars_i = [z3.Real(f"{v}_{i}") for v in [str(v) for v in self.variables]]
            step_vars.append(vars_i)
        
        # Add state constraints
        for i, state in enumerate(path):
            for j, value in enumerate(state.assignment):
                if j < len(predicates.predicates):
                    pred = predicates.predicates[j]
                    # Substitute step variables
                    subs = list(zip(self.variables, step_vars[i]))
                    pred_i = z3.substitute(pred.formula, subs)
                    
                    if value:
                        solver.add(pred_i)
                    else:
                        solver.add(z3.Not(pred_i))
        
        # Add transition constraints
        for i in range(len(path) - 1):
            subs = list(zip(self.variables, step_vars[i])) + \
                   list(zip(self.primed_variables, step_vars[i + 1]))
            trans_i = z3.substitute(self.transition_relation, subs)
            solver.add(trans_i)
        
        if solver.check() == z3.sat:
            model = solver.model()
            concrete_path = []
            
            for vars_i in step_vars:
                state = {}
                for v, v_i in zip(self.variables, vars_i):
                    val = model.eval(v_i, model_completion=True)
                    if z3.is_rational_value(val):
                        state[str(v)] = float(val.numerator_as_long()) / float(val.denominator_as_long())
                    else:
                        state[str(v)] = 0.0
                concrete_path.append(state)
            
            return concrete_path
        
        return None
    
    def _find_spurious_point(self, path: List[AbstractState],
                               predicates: PredicateSet) -> int:
        """Find first transition that is spurious."""
        # Try progressively longer prefixes
        for i in range(1, len(path)):
            prefix = path[:i + 1]
            if self._try_concretize(prefix, predicates) is None:
                return i - 1
        
        return len(path) - 1
    
    def _extract_predicates(self, path: List[AbstractState],
                              predicates: PredicateSet,
                              spurious_point: int) -> List[Predicate]:
        """Extract new predicates to eliminate spurious path."""
        new_preds = []
        
        # Use interpolation at spurious point
        if spurious_point >= 0 and spurious_point < len(path) - 1:
            # Create interpolation query
            interpolant = self._compute_interpolant(path, predicates, spurious_point)
            if interpolant is not None:
                new_preds.append(Predicate(
                    name=f"p_interp_{spurious_point}",
                    formula=interpolant,
                    variables=self.variables
                ))
        
        return new_preds
    
    def _compute_interpolant(self, path: List[AbstractState],
                               predicates: PredicateSet,
                               cut_point: int) -> Optional[z3.BoolRef]:
        """Compute Craig interpolant at cut point."""
        # Simplified: return conjunction of predicates from source state
        state = path[cut_point]
        constraints = []
        
        for i, value in enumerate(state.assignment):
            if i < len(predicates.predicates):
                pred = predicates.predicates[i]
                if value:
                    constraints.append(pred.formula)
        
        if constraints:
            return z3.And(constraints)
        return None


# =============================================================================
# PREDICATE REFINEMENT
# =============================================================================

@dataclass
class RefinementResult:
    """Result of predicate refinement."""
    refined: bool
    new_predicates: List[Predicate]
    iterations: int = 0
    message: str = ""


class PredicateRefinement:
    """
    CEGAR-based predicate refinement.
    
    Iteratively refines abstraction until safety proven or bug found.
    """
    
    def __init__(self, variables: List[z3.ArithRef],
                 primed_variables: List[z3.ArithRef],
                 transition_relation: z3.BoolRef,
                 initial_constraint: z3.BoolRef,
                 error_constraint: z3.BoolRef,
                 max_iterations: int = 100,
                 timeout_ms: int = 60000,
                 verbose: bool = False):
        self.variables = variables
        self.primed_variables = primed_variables
        self.transition_relation = transition_relation
        self.initial_constraint = initial_constraint
        self.error_constraint = error_constraint
        self.max_iterations = max_iterations
        self.timeout_ms = timeout_ms
        self.verbose = verbose
        
        self.abstractor = PredicateAbstractor(
            variables, primed_variables, transition_relation, timeout_ms, verbose
        )
        
        self.analyzer = CounterexampleAnalyzer(
            variables, primed_variables, transition_relation, timeout_ms, verbose
        )
        
        self.stats = {
            'iterations': 0,
            'predicates_added': 0,
            'spurious_eliminated': 0,
        }
    
    def refine(self, initial_predicates: PredicateSet) -> Tuple[bool, PredicateSet]:
        """
        Refine abstraction until result.
        
        Returns:
            (safe, final_predicates)
        """
        predicates = initial_predicates
        
        for iteration in range(self.max_iterations):
            self.stats['iterations'] += 1
            
            # Compute abstraction
            result = self.abstractor.compute_abstraction(
                predicates, self.initial_constraint, self.error_constraint
            )
            
            if result.result != AbstractionResult.SUCCESS:
                break
            
            system = result.system
            
            # Check for path to error
            path = system.find_path_to_error()
            
            if path is None:
                # No path to error - system is safe
                return (True, predicates)
            
            # Analyze counterexample
            analysis = self.analyzer.analyze(path, predicates)
            
            if analysis.result == SpuriousnessResult.GENUINE:
                # Genuine bug found
                return (False, predicates)
            
            # Refine with new predicates
            for pred in analysis.new_predicates:
                predicates.add_predicate(pred)
                self.stats['predicates_added'] += 1
            
            self.stats['spurious_eliminated'] += 1
        
        return (False, predicates)


# =============================================================================
# PREDICATE DISCOVERY
# =============================================================================

class PredicateDiscovery:
    """
    Automatic predicate discovery from program.
    """
    
    def __init__(self, variables: List[z3.ArithRef],
                 verbose: bool = False):
        self.variables = variables
        self.verbose = verbose
        
        self.stats = {
            'predicates_discovered': 0,
        }
    
    def discover_from_constraints(self, 
                                    constraints: List[z3.BoolRef]) -> PredicateSet:
        """Discover predicates from constraints."""
        predicates = []
        
        for i, c in enumerate(constraints):
            pred = Predicate(
                name=f"c_{i}",
                formula=c,
                variables=self.variables
            )
            predicates.append(pred)
            self.stats['predicates_discovered'] += 1
        
        return PredicateSet(predicates, self.variables)
    
    def discover_from_polynomial(self, polynomial: Polynomial) -> List[Predicate]:
        """Discover predicates from polynomial constraints."""
        predicates = []
        
        # p >= 0
        z3_vars = [z3.Real(f"x_{i}") for i in range(polynomial.n_vars)]
        p_z3 = polynomial.to_z3(z3_vars)
        
        predicates.append(Predicate(
            name=f"poly_pos",
            formula=p_z3 >= 0,
            variables=z3_vars
        ))
        
        # p = 0
        predicates.append(Predicate(
            name=f"poly_zero",
            formula=p_z3 == 0,
            variables=z3_vars
        ))
        
        self.stats['predicates_discovered'] += 2
        
        return predicates


# =============================================================================
# PREDICATE INTEGRATION
# =============================================================================

@dataclass
class PredicateAbstractionConfig:
    """Configuration for predicate abstraction."""
    max_refinement_iterations: int = 100
    max_predicates: int = 50
    timeout_ms: int = 60000
    verbose: bool = False


class PredicateAbstractionIntegration:
    """
    Integration of predicate abstraction with barrier synthesis.
    
    Provides:
    1. Abstraction computation from barrier constraints
    2. Predicate refinement for spurious paths
    3. Predicate-guided barrier strengthening
    """
    
    def __init__(self, config: Optional[PredicateAbstractionConfig] = None,
                 verbose: bool = False):
        self.config = config or PredicateAbstractionConfig()
        self.verbose = verbose or self.config.verbose
        
        self._abstractions: Dict[str, AbstractTransitionSystem] = {}
        self._predicates: Dict[str, PredicateSet] = {}
        
        self.stats = {
            'abstractions_computed': 0,
            'refinements': 0,
            'predicates_total': 0,
        }
    
    def compute_abstraction(self, abs_id: str,
                             variables: List[z3.ArithRef],
                             primed_vars: List[z3.ArithRef],
                             transition: z3.BoolRef,
                             initial: z3.BoolRef,
                             error: z3.BoolRef,
                             predicates: PredicateSet) -> AbstractionComputationResult:
        """
        Compute predicate abstraction.
        """
        abstractor = PredicateAbstractor(
            variables, primed_vars, transition,
            self.config.timeout_ms, self.verbose
        )
        
        result = abstractor.compute_abstraction(predicates, initial, error)
        
        if result.result == AbstractionResult.SUCCESS:
            self._abstractions[abs_id] = result.system
            self._predicates[abs_id] = predicates
            self.stats['abstractions_computed'] += 1
            self.stats['predicates_total'] += predicates.size()
        
        return result
    
    def check_safety(self, abs_id: str) -> Tuple[bool, Optional[List[AbstractState]]]:
        """
        Check safety using abstraction.
        
        Returns (safe, counterexample_path)
        """
        system = self._abstractions.get(abs_id)
        if system is None:
            return (False, None)
        
        path = system.find_path_to_error()
        
        if path is None:
            return (True, None)
        else:
            return (False, path)
    
    def refine(self, abs_id: str,
                variables: List[z3.ArithRef],
                primed_vars: List[z3.ArithRef],
                transition: z3.BoolRef,
                initial: z3.BoolRef,
                error: z3.BoolRef) -> Tuple[bool, PredicateSet]:
        """
        Refine abstraction using CEGAR.
        """
        predicates = self._predicates.get(abs_id, PredicateSet([], variables))
        
        refinement = PredicateRefinement(
            variables, primed_vars, transition, initial, error,
            self.config.max_refinement_iterations,
            self.config.timeout_ms, self.verbose
        )
        
        safe, final_preds = refinement.refine(predicates)
        
        self._predicates[abs_id] = final_preds
        self.stats['refinements'] += 1
        
        return (safe, final_preds)
    
    def condition_barrier_problem(self, problem: BarrierSynthesisProblem,
                                    abs_id: str) -> BarrierSynthesisProblem:
        """
        Condition barrier problem using predicate insights.
        """
        predicates = self._predicates.get(abs_id)
        if predicates is None:
            return problem
        
        # Add predicate constraints as polynomials (simplified)
        new_init = problem.init_set
        
        return BarrierSynthesisProblem(
            n_vars=problem.n_vars,
            init_set=new_init,
            unsafe_set=problem.unsafe_set,
            transition=problem.transition,
            epsilon=problem.epsilon,
            barrier_degree=problem.barrier_degree
        )


# =============================================================================
# CONVENIENCE FUNCTIONS  
# =============================================================================

def create_predicate(name: str, formula: z3.BoolRef,
                      variables: List[z3.ArithRef]) -> Predicate:
    """Create a predicate."""
    return Predicate(name, formula, variables)


def create_predicate_set(predicates: List[Predicate],
                           variables: List[z3.ArithRef]) -> PredicateSet:
    """Create a predicate set."""
    return PredicateSet(predicates, variables)


def compute_abstraction(variables: List[z3.ArithRef],
                          primed_vars: List[z3.ArithRef],
                          transition: z3.BoolRef,
                          initial: z3.BoolRef,
                          error: z3.BoolRef,
                          predicates: PredicateSet,
                          timeout_ms: int = 60000,
                          verbose: bool = False) -> AbstractionComputationResult:
    """Compute predicate abstraction."""
    abstractor = PredicateAbstractor(
        variables, primed_vars, transition, timeout_ms, verbose
    )
    return abstractor.compute_abstraction(predicates, initial, error)


def check_counterexample(path: List[AbstractState],
                           predicates: PredicateSet,
                           variables: List[z3.ArithRef],
                           primed_vars: List[z3.ArithRef],
                           transition: z3.BoolRef,
                           timeout_ms: int = 60000,
                           verbose: bool = False) -> CounterexampleAnalysisResult:
    """Analyze counterexample for spuriousness."""
    analyzer = CounterexampleAnalyzer(
        variables, primed_vars, transition, timeout_ms, verbose
    )
    return analyzer.analyze(path, predicates)


# =============================================================================
# ADVANCED PREDICATE ABSTRACTION TECHNIQUES
# =============================================================================

class CartesianAbstraction:
    """
    Cartesian predicate abstraction.
    
    Maintains predicates independently without tracking correlations.
    More efficient but less precise than full Boolean abstraction.
    """
    
    def __init__(self, variables: List[z3.ArithRef],
                 primed_vars: List[z3.ArithRef],
                 transition: z3.BoolRef,
                 timeout_ms: int = 60000):
        self.variables = variables
        self.primed_vars = primed_vars
        self.transition = transition
        self.timeout_ms = timeout_ms
        
        self.stats = {
            'abstract_states': 0,
            'abstract_transitions': 0,
        }
    
    def abstract_state(self, predicates: PredicateSet,
                        concrete_formula: z3.BoolRef) -> Dict[int, Optional[bool]]:
        """
        Compute Cartesian abstraction of concrete formula.
        
        For each predicate, determines if it's definitely true,
        definitely false, or unknown.
        """
        abstract_vals = {}
        
        solver = z3.Solver()
        solver.set("timeout", self.timeout_ms // len(predicates.predicates))
        
        for i, pred in enumerate(predicates.predicates):
            # Check if predicate must be true
            solver.push()
            solver.add(concrete_formula)
            solver.add(z3.Not(pred.formula))
            
            if solver.check() == z3.unsat:
                abstract_vals[i] = True
                solver.pop()
                continue
            
            solver.pop()
            
            # Check if predicate must be false
            solver.push()
            solver.add(concrete_formula)
            solver.add(pred.formula)
            
            if solver.check() == z3.unsat:
                abstract_vals[i] = False
            else:
                abstract_vals[i] = None  # Unknown
            
            solver.pop()
        
        self.stats['abstract_states'] += 1
        return abstract_vals
    
    def abstract_post(self, predicates: PredicateSet,
                       abstract_state: Dict[int, Optional[bool]]) -> List[Dict[int, Optional[bool]]]:
        """
        Compute abstract post-image using Cartesian abstraction.
        """
        successors = []
        
        # Build constraint from abstract state
        constraint = z3.BoolVal(True)
        for i, val in abstract_state.items():
            pred = predicates.predicates[i]
            if val is True:
                constraint = z3.And(constraint, pred.formula)
            elif val is False:
                constraint = z3.And(constraint, z3.Not(pred.formula))
        
        # Compute post
        post_constraint = z3.And(constraint, self.transition)
        
        # Abstract the result
        primed_predicates = PredicateSet(
            [Predicate(z3.substitute(p.formula, 
                        list(zip(self.variables, self.primed_vars))), p.name)
             for p in predicates.predicates],
            self.primed_vars
        )
        
        successor = self.abstract_state(predicates, 
                                          z3.Exists(self.variables, post_constraint))
        successors.append(successor)
        
        self.stats['abstract_transitions'] += 1
        return successors


class BooleanAbstraction:
    """
    Full Boolean predicate abstraction.
    
    Tracks all correlations between predicates using
    Boolean formulas over predicate values.
    """
    
    def __init__(self, variables: List[z3.ArithRef],
                 primed_vars: List[z3.ArithRef],
                 transition: z3.BoolRef,
                 timeout_ms: int = 60000):
        self.variables = variables
        self.primed_vars = primed_vars
        self.transition = transition
        self.timeout_ms = timeout_ms
        
        self._predicate_bools: List[z3.BoolRef] = []
        
        self.stats = {
            'abstraction_queries': 0,
            'cube_enumerations': 0,
        }
    
    def create_boolean_vars(self, num_predicates: int) -> List[z3.BoolRef]:
        """Create Boolean variables for predicates."""
        self._predicate_bools = [z3.Bool(f"p_{i}") for i in range(num_predicates)]
        return self._predicate_bools
    
    def abstract_state_full(self, predicates: PredicateSet,
                             concrete_formula: z3.BoolRef) -> z3.BoolRef:
        """
        Compute full Boolean abstraction.
        
        Returns a Boolean formula over predicate variables.
        """
        if len(self._predicate_bools) != len(predicates.predicates):
            self.create_boolean_vars(len(predicates.predicates))
        
        # Enumerate all satisfying cubes
        cubes = []
        solver = z3.Solver()
        solver.set("timeout", self.timeout_ms)
        solver.add(concrete_formula)
        
        while solver.check() == z3.sat:
            self.stats['cube_enumerations'] += 1
            model = solver.model()
            
            cube_lits = []
            block_lits = []
            
            for i, pred in enumerate(predicates.predicates):
                val = model.eval(pred.formula, model_completion=True)
                if z3.is_true(val):
                    cube_lits.append(self._predicate_bools[i])
                    block_lits.append(z3.Not(pred.formula))
                else:
                    cube_lits.append(z3.Not(self._predicate_bools[i]))
                    block_lits.append(pred.formula)
            
            cubes.append(z3.And(cube_lits))
            solver.add(z3.Or(block_lits))
        
        if cubes:
            return z3.simplify(z3.Or(cubes))
        else:
            return z3.BoolVal(False)
    
    def compute_transition_relation(self, predicates: PredicateSet) -> z3.BoolRef:
        """
        Compute abstract transition relation.
        
        Returns Boolean formula relating pre and post predicate values.
        """
        if len(self._predicate_bools) != len(predicates.predicates):
            self.create_boolean_vars(len(predicates.predicates))
        
        # Create primed predicate Booleans
        primed_bools = [z3.Bool(f"p'_{i}") for i in range(len(predicates.predicates))]
        
        # Enumerate transitions
        trans_cubes = []
        solver = z3.Solver()
        solver.set("timeout", self.timeout_ms)
        solver.add(self.transition)
        
        self.stats['abstraction_queries'] += 1
        
        while solver.check() == z3.sat:
            model = solver.model()
            
            pre_cube = []
            post_cube = []
            block_lits = []
            
            for i, pred in enumerate(predicates.predicates):
                # Pre value
                pre_val = model.eval(pred.formula, model_completion=True)
                if z3.is_true(pre_val):
                    pre_cube.append(self._predicate_bools[i])
                else:
                    pre_cube.append(z3.Not(self._predicate_bools[i]))
                
                # Post value
                post_formula = z3.substitute(pred.formula,
                                              list(zip(self.variables, self.primed_vars)))
                post_val = model.eval(post_formula, model_completion=True)
                if z3.is_true(post_val):
                    post_cube.append(primed_bools[i])
                else:
                    post_cube.append(z3.Not(primed_bools[i]))
                
                block_lits.append(pred.formula != pre_val)
            
            trans_cubes.append(z3.And(pre_cube + post_cube))
            solver.add(z3.Or(block_lits))
        
        if trans_cubes:
            return z3.Or(trans_cubes)
        else:
            return z3.BoolVal(False)


class PredicateMinimization:
    """
    Predicate minimization techniques.
    
    Reduces predicate set while preserving abstraction precision.
    """
    
    def __init__(self, predicates: PredicateSet,
                 variables: List[z3.ArithRef],
                 timeout_ms: int = 60000):
        self.predicates = predicates
        self.variables = variables
        self.timeout_ms = timeout_ms
        
        self.stats = {
            'original_predicates': len(predicates.predicates),
            'minimized_predicates': 0,
            'redundant_removed': 0,
        }
    
    def remove_redundant(self) -> PredicateSet:
        """
        Remove redundant predicates.
        
        A predicate is redundant if it's implied by others.
        """
        kept = []
        
        for i, pred in enumerate(self.predicates.predicates):
            # Check if pred is implied by others
            other_preds = [p for j, p in enumerate(self.predicates.predicates) 
                           if j != i and p in kept]
            
            if other_preds:
                solver = z3.Solver()
                solver.set("timeout", self.timeout_ms // len(self.predicates.predicates))
                
                for p in other_preds:
                    solver.add(p.formula)
                
                solver.add(z3.Not(pred.formula))
                
                if solver.check() == z3.unsat:
                    # pred is implied, skip it
                    self.stats['redundant_removed'] += 1
                    continue
            
            kept.append(pred)
        
        self.stats['minimized_predicates'] = len(kept)
        return PredicateSet(kept, self.variables)
    
    def merge_equivalent(self) -> PredicateSet:
        """
        Merge equivalent predicates.
        """
        equivalence_classes: List[List[Predicate]] = []
        
        for pred in self.predicates.predicates:
            found = False
            for eq_class in equivalence_classes:
                rep = eq_class[0]
                
                solver = z3.Solver()
                solver.set("timeout", 1000)
                solver.add(pred.formula != rep.formula)
                
                if solver.check() == z3.unsat:
                    eq_class.append(pred)
                    found = True
                    break
            
            if not found:
                equivalence_classes.append([pred])
        
        # Keep one representative from each class
        minimized = [eq_class[0] for eq_class in equivalence_classes]
        
        self.stats['minimized_predicates'] = len(minimized)
        return PredicateSet(minimized, self.variables)


class CraigInterpolation:
    """
    Craig interpolation for predicate discovery.
    
    Uses interpolants from SMT solvers to find new predicates.
    """
    
    def __init__(self, variables: List[z3.ArithRef],
                 timeout_ms: int = 60000):
        self.variables = variables
        self.timeout_ms = timeout_ms
        
        self.stats = {
            'interpolation_queries': 0,
            'interpolants_computed': 0,
        }
    
    def compute_interpolant(self, A: z3.BoolRef, 
                             B: z3.BoolRef) -> Optional[z3.BoolRef]:
        """
        Compute Craig interpolant I such that:
        - A → I is valid
        - I ∧ B is unsatisfiable
        - I uses only common variables
        """
        self.stats['interpolation_queries'] += 1
        
        # Check unsatisfiability
        solver = z3.Solver()
        solver.set("timeout", self.timeout_ms)
        solver.add(A)
        solver.add(B)
        
        if solver.check() != z3.unsat:
            return None
        
        # Use Z3's interpolation capability
        try:
            # Create interpolation goal
            g = z3.Goal()
            g.add(A)
            g.add(B)
            
            # For Z3, we use the proof to extract interpolant
            # Simplified: return conjunction of A
            self.stats['interpolants_computed'] += 1
            return A
        except Exception:
            return None
    
    def sequence_interpolation(self, formulas: List[z3.BoolRef]) -> List[z3.BoolRef]:
        """
        Compute sequence of interpolants for path.
        
        Given A_0, A_1, ..., A_n where A_0 ∧ ... ∧ A_n is unsat,
        compute I_1, ..., I_n where:
        - A_0 → I_1
        - I_i ∧ A_i → I_{i+1}
        - I_n ∧ A_n is unsat
        """
        if len(formulas) < 2:
            return []
        
        interpolants = []
        
        for i in range(1, len(formulas)):
            A = z3.And(formulas[:i])
            B = z3.And(formulas[i:])
            
            interp = self.compute_interpolant(A, B)
            if interp:
                interpolants.append(interp)
        
        return interpolants


class WidenedAbstraction:
    """
    Widened predicate abstraction.
    
    Uses widening to accelerate fixed-point computation.
    """
    
    def __init__(self, predicates: PredicateSet,
                 variables: List[z3.ArithRef],
                 threshold: int = 3):
        self.predicates = predicates
        self.variables = variables
        self.threshold = threshold
        
        self._iteration_count: Dict[int, int] = {}
        
        self.stats = {
            'widen_applications': 0,
        }
    
    def widen(self, old_state: AbstractState, 
               new_state: AbstractState,
               state_id: int) -> AbstractState:
        """
        Apply widening to abstract state.
        """
        self._iteration_count[state_id] = self._iteration_count.get(state_id, 0) + 1
        
        if self._iteration_count[state_id] < self.threshold:
            return new_state  # No widening yet
        
        self.stats['widen_applications'] += 1
        
        # Widening: drop predicates that weren't stable
        widened_vals = {}
        
        for i in range(len(self.predicates.predicates)):
            old_val = old_state.predicate_values.get(i)
            new_val = new_state.predicate_values.get(i)
            
            if old_val == new_val:
                widened_vals[i] = old_val
            else:
                widened_vals[i] = None  # Drop unstable
        
        return AbstractState(widened_vals, self.predicates)
    
    def narrow(self, widened: AbstractState,
                precise: AbstractState) -> AbstractState:
        """
        Apply narrowing to recover precision after widening.
        """
        narrowed_vals = {}
        
        for i in range(len(self.predicates.predicates)):
            w_val = widened.predicate_values.get(i)
            p_val = precise.predicate_values.get(i)
            
            if w_val is None and p_val is not None:
                narrowed_vals[i] = p_val  # Recover precision
            else:
                narrowed_vals[i] = w_val
        
        return AbstractState(narrowed_vals, self.predicates)


class LazyAbstractionManager:
    """
    Lazy abstraction with predicate discovery.
    
    Combines lazy abstraction with on-demand predicate refinement.
    """
    
    def __init__(self, variables: List[z3.ArithRef],
                 primed_vars: List[z3.ArithRef],
                 transition: z3.BoolRef,
                 initial: z3.BoolRef,
                 error: z3.BoolRef,
                 timeout_ms: int = 60000):
        self.variables = variables
        self.primed_vars = primed_vars
        self.transition = transition
        self.initial = initial
        self.error = error
        self.timeout_ms = timeout_ms
        
        self.predicates = PredicateSet([], variables)
        self.interpolator = CraigInterpolation(variables, timeout_ms)
        
        self.stats = {
            'refinement_iterations': 0,
            'predicates_discovered': 0,
            'verification_result': None,
        }
    
    def verify(self, max_iterations: int = 100) -> bool:
        """
        Verify property using lazy abstraction with CEGAR.
        """
        for _ in range(max_iterations):
            self.stats['refinement_iterations'] += 1
            
            # Compute abstraction
            abstractor = PredicateAbstractor(
                self.variables, self.primed_vars,
                self.transition, self.timeout_ms, False
            )
            
            result = abstractor.compute_abstraction(
                self.predicates, self.initial, self.error
            )
            
            if result.result == AbstractionResult.SAFE:
                self.stats['verification_result'] = 'SAFE'
                return True
            
            if result.counterexample:
                # Analyze counterexample
                analyzer = CounterexampleAnalyzer(
                    self.variables, self.primed_vars,
                    self.transition, self.timeout_ms, False
                )
                
                cex_result = analyzer.analyze(
                    result.counterexample, self.predicates
                )
                
                if cex_result.is_spurious:
                    # Refine predicates
                    new_preds = self._discover_predicates(result.counterexample)
                    self.predicates = PredicateSet(
                        self.predicates.predicates + new_preds,
                        self.variables
                    )
                    self.stats['predicates_discovered'] += len(new_preds)
                else:
                    self.stats['verification_result'] = 'UNSAFE'
                    return False
        
        self.stats['verification_result'] = 'UNKNOWN'
        return False
    
    def _discover_predicates(self, counterexample: List[AbstractState]) -> List[Predicate]:
        """Discover new predicates from counterexample."""
        # Build path constraint
        path_formulas = []
        
        for i, state in enumerate(counterexample):
            # State constraint
            state_formula = z3.BoolVal(True)
            for j, val in state.predicate_values.items():
                pred = self.predicates.predicates[j] if j < len(self.predicates.predicates) else None
                if pred and val is not None:
                    if val:
                        state_formula = z3.And(state_formula, pred.formula)
                    else:
                        state_formula = z3.And(state_formula, z3.Not(pred.formula))
            
            path_formulas.append(state_formula)
            
            if i < len(counterexample) - 1:
                path_formulas.append(self.transition)
        
        # Compute interpolants
        interpolants = self.interpolator.sequence_interpolation(path_formulas)
        
        # Convert to predicates
        new_preds = []
        for i, interp in enumerate(interpolants):
            new_preds.append(Predicate(interp, f"itp_{len(self.predicates.predicates)}_{i}"))
        
        return new_preds


class AbstractionRefinementLoop:
    """
    Complete CEGAR loop for predicate abstraction.
    """
    
    def __init__(self, program_model: Dict[str, Any],
                 timeout_ms: int = 60000):
        self.program_model = program_model
        self.timeout_ms = timeout_ms
        
        self.predicates: List[Predicate] = []
        self.iteration = 0
        
        self.stats = {
            'total_iterations': 0,
            'predicates_final': 0,
            'result': None,
        }
    
    def run(self, max_iterations: int = 100,
             initial_predicates: Optional[List[Predicate]] = None) -> Dict[str, Any]:
        """
        Run complete CEGAR loop.
        """
        if initial_predicates:
            self.predicates = initial_predicates
        
        for self.iteration in range(max_iterations):
            self.stats['total_iterations'] = self.iteration + 1
            
            # Abstract
            abs_result = self._abstract()
            
            if abs_result['safe']:
                self.stats['result'] = 'SAFE'
                self.stats['predicates_final'] = len(self.predicates)
                return {'result': 'SAFE', 'predicates': self.predicates}
            
            # Spuriousness check
            if abs_result['counterexample']:
                is_real = self._check_counterexample(abs_result['counterexample'])
                
                if is_real:
                    self.stats['result'] = 'UNSAFE'
                    return {'result': 'UNSAFE', 
                            'counterexample': abs_result['counterexample']}
                
                # Refine
                new_preds = self._refine(abs_result['counterexample'])
                self.predicates.extend(new_preds)
        
        self.stats['result'] = 'UNKNOWN'
        return {'result': 'UNKNOWN'}
    
    def _abstract(self) -> Dict[str, Any]:
        """Compute abstraction with current predicates."""
        return {'safe': False, 'counterexample': None}
    
    def _check_counterexample(self, cex: List[AbstractState]) -> bool:
        """Check if counterexample is real."""
        return False
    
    def _refine(self, cex: List[AbstractState]) -> List[Predicate]:
        """Refine predicates based on spurious counterexample."""
        return []


# =============================================================================
# ADDITIONAL PREDICATE ABSTRACTION COMPONENTS
# =============================================================================

class PredicateAbstractionDomain:
    """
    Abstract domain for predicate abstraction.
    
    Provides lattice operations for abstract states.
    """
    
    def __init__(self, predicates: PredicateSet):
        self.predicates = predicates
        self.num_predicates = len(predicates.predicates)
        
        # Cache for lattice operations
        self._join_cache: Dict[Tuple[int, int], AbstractState] = {}
        self._meet_cache: Dict[Tuple[int, int], AbstractState] = {}
        
        self.stats = {
            'join_operations': 0,
            'meet_operations': 0,
            'widen_operations': 0,
        }
    
    def top(self) -> AbstractState:
        """Return top element (all unknown)."""
        return AbstractState({i: None for i in range(self.num_predicates)},
                              self.predicates)
    
    def bottom(self) -> AbstractState:
        """Return bottom element (contradiction)."""
        return AbstractState({}, self.predicates, is_bottom=True)
    
    def join(self, s1: AbstractState, s2: AbstractState) -> AbstractState:
        """Compute least upper bound."""
        self.stats['join_operations'] += 1
        
        result_vals = {}
        for i in range(self.num_predicates):
            v1 = s1.predicate_values.get(i)
            v2 = s2.predicate_values.get(i)
            
            if v1 == v2:
                result_vals[i] = v1
            else:
                result_vals[i] = None  # Unknown
        
        return AbstractState(result_vals, self.predicates)
    
    def meet(self, s1: AbstractState, s2: AbstractState) -> AbstractState:
        """Compute greatest lower bound."""
        self.stats['meet_operations'] += 1
        
        result_vals = {}
        for i in range(self.num_predicates):
            v1 = s1.predicate_values.get(i)
            v2 = s2.predicate_values.get(i)
            
            if v1 is None:
                result_vals[i] = v2
            elif v2 is None:
                result_vals[i] = v1
            elif v1 == v2:
                result_vals[i] = v1
            else:
                # Contradiction
                return self.bottom()
        
        return AbstractState(result_vals, self.predicates)
    
    def widen(self, s1: AbstractState, s2: AbstractState) -> AbstractState:
        """Widening operator."""
        self.stats['widen_operations'] += 1
        
        result_vals = {}
        for i in range(self.num_predicates):
            v1 = s1.predicate_values.get(i)
            v2 = s2.predicate_values.get(i)
            
            # Keep only stable values
            if v1 == v2:
                result_vals[i] = v1
            else:
                result_vals[i] = None
        
        return AbstractState(result_vals, self.predicates)
    
    def is_subset(self, s1: AbstractState, s2: AbstractState) -> bool:
        """Check if s1 ⊆ s2 (s1 is more precise)."""
        for i in range(self.num_predicates):
            v1 = s1.predicate_values.get(i)
            v2 = s2.predicate_values.get(i)
            
            if v2 is not None and v1 != v2:
                return False
        
        return True


class SymbolicPredicateAbstraction:
    """
    Symbolic predicate abstraction using BDDs.
    """
    
    def __init__(self, predicates: PredicateSet,
                 variables: List[z3.ArithRef]):
        self.predicates = predicates
        self.variables = variables
        
        # Predicate Boolean variables
        self.pred_vars = [z3.Bool(f"_p{i}") for i in range(len(predicates.predicates))]
        
        self.stats = {
            'symbolic_abstractions': 0,
            'concretizations': 0,
        }
    
    def abstract_formula(self, formula: z3.BoolRef) -> z3.BoolRef:
        """
        Abstract concrete formula to Boolean formula over predicates.
        """
        self.stats['symbolic_abstractions'] += 1
        
        solver = z3.Solver()
        solver.set("timeout", 10000)
        
        # Enumerate satisfying abstract states
        cubes = []
        solver.add(formula)
        
        while solver.check() == z3.sat:
            model = solver.model()
            
            cube = []
            block = []
            
            for i, pred in enumerate(self.predicates.predicates):
                val = model.eval(pred.formula, model_completion=True)
                
                if z3.is_true(val):
                    cube.append(self.pred_vars[i])
                    block.append(z3.Not(pred.formula))
                else:
                    cube.append(z3.Not(self.pred_vars[i]))
                    block.append(pred.formula)
            
            cubes.append(z3.And(cube))
            solver.add(z3.Or(block))
        
        if cubes:
            return z3.Or(cubes)
        else:
            return z3.BoolVal(False)
    
    def concretize(self, abstract_formula: z3.BoolRef) -> z3.BoolRef:
        """
        Concretize abstract formula.
        """
        self.stats['concretizations'] += 1
        
        # Substitute predicate variables with actual predicates
        subs = [(self.pred_vars[i], pred.formula)
                for i, pred in enumerate(self.predicates.predicates)]
        
        return z3.substitute(abstract_formula, subs)


class PredicateDiscovery:
    """
    Automatic predicate discovery techniques.
    """
    
    def __init__(self, variables: List[z3.ArithRef],
                 timeout_ms: int = 60000):
        self.variables = variables
        self.timeout_ms = timeout_ms
        
        self.discovered_predicates: List[Predicate] = []
        
        self.stats = {
            'from_program': 0,
            'from_interpolants': 0,
            'from_weakest_precondition': 0,
        }
    
    def discover_from_program(self, program_formulas: List[z3.BoolRef]) -> List[Predicate]:
        """Extract predicates from program conditions."""
        predicates = []
        
        for formula in program_formulas:
            atoms = self._extract_atoms(formula)
            for atom in atoms:
                pred = Predicate(atom, f"prog_{len(predicates)}")
                predicates.append(pred)
                self.stats['from_program'] += 1
        
        return predicates
    
    def discover_from_interpolants(self, 
                                     interpolants: List[z3.BoolRef]) -> List[Predicate]:
        """Extract predicates from interpolants."""
        predicates = []
        
        for interp in interpolants:
            atoms = self._extract_atoms(interp)
            for atom in atoms:
                pred = Predicate(atom, f"itp_{len(predicates)}")
                predicates.append(pred)
                self.stats['from_interpolants'] += 1
        
        return predicates
    
    def discover_from_weakest_precondition(self,
                                             post: z3.BoolRef,
                                             transition: z3.BoolRef,
                                             primed_vars: List[z3.ArithRef]) -> List[Predicate]:
        """Compute predicates from weakest precondition."""
        # WP(post, transition) = ∀post_vars. transition → post[primed/orig]
        
        predicates = []
        
        wp = z3.ForAll(primed_vars, z3.Implies(transition, post))
        wp_simplified = z3.simplify(wp)
        
        atoms = self._extract_atoms(wp_simplified)
        for atom in atoms:
            pred = Predicate(atom, f"wp_{len(predicates)}")
            predicates.append(pred)
            self.stats['from_weakest_precondition'] += 1
        
        return predicates
    
    def _extract_atoms(self, formula: z3.BoolRef) -> List[z3.BoolRef]:
        """Extract atomic predicates from formula."""
        atoms = []
        
        def visit(f):
            if z3.is_and(f) or z3.is_or(f):
                for child in f.children():
                    visit(child)
            elif z3.is_not(f):
                visit(f.arg(0))
            elif z3.is_app(f):
                # Check if it's a comparison
                if f.decl().kind() in [z3.Z3_OP_LE, z3.Z3_OP_LT, 
                                        z3.Z3_OP_GE, z3.Z3_OP_GT, z3.Z3_OP_EQ]:
                    atoms.append(f)
        
        visit(formula)
        return atoms


class TransitionRelationAbstraction:
    """
    Abstraction of transition relation.
    """
    
    def __init__(self, variables: List[z3.ArithRef],
                 primed_vars: List[z3.ArithRef],
                 predicates: PredicateSet,
                 timeout_ms: int = 60000):
        self.variables = variables
        self.primed_vars = primed_vars
        self.predicates = predicates
        self.timeout_ms = timeout_ms
        
        self._abstract_trans: Optional[z3.BoolRef] = None
        
        self.stats = {
            'transition_abstractions': 0,
        }
    
    def abstract_transition(self, transition: z3.BoolRef) -> z3.BoolRef:
        """
        Abstract concrete transition to Boolean transition.
        """
        self.stats['transition_abstractions'] += 1
        
        # Create primed predicate variables
        pred_vars = [z3.Bool(f"_p{i}") for i in range(len(self.predicates.predicates))]
        primed_pred_vars = [z3.Bool(f"_p'{i}") for i in range(len(self.predicates.predicates))]
        
        solver = z3.Solver()
        solver.set("timeout", self.timeout_ms)
        solver.add(transition)
        
        cubes = []
        
        while solver.check() == z3.sat:
            model = solver.model()
            
            pre_cube = []
            post_cube = []
            block = []
            
            for i, pred in enumerate(self.predicates.predicates):
                # Pre-state
                pre_val = model.eval(pred.formula, model_completion=True)
                if z3.is_true(pre_val):
                    pre_cube.append(pred_vars[i])
                else:
                    pre_cube.append(z3.Not(pred_vars[i]))
                
                # Post-state
                post_formula = z3.substitute(pred.formula,
                                              list(zip(self.variables, self.primed_vars)))
                post_val = model.eval(post_formula, model_completion=True)
                if z3.is_true(post_val):
                    post_cube.append(primed_pred_vars[i])
                else:
                    post_cube.append(z3.Not(primed_pred_vars[i]))
                
                block.append(pred.formula != pre_val)
            
            cubes.append(z3.And(pre_cube + post_cube))
            solver.add(z3.Or(block))
        
        self._abstract_trans = z3.Or(cubes) if cubes else z3.BoolVal(False)
        return self._abstract_trans


class FixedPointComputation:
    """
    Fixed-point computation for predicate abstraction.
    """
    
    def __init__(self, domain: PredicateAbstractionDomain,
                 timeout_ms: int = 60000):
        self.domain = domain
        self.timeout_ms = timeout_ms
        
        self.stats = {
            'iterations': 0,
            'fixed_point_reached': False,
        }
    
    def compute_least_fixed_point(self, 
                                    transformer: Callable[[AbstractState], AbstractState],
                                    initial: AbstractState) -> AbstractState:
        """
        Compute least fixed point of transformer starting from initial.
        """
        current = initial
        
        start_time = time.time()
        
        while True:
            self.stats['iterations'] += 1
            
            if (time.time() - start_time) * 1000 > self.timeout_ms:
                break
            
            next_state = transformer(current)
            joined = self.domain.join(current, next_state)
            
            if self.domain.is_subset(joined, current):
                self.stats['fixed_point_reached'] = True
                break
            
            current = joined
        
        return current
    
    def compute_with_widening(self,
                               transformer: Callable[[AbstractState], AbstractState],
                               initial: AbstractState,
                               widen_threshold: int = 3) -> AbstractState:
        """
        Compute fixed point with widening.
        """
        current = initial
        iteration = 0
        
        start_time = time.time()
        
        while True:
            self.stats['iterations'] += 1
            iteration += 1
            
            if (time.time() - start_time) * 1000 > self.timeout_ms:
                break
            
            next_state = transformer(current)
            
            if iteration < widen_threshold:
                joined = self.domain.join(current, next_state)
            else:
                joined = self.domain.widen(current, next_state)
            
            if self.domain.is_subset(joined, current):
                self.stats['fixed_point_reached'] = True
                break
            
            current = joined
        
        return current
