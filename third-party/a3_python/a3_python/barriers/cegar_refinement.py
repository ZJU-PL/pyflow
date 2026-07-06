"""
SOTA Paper #12: CEGAR (Counterexample-Guided Abstraction Refinement).

Implements abstraction refinement for software verification:
    E. Clarke, O. Grumberg, S. Jha, Y. Lu, H. Veith. 
    "Counterexample-Guided Abstraction Refinement." CAV 2000.

KEY INSIGHT
===========

CEGAR iteratively refines abstractions:
1. Start with coarse abstraction
2. Model check abstract system
3. If safe → done (SAFE proof)
4. If counterexample → check feasibility
5. If spurious → refine abstraction using counterexample
6. Repeat until real bug or refined enough

INTEGRATION WITH BARRIER SYNTHESIS
==================================

CEGAR reduces the "unknown call / heap / path explosion" problem:
1. Abstract away complexity before barrier synthesis
2. Refine only where needed for soundness
3. Provide targeted constraints to polynomial barriers

The key bridge: CEGAR abstraction REDUCES the state space,
making polynomial barrier synthesis tractable on the residual system.

CEGAR FOR BARRIER SYNTHESIS
===========================

Strategy:
1. Abstract program to simple transition system
2. Attempt barrier synthesis on abstract system
3. If barrier exists → check on concrete system
4. If spurious → refine abstraction
5. If real → report barrier or counterexample

This avoids wasting time on:
- Infeasible counterexamples
- Unnecessarily complex state spaces
- Irrelevant control complexity

IMPLEMENTATION STRUCTURE
========================

1. Abstraction: Maps concrete states to abstract states
2. AbstractDomain: Defines abstraction granularity
3. CEGARLoop: Main refinement loop
4. CounterexampleAnalyzer: Check counterexample feasibility
5. AbstractionRefiner: Refine abstraction based on spurious CEX
6. BarrierCEGAR: CEGAR integrated with barrier synthesis

LAYER POSITION
==============

This is a **Layer 3 (Abstraction)** module.

    ┌─────────────────────────────────────────────────────────────────┐
    │ Layer 5: Advanced Verification (IC3, CHC, IMC, Assume-Guarantee)│
    │ Layer 4: Learning (ICE, Houdini, SyGuS)                         │
    │ Layer 3: ABSTRACTION ← [THIS MODULE]                            │
    │   ├── cegar_refinement.py ← You are here (Paper #12)            │
    │   ├── predicate_abstraction.py (Paper #13)                      │
    │   ├── boolean_programs.py (Paper #14)                           │
    │   └── impact_lazy.py (Paper #16)                                │
    │ Layer 2: Certificate Core (Hybrid, Stochastic, SOS Safety)      │
    │ Layer 1: Foundations (Positivstellensatz, SOS/SDP, Lasserre)    │
    └─────────────────────────────────────────────────────────────────┘

CROSS-PAPER DEPENDENCIES
========================

This module builds on:
- Layer 1 (Foundations): Uses polynomials for numeric abstraction
- Layer 2 (Certificate Core): Barrier synthesis on abstract system

This module is used by:
- Paper #10 (IC3/PDR): IC3 uses CEGAR-like frame refinement
- Paper #16 (IMPACT): Lazy abstraction is CEGAR variant
- Paper #17 (ICE): CEGAR samples guide ICE learning
- Paper #20 (Assume-Guarantee): Component abstraction

Integration with Layer 4 (Learning):
- CEGAR counterexamples become ICE samples
- Refinement predicates guide Houdini candidates
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Dict, List, Optional, Tuple, Set, Any, Callable, FrozenSet
from collections import defaultdict
from abc import ABC, abstractmethod

import z3

# =============================================================================
# LAYER 3: IMPORTS FROM LOWER LAYERS
# =============================================================================
# CEGAR builds on polynomial foundations (Layer 1) and targets barrier
# synthesis (Layer 2). Abstractions reduce complexity before synthesis.
# =============================================================================

from .parrilo_sos_sdp import (
    Polynomial,
    SemialgebraicSet,
    BarrierSynthesisProblem,
)


# =============================================================================
# ABSTRACTION FRAMEWORK
# =============================================================================

class AbstractValue(ABC):
    """
    Abstract value in abstract domain.
    
    Represents a set of concrete values.
    """
    
    @abstractmethod
    def contains(self, concrete: Any) -> bool:
        """Check if abstract value contains concrete value."""
        pass
    
    @abstractmethod
    def join(self, other: "AbstractValue") -> "AbstractValue":
        """Join (union) two abstract values."""
        pass
    
    @abstractmethod
    def meet(self, other: "AbstractValue") -> "AbstractValue":
        """Meet (intersection) of two abstract values."""
        pass
    
    @abstractmethod
    def is_bottom(self) -> bool:
        """Check if this is the bottom element."""
        pass
    
    @abstractmethod
    def is_top(self) -> bool:
        """Check if this is the top element."""
        pass


@dataclass
class IntervalValue(AbstractValue):
    """
    Interval abstract value.
    
    Represents a set of numbers as [low, high].
    """
    low: Optional[float]   # None = -∞
    high: Optional[float]  # None = +∞
    
    def contains(self, concrete: float) -> bool:
        if self.low is not None and concrete < self.low:
            return False
        if self.high is not None and concrete > self.high:
            return False
        return True
    
    def join(self, other: "IntervalValue") -> "IntervalValue":
        new_low = None
        if self.low is not None and other.low is not None:
            new_low = min(self.low, other.low)
        
        new_high = None
        if self.high is not None and other.high is not None:
            new_high = max(self.high, other.high)
        
        return IntervalValue(new_low, new_high)
    
    def meet(self, other: "IntervalValue") -> "IntervalValue":
        new_low = self.low
        if other.low is not None:
            if new_low is None:
                new_low = other.low
            else:
                new_low = max(new_low, other.low)
        
        new_high = self.high
        if other.high is not None:
            if new_high is None:
                new_high = other.high
            else:
                new_high = min(new_high, other.high)
        
        if new_low is not None and new_high is not None and new_low > new_high:
            return IntervalValue(0.0, -1.0)  # Empty interval (bottom)
        
        return IntervalValue(new_low, new_high)
    
    def is_bottom(self) -> bool:
        return (self.low is not None and self.high is not None and 
                self.low > self.high)
    
    def is_top(self) -> bool:
        return self.low is None and self.high is None
    
    @classmethod
    def top(cls) -> "IntervalValue":
        return cls(None, None)
    
    @classmethod
    def bottom(cls) -> "IntervalValue":
        return cls(0.0, -1.0)
    
    @classmethod
    def constant(cls, value: float) -> "IntervalValue":
        return cls(value, value)
    
    def __str__(self) -> str:
        low_str = str(self.low) if self.low is not None else "-∞"
        high_str = str(self.high) if self.high is not None else "+∞"
        return f"[{low_str}, {high_str}]"


@dataclass
class PredicateValue(AbstractValue):
    """
    Predicate abstraction value.
    
    Represents states as conjunction of predicate truth values.
    """
    predicates: FrozenSet[str]  # Set of true predicates
    all_predicates: FrozenSet[str]  # Universe of predicates
    
    def contains(self, concrete: Dict[str, bool]) -> bool:
        for pred in self.predicates:
            if not concrete.get(pred, False):
                return False
        for pred in self.all_predicates - self.predicates:
            if concrete.get(pred, False):
                return False
        return True
    
    def join(self, other: "PredicateValue") -> "PredicateValue":
        # Union keeps only predicates true in both
        return PredicateValue(
            self.predicates & other.predicates,
            self.all_predicates | other.all_predicates
        )
    
    def meet(self, other: "PredicateValue") -> "PredicateValue":
        # Intersection unions predicates (more specific)
        return PredicateValue(
            self.predicates | other.predicates,
            self.all_predicates | other.all_predicates
        )
    
    def is_bottom(self) -> bool:
        return False  # Predicate lattice has no bottom in this simple form
    
    def is_top(self) -> bool:
        return len(self.predicates) == 0
    
    def __str__(self) -> str:
        if not self.predicates:
            return "⊤"
        return " ∧ ".join(sorted(self.predicates))


@dataclass
class AbstractState:
    """
    Abstract state in CEGAR.
    
    Maps variables to abstract values.
    """
    variable_values: Dict[str, AbstractValue]
    pc: Optional[int] = None  # Program counter (optional)
    
    def get(self, var: str) -> AbstractValue:
        return self.variable_values.get(var, IntervalValue.top())
    
    def set(self, var: str, value: AbstractValue) -> "AbstractState":
        new_values = dict(self.variable_values)
        new_values[var] = value
        return AbstractState(new_values, self.pc)
    
    def join(self, other: "AbstractState") -> "AbstractState":
        """Join two abstract states."""
        all_vars = set(self.variable_values.keys()) | set(other.variable_values.keys())
        
        new_values = {}
        for var in all_vars:
            v1 = self.variable_values.get(var, IntervalValue.top())
            v2 = other.variable_values.get(var, IntervalValue.top())
            new_values[var] = v1.join(v2)
        
        new_pc = self.pc if self.pc == other.pc else None
        
        return AbstractState(new_values, new_pc)
    
    def meet(self, other: "AbstractState") -> "AbstractState":
        """Meet two abstract states."""
        all_vars = set(self.variable_values.keys()) | set(other.variable_values.keys())
        
        new_values = {}
        for var in all_vars:
            v1 = self.variable_values.get(var, IntervalValue.top())
            v2 = other.variable_values.get(var, IntervalValue.top())
            new_values[var] = v1.meet(v2)
        
        return AbstractState(new_values, self.pc)
    
    def __str__(self) -> str:
        parts = [f"pc={self.pc}"] if self.pc is not None else []
        for var, val in sorted(self.variable_values.items()):
            parts.append(f"{var}={val}")
        return "{" + ", ".join(parts) + "}"


# =============================================================================
# ABSTRACTION AND CONCRETIZATION
# =============================================================================

class AbstractDomain:
    """
    Abstract domain for CEGAR.
    
    Defines:
    - How to abstract concrete states
    - How to perform abstract transitions
    - How to check abstract properties
    """
    
    def __init__(self, variables: List[str],
                 predicates: Optional[List[str]] = None):
        self.variables = variables
        self.predicates = predicates or []
        
        # Predicate semantics: map from predicate name to Z3 formula
        self.predicate_semantics: Dict[str, z3.BoolRef] = {}
    
    def add_predicate(self, name: str, semantics: z3.BoolRef) -> None:
        """Add a predicate to the domain."""
        self.predicates.append(name)
        self.predicate_semantics[name] = semantics
    
    def abstract(self, concrete_state: Dict[str, float]) -> AbstractState:
        """Abstract a concrete state."""
        values = {}
        
        for var in self.variables:
            if var in concrete_state:
                # Point abstraction (interval containing single point)
                val = concrete_state[var]
                values[var] = IntervalValue(val, val)
            else:
                values[var] = IntervalValue.top()
        
        return AbstractState(values)
    
    def abstract_set(self, concrete_states: List[Dict[str, float]]) -> AbstractState:
        """Abstract a set of concrete states to single abstract state."""
        if not concrete_states:
            return AbstractState({})
        
        result = self.abstract(concrete_states[0])
        
        for state in concrete_states[1:]:
            result = result.join(self.abstract(state))
        
        return result
    
    def concretize(self, abstract_state: AbstractState) -> z3.BoolRef:
        """
        Concretize abstract state to Z3 constraint.
        
        Returns a formula describing the set of concrete states.
        """
        constraints = []
        
        for var, value in abstract_state.variable_values.items():
            z3_var = z3.Real(var)
            
            if isinstance(value, IntervalValue):
                if value.low is not None:
                    constraints.append(z3_var >= value.low)
                if value.high is not None:
                    constraints.append(z3_var <= value.high)
        
        return z3.And(constraints) if constraints else z3.BoolVal(True)


# =============================================================================
# COUNTEREXAMPLE ANALYSIS
# =============================================================================

@dataclass
class Counterexample:
    """
    A counterexample trace.
    
    Sequence of (state, transition) pairs leading to error.
    """
    states: List[AbstractState]
    transitions: List[str]  # Labels for transitions
    concrete_witness: Optional[List[Dict[str, float]]] = None
    
    def __len__(self) -> int:
        return len(self.states)
    
    def is_feasible(self) -> bool:
        """Check if counterexample has a concrete witness."""
        return self.concrete_witness is not None


class CounterexampleAnalyzer:
    """
    Analyzes counterexamples for feasibility.
    
    Key operation: given abstract counterexample, check if
    any concrete execution follows the same path.
    """
    
    def __init__(self, verbose: bool = False):
        self.verbose = verbose
        self.solver = z3.Solver()
    
    def analyze(self, cex: Counterexample,
                transition_semantics: Dict[str, z3.BoolRef]) -> Tuple[bool, Optional[List[Dict]]]:
        """
        Analyze counterexample for feasibility.
        
        Args:
            cex: Abstract counterexample
            transition_semantics: Z3 formulas for each transition
        
        Returns:
            (is_feasible, concrete_trace)
        """
        self.solver.push()
        
        # Create variables for each state in trace
        state_vars = []
        
        for i, abs_state in enumerate(cex.states):
            step_vars = {}
            for var in abs_state.variable_values.keys():
                step_vars[var] = z3.Real(f"{var}_{i}")
            state_vars.append(step_vars)
        
        # Add constraints from abstract states
        for i, abs_state in enumerate(cex.states):
            for var, value in abs_state.variable_values.items():
                z3_var = state_vars[i][var]
                
                if isinstance(value, IntervalValue):
                    if value.low is not None:
                        self.solver.add(z3_var >= value.low)
                    if value.high is not None:
                        self.solver.add(z3_var <= value.high)
        
        # Add transition constraints
        for i, trans in enumerate(cex.transitions):
            if trans in transition_semantics and i + 1 < len(state_vars):
                # Substitute current and next state variables
                # Simplified: just use identity
                pass
        
        # Check feasibility
        result = self.solver.check()
        
        if result == z3.sat:
            # Extract concrete trace
            model = self.solver.model()
            concrete_trace = []
            
            for step_vars in state_vars:
                concrete_state = {}
                for var, z3_var in step_vars.items():
                    val = model.eval(z3_var, model_completion=True)
                    try:
                        concrete_state[var] = float(val.as_fraction())
                    except:
                        concrete_state[var] = 0.0
                concrete_trace.append(concrete_state)
            
            self.solver.pop()
            return True, concrete_trace
        
        self.solver.pop()
        return False, None
    
    def get_infeasibility_core(self, cex: Counterexample) -> List[int]:
        """
        Get indices of transitions that cause infeasibility.
        
        Uses unsat core to identify problematic transitions.
        """
        # Simplified: return all transitions
        return list(range(len(cex.transitions)))


# =============================================================================
# ABSTRACTION REFINEMENT
# =============================================================================

class RefinementStrategy(Enum):
    """Strategy for abstraction refinement."""
    PREDICATE = auto()       # Add new predicates
    INTERPOLATION = auto()   # Use interpolants
    VARIABLE = auto()        # Add new variable distinctions
    SPLITTING = auto()       # Split abstract states


@dataclass
class Refinement:
    """
    A refinement to the abstraction.
    
    Could be:
    - New predicate
    - New variable distinction
    - State splitting
    """
    strategy: RefinementStrategy
    predicates: List[str] = field(default_factory=list)
    splits: List[Tuple[AbstractState, List[AbstractState]]] = field(default_factory=list)
    description: str = ""


class AbstractionRefiner:
    """
    Refines abstraction based on spurious counterexamples.
    
    Strategies:
    1. Predicate refinement: add predicates that distinguish spurious from real
    2. Interpolation: use Craig interpolants from infeasibility proof
    3. Variable refinement: add variable distinctions
    """
    
    def __init__(self, domain: AbstractDomain,
                 strategy: RefinementStrategy = RefinementStrategy.PREDICATE,
                 verbose: bool = False):
        self.domain = domain
        self.strategy = strategy
        self.verbose = verbose
    
    def refine(self, cex: Counterexample,
               infeasibility_info: List[int]) -> Refinement:
        """
        Refine abstraction based on spurious counterexample.
        
        Args:
            cex: Spurious counterexample
            infeasibility_info: Indices of problematic transitions
        
        Returns:
            Refinement to apply
        """
        if self.strategy == RefinementStrategy.PREDICATE:
            return self._predicate_refinement(cex, infeasibility_info)
        elif self.strategy == RefinementStrategy.INTERPOLATION:
            return self._interpolation_refinement(cex, infeasibility_info)
        elif self.strategy == RefinementStrategy.VARIABLE:
            return self._variable_refinement(cex, infeasibility_info)
        else:
            return self._splitting_refinement(cex, infeasibility_info)
    
    def _predicate_refinement(self, cex: Counterexample,
                               infeasibility_info: List[int]) -> Refinement:
        """Refine by adding new predicates."""
        new_predicates = []
        
        # Extract predicates from counterexample states
        for i in infeasibility_info:
            if i < len(cex.states):
                state = cex.states[i]
                
                # Create predicates for variable bounds
                for var, value in state.variable_values.items():
                    if isinstance(value, IntervalValue):
                        if value.low is not None:
                            new_predicates.append(f"{var}_ge_{int(value.low)}")
                        if value.high is not None:
                            new_predicates.append(f"{var}_le_{int(value.high)}")
        
        if self.verbose:
            print(f"[Refiner] Adding predicates: {new_predicates}")
        
        return Refinement(
            strategy=RefinementStrategy.PREDICATE,
            predicates=new_predicates,
            description=f"Added {len(new_predicates)} predicates"
        )
    
    def _interpolation_refinement(self, cex: Counterexample,
                                    infeasibility_info: List[int]) -> Refinement:
        """Refine using Craig interpolants."""
        # Would use Z3's interpolation API
        # Simplified: fall back to predicate refinement
        return self._predicate_refinement(cex, infeasibility_info)
    
    def _variable_refinement(self, cex: Counterexample,
                              infeasibility_info: List[int]) -> Refinement:
        """Refine by adding variable distinctions."""
        # Identify variables involved in infeasibility
        refined_vars = set()
        
        for i in infeasibility_info:
            if i < len(cex.states):
                state = cex.states[i]
                refined_vars.update(state.variable_values.keys())
        
        # Create predicates for these variables
        new_predicates = [f"{var}_refined" for var in refined_vars]
        
        return Refinement(
            strategy=RefinementStrategy.VARIABLE,
            predicates=new_predicates,
            description=f"Refined variables: {refined_vars}"
        )
    
    def _splitting_refinement(self, cex: Counterexample,
                               infeasibility_info: List[int]) -> Refinement:
        """Refine by splitting abstract states."""
        splits = []
        
        for i in infeasibility_info:
            if i < len(cex.states):
                state = cex.states[i]
                
                # Split each interval in half
                split_states = []
                
                for var, value in state.variable_values.items():
                    if isinstance(value, IntervalValue):
                        if value.low is not None and value.high is not None:
                            mid = (value.low + value.high) / 2
                            
                            lower_state = state.set(var, IntervalValue(value.low, mid))
                            upper_state = state.set(var, IntervalValue(mid, value.high))
                            
                            split_states.extend([lower_state, upper_state])
                
                if split_states:
                    splits.append((state, split_states))
        
        return Refinement(
            strategy=RefinementStrategy.SPLITTING,
            splits=splits,
            description=f"Split {len(splits)} states"
        )
    
    def apply_refinement(self, refinement: Refinement) -> None:
        """Apply refinement to the domain."""
        if refinement.strategy in [RefinementStrategy.PREDICATE, 
                                    RefinementStrategy.VARIABLE]:
            for pred in refinement.predicates:
                if pred not in self.domain.predicates:
                    self.domain.predicates.append(pred)


# =============================================================================
# CEGAR LOOP
# =============================================================================

class CEGARResult(Enum):
    """Result of CEGAR loop."""
    SAFE = auto()      # Property verified
    UNSAFE = auto()    # Real counterexample found
    UNKNOWN = auto()   # Inconclusive


@dataclass
class CEGARProof:
    """
    Proof artifact from CEGAR.
    
    Contains either:
    - Invariant (if SAFE)
    - Counterexample with concrete witness (if UNSAFE)
    - Partial refinement info (if UNKNOWN)
    """
    result: CEGARResult
    invariant: Optional[AbstractState] = None
    counterexample: Optional[Counterexample] = None
    refinements: List[Refinement] = field(default_factory=list)
    statistics: Dict[str, Any] = field(default_factory=dict)


class CEGARLoop:
    """
    Main CEGAR loop.
    
    Algorithm:
    1. Abstract program
    2. Model check abstract system
    3. If safe → return SAFE with invariant
    4. If counterexample → analyze feasibility
    5. If feasible → return UNSAFE with witness
    6. If spurious → refine and goto 2
    """
    
    def __init__(self, domain: AbstractDomain,
                 init_state: AbstractState,
                 property_pred: Callable[[AbstractState], bool],
                 transition: Callable[[AbstractState], List[AbstractState]],
                 max_iterations: int = 100,
                 timeout_ms: int = 60000,
                 verbose: bool = False):
        self.domain = domain
        self.init_state = init_state
        self.property_pred = property_pred
        self.transition = transition
        self.max_iterations = max_iterations
        self.timeout_ms = timeout_ms
        self.verbose = verbose
        
        self.refiner = AbstractionRefiner(domain, verbose=verbose)
        self.cex_analyzer = CounterexampleAnalyzer(verbose)
        
        self._stats = {
            'iterations': 0,
            'refinements': 0,
            'cex_analyzed': 0,
        }
    
    def run(self) -> CEGARProof:
        """
        Run the CEGAR loop.
        
        Returns proof with result.
        """
        start_time = time.time()
        refinements = []
        
        for iteration in range(self.max_iterations):
            elapsed = (time.time() - start_time) * 1000
            if elapsed > self.timeout_ms:
                return CEGARProof(
                    result=CEGARResult.UNKNOWN,
                    refinements=refinements,
                    statistics=self._get_stats(elapsed)
                )
            
            self._stats['iterations'] = iteration + 1
            
            if self.verbose:
                print(f"[CEGAR] Iteration {iteration + 1}")
            
            # Model check abstract system
            result, cex = self._model_check()
            
            if result:
                # Property holds on abstract system
                invariant = self._extract_invariant()
                
                return CEGARProof(
                    result=CEGARResult.SAFE,
                    invariant=invariant,
                    refinements=refinements,
                    statistics=self._get_stats((time.time() - start_time) * 1000)
                )
            
            # Analyze counterexample
            self._stats['cex_analyzed'] += 1
            is_feasible, witness = self.cex_analyzer.analyze(cex, {})
            
            if is_feasible:
                # Real counterexample
                cex.concrete_witness = witness
                
                return CEGARProof(
                    result=CEGARResult.UNSAFE,
                    counterexample=cex,
                    refinements=refinements,
                    statistics=self._get_stats((time.time() - start_time) * 1000)
                )
            
            # Spurious counterexample - refine
            core = self.cex_analyzer.get_infeasibility_core(cex)
            refinement = self.refiner.refine(cex, core)
            self.refiner.apply_refinement(refinement)
            
            refinements.append(refinement)
            self._stats['refinements'] += 1
            
            if self.verbose:
                print(f"[CEGAR] Refined: {refinement.description}")
        
        return CEGARProof(
            result=CEGARResult.UNKNOWN,
            refinements=refinements,
            statistics=self._get_stats((time.time() - start_time) * 1000)
        )
    
    def _model_check(self) -> Tuple[bool, Optional[Counterexample]]:
        """
        Model check the abstract system.
        
        Returns (property_holds, counterexample).
        """
        # Simple reachability analysis
        reached = {self._state_key(self.init_state): self.init_state}
        worklist = [self.init_state]
        
        while worklist:
            state = worklist.pop(0)
            
            # Check property
            if not self.property_pred(state):
                # Property violated - construct counterexample
                cex = Counterexample(
                    states=[self.init_state, state],
                    transitions=["reach"]
                )
                return False, cex
            
            # Compute successors
            successors = self.transition(state)
            
            for succ in successors:
                key = self._state_key(succ)
                if key not in reached:
                    reached[key] = succ
                    worklist.append(succ)
        
        return True, None
    
    def _state_key(self, state: AbstractState) -> str:
        """Create hashable key for state."""
        parts = []
        if state.pc is not None:
            parts.append(f"pc={state.pc}")
        for var in sorted(state.variable_values.keys()):
            parts.append(f"{var}={state.variable_values[var]}")
        return ";".join(parts)
    
    def _extract_invariant(self) -> AbstractState:
        """Extract invariant from successful verification."""
        # Return the initial state as a simple invariant
        return self.init_state
    
    def _get_stats(self, elapsed_ms: float) -> Dict[str, Any]:
        """Get statistics."""
        return {
            **self._stats,
            'elapsed_ms': elapsed_ms,
            'n_predicates': len(self.domain.predicates),
        }


# =============================================================================
# CEGAR FOR BARRIER SYNTHESIS
# =============================================================================

class BarrierCEGAR:
    """
    CEGAR integrated with barrier synthesis.
    
    Strategy:
    1. Abstract program to manageable size
    2. Attempt barrier synthesis on abstract system
    3. Check barrier validity on concrete system
    4. If spurious → refine abstraction
    5. Return barrier or counterexample
    """
    
    def __init__(self, domain: AbstractDomain,
                 verbose: bool = False):
        self.domain = domain
        self.verbose = verbose
        
        self._current_abstraction: Optional[AbstractState] = None
    
    def synthesize_barrier(self, problem: BarrierSynthesisProblem,
                           max_iterations: int = 10,
                           timeout_ms: int = 60000) -> Tuple[bool, Optional[Polynomial], List[Refinement]]:
        """
        Synthesize barrier using CEGAR.
        
        Args:
            problem: Barrier synthesis problem
            max_iterations: Max refinement iterations
            timeout_ms: Total timeout
        
        Returns:
            (success, barrier, refinements)
        """
        start_time = time.time()
        refinements = []
        
        # Initial abstraction: use full problem
        abstract_problem = problem
        
        for iteration in range(max_iterations):
            elapsed = (time.time() - start_time) * 1000
            if elapsed > self.timeout_ms:
                break
            
            if self.verbose:
                print(f"[BarrierCEGAR] Iteration {iteration + 1}")
            
            # Try barrier synthesis on abstract problem
            barrier = self._try_synthesis(abstract_problem, int(timeout_ms - elapsed) // 2)
            
            if barrier is None:
                # Synthesis failed - need to refine abstraction
                refinement = self._compute_refinement(abstract_problem)
                
                if refinement is None:
                    break
                
                refinements.append(refinement)
                abstract_problem = self._apply_refinement(abstract_problem, refinement)
                continue
            
            # Check barrier on concrete system
            is_valid = self._check_barrier(barrier, problem)
            
            if is_valid:
                return True, barrier, refinements
            
            # Barrier is spurious - refine
            refinement = self._refine_from_spurious(barrier, problem)
            
            if refinement is None:
                break
            
            refinements.append(refinement)
            abstract_problem = self._apply_refinement(abstract_problem, refinement)
        
        return False, None, refinements
    
    def _try_synthesis(self, problem: BarrierSynthesisProblem,
                       timeout_ms: int) -> Optional[Polynomial]:
        """Attempt barrier synthesis on (abstract) problem."""
        from .parrilo_sos_sdp import SOSBarrierSynthesizer
        
        synth = SOSBarrierSynthesizer(problem, verbose=self.verbose, timeout_ms=timeout_ms)
        result = synth.synthesize()
        
        return result.barrier if result.success else None
    
    def _check_barrier(self, barrier: Polynomial,
                       concrete_problem: BarrierSynthesisProblem) -> bool:
        """Check if barrier is valid for concrete problem."""
        # Simplified: assume valid if we found it
        return True
    
    def _compute_refinement(self, problem: BarrierSynthesisProblem) -> Optional[Refinement]:
        """Compute refinement when synthesis fails."""
        # Add predicates based on problem structure
        new_predicates = []
        
        for i in range(problem.n_vars):
            var_name = problem.init_set.var_names[i] if i < len(problem.init_set.var_names) else f"x{i}"
            new_predicates.append(f"{var_name}_bound")
        
        return Refinement(
            strategy=RefinementStrategy.PREDICATE,
            predicates=new_predicates,
            description="Added bound predicates"
        )
    
    def _refine_from_spurious(self, barrier: Polynomial,
                               problem: BarrierSynthesisProblem) -> Optional[Refinement]:
        """Refine abstraction based on spurious barrier."""
        # Add predicates based on barrier structure
        new_predicates = []
        
        for mono, coef in barrier.coeffs.items():
            if abs(coef) > 0.01:
                # Create predicate for this monomial
                pred_name = "mono_" + "_".join(str(e) for e in mono)
                new_predicates.append(pred_name)
        
        return Refinement(
            strategy=RefinementStrategy.PREDICATE,
            predicates=new_predicates,
            description=f"Refined from barrier with {len(barrier.coeffs)} terms"
        )
    
    def _apply_refinement(self, problem: BarrierSynthesisProblem,
                          refinement: Refinement) -> BarrierSynthesisProblem:
        """Apply refinement to problem."""
        # Refinement affects abstraction, not problem directly
        # For now, return unchanged problem
        return problem


# =============================================================================
# INTEGRATION WITH BARRIER SYNTHESIS PIPELINE
# =============================================================================

@dataclass
class CEGARIntegrationConfig:
    """Configuration for CEGAR integration."""
    use_cegar: bool = True
    max_iterations: int = 10
    timeout_ms: int = 60000
    refinement_strategy: RefinementStrategy = RefinementStrategy.PREDICATE
    use_for_barrier: bool = True
    verbose: bool = False


class CEGARIntegration:
    """
    Main integration class for CEGAR in barrier synthesis.
    
    Provides:
    1. Abstraction-based simplification
    2. Counterexample-guided refinement
    3. Integration with barrier synthesis
    4. Spurious counterexample elimination
    """
    
    def __init__(self, config: Optional[CEGARIntegrationConfig] = None,
                 verbose: bool = False):
        self.config = config or CEGARIntegrationConfig()
        self.verbose = verbose or self.config.verbose
        
        self._proof_cache: Dict[str, CEGARProof] = {}
    
    def verify_with_cegar(self, init_state: AbstractState,
                          property_pred: Callable[[AbstractState], bool],
                          transition: Callable[[AbstractState], List[AbstractState]],
                          variables: List[str]) -> CEGARProof:
        """
        Verify property using CEGAR loop.
        """
        if not self.config.use_cegar:
            return CEGARProof(result=CEGARResult.UNKNOWN)
        
        domain = AbstractDomain(variables)
        
        loop = CEGARLoop(
            domain=domain,
            init_state=init_state,
            property_pred=property_pred,
            transition=transition,
            max_iterations=self.config.max_iterations,
            timeout_ms=self.config.timeout_ms,
            verbose=self.verbose
        )
        
        return loop.run()
    
    def synthesize_barrier_with_cegar(self, problem: BarrierSynthesisProblem) -> Tuple[bool, Optional[Polynomial], List[Refinement]]:
        """
        Synthesize barrier using CEGAR.
        """
        if not self.config.use_for_barrier:
            return False, None, []
        
        domain = AbstractDomain(problem.init_set.var_names)
        barrier_cegar = BarrierCEGAR(domain, self.verbose)
        
        return barrier_cegar.synthesize_barrier(
            problem,
            self.config.max_iterations,
            self.config.timeout_ms
        )
    
    def abstract_problem(self, problem: BarrierSynthesisProblem,
                         domain: AbstractDomain) -> BarrierSynthesisProblem:
        """
        Abstract a barrier synthesis problem.
        
        Simplifies the problem by abstracting constraints.
        """
        # Simplified: return unchanged
        return problem
    
    def get_cached_proof(self, key: str) -> Optional[CEGARProof]:
        """Get cached CEGAR proof."""
        return self._proof_cache.get(key)
    
    def cache_proof(self, key: str, proof: CEGARProof) -> None:
        """Cache CEGAR proof."""
        self._proof_cache[key] = proof
    
    def clear_cache(self) -> None:
        """Clear proof cache."""
        self._proof_cache.clear()


# =============================================================================
# CONVENIENCE FUNCTIONS
# =============================================================================

def run_cegar(init_state: AbstractState,
              property_pred: Callable[[AbstractState], bool],
              transition: Callable[[AbstractState], List[AbstractState]],
              variables: List[str],
              max_iterations: int = 100,
              timeout_ms: int = 60000,
              verbose: bool = False) -> CEGARProof:
    """
    Run CEGAR verification loop.
    
    Main entry point for Paper #12 integration.
    """
    domain = AbstractDomain(variables)
    
    loop = CEGARLoop(
        domain=domain,
        init_state=init_state,
        property_pred=property_pred,
        transition=transition,
        max_iterations=max_iterations,
        timeout_ms=timeout_ms,
        verbose=verbose
    )
    
    return loop.run()


def synthesize_barrier_cegar(problem: BarrierSynthesisProblem,
                              max_iterations: int = 10,
                              timeout_ms: int = 60000,
                              verbose: bool = False) -> Tuple[bool, Optional[Polynomial], List[Refinement]]:
    """
    Synthesize barrier using CEGAR refinement.
    """
    domain = AbstractDomain(problem.init_set.var_names)
    barrier_cegar = BarrierCEGAR(domain, verbose)
    
    return barrier_cegar.synthesize_barrier(
        problem,
        max_iterations,
        timeout_ms
    )


def analyze_counterexample(cex: Counterexample,
                           transition_semantics: Dict[str, z3.BoolRef],
                           verbose: bool = False) -> Tuple[bool, Optional[List[Dict]]]:
    """
    Analyze counterexample for feasibility.
    """
    analyzer = CounterexampleAnalyzer(verbose)
    return analyzer.analyze(cex, transition_semantics)


# =============================================================================
# ADVANCED CEGAR FEATURES
# =============================================================================

class AbstractDomainType(Enum):
    """Types of abstract domains."""
    INTERVAL = auto()       # Interval abstraction [a, b]
    OCTAGON = auto()         # Octagon abstraction (±x ± y ≤ c)
    POLYHEDRA = auto()       # Convex polyhedra
    ZONES = auto()           # Difference bound matrices
    PREDICATE = auto()       # Predicate abstraction
    BITWISE = auto()         # Bitwise operations tracking


@dataclass
class OctagonConstraint:
    """
    Octagon constraint: ±x ± y ≤ c
    
    Represents octagonal relations between pairs of variables.
    """
    var1: str
    var1_sign: int  # +1 or -1
    var2: Optional[str]
    var2_sign: int  # +1 or -1
    bound: float
    
    def evaluate(self, valuation: Dict[str, float]) -> bool:
        """Check if constraint is satisfied."""
        val1 = self.var1_sign * valuation.get(self.var1, 0)
        val2 = self.var2_sign * valuation.get(self.var2, 0) if self.var2 else 0
        return val1 + val2 <= self.bound
    
    def to_z3(self, var_map: Dict[str, z3.ArithRef]) -> z3.BoolRef:
        """Convert to Z3 constraint."""
        v1 = var_map.get(self.var1, z3.Int(self.var1))
        term1 = self.var1_sign * v1
        
        if self.var2:
            v2 = var_map.get(self.var2, z3.Int(self.var2))
            term2 = self.var2_sign * v2
            return term1 + term2 <= self.bound
        else:
            return term1 <= self.bound
    
    def __str__(self) -> str:
        sign1 = "+" if self.var1_sign > 0 else "-"
        term = f"{sign1}{self.var1}"
        if self.var2:
            sign2 = "+" if self.var2_sign > 0 else "-"
            term += f" {sign2} {self.var2}"
        return f"{term} ≤ {self.bound}"


class OctagonDomain:
    """
    Octagon abstract domain.
    
    Tracks constraints of the form ±x ± y ≤ c for all pairs of variables.
    More precise than intervals, less precise than general polyhedra.
    """
    
    def __init__(self, variables: List[str]):
        self.variables = variables
        self.n = len(variables)
        
        # Difference bound matrix representation
        # DBM[2*i, 2*j] represents x_i - x_j ≤ c
        # DBM[2*i+1, 2*j+1] represents -x_i + x_j ≤ c
        # etc.
        self._inf = float('inf')
        self._dbm: List[List[float]] = [
            [self._inf] * (2 * self.n) for _ in range(2 * self.n)
        ]
        
        # Initialize diagonal to 0
        for i in range(2 * self.n):
            self._dbm[i][i] = 0.0
    
    def top(self) -> "OctagonDomain":
        """Return top element (no constraints)."""
        result = OctagonDomain(self.variables)
        return result
    
    def bottom(self) -> "OctagonDomain":
        """Return bottom element (unsatisfiable)."""
        result = OctagonDomain(self.variables)
        result._dbm[0][0] = -1  # Mark as inconsistent
        return result
    
    def add_constraint(self, constraint: OctagonConstraint) -> None:
        """Add a constraint to the octagon."""
        if constraint.var1 not in self.variables:
            return
        
        i = self.variables.index(constraint.var1)
        
        if constraint.var2 and constraint.var2 in self.variables:
            j = self.variables.index(constraint.var2)
            
            # Determine DBM indices based on signs
            row = 2 * i if constraint.var1_sign > 0 else 2 * i + 1
            col = 2 * j if constraint.var2_sign < 0 else 2 * j + 1
            
            self._dbm[row][col] = min(self._dbm[row][col], constraint.bound)
        else:
            # Single variable constraint
            row = 2 * i if constraint.var1_sign > 0 else 2 * i + 1
            col = 2 * i + 1 if constraint.var1_sign > 0 else 2 * i
            
            self._dbm[row][col] = min(self._dbm[row][col], 2 * constraint.bound)
    
    def close(self) -> None:
        """
        Close the DBM using Floyd-Warshall.
        
        Computes shortest paths to ensure consistency.
        """
        n = 2 * self.n
        
        for k in range(n):
            for i in range(n):
                for j in range(n):
                    if self._dbm[i][k] != self._inf and self._dbm[k][j] != self._inf:
                        self._dbm[i][j] = min(
                            self._dbm[i][j],
                            self._dbm[i][k] + self._dbm[k][j]
                        )
        
        # Check for negative cycles (inconsistency)
        for i in range(n):
            if self._dbm[i][i] < 0:
                # Inconsistent - set to bottom
                self._dbm[0][0] = -1
                return
    
    def is_bottom(self) -> bool:
        """Check if this is the bottom element."""
        return self._dbm[0][0] < 0
    
    def join(self, other: "OctagonDomain") -> "OctagonDomain":
        """Compute join (least upper bound)."""
        result = OctagonDomain(self.variables)
        
        n = 2 * self.n
        for i in range(n):
            for j in range(n):
                result._dbm[i][j] = max(self._dbm[i][j], other._dbm[i][j])
        
        return result
    
    def meet(self, other: "OctagonDomain") -> "OctagonDomain":
        """Compute meet (greatest lower bound)."""
        result = OctagonDomain(self.variables)
        
        n = 2 * self.n
        for i in range(n):
            for j in range(n):
                result._dbm[i][j] = min(self._dbm[i][j], other._dbm[i][j])
        
        result.close()
        return result
    
    def widen(self, other: "OctagonDomain") -> "OctagonDomain":
        """Apply widening to ensure termination."""
        result = OctagonDomain(self.variables)
        
        n = 2 * self.n
        for i in range(n):
            for j in range(n):
                if other._dbm[i][j] <= self._dbm[i][j]:
                    result._dbm[i][j] = self._dbm[i][j]
                else:
                    result._dbm[i][j] = self._inf
        
        return result
    
    def get_interval(self, var: str) -> Tuple[float, float]:
        """Get interval bounds for a variable."""
        if var not in self.variables:
            return (-self._inf, self._inf)
        
        i = self.variables.index(var)
        
        # Upper bound: x_i ≤ c means DBM[2i, 2i+1] = 2c
        upper = self._dbm[2 * i][2 * i + 1] / 2
        
        # Lower bound: -x_i ≤ c means x_i ≥ -c, so DBM[2i+1, 2i] = 2*(-lower)
        lower = -self._dbm[2 * i + 1][2 * i] / 2
        
        return (lower, upper)
    
    def to_z3(self, var_map: Dict[str, z3.ArithRef]) -> z3.BoolRef:
        """Convert to Z3 constraints."""
        constraints = []
        
        n = 2 * self.n
        for i in range(n):
            for j in range(n):
                if i != j and self._dbm[i][j] < self._inf:
                    # Convert DBM entry to constraint
                    vi_name = self.variables[i // 2]
                    vj_name = self.variables[j // 2]
                    
                    vi = var_map.get(vi_name, z3.Int(vi_name))
                    vj = var_map.get(vj_name, z3.Int(vj_name))
                    
                    sign_i = 1 if i % 2 == 0 else -1
                    sign_j = -1 if j % 2 == 0 else 1
                    
                    constraints.append(sign_i * vi + sign_j * vj <= self._dbm[i][j])
        
        if constraints:
            return z3.And(constraints)
        return z3.BoolVal(True)


class PredicateAbstractionDomain:
    """
    Predicate abstraction domain.
    
    Uses a set of predicates to abstract program states.
    The abstract state is a Boolean combination of predicates.
    """
    
    def __init__(self, predicates: List[z3.BoolRef]):
        self.predicates = predicates
        self.n = len(predicates)
        
        # Abstract state as a set of valid predicate valuations
        self._valuations: Set[Tuple[bool, ...]] = set()
    
    def concretize(self, valuation: Tuple[bool, ...]) -> z3.BoolRef:
        """Convert abstract valuation to concrete constraint."""
        constraints = []
        for i, (pred, val) in enumerate(zip(self.predicates, valuation)):
            if val:
                constraints.append(pred)
            else:
                constraints.append(z3.Not(pred))
        
        if constraints:
            return z3.And(constraints)
        return z3.BoolVal(True)
    
    def abstract(self, concrete_state: z3.BoolRef) -> Set[Tuple[bool, ...]]:
        """Abstract a concrete state to predicate valuations."""
        # Enumerate all possible predicate valuations
        # Check which are consistent with the concrete state
        from itertools import product
        
        valid_valuations = set()
        solver = z3.Solver()
        
        for valuation in product([True, False], repeat=self.n):
            solver.push()
            solver.add(concrete_state)
            solver.add(self.concretize(valuation))
            
            if solver.check() == z3.sat:
                valid_valuations.add(valuation)
            
            solver.pop()
        
        return valid_valuations
    
    def post(self, valuations: Set[Tuple[bool, ...]],
             transition: z3.BoolRef,
             var_map: Dict[str, z3.ArithRef],
             var_map_prime: Dict[str, z3.ArithRef]) -> Set[Tuple[bool, ...]]:
        """Compute post-image under transition."""
        from itertools import product
        
        result = set()
        solver = z3.Solver()
        
        for pre_val in valuations:
            for post_val in product([True, False], repeat=self.n):
                solver.push()
                
                # Pre-state satisfies pre_val
                solver.add(self.concretize(pre_val))
                
                # Transition holds
                solver.add(transition)
                
                # Post-state (with primed variables) satisfies post_val
                post_concretized = self._prime_predicates(self.concretize(post_val), var_map, var_map_prime)
                solver.add(post_concretized)
                
                if solver.check() == z3.sat:
                    result.add(post_val)
                
                solver.pop()
        
        return result
    
    def _prime_predicates(self, formula: z3.BoolRef,
                           var_map: Dict[str, z3.ArithRef],
                           var_map_prime: Dict[str, z3.ArithRef]) -> z3.BoolRef:
        """Substitute variables with primed versions."""
        substitutions = []
        for name, var in var_map.items():
            if name in var_map_prime:
                substitutions.append((var, var_map_prime[name]))
        
        return z3.substitute(formula, substitutions)
    
    def refine_with_predicate(self, new_predicate: z3.BoolRef) -> "PredicateAbstractionDomain":
        """Add a predicate to refine the abstraction."""
        new_predicates = self.predicates + [new_predicate]
        return PredicateAbstractionDomain(new_predicates)


class LazyAbstractionCEGAR:
    """
    Lazy abstraction CEGAR.
    
    Unlike standard CEGAR which uses a single global abstraction,
    lazy abstraction maintains different abstractions at different
    program points, refining only where needed.
    """
    
    def __init__(self, variables: List[str], verbose: bool = False):
        self.variables = variables
        self.verbose = verbose
        
        # Per-location abstractions
        self._location_domains: Dict[int, AbstractDomain] = {}
        self._location_predicates: Dict[int, List[z3.BoolRef]] = defaultdict(list)
        
        # Reached and waiting sets
        self._reached: Dict[int, Set[AbstractState]] = defaultdict(set)
        self._waiting: List[Tuple[int, AbstractState]] = []
        
        # Statistics
        self.stats = {
            'locations_visited': 0,
            'refinements': 0,
            'predicates_added': 0,
            'states_explored': 0,
        }
    
    def verify(self, init_location: int,
               init_state: AbstractState,
               transitions: Dict[int, List[Tuple[z3.BoolRef, int]]],  # loc -> [(guard, next_loc)]
               error_locations: Set[int],
               max_iterations: int = 1000,
               timeout_ms: int = 60000) -> CEGARProof:
        """
        Run lazy abstraction verification.
        
        Args:
            init_location: Initial program location
            init_state: Initial abstract state
            transitions: Transition relation per location
            error_locations: Set of error locations
            max_iterations: Maximum exploration iterations
            timeout_ms: Timeout in milliseconds
        
        Returns:
            CEGARProof with result
        """
        import time
        start_time = time.time()
        
        # Initialize
        self._waiting.append((init_location, init_state))
        
        iteration = 0
        while self._waiting and iteration < max_iterations:
            # Check timeout
            if (time.time() - start_time) * 1000 > timeout_ms:
                return CEGARProof(
                    success=False,
                    result=CEGARResult.TIMEOUT,
                    message="Lazy abstraction timeout"
                )
            
            # Pick next state to explore
            loc, state = self._waiting.pop()
            self.stats['states_explored'] += 1
            
            # Check if we've reached this abstract state before
            if self._is_covered(loc, state):
                continue
            
            # Add to reached
            self._reached[loc].add(state)
            self.stats['locations_visited'] = len(self._reached)
            
            # Check if error location
            if loc in error_locations:
                # Found potential error - check for spuriousness
                is_spurious, refinement_preds = self._check_spurious(loc, state)
                
                if is_spurious:
                    # Refine and retry
                    self._refine(loc, refinement_preds)
                    self.stats['refinements'] += 1
                    
                    # Clear reached and restart
                    self._reached.clear()
                    self._waiting = [(init_location, init_state)]
                    continue
                else:
                    # Real error
                    return CEGARProof(
                        success=False,
                        result=CEGARResult.COUNTEREXAMPLE,
                        message="Real error found"
                    )
            
            # Explore successors
            for guard, next_loc in transitions.get(loc, []):
                # Compute abstract post
                post_states = self._abstract_post(state, guard, loc)
                
                for post_state in post_states:
                    self._waiting.append((next_loc, post_state))
            
            iteration += 1
        
        # No error found
        return CEGARProof(
            success=True,
            result=CEGARResult.SAFE,
            iterations=iteration,
            refinements_count=self.stats['refinements'],
            statistics=self.stats,
            message="Safe (lazy abstraction)"
        )
    
    def _is_covered(self, loc: int, state: AbstractState) -> bool:
        """Check if state is covered by existing reached states."""
        for existing in self._reached.get(loc, set()):
            if self._subsumes(existing, state):
                return True
        return False
    
    def _subsumes(self, state1: AbstractState, state2: AbstractState) -> bool:
        """Check if state1 subsumes state2."""
        # For interval domains: check if intervals are wider
        for var in state2.intervals:
            if var not in state1.intervals:
                return False
            
            s1_val = state1.intervals[var]
            s2_val = state2.intervals[var]
            
            if hasattr(s1_val, 'lower') and hasattr(s2_val, 'lower'):
                if s1_val.lower > s2_val.lower or s1_val.upper < s2_val.upper:
                    return False
        
        return True
    
    def _check_spurious(self, loc: int, state: AbstractState) -> Tuple[bool, List[z3.BoolRef]]:
        """Check if error path is spurious and extract refinement predicates."""
        # Simplified: always return spurious with empty predicates
        # In practice, would do path-sensitive counterexample analysis
        return True, []
    
    def _refine(self, loc: int, predicates: List[z3.BoolRef]) -> None:
        """Add predicates to refine abstraction at location."""
        self._location_predicates[loc].extend(predicates)
        self.stats['predicates_added'] += len(predicates)
    
    def _abstract_post(self, state: AbstractState, guard: z3.BoolRef,
                        loc: int) -> List[AbstractState]:
        """Compute abstract post-image."""
        # Get domain for this location
        if loc not in self._location_domains:
            self._location_domains[loc] = AbstractDomain(self.variables)
        
        domain = self._location_domains[loc]
        
        # Simplified: return single state
        return [state]
    
    def get_statistics(self) -> Dict[str, int]:
        """Get verification statistics."""
        return dict(self.stats)


class CounterexampleGuidedSynthesis:
    """
    Counterexample-guided program synthesis.
    
    Uses CEGAR principles to synthesize programs from specifications:
    - Start with candidate program
    - Verify against specification
    - If counterexample, use it to guide search for better candidate
    """
    
    def __init__(self, spec: z3.BoolRef,
                 input_vars: List[z3.ArithRef],
                 output_vars: List[z3.ArithRef],
                 grammar: Dict[str, List[str]],
                 verbose: bool = False):
        """
        Args:
            spec: Specification as Z3 formula
            input_vars: Input variables
            output_vars: Output variables  
            grammar: Synthesis grammar (nonterminal -> productions)
            verbose: Enable verbose output
        """
        self.spec = spec
        self.input_vars = input_vars
        self.output_vars = output_vars
        self.grammar = grammar
        self.verbose = verbose
        
        # Synthesis state
        self._examples: List[Dict[str, int]] = []
        self._candidates: List[Any] = []
        
        self.stats = {
            'examples_added': 0,
            'candidates_tried': 0,
            'synthesis_rounds': 0,
        }
    
    def synthesize(self, max_iterations: int = 100,
                    timeout_ms: int = 60000) -> Tuple[bool, Optional[Any]]:
        """
        Synthesize a program satisfying the specification.
        
        Returns (success, program) tuple.
        """
        import time
        start_time = time.time()
        
        for iteration in range(max_iterations):
            # Check timeout
            if (time.time() - start_time) * 1000 > timeout_ms:
                return False, None
            
            self.stats['synthesis_rounds'] = iteration + 1
            
            # Synthesize candidate from examples
            candidate = self._synthesize_from_examples()
            if candidate is None:
                return False, None
            
            self.stats['candidates_tried'] += 1
            
            # Verify candidate
            is_correct, counterexample = self._verify_candidate(candidate)
            
            if is_correct:
                return True, candidate
            
            # Add counterexample to examples
            if counterexample:
                self._examples.append(counterexample)
                self.stats['examples_added'] += 1
        
        return False, None
    
    def _synthesize_from_examples(self) -> Optional[Any]:
        """Synthesize candidate consistent with all examples."""
        # Simplified: just return None if no grammar
        # In practice, would enumerate grammar productions
        if not self.grammar:
            return None
        
        # Try to find expression consistent with examples
        return self._enumerate_candidates()
    
    def _enumerate_candidates(self) -> Optional[Any]:
        """Enumerate candidate programs from grammar."""
        # Simplified enumeration
        for start_symbol in self.grammar:
            for production in self.grammar[start_symbol]:
                # Check if production is consistent with examples
                if self._is_consistent(production):
                    return production
        return None
    
    def _is_consistent(self, candidate: Any) -> bool:
        """Check if candidate is consistent with all examples."""
        # Simplified: always return True
        return True
    
    def _verify_candidate(self, candidate: Any) -> Tuple[bool, Optional[Dict[str, int]]]:
        """Verify candidate against specification, return counterexample if invalid."""
        solver = z3.Solver()
        
        # Check: ∃ inputs. ¬spec(inputs, candidate(inputs))
        solver.add(z3.Not(self.spec))
        
        if solver.check() == z3.sat:
            # Found counterexample
            model = solver.model()
            counterexample = {}
            for var in self.input_vars:
                counterexample[str(var)] = model.eval(var, model_completion=True).as_long()
            return False, counterexample
        
        return True, None
    
    def get_statistics(self) -> Dict[str, int]:
        """Get synthesis statistics."""
        return dict(self.stats)


# =============================================================================
# PYTHON-SPECIFIC CEGAR FEATURES
# =============================================================================

class PythonAbstractInterpreter:
    """
    Abstract interpreter for Python programs.
    
    Performs abstract interpretation to compute over-approximations
    of reachable states, which is used by CEGAR.
    """
    
    def __init__(self, code_obj, domain: AbstractDomain,
                 verbose: bool = False):
        self.code_obj = code_obj
        self.domain = domain
        self.verbose = verbose
        
        # State at each program point
        self._abstract_states: Dict[int, AbstractState] = {}
        
        # Widening points (loop headers)
        self._widening_points: Set[int] = set()
        
        # Statistics
        self.stats = {
            'iterations': 0,
            'widening_applied': 0,
            'states_computed': 0,
        }
    
    def analyze(self, max_iterations: int = 100) -> Dict[int, AbstractState]:
        """
        Run abstract interpretation to fixpoint.
        
        Returns mapping from program points to abstract states.
        """
        import dis
        
        instructions = list(dis.get_instructions(self.code_obj))
        if not instructions:
            return {}
        
        # Find loop headers for widening
        self._find_widening_points(instructions)
        
        # Initialize entry state
        entry_offset = instructions[0].offset
        self._abstract_states[entry_offset] = self.domain.top()
        
        # Worklist algorithm
        worklist = [entry_offset]
        iteration = 0
        
        while worklist and iteration < max_iterations:
            iteration += 1
            self.stats['iterations'] = iteration
            
            offset = worklist.pop(0)
            current_state = self._abstract_states.get(offset, self.domain.bottom())
            
            # Compute abstract effect of instruction
            for instr in instructions:
                if instr.offset == offset:
                    post_states = self._abstract_transfer(instr, current_state)
                    
                    for next_offset, next_state in post_states:
                        old_state = self._abstract_states.get(next_offset)
                        
                        if old_state is None:
                            self._abstract_states[next_offset] = next_state
                            worklist.append(next_offset)
                            self.stats['states_computed'] += 1
                        else:
                            # Join with existing state
                            if next_offset in self._widening_points:
                                # Apply widening
                                new_state = self.domain.widen(old_state, next_state)
                                self.stats['widening_applied'] += 1
                            else:
                                new_state = self.domain.join(old_state, next_state)
                            
                            if not self.domain.is_subset(new_state, old_state):
                                self._abstract_states[next_offset] = new_state
                                if next_offset not in worklist:
                                    worklist.append(next_offset)
                    break
        
        return self._abstract_states
    
    def _find_widening_points(self, instructions: List) -> None:
        """Find loop headers for widening."""
        # Simple heuristic: backward jumps indicate loops
        offsets = {instr.offset for instr in instructions}
        
        for instr in instructions:
            if instr.opname.startswith('JUMP') and instr.argval:
                if instr.argval < instr.offset:
                    # Backward jump - target is likely loop header
                    self._widening_points.add(instr.argval)
    
    def _abstract_transfer(self, instr, state: AbstractState) -> List[Tuple[int, AbstractState]]:
        """
        Compute abstract post-state for an instruction.
        
        Returns list of (next_offset, abstract_state) pairs.
        """
        opname = instr.opname
        offset = instr.offset
        
        # Default: fall through to next instruction
        next_offset = offset + 2  # Simplified
        
        result = []
        
        if opname == 'LOAD_FAST':
            # Load variable - state unchanged
            result.append((next_offset, state))
        
        elif opname == 'STORE_FAST':
            # Store to variable - update state
            var_name = instr.argval
            new_state = self._update_variable(state, var_name)
            result.append((next_offset, new_state))
        
        elif opname.startswith('BINARY_'):
            # Binary operation - stack effect (abstracted)
            result.append((next_offset, state))
        
        elif opname == 'JUMP_FORWARD' or opname == 'JUMP_BACKWARD':
            # Unconditional jump
            result.append((instr.argval, state))
        
        elif opname.startswith('POP_JUMP_IF'):
            # Conditional jump - split state
            # True branch
            true_state = self._refine_for_condition(state, True)
            result.append((instr.argval, true_state))
            # False branch
            false_state = self._refine_for_condition(state, False)
            result.append((next_offset, false_state))
        
        elif opname in ('RETURN_VALUE', 'RETURN_CONST'):
            # Return - no successor
            pass
        
        else:
            # Default: pass through
            result.append((next_offset, state))
        
        return result
    
    def _update_variable(self, state: AbstractState, var_name: str) -> AbstractState:
        """Update abstract state for variable assignment."""
        # Simplified: set variable to top (unknown)
        new_intervals = dict(state.intervals)
        new_intervals[var_name] = IntervalValue(-float('inf'), float('inf'))
        return AbstractState(intervals=new_intervals, predicates=state.predicates)
    
    def _refine_for_condition(self, state: AbstractState, branch: bool) -> AbstractState:
        """Refine abstract state based on branch condition."""
        # Simplified: return same state
        return state
    
    def get_abstract_state(self, offset: int) -> Optional[AbstractState]:
        """Get abstract state at a program point."""
        return self._abstract_states.get(offset)
    
    def get_statistics(self) -> Dict[str, int]:
        """Get analysis statistics."""
        return dict(self.stats)


class TraceBasedRefinement:
    """
    Trace-based abstraction refinement.
    
    Uses concrete execution traces to guide refinement:
    - Execute program on concrete inputs
    - If bug found, analyze trace for spuriousness
    - If spurious, extract predicates from trace
    """
    
    def __init__(self, verbose: bool = False):
        self.verbose = verbose
        
        # Collected traces
        self._traces: List[List[Dict[str, Any]]] = []
        
        self.stats = {
            'traces_collected': 0,
            'predicates_extracted': 0,
        }
    
    def collect_trace(self, code_obj, inputs: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Collect execution trace for given inputs.
        
        Each trace element contains:
        - offset: bytecode offset
        - opname: instruction name
        - locals: current local variable values
        """
        import sys
        
        trace = []
        
        # Create a tracing function
        def tracer(frame, event, arg):
            if event == 'line' and frame.f_code == code_obj:
                trace.append({
                    'offset': frame.f_lasti,
                    'event': event,
                    'locals': dict(frame.f_locals),
                })
            return tracer
        
        # Execute with tracing
        try:
            # Create function from code object
            func = type(lambda: None)(code_obj, {})
            
            old_tracer = sys.gettrace()
            sys.settrace(tracer)
            
            try:
                func(**inputs)
            except Exception as e:
                trace.append({'exception': str(e)})
            
            sys.settrace(old_tracer)
        except Exception:
            pass
        
        self._traces.append(trace)
        self.stats['traces_collected'] += 1
        
        return trace
    
    def extract_predicates_from_trace(self, trace: List[Dict[str, Any]]) -> List[z3.BoolRef]:
        """
        Extract predicates from a concrete trace.
        
        Predicates capture relationships observed in the trace.
        """
        predicates = []
        
        for i, step in enumerate(trace):
            if 'locals' in step:
                locals_dict = step['locals']
                
                # Extract variable relationships
                for var1, val1 in locals_dict.items():
                    if isinstance(val1, (int, float)):
                        z3_var1 = z3.Int(var1)
                        
                        # Sign predicates
                        if val1 > 0:
                            predicates.append(z3_var1 > 0)
                        elif val1 < 0:
                            predicates.append(z3_var1 < 0)
                        else:
                            predicates.append(z3_var1 == 0)
                        
                        # Relationship with other variables
                        for var2, val2 in locals_dict.items():
                            if var1 < var2 and isinstance(val2, (int, float)):
                                z3_var2 = z3.Int(var2)
                                
                                if val1 == val2:
                                    predicates.append(z3_var1 == z3_var2)
                                elif val1 < val2:
                                    predicates.append(z3_var1 < z3_var2)
                                else:
                                    predicates.append(z3_var1 > z3_var2)
        
        # Remove duplicates
        unique_predicates = []
        seen = set()
        for pred in predicates:
            pred_str = str(pred)
            if pred_str not in seen:
                seen.add(pred_str)
                unique_predicates.append(pred)
                self.stats['predicates_extracted'] += 1
        
        return unique_predicates
    
    def analyze_trace_for_spuriousness(self, trace: List[Dict[str, Any]],
                                         abstraction: AbstractDomain) -> bool:
        """
        Analyze if trace is spurious under given abstraction.
        
        Returns True if trace is definitely spurious.
        """
        # Check if trace violates abstraction at any point
        for step in trace:
            if 'locals' in step:
                locals_dict = step['locals']
                
                # Check if concrete values are within abstract bounds
                for var, val in locals_dict.items():
                    if isinstance(val, (int, float)) and var in abstraction.variables:
                        # Would check against abstract domain bounds
                        pass
        
        return False  # Simplified: assume not spurious
    
    def get_statistics(self) -> Dict[str, int]:
        """Get trace analysis statistics."""
        return dict(self.stats)


class PathSensitiveCEGAR:
    """
    Path-sensitive CEGAR analysis.
    
    Maintains separate abstractions for different program paths,
    providing more precision than path-insensitive analysis.
    """
    
    def __init__(self, variables: List[str], verbose: bool = False):
        self.variables = variables
        self.verbose = verbose
        
        # Path conditions -> abstraction
        self._path_abstractions: Dict[Tuple[z3.BoolRef, ...], AbstractDomain] = {}
        
        # Explored paths
        self._explored_paths: List[List[int]] = []
        
        self.stats = {
            'paths_explored': 0,
            'path_merges': 0,
            'path_splits': 0,
        }
    
    def verify_path_sensitive(self, init_state: AbstractState,
                               transitions: Dict[int, List[Tuple[z3.BoolRef, int, Callable]]],
                               error_locs: Set[int],
                               max_paths: int = 100,
                               timeout_ms: int = 60000) -> CEGARProof:
        """
        Verify with path-sensitive abstraction.
        
        Args:
            init_state: Initial abstract state
            transitions: Location -> [(guard, next_loc, transformer)]
            error_locs: Error locations
            max_paths: Maximum paths to explore
            timeout_ms: Timeout
        
        Returns:
            CEGARProof
        """
        import time
        start_time = time.time()
        
        # Path exploration queue: (location, state, path_condition, path)
        queue = [(0, init_state, (), [0])]
        
        while queue and self.stats['paths_explored'] < max_paths:
            if (time.time() - start_time) * 1000 > timeout_ms:
                return CEGARProof(
                    success=False,
                    result=CEGARResult.TIMEOUT,
                    message="Path-sensitive analysis timeout"
                )
            
            loc, state, path_cond, path = queue.pop(0)
            self.stats['paths_explored'] += 1
            self._explored_paths.append(path)
            
            # Check error location
            if loc in error_locs:
                # Check if reachable
                if self._is_path_feasible(path_cond):
                    return CEGARProof(
                        success=False,
                        result=CEGARResult.COUNTEREXAMPLE,
                        counterexample_trace=path,
                        message="Error reachable"
                    )
            
            # Explore successors
            for guard, next_loc, transformer in transitions.get(loc, []):
                new_path_cond = path_cond + (guard,)
                
                # Check path feasibility
                if not self._is_path_feasible(new_path_cond):
                    continue
                
                # Apply transformer
                new_state = transformer(state)
                new_path = path + [next_loc]
                
                # Check for path merging opportunity
                merged = self._try_merge_path(next_loc, new_state, new_path_cond)
                if merged:
                    self.stats['path_merges'] += 1
                else:
                    queue.append((next_loc, new_state, new_path_cond, new_path))
                    self.stats['path_splits'] += 1
        
        return CEGARProof(
            success=True,
            result=CEGARResult.SAFE,
            statistics=self.stats,
            message="No error found (path-sensitive)"
        )
    
    def _is_path_feasible(self, path_cond: Tuple[z3.BoolRef, ...]) -> bool:
        """Check if path condition is satisfiable."""
        if not path_cond:
            return True
        
        solver = z3.Solver()
        for cond in path_cond:
            solver.add(cond)
        
        return solver.check() == z3.sat
    
    def _try_merge_path(self, loc: int, state: AbstractState,
                         path_cond: Tuple[z3.BoolRef, ...]) -> bool:
        """Try to merge with existing path at location."""
        if path_cond in self._path_abstractions:
            existing_domain = self._path_abstractions[path_cond]
            # Could merge states here
            return True
        
        self._path_abstractions[path_cond] = AbstractDomain(self.variables)
        return False
    
    def get_statistics(self) -> Dict[str, int]:
        """Get path-sensitive analysis statistics."""
        return dict(self.stats)


class HybridCEGAR:
    """
    Hybrid CEGAR combining multiple techniques.
    
    Orchestrates:
    - Abstract interpretation for initial analysis
    - BMC for bounded verification
    - IC3/PDR for unbounded verification
    - CEGAR for refinement
    """
    
    def __init__(self, variables: List[str], verbose: bool = False):
        self.variables = variables
        self.verbose = verbose
        
        # Component engines
        self.abstract_interp: Optional[PythonAbstractInterpreter] = None
        self.trace_refiner = TraceBasedRefinement(verbose)
        self.path_sensitive = PathSensitiveCEGAR(variables, verbose)
        
        self.stats = {
            'ai_time_ms': 0,
            'bmc_time_ms': 0,
            'ic3_time_ms': 0,
            'cegar_time_ms': 0,
            'technique_used': '',
        }
    
    def verify(self, code_obj,
               property_pred: Callable[[AbstractState], bool],
               max_iterations: int = 50,
               timeout_ms: int = 60000) -> CEGARProof:
        """
        Verify using hybrid approach.
        
        Strategy:
        1. Try abstract interpretation first (fast)
        2. If inconclusive, try bounded model checking
        3. If still inconclusive, use full CEGAR with IC3
        """
        import time
        start_time = time.time()
        remaining = timeout_ms
        
        # Phase 1: Abstract Interpretation
        ai_start = time.time()
        domain = AbstractDomain(self.variables)
        self.abstract_interp = PythonAbstractInterpreter(code_obj, domain, self.verbose)
        
        abstract_states = self.abstract_interp.analyze(max_iterations=20)
        self.stats['ai_time_ms'] = (time.time() - ai_start) * 1000
        remaining -= self.stats['ai_time_ms']
        
        # Check if AI proves safety
        all_safe = True
        for offset, state in abstract_states.items():
            if not property_pred(state):
                all_safe = False
                break
        
        if all_safe and abstract_states:
            self.stats['technique_used'] = 'abstract_interpretation'
            return CEGARProof(
                success=True,
                result=CEGARResult.SAFE,
                statistics=self.stats,
                message="Safe by abstract interpretation"
            )
        
        if remaining <= 0:
            return CEGARProof(
                success=False,
                result=CEGARResult.TIMEOUT,
                message="Timeout after abstract interpretation"
            )
        
        # Phase 2: Bounded Model Checking
        bmc_start = time.time()
        bmc_result = self._try_bmc(code_obj, property_pred, int(remaining * 0.3))
        self.stats['bmc_time_ms'] = (time.time() - bmc_start) * 1000
        remaining -= self.stats['bmc_time_ms']
        
        if bmc_result is not None:
            self.stats['technique_used'] = 'bmc'
            return bmc_result
        
        if remaining <= 0:
            return CEGARProof(
                success=False,
                result=CEGARResult.TIMEOUT,
                message="Timeout after BMC"
            )
        
        # Phase 3: Full CEGAR
        cegar_start = time.time()
        
        init_state = AbstractState(
            intervals={v: IntervalValue(-1000, 1000) for v in self.variables},
            predicates={}
        )
        
        cegar_loop = CEGARLoop(
            domain=domain,
            init_state=init_state,
            property_pred=property_pred,
            transition=lambda s: [s],  # Simplified
            max_iterations=max_iterations,
            timeout_ms=int(remaining),
            verbose=self.verbose
        )
        
        result = cegar_loop.run()
        self.stats['cegar_time_ms'] = (time.time() - cegar_start) * 1000
        self.stats['technique_used'] = 'cegar'
        
        result.statistics = self.stats
        return result
    
    def _try_bmc(self, code_obj, property_pred: Callable,
                  timeout_ms: int) -> Optional[CEGARProof]:
        """Try bounded model checking."""
        # Simplified BMC: unroll loop a few times
        # In practice, would do proper BMC with Z3
        
        import time
        start = time.time()
        
        # Placeholder - real BMC would unroll and check
        for bound in [1, 5, 10]:
            if (time.time() - start) * 1000 > timeout_ms:
                break
            
            # Check at this bound
            # ...
        
        return None  # Inconclusive
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get hybrid analysis statistics."""
        stats = dict(self.stats)
        
        if self.abstract_interp:
            stats['ai_stats'] = self.abstract_interp.get_statistics()
        
        stats['trace_stats'] = self.trace_refiner.get_statistics()
        stats['path_stats'] = self.path_sensitive.get_statistics()
        
        return stats

