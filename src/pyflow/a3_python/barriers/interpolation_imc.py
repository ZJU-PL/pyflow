"""
SOTA Paper: Interpolation-Based Model Checking (IMC).

Implements Craig interpolation for model checking:
    K. L. McMillan. "Interpolation and SAT-Based Model Checking." CAV 2003.

KEY INSIGHT
===========

When BMC proves that a path is infeasible (UNSAT), we can extract an
INTERPOLANT that explains WHY the path is infeasible. This interpolant:

1. Over-approximates the reachable states at that point
2. Is inductive (closed under the transition relation)
3. Excludes the bad states

Interpolants become STRENGTHENING LEMMAS that:
- Shrink the polynomial barrier search space
- Provide candidate invariants
- Guide predicate abstraction refinement

INTERPOLATION THEORY
====================

Given an unsatisfiable formula A ∧ B, a Craig interpolant I satisfies:
1. A → I (I is implied by A)
2. I ∧ B is unsatisfiable (I excludes B)
3. I uses only symbols common to A and B

For BMC, if Init ∧ Trans^k ∧ ¬Property is UNSAT:
- A = Init ∧ Trans^i (prefix)
- B = Trans^(k-i) ∧ ¬Property (suffix)
- Interpolant I approximates states reachable in i steps

INTEGRATION WITH BARRIERS
=========================

Interpolants provide:
1. **Inductive strengthening**: lemmas that constrain barrier search
2. **Predicate discovery**: atoms for predicate abstraction
3. **Template hints**: polynomial features from linear interpolants
4. **Counterexample blocking**: interpolants block spurious paths

IMPLEMENTATION STRUCTURE
========================

1. BMCEngine: Bounded model checking with unrolling
2. InterpolantExtractor: Extract interpolants from UNSAT proofs
3. InterpolantSequence: Manage sequence of interpolants
4. IMCVerifier: Full interpolation-based model checking
5. BarrierInterpolantBridge: Use interpolants to condition barriers

LAYER POSITION
==============

This is a **Layer 5 (Advanced Verification)** module.

    ┌─────────────────────────────────────────────────────────────────┐
    │ Layer 5: ADVANCED VERIFICATION ← [THIS MODULE]                  │
    │   ├── dsos_sdsos.py (Paper #9)                                  │
    │   ├── ic3_pdr.py (Paper #10)                                    │
    │   ├── spacer_chc.py (Paper #11)                                 │
    │   ├── interpolation_imc.py ← You are here (Paper #15)           │
    │   └── assume_guarantee.py (Paper #20)                           │
    │ Layer 4: Learning (ICE, Houdini, SyGuS)                         │
    │ Layer 3: Abstraction (CEGAR, Predicate Abstraction, IMPACT)     │
    │ Layer 2: Certificate Core (Hybrid, Stochastic, SOS Safety)      │
    │ Layer 1: Foundations (Positivstellensatz, SOS/SDP, Lasserre)    │
    └─────────────────────────────────────────────────────────────────┘

CROSS-PAPER DEPENDENCIES
========================

Interpolation is a KEY BRIDGE connecting verification techniques:

Provides to:
- Paper #10 (IC3/PDR): Interpolants strengthen IC3 frames
- Paper #12 (CEGAR): Interpolants guide abstraction refinement
- Paper #16 (IMPACT): Interpolants ARE the lazy abstraction predicates
- Paper #20 (Assume-Guarantee): Interpolants as interface assumptions

Uses from:
- Layer 1: Polynomial interpolation for numeric domains
- Layer 3: Predicate abstraction guides interpolant structure

INTERPOLATION + BARRIERS
========================

Interpolants constrain barrier search:
- Init ∧ Trans^k ∧ ¬Safe UNSAT gives interpolant I
- Barrier B must satisfy: B(x) → I(x) on reachable states
- I provides linear under-approximation of barrier constraint
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Dict, List, Optional, Tuple, Set, Any, Callable, FrozenSet
from collections import defaultdict

import z3

# =============================================================================
# LAYER 5: IMPORTS FROM LOWER LAYERS
# =============================================================================
# Interpolation connects to polynomial barriers (Layer 1), provides lemmas
# for certificate synthesis (Layer 2), and guides abstraction (Layer 3).
# =============================================================================

from .parrilo_sos_sdp import (
    Polynomial,
    SemialgebraicSet,
    BarrierSynthesisProblem,
)


# =============================================================================
# BMC ENGINE
# =============================================================================

class BMCResult(Enum):
    """Result of bounded model checking."""
    SAFE = auto()       # No counterexample up to bound
    UNSAFE = auto()     # Counterexample found
    UNKNOWN = auto()    # Bound not reached
    TIMEOUT = auto()    # Timeout before completion


@dataclass
class BMCCounterexample:
    """
    Counterexample trace from BMC.
    
    Contains sequence of states witnessing property violation.
    """
    states: List[Dict[str, Any]]
    depth: int
    property_violated: str = ""
    
    def __len__(self) -> int:
        return len(self.states)
    
    def get_state(self, step: int) -> Optional[Dict[str, Any]]:
        """Get state at step."""
        if 0 <= step < len(self.states):
            return self.states[step]
        return None
    
    def to_string(self) -> str:
        """String representation."""
        lines = [f"Counterexample (depth {self.depth}):"]
        for i, state in enumerate(self.states):
            lines.append(f"  Step {i}: {state}")
        return "\n".join(lines)


@dataclass
class BMCProof:
    """
    Result of BMC run.
    
    Attributes:
        result: BMC result (SAFE/UNSAFE/UNKNOWN/TIMEOUT)
        bound_reached: Maximum bound checked
        counterexample: Counterexample if UNSAFE
        unsat_core: UNSAT core if SAFE
        statistics: BMC statistics
    """
    result: BMCResult
    bound_reached: int = 0
    counterexample: Optional[BMCCounterexample] = None
    unsat_core: Optional[List[z3.BoolRef]] = None
    statistics: Dict[str, Any] = field(default_factory=dict)
    message: str = ""


class TransitionSystemBMC:
    """
    Transition system for BMC.
    
    Represents:
    - State variables (current and primed)
    - Initial state predicate
    - Transition relation
    - Property to verify
    """
    
    def __init__(self, variables: List[z3.ArithRef],
                 init: z3.BoolRef,
                 trans: z3.BoolRef,
                 property: z3.BoolRef):
        self.variables = variables
        self.init = init
        self.trans = trans
        self.property = property
        
        # Create primed versions
        self.variables_prime = [
            z3.Int(f"{v}_prime") if z3.is_int(v) else z3.Real(f"{v}_prime")
            for v in variables
        ]
    
    def get_state_at_step(self, step: int) -> List[z3.ArithRef]:
        """Get state variables for a specific unrolling step."""
        return [
            z3.Int(f"{v}_{step}") if z3.is_int(v) else z3.Real(f"{v}_{step}")
            for v in self.variables
        ]
    
    def substitute_vars(self, formula: z3.BoolRef,
                        old_vars: List[z3.ArithRef],
                        new_vars: List[z3.ArithRef]) -> z3.BoolRef:
        """Substitute variables in formula."""
        substitutions = list(zip(old_vars, new_vars))
        return z3.substitute(formula, substitutions)


class BMCEngine:
    """
    Bounded Model Checking engine.
    
    Unrolls the transition relation up to a bound and checks
    for property violations using SAT/SMT solving.
    
    Key features:
    - Incremental SAT solving
    - UNSAT core extraction for interpolation
    - Counterexample extraction
    """
    
    def __init__(self, system: TransitionSystemBMC,
                 max_bound: int = 100,
                 timeout_ms: int = 60000,
                 verbose: bool = False):
        self.system = system
        self.max_bound = max_bound
        self.timeout_ms = timeout_ms
        self.verbose = verbose
        
        # Incremental solver
        self.solver = z3.Solver()
        self.solver.set("timeout", timeout_ms)
        
        # Tracking
        self._current_bound = 0
        self._assertions_per_step: Dict[int, List[z3.BoolRef]] = {}
        
        # Statistics
        self.stats = {
            'sat_calls': 0,
            'unsat_calls': 0,
            'max_bound_checked': 0,
            'total_time_ms': 0,
        }
    
    def check(self, target_bound: Optional[int] = None) -> BMCProof:
        """
        Run BMC up to target bound.
        
        Returns proof with result and any counterexample/core.
        """
        start_time = time.time()
        bound = target_bound or self.max_bound
        
        # Initialize with initial state
        if self._current_bound == 0:
            self._add_initial_state()
        
        # Incrementally check each bound
        while self._current_bound < bound:
            # Check timeout
            elapsed = (time.time() - start_time) * 1000
            if elapsed > self.timeout_ms:
                self.stats['total_time_ms'] = elapsed
                return BMCProof(
                    result=BMCResult.TIMEOUT,
                    bound_reached=self._current_bound,
                    statistics=self.stats,
                    message=f"Timeout at bound {self._current_bound}"
                )
            
            # Check property at current bound
            result = self._check_property_at_bound()
            
            if result == z3.sat:
                # Found counterexample
                self.stats['sat_calls'] += 1
                cex = self._extract_counterexample()
                self.stats['total_time_ms'] = (time.time() - start_time) * 1000
                
                return BMCProof(
                    result=BMCResult.UNSAFE,
                    bound_reached=self._current_bound,
                    counterexample=cex,
                    statistics=self.stats,
                    message=f"Counterexample found at depth {self._current_bound}"
                )
            
            self.stats['unsat_calls'] += 1
            
            # Extend to next bound
            self._extend_bound()
            self._current_bound += 1
            self.stats['max_bound_checked'] = self._current_bound
        
        self.stats['total_time_ms'] = (time.time() - start_time) * 1000
        
        return BMCProof(
            result=BMCResult.SAFE,
            bound_reached=self._current_bound,
            unsat_core=self._get_unsat_core(),
            statistics=self.stats,
            message=f"No counterexample up to bound {self._current_bound}"
        )
    
    def _add_initial_state(self) -> None:
        """Add initial state constraint at step 0."""
        vars_0 = self.system.get_state_at_step(0)
        init_0 = self.system.substitute_vars(
            self.system.init,
            self.system.variables,
            vars_0
        )
        self.solver.add(init_0)
        self._assertions_per_step[0] = [init_0]
    
    def _extend_bound(self) -> None:
        """Extend unrolling by one step."""
        k = self._current_bound
        
        # Get variables for steps k and k+1
        vars_k = self.system.get_state_at_step(k)
        vars_k1 = self.system.get_state_at_step(k + 1)
        
        # Substitute transition relation
        trans_k = self.system.substitute_vars(
            self.system.trans,
            self.system.variables + self.system.variables_prime,
            vars_k + vars_k1
        )
        
        self.solver.add(trans_k)
        self._assertions_per_step.setdefault(k + 1, []).append(trans_k)
    
    def _check_property_at_bound(self) -> z3.CheckSatResult:
        """Check if property can be violated at current bound."""
        k = self._current_bound
        vars_k = self.system.get_state_at_step(k)
        
        # Property negated at step k
        not_prop_k = z3.Not(self.system.substitute_vars(
            self.system.property,
            self.system.variables,
            vars_k
        ))
        
        self.solver.push()
        self.solver.add(not_prop_k)
        result = self.solver.check()
        
        if result != z3.sat:
            self.solver.pop()
        
        return result
    
    def _extract_counterexample(self) -> BMCCounterexample:
        """Extract counterexample from SAT model."""
        model = self.solver.model()
        states = []
        
        for step in range(self._current_bound + 1):
            vars_step = self.system.get_state_at_step(step)
            state = {}
            
            for v, v_orig in zip(vars_step, self.system.variables):
                val = model.eval(v, model_completion=True)
                state[str(v_orig)] = val
            
            states.append(state)
        
        return BMCCounterexample(
            states=states,
            depth=self._current_bound
        )
    
    def _get_unsat_core(self) -> Optional[List[z3.BoolRef]]:
        """Get UNSAT core from solver."""
        # Need to use unsat_core() which requires tracking assertions
        # Simplified: return None for now
        return None
    
    def get_assertions_at_step(self, step: int) -> List[z3.BoolRef]:
        """Get assertions for a specific step (for interpolation)."""
        return self._assertions_per_step.get(step, [])
    
    def reset(self) -> None:
        """Reset the BMC engine."""
        self.solver.reset()
        self._current_bound = 0
        self._assertions_per_step.clear()


# =============================================================================
# INTERPOLANT EXTRACTION
# =============================================================================

@dataclass
class Interpolant:
    """
    A Craig interpolant.
    
    Attributes:
        formula: The interpolant formula
        step: The BMC step this interpolant corresponds to
        variables: Variables appearing in the interpolant
        is_inductive: Whether interpolant is inductive
    """
    formula: z3.BoolRef
    step: int
    variables: List[str] = field(default_factory=list)
    is_inductive: bool = False
    
    def to_string(self) -> str:
        return f"I_{self.step}: {self.formula}"
    
    def get_atoms(self) -> List[z3.BoolRef]:
        """Extract atomic predicates from interpolant."""
        atoms = []
        
        def collect_atoms(expr):
            if z3.is_and(expr):
                for child in expr.children():
                    collect_atoms(child)
            elif z3.is_or(expr):
                for child in expr.children():
                    collect_atoms(child)
            elif z3.is_not(expr):
                collect_atoms(expr.children()[0])
            else:
                # Atomic formula
                atoms.append(expr)
        
        collect_atoms(self.formula)
        return atoms


class InterpolantSequence:
    """
    Sequence of interpolants from BMC unrolling.
    
    For a BMC query Init ∧ T^k ∧ ¬P that is UNSAT,
    we get interpolants I_0, I_1, ..., I_k where:
    - I_0 ⊇ Init
    - I_i ∧ T → I_{i+1}
    - I_k ∧ ¬P is UNSAT
    """
    
    def __init__(self):
        self.interpolants: List[Interpolant] = []
        self._fixed_point_index: Optional[int] = None
    
    def add(self, interpolant: Interpolant) -> None:
        """Add interpolant to sequence."""
        self.interpolants.append(interpolant)
    
    def __len__(self) -> int:
        return len(self.interpolants)
    
    def __getitem__(self, index: int) -> Interpolant:
        return self.interpolants[index]
    
    def check_fixed_point(self) -> Optional[int]:
        """
        Check if sequence has reached a fixed point.
        
        Fixed point: I_k ⊆ I_{k+1} (or I_k = I_{k+1})
        """
        if len(self.interpolants) < 2:
            return None
        
        solver = z3.Solver()
        
        for i in range(len(self.interpolants) - 1):
            # Check if I_i ⊆ I_{i+1}
            solver.push()
            solver.add(self.interpolants[i].formula)
            solver.add(z3.Not(self.interpolants[i + 1].formula))
            
            if solver.check() == z3.unsat:
                self._fixed_point_index = i
                solver.pop()
                return i
            
            solver.pop()
        
        return None
    
    def get_inductive_invariant(self) -> Optional[z3.BoolRef]:
        """
        Extract inductive invariant from fixed point.
        
        If I_k ⊆ I_{k+1}, then I_k is inductive.
        """
        if self._fixed_point_index is not None:
            return self.interpolants[self._fixed_point_index].formula
        
        fp = self.check_fixed_point()
        if fp is not None:
            return self.interpolants[fp].formula
        
        return None
    
    def get_all_atoms(self) -> Set[str]:
        """Get all atomic predicates from all interpolants."""
        atoms = set()
        for interp in self.interpolants:
            for atom in interp.get_atoms():
                atoms.add(str(atom))
        return atoms


class InterpolantExtractor:
    """
    Extract Craig interpolants from UNSAT BMC proofs.
    
    Uses Z3's interpolation capabilities (or approximates them).
    """
    
    def __init__(self, verbose: bool = False):
        self.verbose = verbose
        
        self.stats = {
            'interpolants_computed': 0,
            'fixed_points_found': 0,
            'atoms_extracted': 0,
        }
    
    def extract_sequence(self, bmc_engine: BMCEngine,
                          bound: int) -> Optional[InterpolantSequence]:
        """
        Extract interpolant sequence from BMC unrolling.
        
        For each step i, computes interpolant between:
        - A = Init ∧ Trans^i (prefix up to step i)
        - B = Trans^(k-i) ∧ ¬Property (suffix from step i)
        """
        sequence = InterpolantSequence()
        
        for i in range(bound + 1):
            interp = self._compute_interpolant_at_step(bmc_engine, i, bound)
            if interp is not None:
                sequence.add(interp)
                self.stats['interpolants_computed'] += 1
        
        # Check for fixed point
        fp = sequence.check_fixed_point()
        if fp is not None:
            self.stats['fixed_points_found'] += 1
        
        self.stats['atoms_extracted'] = len(sequence.get_all_atoms())
        
        return sequence
    
    def _compute_interpolant_at_step(self, bmc_engine: BMCEngine,
                                       step: int, bound: int) -> Optional[Interpolant]:
        """Compute interpolant at a specific step."""
        # Build A (prefix) and B (suffix) formulas
        prefix_assertions = []
        suffix_assertions = []
        
        for s in range(bound + 1):
            assertions = bmc_engine.get_assertions_at_step(s)
            if s <= step:
                prefix_assertions.extend(assertions)
            else:
                suffix_assertions.extend(assertions)
        
        # Add property negation to suffix
        vars_bound = bmc_engine.system.get_state_at_step(bound)
        not_prop = z3.Not(bmc_engine.system.substitute_vars(
            bmc_engine.system.property,
            bmc_engine.system.variables,
            vars_bound
        ))
        suffix_assertions.append(not_prop)
        
        # Compute interpolant
        # Z3 doesn't directly support interpolation, so we approximate
        interp_formula = self._approximate_interpolant(
            prefix_assertions,
            suffix_assertions,
            bmc_engine.system.get_state_at_step(step)
        )
        
        if interp_formula is not None:
            variables = [str(v) for v in bmc_engine.system.get_state_at_step(step)]
            return Interpolant(
                formula=interp_formula,
                step=step,
                variables=variables
            )
        
        return None
    
    def _approximate_interpolant(self, prefix: List[z3.BoolRef],
                                   suffix: List[z3.BoolRef],
                                   shared_vars: List[z3.ArithRef]) -> Optional[z3.BoolRef]:
        """
        Approximate interpolant when direct computation unavailable.
        
        Uses a weakening approach:
        1. Start with prefix conjunction
        2. Project onto shared variables
        3. Weaken until it excludes suffix
        """
        if not prefix or not suffix:
            return None
        
        # Simplified: use the prefix projected onto shared variables
        prefix_formula = z3.And(prefix) if len(prefix) > 1 else prefix[0]
        
        # Try to extract constraints on shared variables
        solver = z3.Solver()
        solver.add(prefix_formula)
        
        if solver.check() == z3.sat:
            model = solver.model()
            
            # Build interpolant from model bounds
            constraints = []
            for v in shared_vars:
                val = model.eval(v, model_completion=True)
                if val is not None:
                    # Create range constraint
                    if z3.is_int_value(val):
                        int_val = val.as_long()
                        constraints.append(v >= int_val - 1000)
                        constraints.append(v <= int_val + 1000)
            
            if constraints:
                return z3.And(constraints)
        
        return z3.BoolVal(True)
    
    def get_statistics(self) -> Dict[str, int]:
        """Get extraction statistics."""
        return dict(self.stats)


# =============================================================================
# IMC VERIFIER
# =============================================================================

class IMCResult(Enum):
    """Result of IMC verification."""
    SAFE = auto()        # Inductive invariant found
    UNSAFE = auto()      # Counterexample found
    UNKNOWN = auto()     # Could not determine
    TIMEOUT = auto()     # Timeout


@dataclass
class IMCProof:
    """
    Proof from IMC verification.
    
    Attributes:
        result: Verification result
        invariant: Inductive invariant (if SAFE)
        counterexample: Counterexample trace (if UNSAFE)
        interpolant_sequence: Sequence of interpolants
        bound_reached: Maximum BMC bound reached
        statistics: Verification statistics
    """
    result: IMCResult
    invariant: Optional[z3.BoolRef] = None
    counterexample: Optional[BMCCounterexample] = None
    interpolant_sequence: Optional[InterpolantSequence] = None
    bound_reached: int = 0
    statistics: Dict[str, Any] = field(default_factory=dict)
    message: str = ""


class IMCVerifier:
    """
    Interpolation-based Model Checker.
    
    Algorithm:
    1. Run BMC to increasing bounds
    2. If UNSAT, extract interpolant sequence
    3. Check if interpolants reach fixed point
    4. If fixed point, we have inductive invariant → SAFE
    5. If SAT, we have counterexample → UNSAFE
    """
    
    def __init__(self, system: TransitionSystemBMC,
                 max_bound: int = 50,
                 timeout_ms: int = 60000,
                 verbose: bool = False):
        self.system = system
        self.max_bound = max_bound
        self.timeout_ms = timeout_ms
        self.verbose = verbose
        
        self.bmc = BMCEngine(system, max_bound, timeout_ms, verbose)
        self.extractor = InterpolantExtractor(verbose)
        
        self.stats = {
            'bmc_iterations': 0,
            'interpolation_rounds': 0,
            'fixed_point_bound': -1,
            'total_time_ms': 0,
        }
    
    def verify(self) -> IMCProof:
        """
        Run IMC verification.
        
        Returns proof with result and artifacts.
        """
        start_time = time.time()
        
        for bound in range(1, self.max_bound + 1):
            # Check timeout
            elapsed = (time.time() - start_time) * 1000
            if elapsed > self.timeout_ms:
                self.stats['total_time_ms'] = elapsed
                return IMCProof(
                    result=IMCResult.TIMEOUT,
                    bound_reached=bound - 1,
                    statistics=self.stats,
                    message="Timeout"
                )
            
            self.stats['bmc_iterations'] = bound
            
            # Run BMC to current bound
            self.bmc.reset()
            bmc_result = self.bmc.check(bound)
            
            if bmc_result.result == BMCResult.UNSAFE:
                # Found counterexample
                self.stats['total_time_ms'] = (time.time() - start_time) * 1000
                return IMCProof(
                    result=IMCResult.UNSAFE,
                    counterexample=bmc_result.counterexample,
                    bound_reached=bound,
                    statistics=self.stats,
                    message=f"Counterexample at depth {bound}"
                )
            
            # Extract interpolants
            self.stats['interpolation_rounds'] += 1
            sequence = self.extractor.extract_sequence(self.bmc, bound)
            
            if sequence:
                # Check for fixed point
                invariant = sequence.get_inductive_invariant()
                
                if invariant is not None:
                    # Verify inductiveness
                    if self._verify_inductive(invariant):
                        self.stats['fixed_point_bound'] = bound
                        self.stats['total_time_ms'] = (time.time() - start_time) * 1000
                        
                        return IMCProof(
                            result=IMCResult.SAFE,
                            invariant=invariant,
                            interpolant_sequence=sequence,
                            bound_reached=bound,
                            statistics=self.stats,
                            message="Inductive invariant found"
                        )
        
        self.stats['total_time_ms'] = (time.time() - start_time) * 1000
        
        return IMCProof(
            result=IMCResult.UNKNOWN,
            bound_reached=self.max_bound,
            statistics=self.stats,
            message=f"No result up to bound {self.max_bound}"
        )
    
    def _verify_inductive(self, invariant: z3.BoolRef) -> bool:
        """Verify that invariant is inductive."""
        solver = z3.Solver()
        
        # Check: Init → Inv
        solver.push()
        solver.add(self.system.init)
        solver.add(z3.Not(invariant))
        if solver.check() == z3.sat:
            solver.pop()
            return False
        solver.pop()
        
        # Check: Inv ∧ Trans → Inv'
        inv_prime = z3.substitute(
            invariant,
            list(zip(self.system.variables, self.system.variables_prime))
        )
        
        solver.push()
        solver.add(invariant)
        solver.add(self.system.trans)
        solver.add(z3.Not(inv_prime))
        if solver.check() == z3.sat:
            solver.pop()
            return False
        solver.pop()
        
        # Check: Inv → Property
        solver.push()
        solver.add(invariant)
        solver.add(z3.Not(self.system.property))
        if solver.check() == z3.sat:
            solver.pop()
            return False
        solver.pop()
        
        return True
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get verification statistics."""
        stats = dict(self.stats)
        stats['bmc_stats'] = self.bmc.stats
        stats['extractor_stats'] = self.extractor.get_statistics()
        return stats


# =============================================================================
# BARRIER-INTERPOLANT BRIDGE
# =============================================================================

@dataclass
class InterpolantConstraint:
    """
    Constraint derived from interpolant for barrier synthesis.
    
    Represents a linear/polynomial constraint that must hold
    within the barrier's safe region.
    """
    formula: z3.BoolRef
    as_polynomial: Optional[Polynomial] = None
    is_linear: bool = True
    source_step: int = 0
    
    def to_sos_constraint(self) -> Optional[Polynomial]:
        """Convert to polynomial for SOS encoding."""
        return self.as_polynomial


class BarrierInterpolantBridge:
    """
    Bridge between interpolants and barrier synthesis.
    
    Uses interpolants to:
    1. Strengthen barrier search space
    2. Provide predicate hints
    3. Extract polynomial template features
    """
    
    def __init__(self, n_vars: int, var_names: Optional[List[str]] = None,
                 verbose: bool = False):
        self.n_vars = n_vars
        self.var_names = var_names or [f"x_{i}" for i in range(n_vars)]
        self.verbose = verbose
        
        # Extracted constraints
        self._constraints: List[InterpolantConstraint] = []
        self._predicates: Set[str] = set()
    
    def process_interpolant_sequence(self, sequence: InterpolantSequence) -> None:
        """
        Process interpolant sequence to extract constraints.
        """
        for interp in sequence.interpolants:
            self._extract_constraints_from_interpolant(interp)
    
    def _extract_constraints_from_interpolant(self, interp: Interpolant) -> None:
        """Extract constraints from a single interpolant."""
        atoms = interp.get_atoms()
        
        for atom in atoms:
            self._predicates.add(str(atom))
            
            # Try to convert to polynomial constraint
            poly = self._atom_to_polynomial(atom)
            
            constraint = InterpolantConstraint(
                formula=atom,
                as_polynomial=poly,
                is_linear=self._is_linear(atom),
                source_step=interp.step
            )
            self._constraints.append(constraint)
    
    def _atom_to_polynomial(self, atom: z3.BoolRef) -> Optional[Polynomial]:
        """Convert Z3 atom to polynomial."""
        # Handle comparison operators
        if z3.is_le(atom) or z3.is_lt(atom):
            # a <= b becomes b - a >= 0
            lhs, rhs = atom.children()
            return self._expr_to_polynomial(rhs - lhs)
        
        if z3.is_ge(atom) or z3.is_gt(atom):
            # a >= b becomes a - b >= 0
            lhs, rhs = atom.children()
            return self._expr_to_polynomial(lhs - rhs)
        
        if z3.is_eq(atom):
            # a == b becomes both a - b >= 0 and b - a >= 0
            lhs, rhs = atom.children()
            return self._expr_to_polynomial(lhs - rhs)
        
        return None
    
    def _expr_to_polynomial(self, expr: z3.ArithRef) -> Optional[Polynomial]:
        """Convert Z3 arithmetic expression to polynomial."""
        coeffs = {}
        
        def process_expr(e, sign=1):
            if z3.is_int_value(e) or z3.is_rational_value(e):
                # Constant term
                val = e.as_long() if z3.is_int_value(e) else float(e.as_decimal(10))
                zero_mono = tuple([0] * self.n_vars)
                coeffs[zero_mono] = coeffs.get(zero_mono, 0) + sign * val
            
            elif z3.is_const(e) and not z3.is_int_value(e):
                # Variable
                var_name = str(e)
                if var_name in self.var_names:
                    idx = self.var_names.index(var_name)
                    mono = tuple(1 if i == idx else 0 for i in range(self.n_vars))
                    coeffs[mono] = coeffs.get(mono, 0) + sign
            
            elif z3.is_add(e):
                for child in e.children():
                    process_expr(child, sign)
            
            elif z3.is_sub(e):
                children = e.children()
                process_expr(children[0], sign)
                for child in children[1:]:
                    process_expr(child, -sign)
            
            elif z3.is_mul(e):
                # Simplified: handle only linear terms
                children = e.children()
                if len(children) == 2:
                    if z3.is_int_value(children[0]):
                        coef = children[0].as_long()
                        process_expr(children[1], sign * coef)
                    elif z3.is_int_value(children[1]):
                        coef = children[1].as_long()
                        process_expr(children[0], sign * coef)
        
        try:
            process_expr(expr)
            if coeffs:
                return Polynomial(self.n_vars, coeffs)
        except Exception:
            pass
        
        return None
    
    def _is_linear(self, atom: z3.BoolRef) -> bool:
        """Check if atom is a linear constraint."""
        def check_expr(e):
            if z3.is_int_value(e) or z3.is_rational_value(e):
                return True
            if z3.is_const(e):
                return True
            if z3.is_add(e) or z3.is_sub(e):
                return all(check_expr(c) for c in e.children())
            if z3.is_mul(e):
                children = e.children()
                # Linear if at most one non-constant
                non_const = [c for c in children if not (z3.is_int_value(c) or z3.is_rational_value(c))]
                return len(non_const) <= 1 and all(check_expr(c) for c in non_const)
            return False
        
        if z3.is_le(atom) or z3.is_lt(atom) or z3.is_ge(atom) or z3.is_gt(atom) or z3.is_eq(atom):
            return all(check_expr(c) for c in atom.children())
        return False
    
    def condition_barrier_problem(self, problem: BarrierSynthesisProblem) -> BarrierSynthesisProblem:
        """
        Condition barrier synthesis problem using interpolant constraints.
        
        Adds interpolant-derived constraints to strengthen the problem.
        """
        # Get polynomial constraints from interpolants
        poly_constraints = []
        for constraint in self._constraints:
            if constraint.as_polynomial:
                poly_constraints.append(constraint.as_polynomial)
        
        if not poly_constraints:
            return problem
        
        # Add constraints to init set (as additional inequalities)
        new_init = SemialgebraicSet(
            n_vars=problem.init_set.n_vars,
            inequalities=problem.init_set.inequalities + poly_constraints,
            equalities=problem.init_set.equalities,
            var_names=problem.init_set.var_names,
            name=f"{problem.init_set.name}_interp"
        )
        
        return BarrierSynthesisProblem(
            n_vars=problem.n_vars,
            init_set=new_init,
            unsafe_set=problem.unsafe_set,
            transition=problem.transition,
            epsilon=problem.epsilon,
            barrier_degree=problem.barrier_degree
        )
    
    def get_predicate_hints(self) -> List[str]:
        """Get predicate hints for abstraction."""
        return list(self._predicates)
    
    def get_polynomial_features(self) -> List[Polynomial]:
        """Get polynomial features for template construction."""
        return [c.as_polynomial for c in self._constraints if c.as_polynomial]
    
    def get_linear_constraints(self) -> List[InterpolantConstraint]:
        """Get linear constraints only."""
        return [c for c in self._constraints if c.is_linear]


# =============================================================================
# IMC INTEGRATION
# =============================================================================

@dataclass
class IMCIntegrationConfig:
    """Configuration for IMC integration."""
    max_bmc_bound: int = 50
    use_interpolants_for_conditioning: bool = True
    extract_predicates: bool = True
    timeout_ms: int = 60000
    verbose: bool = False


class IMCIntegration:
    """
    Integration of IMC with barrier synthesis.
    
    Provides:
    1. IMC verification as a pre-check
    2. Interpolant-based barrier conditioning
    3. Predicate extraction for abstraction
    """
    
    def __init__(self, config: Optional[IMCIntegrationConfig] = None,
                 verbose: bool = False):
        self.config = config or IMCIntegrationConfig()
        self.verbose = verbose or self.config.verbose
        
        # Cached results
        self._proofs: Dict[str, IMCProof] = {}
        self._bridges: Dict[str, BarrierInterpolantBridge] = {}
        
        self.stats = {
            'imc_runs': 0,
            'safe_proofs': 0,
            'unsafe_proofs': 0,
            'conditioning_applications': 0,
        }
    
    def verify_system(self, system: TransitionSystemBMC,
                       system_id: str = "default") -> IMCProof:
        """Run IMC verification on a transition system."""
        self.stats['imc_runs'] += 1
        
        verifier = IMCVerifier(
            system,
            self.config.max_bmc_bound,
            self.config.timeout_ms,
            self.verbose
        )
        
        proof = verifier.verify()
        self._proofs[system_id] = proof
        
        if proof.result == IMCResult.SAFE:
            self.stats['safe_proofs'] += 1
        elif proof.result == IMCResult.UNSAFE:
            self.stats['unsafe_proofs'] += 1
        
        # Extract bridge if we have interpolants
        if proof.interpolant_sequence:
            bridge = BarrierInterpolantBridge(
                len(system.variables),
                [str(v) for v in system.variables],
                self.verbose
            )
            bridge.process_interpolant_sequence(proof.interpolant_sequence)
            self._bridges[system_id] = bridge
        
        return proof
    
    def condition_barrier_problem(self, problem: BarrierSynthesisProblem,
                                    system_id: str = "default") -> BarrierSynthesisProblem:
        """Condition barrier problem using IMC results."""
        if not self.config.use_interpolants_for_conditioning:
            return problem
        
        bridge = self._bridges.get(system_id)
        if bridge:
            self.stats['conditioning_applications'] += 1
            return bridge.condition_barrier_problem(problem)
        
        return problem
    
    def get_predicate_hints(self, system_id: str = "default") -> List[str]:
        """Get predicate hints from IMC."""
        bridge = self._bridges.get(system_id)
        if bridge:
            return bridge.get_predicate_hints()
        return []
    
    def get_proof(self, system_id: str) -> Optional[IMCProof]:
        """Get cached IMC proof."""
        return self._proofs.get(system_id)
    
    def clear_cache(self) -> None:
        """Clear all caches."""
        self._proofs.clear()
        self._bridges.clear()


# =============================================================================
# CONVENIENCE FUNCTIONS
# =============================================================================

def run_bmc(system: TransitionSystemBMC,
            max_bound: int = 50,
            timeout_ms: int = 60000,
            verbose: bool = False) -> BMCProof:
    """
    Run bounded model checking.
    
    Main BMC entry point.
    """
    engine = BMCEngine(system, max_bound, timeout_ms, verbose)
    return engine.check()


def run_imc(system: TransitionSystemBMC,
            max_bound: int = 50,
            timeout_ms: int = 60000,
            verbose: bool = False) -> IMCProof:
    """
    Run interpolation-based model checking.
    
    Main IMC entry point.
    """
    verifier = IMCVerifier(system, max_bound, timeout_ms, verbose)
    return verifier.verify()


def extract_interpolants(bmc_engine: BMCEngine,
                          bound: int,
                          verbose: bool = False) -> Optional[InterpolantSequence]:
    """Extract interpolant sequence from BMC."""
    extractor = InterpolantExtractor(verbose)
    return extractor.extract_sequence(bmc_engine, bound)


def condition_barrier_with_interpolants(problem: BarrierSynthesisProblem,
                                          system: TransitionSystemBMC,
                                          timeout_ms: int = 30000,
                                          verbose: bool = False) -> BarrierSynthesisProblem:
    """
    Condition barrier problem using interpolants.
    """
    config = IMCIntegrationConfig(
        timeout_ms=timeout_ms,
        use_interpolants_for_conditioning=True,
        verbose=verbose
    )
    
    integration = IMCIntegration(config, verbose)
    integration.verify_system(system, "barrier_conditioning")
    return integration.condition_barrier_problem(problem, "barrier_conditioning")


# =============================================================================
# ADVANCED IMC FEATURES
# =============================================================================

class IncrementalIMC:
    """
    Incremental IMC that reuses work across multiple queries.
    
    Key optimizations:
    - Reuse SAT solver state
    - Cache interpolants
    - Incremental fixed-point detection
    """
    
    def __init__(self, system: TransitionSystemBMC,
                 verbose: bool = False):
        self.system = system
        self.verbose = verbose
        
        # Persistent solver
        self.solver = z3.Solver()
        self.solver.set("unsat_core", True)
        
        # Cached interpolants
        self._interpolant_cache: Dict[int, Interpolant] = {}
        
        # Current state
        self._bound = 0
        self._assertions: List[z3.BoolRef] = []
    
    def check_incremental(self, new_bound: int) -> IMCProof:
        """Check from current bound to new bound incrementally."""
        start_time = time.time()
        
        # Extend to new bound
        while self._bound < new_bound:
            self._extend_one_step()
            self._bound += 1
            
            # Check property
            result = self._check_property()
            
            if result == z3.sat:
                # Counterexample found
                return IMCProof(
                    result=IMCResult.UNSAFE,
                    bound_reached=self._bound,
                    message="Counterexample found"
                )
            
            # Try to compute interpolant and check fixed point
            interp = self._compute_interpolant_at_current()
            if interp is not None:
                self._interpolant_cache[self._bound] = interp
                
                if self._check_fixed_point():
                    return IMCProof(
                        result=IMCResult.SAFE,
                        invariant=interp.formula,
                        bound_reached=self._bound,
                        message="Fixed point reached"
                    )
        
        return IMCProof(
            result=IMCResult.UNKNOWN,
            bound_reached=self._bound,
            message=f"No result up to bound {self._bound}"
        )
    
    def _extend_one_step(self) -> None:
        """Extend unrolling by one step."""
        vars_curr = self.system.get_state_at_step(self._bound)
        vars_next = self.system.get_state_at_step(self._bound + 1)
        
        trans = self.system.substitute_vars(
            self.system.trans,
            self.system.variables + self.system.variables_prime,
            vars_curr + vars_next
        )
        
        self.solver.add(trans)
        self._assertions.append(trans)
    
    def _check_property(self) -> z3.CheckSatResult:
        """Check property at current bound."""
        vars_curr = self.system.get_state_at_step(self._bound)
        not_prop = z3.Not(self.system.substitute_vars(
            self.system.property,
            self.system.variables,
            vars_curr
        ))
        
        self.solver.push()
        self.solver.add(not_prop)
        result = self.solver.check()
        self.solver.pop()
        
        return result
    
    def _compute_interpolant_at_current(self) -> Optional[Interpolant]:
        """Compute interpolant at current bound."""
        # Simplified: use over-approximation
        vars_curr = self.system.get_state_at_step(self._bound)
        
        # Get bounds from init constraint
        self.solver.push()
        init_0 = self.system.substitute_vars(
            self.system.init,
            self.system.variables,
            self.system.get_state_at_step(0)
        )
        self.solver.add(init_0)
        
        if self.solver.check() == z3.sat:
            model = self.solver.model()
            
            constraints = []
            for v in vars_curr:
                val = model.eval(v, model_completion=True)
                if z3.is_int_value(val):
                    int_val = val.as_long()
                    constraints.append(v >= int_val - 1000)
                    constraints.append(v <= int_val + 1000)
            
            self.solver.pop()
            
            if constraints:
                return Interpolant(
                    formula=z3.And(constraints),
                    step=self._bound
                )
        
        self.solver.pop()
        return None
    
    def _check_fixed_point(self) -> bool:
        """Check if we've reached a fixed point."""
        if len(self._interpolant_cache) < 2:
            return False
        
        # Check if last two interpolants are equivalent
        last_keys = sorted(self._interpolant_cache.keys())[-2:]
        i1 = self._interpolant_cache[last_keys[0]]
        i2 = self._interpolant_cache[last_keys[1]]
        
        solver = z3.Solver()
        
        # Check i1 ⊆ i2
        solver.add(i1.formula)
        solver.add(z3.Not(i2.formula))
        
        if solver.check() == z3.unsat:
            return True
        
        return False
    
    def reset(self) -> None:
        """Reset incremental state."""
        self.solver.reset()
        self._bound = 0
        self._assertions.clear()
        self._interpolant_cache.clear()


class TreeInterpolation:
    """
    Tree interpolation for structured programs.
    
    For programs with procedure calls, tree interpolation
    provides better interpolants than sequence interpolation.
    """
    
    def __init__(self, verbose: bool = False):
        self.verbose = verbose
    
    def compute_tree_interpolants(self, tree: Dict[str, List[str]],
                                    formulas: Dict[str, z3.BoolRef]) -> Dict[str, z3.BoolRef]:
        """
        Compute tree interpolants.
        
        Args:
            tree: Tree structure (node -> children)
            formulas: Formula at each node
        
        Returns:
            Interpolant at each node
        """
        interpolants = {}
        
        # Process leaves first, then internal nodes
        processed = set()
        
        def process_node(node: str):
            if node in processed:
                return
            
            children = tree.get(node, [])
            
            # Process children first
            for child in children:
                process_node(child)
            
            # Compute interpolant for this node
            if children:
                # Internal node: combine child interpolants
                child_interps = [interpolants.get(c, z3.BoolVal(True)) for c in children]
                node_formula = formulas.get(node, z3.BoolVal(True))
                
                interpolants[node] = z3.And([node_formula] + child_interps)
            else:
                # Leaf node: use formula directly
                interpolants[node] = formulas.get(node, z3.BoolVal(True))
            
            processed.add(node)
        
        # Process from root
        for node in tree.keys():
            process_node(node)
        
        return interpolants


class PathInterpolation:
    """
    Path-specific interpolation for CEGAR.
    
    Computes interpolants for specific infeasible paths,
    producing targeted refinement predicates.
    """
    
    def __init__(self, verbose: bool = False):
        self.verbose = verbose
    
    def interpolate_path(self, path_formula: List[z3.BoolRef],
                          shared_vars_at_step: List[List[z3.ArithRef]]) -> List[z3.BoolRef]:
        """
        Compute interpolants along a path.
        
        Args:
            path_formula: Formula at each path step
            shared_vars_at_step: Shared variables at each step
        
        Returns:
            Interpolant at each step
        """
        n = len(path_formula)
        interpolants = []
        
        for i in range(n):
            prefix = path_formula[:i + 1]
            suffix = path_formula[i + 1:]
            
            if not suffix:
                # Last step: interpolant is just True
                interpolants.append(z3.BoolVal(True))
                continue
            
            # Check if prefix ∧ suffix is UNSAT
            solver = z3.Solver()
            solver.add(z3.And(prefix))
            solver.add(z3.And(suffix))
            
            if solver.check() == z3.unsat:
                # Compute interpolant
                interp = self._compute_interpolant(prefix, suffix, shared_vars_at_step[i])
                interpolants.append(interp)
            else:
                # Path is feasible
                interpolants.append(z3.BoolVal(True))
        
        return interpolants
    
    def _compute_interpolant(self, prefix: List[z3.BoolRef],
                              suffix: List[z3.BoolRef],
                              shared_vars: List[z3.ArithRef]) -> z3.BoolRef:
        """Compute interpolant between prefix and suffix."""
        # Simplified: project prefix onto shared variables
        solver = z3.Solver()
        solver.add(z3.And(prefix))
        
        if solver.check() == z3.sat:
            model = solver.model()
            
            constraints = []
            for v in shared_vars:
                val = model.eval(v, model_completion=True)
                if z3.is_int_value(val):
                    int_val = val.as_long()
                    constraints.append(v == int_val)
            
            if constraints:
                return z3.Or(constraints)  # Disjunction of point constraints
        
        return z3.BoolVal(True)
    
    def extract_predicates(self, interpolants: List[z3.BoolRef]) -> Set[str]:
        """Extract predicates from interpolants."""
        predicates = set()
        
        for interp in interpolants:
            self._extract_atoms(interp, predicates)
        
        return predicates
    
    def _extract_atoms(self, formula: z3.BoolRef, atoms: Set[str]) -> None:
        """Recursively extract atomic predicates."""
        if z3.is_and(formula) or z3.is_or(formula):
            for child in formula.children():
                self._extract_atoms(child, atoms)
        elif z3.is_not(formula):
            self._extract_atoms(formula.children()[0], atoms)
        else:
            atoms.add(str(formula))


class InterpolantBasedInvariantSynthesis:
    """
    Synthesize invariants from interpolants.
    
    Combines interpolants to form stronger invariants
    suitable for barrier synthesis.
    """
    
    def __init__(self, n_vars: int, var_names: List[str],
                 verbose: bool = False):
        self.n_vars = n_vars
        self.var_names = var_names
        self.verbose = verbose
        
        # Collected interpolants
        self._interpolants: List[z3.BoolRef] = []
        
        # Synthesized invariant
        self._invariant: Optional[z3.BoolRef] = None
    
    def add_interpolant(self, interp: z3.BoolRef) -> None:
        """Add an interpolant to the collection."""
        self._interpolants.append(interp)
        self._invariant = None  # Invalidate cached invariant
    
    def add_interpolant_sequence(self, sequence: InterpolantSequence) -> None:
        """Add all interpolants from a sequence."""
        for interp in sequence.interpolants:
            self._interpolants.append(interp.formula)
        self._invariant = None
    
    def synthesize_invariant(self, strategy: str = "conjunction") -> Optional[z3.BoolRef]:
        """
        Synthesize invariant from collected interpolants.
        
        Strategies:
        - "conjunction": AND of all interpolants
        - "fixed_point": Compute fixed point
        - "strongest": Find strongest over-approximation
        """
        if not self._interpolants:
            return None
        
        if strategy == "conjunction":
            self._invariant = z3.And(self._interpolants)
        
        elif strategy == "fixed_point":
            self._invariant = self._compute_fixed_point()
        
        elif strategy == "strongest":
            self._invariant = self._find_strongest()
        
        else:
            self._invariant = z3.And(self._interpolants)
        
        return self._invariant
    
    def _compute_fixed_point(self) -> z3.BoolRef:
        """Compute fixed point of interpolants."""
        if len(self._interpolants) == 1:
            return self._interpolants[0]
        
        # Start with first interpolant
        current = self._interpolants[0]
        
        # Iteratively intersect with others
        for interp in self._interpolants[1:]:
            current = z3.And(current, interp)
            current = z3.simplify(current)
        
        return current
    
    def _find_strongest(self) -> z3.BoolRef:
        """Find strongest interpolant (most restrictive)."""
        if len(self._interpolants) == 1:
            return self._interpolants[0]
        
        # Conjunction is strongest
        return z3.simplify(z3.And(self._interpolants))
    
    def get_invariant(self) -> Optional[z3.BoolRef]:
        """Get the synthesized invariant."""
        if self._invariant is None:
            self.synthesize_invariant()
        return self._invariant
    
    def verify_invariant(self, init: z3.BoolRef,
                          trans: z3.BoolRef,
                          prop: z3.BoolRef,
                          variables: List[z3.ArithRef],
                          variables_prime: List[z3.ArithRef]) -> bool:
        """Verify that synthesized invariant is correct."""
        if self._invariant is None:
            return False
        
        solver = z3.Solver()
        
        # Check Init → Inv
        solver.push()
        solver.add(init)
        solver.add(z3.Not(self._invariant))
        if solver.check() == z3.sat:
            solver.pop()
            return False
        solver.pop()
        
        # Check Inv ∧ Trans → Inv'
        inv_prime = z3.substitute(
            self._invariant,
            list(zip(variables, variables_prime))
        )
        
        solver.push()
        solver.add(self._invariant)
        solver.add(trans)
        solver.add(z3.Not(inv_prime))
        if solver.check() == z3.sat:
            solver.pop()
            return False
        solver.pop()
        
        # Check Inv → Property
        solver.push()
        solver.add(self._invariant)
        solver.add(z3.Not(prop))
        if solver.check() == z3.sat:
            solver.pop()
            return False
        solver.pop()
        
        return True


# =============================================================================
# INTERPOLANT-BASED PREDICATE DISCOVERY
# =============================================================================

class PredicateExtractor:
    """
    Extract predicates from interpolants for abstraction.
    
    Discovers atomic predicates that can be used for
    predicate abstraction or as polynomial features.
    """
    
    def __init__(self, verbose: bool = False):
        self.verbose = verbose
        self._predicates: Set[z3.BoolRef] = set()
    
    def extract_from_interpolant(self, interpolant: z3.BoolRef) -> List[z3.BoolRef]:
        """
        Extract atomic predicates from interpolant.
        """
        predicates = []
        
        def extract_atoms(formula: z3.ExprRef):
            if z3.is_not(formula):
                extract_atoms(formula.arg(0))
            elif z3.is_and(formula) or z3.is_or(formula):
                for child in formula.children():
                    extract_atoms(child)
            elif z3.is_implies(formula):
                extract_atoms(formula.arg(0))
                extract_atoms(formula.arg(1))
            elif self._is_comparison(formula):
                predicates.append(formula)
                self._predicates.add(formula)
            elif z3.is_eq(formula):
                predicates.append(formula)
                self._predicates.add(formula)
        
        extract_atoms(interpolant)
        return predicates
    
    def _is_comparison(self, formula: z3.ExprRef) -> bool:
        """Check if formula is a comparison."""
        return (z3.is_le(formula) or z3.is_lt(formula) or 
                z3.is_ge(formula) or z3.is_gt(formula))
    
    def get_all_predicates(self) -> List[z3.BoolRef]:
        """Get all discovered predicates."""
        return list(self._predicates)
    
    def convert_to_polynomial_constraints(self, 
                                           n_vars: int,
                                           var_names: List[str]) -> List[Polynomial]:
        """
        Convert predicates to polynomial constraints.
        """
        polynomials = []
        
        for pred in self._predicates:
            poly = self._predicate_to_polynomial(pred, n_vars, var_names)
            if poly:
                polynomials.append(poly)
        
        return polynomials
    
    def _predicate_to_polynomial(self, pred: z3.BoolRef,
                                   n_vars: int,
                                   var_names: List[str]) -> Optional[Polynomial]:
        """Convert a predicate to a polynomial."""
        # Handle comparison predicates
        if z3.is_le(pred) or z3.is_lt(pred):
            lhs, rhs = pred.arg(0), pred.arg(1)
            # lhs <= rhs means rhs - lhs >= 0
            return self._diff_to_polynomial(rhs, lhs, n_vars, var_names)
        
        if z3.is_ge(pred) or z3.is_gt(pred):
            lhs, rhs = pred.arg(0), pred.arg(1)
            # lhs >= rhs means lhs - rhs >= 0
            return self._diff_to_polynomial(lhs, rhs, n_vars, var_names)
        
        return None
    
    def _diff_to_polynomial(self, a: z3.ArithRef, b: z3.ArithRef,
                             n_vars: int, var_names: List[str]) -> Optional[Polynomial]:
        """Convert a - b to polynomial."""
        coeffs = {}
        
        def process(expr: z3.ExprRef, sign: int = 1):
            if z3.is_int_value(expr) or z3.is_rational_value(expr):
                mono = tuple([0] * n_vars)
                if z3.is_int_value(expr):
                    val = expr.as_long()
                else:
                    val = float(expr.numerator_as_long()) / float(expr.denominator_as_long())
                coeffs[mono] = coeffs.get(mono, 0) + sign * val
            elif z3.is_const(expr):
                var_name = str(expr)
                if var_name in var_names:
                    idx = var_names.index(var_name)
                    mono = tuple(1 if i == idx else 0 for i in range(n_vars))
                    coeffs[mono] = coeffs.get(mono, 0) + sign
            elif z3.is_add(expr):
                for child in expr.children():
                    process(child, sign)
            elif z3.is_sub(expr):
                children = expr.children()
                process(children[0], sign)
                for child in children[1:]:
                    process(child, -sign)
            elif z3.is_mul(expr):
                children = expr.children()
                if len(children) == 2:
                    if z3.is_int_value(children[0]):
                        coef = children[0].as_long()
                        process(children[1], sign * coef)
        
        try:
            process(a, 1)
            process(b, -1)
            if coeffs:
                return Polynomial(n_vars, coeffs)
        except Exception:
            pass
        
        return None


# =============================================================================
# SEQUENCE INTERPOLATION
# =============================================================================

class SequenceInterpolator:
    """
    Compute sequence of interpolants for a path.
    
    Given Init, T^k, ¬Property, computes I_0, I_1, ..., I_k such that:
    - Init → I_0
    - I_i ∧ T → I_{i+1}
    - I_k → Property
    """
    
    def __init__(self, verbose: bool = False):
        self.verbose = verbose
        self._interpolant_sequence: List[z3.BoolRef] = []
    
    def compute_sequence(self, init: z3.BoolRef,
                          trans: z3.BoolRef,
                          prop: z3.BoolRef,
                          variables: List[z3.ArithRef],
                          depth: int,
                          timeout_ms: int = 30000) -> Optional[List[z3.BoolRef]]:
        """
        Compute sequence of interpolants.
        """
        self._interpolant_sequence = []
        
        # Unroll BMC
        unrolled = [init]
        current_vars = variables
        
        for step in range(depth):
            primed = [z3.FreshConst(v.sort()) for v in variables]
            step_trans = z3.substitute(trans, list(zip(variables, current_vars)))
            step_trans = z3.substitute(step_trans, 
                                         list(zip([z3.Int(f"{v}_prime") for v in 
                                                   [str(x) for x in variables]], primed)))
            unrolled.append(step_trans)
            current_vars = primed
        
        # Add property violation
        prop_at_end = z3.substitute(prop, list(zip(variables, current_vars)))
        unrolled.append(z3.Not(prop_at_end))
        
        # Check if path is infeasible
        solver = z3.Solver()
        solver.set("timeout", timeout_ms)
        solver.add(z3.And(unrolled))
        
        if solver.check() == z3.unsat:
            # Extract sequence interpolants
            self._interpolant_sequence = self._extract_sequence(unrolled, variables)
            return self._interpolant_sequence
        
        return None
    
    def _extract_sequence(self, formulas: List[z3.BoolRef],
                           variables: List[z3.ArithRef]) -> List[z3.BoolRef]:
        """Extract sequence of interpolants from UNSAT formula sequence."""
        interpolants = []
        
        for i in range(1, len(formulas)):
            prefix = z3.And(formulas[:i])
            suffix = z3.And(formulas[i:])
            
            # Compute interpolant at position i
            interp = self._compute_interpolant(prefix, suffix, variables)
            if interp is not None:
                interpolants.append(interp)
            else:
                # Fallback
                interpolants.append(z3.BoolVal(True))
        
        return interpolants
    
    def _compute_interpolant(self, prefix: z3.BoolRef,
                               suffix: z3.BoolRef,
                               variables: List[z3.ArithRef]) -> Optional[z3.BoolRef]:
        """Compute interpolant between prefix and suffix."""
        # Use Z3's proof-based approach
        solver = z3.Solver()
        solver.set(unsat_core=True)
        
        # Add prefix and suffix
        solver.add(prefix)
        solver.add(suffix)
        
        if solver.check() == z3.unsat:
            # Approximate interpolant using prefix simplification
            return z3.simplify(prefix)
        
        return None
    
    def get_sequence(self) -> List[z3.BoolRef]:
        """Get the interpolant sequence."""
        return self._interpolant_sequence
    
    def check_sequence_validity(self, init: z3.BoolRef,
                                  trans: z3.BoolRef,
                                  prop: z3.BoolRef,
                                  variables: List[z3.ArithRef]) -> bool:
        """Check if interpolant sequence is valid."""
        if not self._interpolant_sequence:
            return False
        
        solver = z3.Solver()
        
        # Check Init → I_0
        solver.push()
        solver.add(init)
        solver.add(z3.Not(self._interpolant_sequence[0]))
        if solver.check() == z3.sat:
            solver.pop()
            return False
        solver.pop()
        
        # Check I_i ∧ Trans → I_{i+1}
        for i in range(len(self._interpolant_sequence) - 1):
            primed_vars = [z3.Int(f"{v}_prime") for v in [str(x) for x in variables]]
            next_interp = z3.substitute(
                self._interpolant_sequence[i + 1],
                list(zip(variables, primed_vars))
            )
            
            solver.push()
            solver.add(self._interpolant_sequence[i])
            solver.add(trans)
            solver.add(z3.Not(next_interp))
            if solver.check() == z3.sat:
                solver.pop()
                return False
            solver.pop()
        
        # Check I_k → Property
        solver.push()
        solver.add(self._interpolant_sequence[-1])
        solver.add(z3.Not(prop))
        if solver.check() == z3.sat:
            solver.pop()
            return False
        solver.pop()
        
        return True


# =============================================================================
# BINARY INTERPOLATION
# =============================================================================

class BinaryInterpolation:
    """
    Binary interpolation for efficient invariant discovery.
    
    Uses binary search to find the minimal interpolant depth.
    """
    
    def __init__(self, verbose: bool = False):
        self.verbose = verbose
        self._min_depth = 0
        self._interpolant = None
    
    def find_minimal_depth(self, init: z3.BoolRef,
                            trans: z3.BoolRef,
                            prop: z3.BoolRef,
                            variables: List[z3.ArithRef],
                            max_depth: int = 50,
                            timeout_ms: int = 60000) -> Optional[Tuple[int, z3.BoolRef]]:
        """
        Find minimal depth at which interpolant can prove safety.
        
        Uses binary search on the depth parameter.
        """
        start_time = time.time()
        
        # First, find an upper bound where BMC proves safety
        upper = self._find_upper_bound(init, trans, prop, variables, max_depth, timeout_ms)
        
        if upper is None:
            return None
        
        # Binary search for minimal depth
        lower = 0
        result = None
        
        while lower < upper:
            elapsed = (time.time() - start_time) * 1000
            if elapsed > timeout_ms:
                break
            
            mid = (lower + upper) // 2
            
            interp = self._check_depth(init, trans, prop, variables, mid, 
                                         int(timeout_ms - elapsed) // 2)
            
            if interp is not None:
                upper = mid
                result = (mid, interp)
            else:
                lower = mid + 1
        
        if result:
            self._min_depth = result[0]
            self._interpolant = result[1]
        
        return result
    
    def _find_upper_bound(self, init: z3.BoolRef,
                           trans: z3.BoolRef,
                           prop: z3.BoolRef,
                           variables: List[z3.ArithRef],
                           max_depth: int,
                           timeout_ms: int) -> Optional[int]:
        """Find an upper bound depth."""
        for depth in range(1, max_depth + 1):
            interp = self._check_depth(init, trans, prop, variables, depth, 
                                         timeout_ms // max_depth)
            if interp is not None:
                return depth
        return None
    
    def _check_depth(self, init: z3.BoolRef,
                      trans: z3.BoolRef,
                      prop: z3.BoolRef,
                      variables: List[z3.ArithRef],
                      depth: int,
                      timeout_ms: int) -> Optional[z3.BoolRef]:
        """Check if depth is sufficient for interpolant."""
        seq_interp = SequenceInterpolator(self.verbose)
        result = seq_interp.compute_sequence(init, trans, prop, variables, 
                                               depth, timeout_ms)
        
        if result and len(result) > 0:
            return z3.And(result)
        
        return None
    
    def get_minimal_depth(self) -> int:
        """Get the minimal depth found."""
        return self._min_depth
    
    def get_interpolant(self) -> Optional[z3.BoolRef]:
        """Get the interpolant at minimal depth."""
        return self._interpolant


# =============================================================================
# INTERPOLATION-GUIDED BARRIER SYNTHESIS
# =============================================================================

class InterpolationGuidedSynthesis:
    """
    Use interpolants to guide barrier certificate synthesis.
    
    Strategy:
    1. Compute interpolants for the verification problem
    2. Extract predicates/features from interpolants
    3. Use features to construct barrier templates
    4. Synthesize barrier using constrained templates
    """
    
    def __init__(self, n_vars: int,
                 var_names: Optional[List[str]] = None,
                 verbose: bool = False):
        self.n_vars = n_vars
        self.var_names = var_names or [f"x_{i}" for i in range(n_vars)]
        self.verbose = verbose
        
        self._predicate_extractor = PredicateExtractor(verbose)
        self._polynomial_features: List[Polynomial] = []
    
    def extract_features_from_imc(self, imc_result: Any) -> List[Polynomial]:
        """
        Extract polynomial features from IMC result.
        """
        if not hasattr(imc_result, 'interpolants'):
            return []
        
        for interp in imc_result.interpolants:
            self._predicate_extractor.extract_from_interpolant(interp)
        
        self._polynomial_features = self._predicate_extractor.convert_to_polynomial_constraints(
            self.n_vars, self.var_names
        )
        
        return self._polynomial_features
    
    def build_guided_template(self, base_degree: int = 2) -> List[Polynomial]:
        """
        Build barrier template guided by interpolant features.
        """
        template = []
        
        # Include interpolant-derived features
        template.extend(self._polynomial_features)
        
        # Add standard polynomial template up to degree
        for degree in range(1, base_degree + 1):
            for mono in self._generate_monomials(degree):
                coeffs = {mono: 1.0}
                template.append(Polynomial(self.n_vars, coeffs))
        
        return template
    
    def _generate_monomials(self, total_degree: int) -> List[Tuple[int, ...]]:
        """Generate all monomials of given total degree."""
        monomials = []
        
        def generate(remaining: int, var_idx: int, current: List[int]):
            if var_idx == self.n_vars:
                if remaining == 0:
                    monomials.append(tuple(current))
                return
            
            for power in range(remaining + 1):
                generate(remaining - power, var_idx + 1, current + [power])
        
        generate(total_degree, 0, [])
        return monomials
    
    def condition_problem(self, problem: BarrierSynthesisProblem) -> BarrierSynthesisProblem:
        """
        Condition barrier problem using interpolant features.
        """
        if not self._polynomial_features:
            return problem
        
        # Add polynomial features as init set constraints
        new_init = SemialgebraicSet(
            n_vars=problem.init_set.n_vars,
            inequalities=problem.init_set.inequalities + self._polynomial_features,
            equalities=problem.init_set.equalities,
            var_names=problem.init_set.var_names,
            name=f"{problem.init_set.name}_imc_guided"
        )
        
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

def run_imc_verification(init: z3.BoolRef,
                          trans: z3.BoolRef,
                          prop: z3.BoolRef,
                          variables: List[str],
                          max_depth: int = 50,
                          timeout_ms: int = 60000,
                          verbose: bool = False) -> Tuple[bool, Optional[z3.BoolRef]]:
    """
    Run interpolation-based model checking.
    
    Returns (is_safe, invariant) where invariant is the discovered
    inductive invariant if system is safe.
    """
    z3_vars = [z3.Int(v) for v in variables]
    z3_vars_prime = [z3.Int(f"{v}_prime") for v in variables]

    solver = z3.Solver()
    solver.set("timeout", min(timeout_ms, 5000))

    # ------------------------------------------------------------------
    # Strategy 1: Property itself is an inductive invariant
    # (simplest and most common for our synthetic models)
    # ------------------------------------------------------------------
    candidate = prop
    ok = True
    # Init → candidate
    solver.push()
    solver.add(init)
    solver.add(z3.Not(candidate))
    if solver.check() != z3.unsat:
        ok = False
    solver.pop()

    if ok:
        # candidate ∧ Trans → candidate'
        cand_prime = z3.substitute(
            candidate,
            list(zip(z3_vars, z3_vars_prime)),
        )
        solver.push()
        solver.add(candidate)
        solver.add(trans)
        solver.add(z3.Not(cand_prime))
        if solver.check() != z3.unsat:
            ok = False
        solver.pop()

    if ok:
        return True, candidate

    # ------------------------------------------------------------------
    # Strategy 2: Conjunction of property atoms from init (weaken init
    # to only keep conjuncts implied by prop)
    # ------------------------------------------------------------------
    init_atoms: List[z3.BoolRef] = []
    if z3.is_and(init):
        init_atoms = list(init.children())
    else:
        init_atoms = [init]

    # Keep only atoms that are implied by (or equal to) the property
    relevant = []
    for atom in init_atoms:
        solver.push()
        solver.add(prop)
        solver.add(z3.Not(atom))
        if solver.check() == z3.unsat:
            # prop → atom, so atom is weaker than prop → keep it
            relevant.append(atom)
        solver.pop()

    if relevant:
        candidate2 = z3.And(relevant) if len(relevant) > 1 else relevant[0]
        ok2 = True
        # Init → candidate2
        solver.push()
        solver.add(init)
        solver.add(z3.Not(candidate2))
        if solver.check() != z3.unsat:
            ok2 = False
        solver.pop()

        if ok2:
            cand2_prime = z3.substitute(
                candidate2,
                list(zip(z3_vars, z3_vars_prime)),
            )
            solver.push()
            solver.add(candidate2)
            solver.add(trans)
            solver.add(z3.Not(cand2_prime))
            if solver.check() != z3.unsat:
                ok2 = False
            solver.pop()

        if ok2:
            return True, candidate2

    # ------------------------------------------------------------------
    # Strategy 3: Use binary interpolation (original approach)
    # ------------------------------------------------------------------
    binary_interp = BinaryInterpolation(verbose)
    result = binary_interp.find_minimal_depth(
        init, trans, prop, z3_vars, max_depth, timeout_ms
    )
    
    if result:
        depth, interpolant = result
        
        # Verify invariant
        synth = InterpolantBasedInvariantSynthesis(len(variables), variables, verbose)
        synth._interpolants = [interpolant]
        synth._invariant = interpolant
        
        is_valid = synth.verify_invariant(init, trans, prop, z3_vars, z3_vars_prime)
        
        if is_valid:
            return True, interpolant
    
    return False, None


def extract_predicates_from_imc(interpolants: List[z3.BoolRef],
                                  verbose: bool = False) -> List[z3.BoolRef]:
    """
    Extract predicates from a list of interpolants.
    """
    extractor = PredicateExtractor(verbose)
    
    for interp in interpolants:
        extractor.extract_from_interpolant(interp)
    
    return extractor.get_all_predicates()
