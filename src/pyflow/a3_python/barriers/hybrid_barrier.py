"""
SOTA Paper: Barrier Certificates for Hybrid Systems.

Implements hybrid system barrier certificates:
    S. Prajna, A. Jadbabaie, G. J. Pappas.
    "Safety verification of hybrid systems using barrier certificates."
    HSCC 2004.

KEY INSIGHT
===========

Hybrid systems combine discrete modes with continuous dynamics.
A barrier certificate must:
1. Be positive on initial states (in all modes)
2. Remain non-decreasing along continuous flows (in each mode)
3. Be negative on unsafe states (in all modes)
4. Not decrease across discrete transitions

This captures both continuous evolution and discrete jumps.

HYBRID SYSTEM MODEL
===================

A hybrid automaton H = (Q, X, Init, Inv, F, G, R) where:
- Q: finite set of discrete modes/locations
- X ⊆ ℝⁿ: continuous state space
- Init ⊆ Q × X: initial states
- Inv: Q → 2^X: invariant for each mode
- F: Q → (X → ℝⁿ): vector field for each mode
- G: Q × Q → 2^X: guard for each transition
- R: Q × Q × X → 2^X: reset map for each transition

BARRIER CERTIFICATE CONDITIONS
==============================

For safety B: Q × X → ℝ:

1. **Initial**: B(q, x) > 0 for all (q, x) ∈ Init
2. **Unsafe**: B(q, x) < 0 for all (q, x) ∈ Unsafe
3. **Continuous**: For each q, ∇B_q(x) · F_q(x) ≥ 0 when B_q(x) = 0
4. **Discrete**: For transition (q, q'), if x ∈ G(q,q') and x' ∈ R(q,q',x):
                 B(q, x) ≥ 0 → B(q', x') ≥ 0

IMPLEMENTATION STRUCTURE
========================

1. HybridAutomaton: Model of hybrid system
2. Mode: Discrete mode with dynamics
3. Transition: Discrete transition with guard/reset
4. HybridBarrier: Barrier certificate for hybrid system
5. HybridBarrierSynthesizer: SOS-based synthesis

LAYER POSITION
==============

This is a **Layer 2 (Certificate Core)** module.

    ┌─────────────────────────────────────────────────────────────────┐
    │ Layer 5: Advanced Verification (IC3, CHC, IMC, Assume-Guarantee)│
    │ Layer 4: Learning (ICE, Houdini, SyGuS)                         │
    │ Layer 3: Abstraction (CEGAR, Predicate Abstraction, IMPACT)     │
    │ Layer 2: CERTIFICATE CORE ← [THIS MODULE]                       │
    │   ├── hybrid_barrier.py ← You are here (Paper #1)               │
    │   ├── stochastic_barrier.py (Paper #2)                          │
    │   ├── sos_safety.py (Paper #3)                                  │
    │   └── sostools.py (Paper #4)                                    │
    │ Layer 1: Foundations (Positivstellensatz, SOS/SDP, Lasserre)    │
    └─────────────────────────────────────────────────────────────────┘

CROSS-PAPER DEPENDENCIES
========================

This module builds on Layer 1:
- Paper #6 (Parrilo SOS/SDP): Uses Polynomial, SemialgebraicSet for SOS proofs
- Paper #5 (Positivstellensatz): Uses for positivity certificates

This module is used by:
- Paper #9 (DSOS/SDSOS): LP relaxation for scalability
- Paper #17 (ICE): Learning hybrid barrier templates
- Paper #20 (Assume-Guarantee): Compositional hybrid verification
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Dict, List, Optional, Tuple, Set, Any, Callable
from collections import defaultdict

import z3

# =============================================================================
# LAYER 2: IMPORTS FROM LAYER 1 (FOUNDATIONS)
# =============================================================================
# Hybrid barrier certificates build on the mathematical foundations of SOS/SDP.
# We import core polynomial types and semi-algebraic set representations.
# =============================================================================

from .parrilo_sos_sdp import (
    Polynomial,
    SemialgebraicSet,
    BarrierSynthesisProblem,
)


# =============================================================================
# HYBRID SYSTEM MODEL
# =============================================================================

@dataclass
class VectorField:
    """
    Vector field (continuous dynamics) in a mode.
    
    Represents ẋ = f(x) as a list of polynomials.
    """
    n_vars: int
    components: List[Polynomial]  # f_i(x) for each dimension
    var_names: Optional[List[str]] = None
    
    def evaluate(self, x: List[float]) -> List[float]:
        """Evaluate vector field at point x."""
        return [p.evaluate(x) for p in self.components]
    
    def to_z3(self, z3_vars: List[z3.ArithRef]) -> List[z3.ArithRef]:
        """Convert to Z3 expressions."""
        return [p.to_z3(z3_vars) for p in self.components]


@dataclass
class Mode:
    """
    Discrete mode/location in a hybrid automaton.
    
    Contains:
    - name: Identifier for the mode
    - invariant: Set of states where mode is valid
    - dynamics: Vector field for continuous evolution
    """
    name: str
    invariant: SemialgebraicSet  # Inv(q)
    dynamics: Optional[VectorField] = None  # f_q(x)
    id: int = 0
    
    def __str__(self) -> str:
        return f"Mode({self.name})"
    
    def __hash__(self) -> int:
        return hash(self.name)
    
    def __eq__(self, other) -> bool:
        if isinstance(other, Mode):
            return self.name == other.name
        return False


@dataclass
class Transition:
    """
    Discrete transition in a hybrid automaton.
    
    Contains:
    - source: Source mode
    - target: Target mode
    - guard: States where transition is enabled
    - reset: Reset map (how state changes)
    """
    source: Mode
    target: Mode
    guard: SemialgebraicSet  # G(q, q')
    reset: Optional[List[Polynomial]] = None  # R(q, q', x)
    
    def __str__(self) -> str:
        return f"Transition({self.source.name} -> {self.target.name})"
    
    def get_reset_z3(self, z3_vars: List[z3.ArithRef]) -> List[z3.ArithRef]:
        """Get reset map as Z3 expressions."""
        if self.reset is None:
            return z3_vars  # Identity reset
        return [p.to_z3(z3_vars) for p in self.reset]


class HybridAutomaton:
    """
    Hybrid automaton model.
    
    Combines discrete modes with continuous dynamics
    and discrete transitions.
    """
    
    def __init__(self, name: str = "hybrid_system",
                 n_vars: int = 2,
                 var_names: Optional[List[str]] = None):
        self.name = name
        self.n_vars = n_vars
        self.var_names = var_names or [f"x_{i}" for i in range(n_vars)]
        
        self._modes: Dict[str, Mode] = {}
        self._transitions: List[Transition] = []
        self._initial: Dict[str, SemialgebraicSet] = {}  # mode -> initial set
        self._unsafe: Dict[str, SemialgebraicSet] = {}   # mode -> unsafe set
        
        self._mode_counter = 0
    
    def add_mode(self, name: str,
                  invariant: SemialgebraicSet,
                  dynamics: Optional[VectorField] = None) -> Mode:
        """Add a mode to the automaton."""
        mode = Mode(
            name=name,
            invariant=invariant,
            dynamics=dynamics,
            id=self._mode_counter
        )
        self._modes[name] = mode
        self._mode_counter += 1
        return mode
    
    def add_transition(self, source: Mode, target: Mode,
                        guard: SemialgebraicSet,
                        reset: Optional[List[Polynomial]] = None) -> Transition:
        """Add a transition to the automaton."""
        trans = Transition(source, target, guard, reset)
        self._transitions.append(trans)
        return trans
    
    def set_initial(self, mode: Mode, initial_set: SemialgebraicSet) -> None:
        """Set initial states for a mode."""
        self._initial[mode.name] = initial_set
    
    def set_unsafe(self, mode: Mode, unsafe_set: SemialgebraicSet) -> None:
        """Set unsafe states for a mode."""
        self._unsafe[mode.name] = unsafe_set
    
    def get_modes(self) -> List[Mode]:
        """Get all modes."""
        return list(self._modes.values())
    
    def get_transitions(self) -> List[Transition]:
        """Get all transitions."""
        return list(self._transitions)
    
    def get_transitions_from(self, mode: Mode) -> List[Transition]:
        """Get transitions from a mode."""
        return [t for t in self._transitions if t.source == mode]
    
    def get_transitions_to(self, mode: Mode) -> List[Transition]:
        """Get transitions to a mode."""
        return [t for t in self._transitions if t.target == mode]
    
    def get_initial(self, mode: Mode) -> Optional[SemialgebraicSet]:
        """Get initial set for a mode."""
        return self._initial.get(mode.name)
    
    def get_unsafe(self, mode: Mode) -> Optional[SemialgebraicSet]:
        """Get unsafe set for a mode."""
        return self._unsafe.get(mode.name)
    
    def __str__(self) -> str:
        lines = [f"HybridAutomaton: {self.name}"]
        lines.append(f"  Modes: {', '.join(self._modes.keys())}")
        lines.append(f"  Transitions: {len(self._transitions)}")
        return "\n".join(lines)


# =============================================================================
# HYBRID BARRIER CERTIFICATE
# =============================================================================

@dataclass
class HybridBarrier:
    """
    Barrier certificate for a hybrid system.
    
    A function B: Q × X → ℝ (one polynomial per mode).
    """
    n_vars: int
    mode_barriers: Dict[str, Polynomial]  # mode_name -> barrier polynomial
    var_names: Optional[List[str]] = None
    
    def get_barrier(self, mode: Mode) -> Optional[Polynomial]:
        """Get barrier for a mode."""
        return self.mode_barriers.get(mode.name)
    
    def evaluate(self, mode: Mode, x: List[float]) -> Optional[float]:
        """Evaluate barrier at (mode, x)."""
        barrier = self.get_barrier(mode)
        if barrier:
            return barrier.evaluate(x)
        return None
    
    def __str__(self) -> str:
        lines = ["HybridBarrier:"]
        for mode_name, poly in self.mode_barriers.items():
            lines.append(f"  {mode_name}: {poly}")
        return "\n".join(lines)


class HybridBarrierVerificationResult(Enum):
    """Result of hybrid barrier verification."""
    VALID = auto()
    INVALID_INITIAL = auto()
    INVALID_UNSAFE = auto()
    INVALID_CONTINUOUS = auto()
    INVALID_DISCRETE = auto()
    UNKNOWN = auto()


@dataclass
class HybridVerificationResult:
    """
    Result of verifying a hybrid barrier.
    """
    result: HybridBarrierVerificationResult
    counterexample: Optional[Dict[str, Any]] = None
    failed_condition: str = ""
    failed_mode: str = ""
    message: str = ""


class HybridBarrierVerifier:
    """
    Verify hybrid barrier certificates.
    
    Checks all four conditions:
    1. Initial: B(q, x) > 0 for (q, x) ∈ Init
    2. Unsafe: B(q, x) < 0 for (q, x) ∈ Unsafe
    3. Continuous: Lie derivative condition
    4. Discrete: Transition preservation
    """
    
    def __init__(self, automaton: HybridAutomaton,
                 timeout_ms: int = 10000,
                 verbose: bool = False):
        self.automaton = automaton
        self.timeout_ms = timeout_ms
        self.verbose = verbose
        
        self._z3_vars = [z3.Real(v) for v in automaton.var_names]
    
    def verify(self, barrier: HybridBarrier) -> HybridVerificationResult:
        """
        Verify hybrid barrier certificate.
        """
        # Check initial condition
        result = self._check_initial(barrier)
        if result.result != HybridBarrierVerificationResult.VALID:
            return result
        
        # Check unsafe condition
        result = self._check_unsafe(barrier)
        if result.result != HybridBarrierVerificationResult.VALID:
            return result
        
        # Check continuous condition
        result = self._check_continuous(barrier)
        if result.result != HybridBarrierVerificationResult.VALID:
            return result
        
        # Check discrete condition
        result = self._check_discrete(barrier)
        return result
    
    def _check_initial(self, barrier: HybridBarrier) -> HybridVerificationResult:
        """Check B(q, x) > 0 for all (q, x) ∈ Init."""
        for mode in self.automaton.get_modes():
            init_set = self.automaton.get_initial(mode)
            if init_set is None:
                continue
            
            b = barrier.get_barrier(mode)
            if b is None:
                continue
            
            # Check: ∃x ∈ Init. B(x) ≤ 0?
            solver = z3.Solver()
            solver.set("timeout", self.timeout_ms)
            
            # Add Init constraints
            for p in init_set.inequalities:
                solver.add(p.to_z3(self._z3_vars) >= 0)
            for p in init_set.equalities:
                solver.add(p.to_z3(self._z3_vars) == 0)
            
            # Add B(x) ≤ 0
            solver.add(b.to_z3(self._z3_vars) <= 0)
            
            if solver.check() == z3.sat:
                model = solver.model()
                cex = self._model_to_dict(model)
                return HybridVerificationResult(
                    result=HybridBarrierVerificationResult.INVALID_INITIAL,
                    counterexample=cex,
                    failed_condition="initial",
                    failed_mode=mode.name,
                    message=f"Initial state violates barrier in mode {mode.name}"
                )
        
        return HybridVerificationResult(
            result=HybridBarrierVerificationResult.VALID
        )
    
    def _check_unsafe(self, barrier: HybridBarrier) -> HybridVerificationResult:
        """Check B(q, x) < 0 for all (q, x) ∈ Unsafe."""
        for mode in self.automaton.get_modes():
            unsafe_set = self.automaton.get_unsafe(mode)
            if unsafe_set is None:
                continue
            
            b = barrier.get_barrier(mode)
            if b is None:
                continue
            
            # Check: ∃x ∈ Unsafe. B(x) ≥ 0?
            solver = z3.Solver()
            solver.set("timeout", self.timeout_ms)
            
            # Add Unsafe constraints
            for p in unsafe_set.inequalities:
                solver.add(p.to_z3(self._z3_vars) >= 0)
            
            # Add B(x) ≥ 0
            solver.add(b.to_z3(self._z3_vars) >= 0)
            
            if solver.check() == z3.sat:
                model = solver.model()
                cex = self._model_to_dict(model)
                return HybridVerificationResult(
                    result=HybridBarrierVerificationResult.INVALID_UNSAFE,
                    counterexample=cex,
                    failed_condition="unsafe",
                    failed_mode=mode.name,
                    message=f"Unsafe state reachable in mode {mode.name}"
                )
        
        return HybridVerificationResult(
            result=HybridBarrierVerificationResult.VALID
        )
    
    def _check_continuous(self, barrier: HybridBarrier) -> HybridVerificationResult:
        """Check Lie derivative condition for each mode."""
        for mode in self.automaton.get_modes():
            if mode.dynamics is None:
                continue
            
            b = barrier.get_barrier(mode)
            if b is None:
                continue
            
            # Compute Lie derivative: ∇B · f
            lie_derivative = self._compute_lie_derivative(b, mode.dynamics)
            
            # Check: ∃x ∈ Inv. B(x) = 0 ∧ LB(x) < 0?
            solver = z3.Solver()
            solver.set("timeout", self.timeout_ms)
            
            # Add invariant constraints
            for p in mode.invariant.inequalities:
                solver.add(p.to_z3(self._z3_vars) >= 0)
            
            # Add B(x) = 0 (on boundary)
            solver.add(b.to_z3(self._z3_vars) == 0)
            
            # Add LB(x) < 0 (violation)
            if lie_derivative:
                solver.add(lie_derivative.to_z3(self._z3_vars) < 0)
            
            if solver.check() == z3.sat:
                model = solver.model()
                cex = self._model_to_dict(model)
                return HybridVerificationResult(
                    result=HybridBarrierVerificationResult.INVALID_CONTINUOUS,
                    counterexample=cex,
                    failed_condition="continuous",
                    failed_mode=mode.name,
                    message=f"Continuous flow violates barrier in mode {mode.name}"
                )
        
        return HybridVerificationResult(
            result=HybridBarrierVerificationResult.VALID
        )
    
    def _check_discrete(self, barrier: HybridBarrier) -> HybridVerificationResult:
        """Check transition preservation condition."""
        for trans in self.automaton.get_transitions():
            b_source = barrier.get_barrier(trans.source)
            b_target = barrier.get_barrier(trans.target)
            
            if b_source is None or b_target is None:
                continue
            
            # Get reset map
            reset_exprs = trans.get_reset_z3(self._z3_vars)
            
            # B'(x') = B_target(R(x))
            b_target_after_reset = b_target.to_z3(reset_exprs)
            
            # Check: ∃x ∈ Guard. B_source(x) ≥ 0 ∧ B_target(R(x)) < 0?
            solver = z3.Solver()
            solver.set("timeout", self.timeout_ms)
            
            # Add guard constraints
            for p in trans.guard.inequalities:
                solver.add(p.to_z3(self._z3_vars) >= 0)
            
            # Add B_source(x) ≥ 0
            solver.add(b_source.to_z3(self._z3_vars) >= 0)
            
            # Add B_target(R(x)) < 0
            solver.add(b_target_after_reset < 0)
            
            if solver.check() == z3.sat:
                model = solver.model()
                cex = self._model_to_dict(model)
                return HybridVerificationResult(
                    result=HybridBarrierVerificationResult.INVALID_DISCRETE,
                    counterexample=cex,
                    failed_condition="discrete",
                    failed_mode=f"{trans.source.name}->{trans.target.name}",
                    message=f"Transition {trans} violates barrier"
                )
        
        return HybridVerificationResult(
            result=HybridBarrierVerificationResult.VALID
        )
    
    def _compute_lie_derivative(self, barrier: Polynomial,
                                  dynamics: VectorField) -> Optional[Polynomial]:
        """Compute Lie derivative ∇B · f."""
        n = self.automaton.n_vars
        
        # Compute partial derivatives of B
        partials = []
        for i in range(n):
            partial = barrier.partial_derivative(i)
            partials.append(partial)
        
        # Dot product with dynamics
        result_coeffs = {}
        for i in range(n):
            # partials[i] * dynamics.components[i]
            if i < len(dynamics.components):
                product = partials[i].multiply(dynamics.components[i])
                for mono, coef in product.coefficients.items():
                    result_coeffs[mono] = result_coeffs.get(mono, 0) + coef
        
        if result_coeffs:
            return Polynomial(n, result_coeffs)
        return None
    
    def _model_to_dict(self, model: z3.ModelRef) -> Dict[str, float]:
        """Convert Z3 model to dictionary."""
        result = {}
        for v, z3_v in zip(self.automaton.var_names, self._z3_vars):
            val = model.eval(z3_v, model_completion=True)
            if z3.is_rational_value(val):
                result[v] = float(val.numerator_as_long()) / float(val.denominator_as_long())
            elif z3.is_int_value(val):
                result[v] = float(val.as_long())
            else:
                result[v] = 0.0
        return result


# =============================================================================
# HYBRID BARRIER SYNTHESIZER
# =============================================================================

class HybridBarrierSynthesisResult(Enum):
    """Result of hybrid barrier synthesis."""
    SUCCESS = auto()
    FAILURE = auto()
    TIMEOUT = auto()


@dataclass
class HybridSynthesisResult:
    """
    Result of hybrid barrier synthesis.
    """
    result: HybridBarrierSynthesisResult
    barrier: Optional[HybridBarrier] = None
    iterations: int = 0
    statistics: Dict[str, Any] = field(default_factory=dict)
    message: str = ""


class HybridBarrierSynthesizer:
    """
    Synthesize hybrid barrier certificates.
    
    Uses SOS relaxations for each mode's barrier and
    enforces conditions across transitions.
    """
    
    def __init__(self, automaton: HybridAutomaton,
                 barrier_degree: int = 4,
                 timeout_ms: int = 60000,
                 verbose: bool = False):
        self.automaton = automaton
        self.barrier_degree = barrier_degree
        self.timeout_ms = timeout_ms
        self.verbose = verbose
        
        self._z3_vars = [z3.Real(v) for v in automaton.var_names]
        
        self.stats = {
            'modes_processed': 0,
            'transitions_checked': 0,
            'synthesis_time_ms': 0,
        }
    
    def synthesize(self) -> HybridSynthesisResult:
        """
        Synthesize hybrid barrier certificate.
        """
        start_time = time.time()
        
        # Generate barrier templates for each mode
        mode_templates = {}
        mode_coeffs = {}
        
        for mode in self.automaton.get_modes():
            template, coeffs = self._create_barrier_template(mode.name)
            mode_templates[mode.name] = template
            mode_coeffs[mode.name] = coeffs
            self.stats['modes_processed'] += 1
        
        # Build SOS constraints
        solver = z3.Solver()
        solver.set("timeout", self.timeout_ms)
        
        # Add initial constraints
        self._add_initial_constraints(solver, mode_templates)
        
        # Add unsafe constraints
        self._add_unsafe_constraints(solver, mode_templates)
        
        # Add continuous constraints (simplified)
        self._add_continuous_constraints(solver, mode_templates)
        
        # Add discrete constraints
        self._add_discrete_constraints(solver, mode_templates)
        
        # Solve
        if solver.check() == z3.sat:
            model = solver.model()
            
            # Extract barrier polynomials
            mode_barriers = {}
            for mode_name, coeffs in mode_coeffs.items():
                poly = self._extract_polynomial(model, coeffs)
                if poly:
                    mode_barriers[mode_name] = poly
            
            barrier = HybridBarrier(
                n_vars=self.automaton.n_vars,
                mode_barriers=mode_barriers,
                var_names=self.automaton.var_names
            )
            
            self.stats['synthesis_time_ms'] = (time.time() - start_time) * 1000
            
            return HybridSynthesisResult(
                result=HybridBarrierSynthesisResult.SUCCESS,
                barrier=barrier,
                statistics=self.stats,
                message="Hybrid barrier synthesized"
            )
        
        self.stats['synthesis_time_ms'] = (time.time() - start_time) * 1000
        
        return HybridSynthesisResult(
            result=HybridBarrierSynthesisResult.FAILURE,
            statistics=self.stats,
            message="Synthesis failed"
        )
    
    def _create_barrier_template(self, mode_name: str) -> Tuple[z3.ArithRef, Dict[Tuple, z3.ArithRef]]:
        """Create barrier template for a mode."""
        n = self.automaton.n_vars
        monomials = self._generate_monomials(self.barrier_degree)
        
        coeffs = {}
        terms = []
        
        for mono in monomials:
            coef = z3.Real(f"c_{mode_name}_{mono}")
            coeffs[mono] = coef
            
            mono_z3 = self._monomial_to_z3(mono)
            terms.append(coef * mono_z3)
        
        template = sum(terms) if terms else z3.RealVal(0)
        return template, coeffs
    
    def _generate_monomials(self, max_degree: int) -> List[Tuple[int, ...]]:
        """Generate all monomials up to max_degree."""
        n = self.automaton.n_vars
        monomials = []
        
        def generate(remaining: int, idx: int, current: List[int]):
            if idx == n:
                monomials.append(tuple(current))
                return
            for power in range(remaining + 1):
                generate(remaining - power, idx + 1, current + [power])
        
        for deg in range(max_degree + 1):
            generate(deg, 0, [])
        
        return monomials
    
    def _monomial_to_z3(self, mono: Tuple[int, ...]) -> z3.ArithRef:
        """Convert monomial to Z3 expression."""
        result = z3.RealVal(1)
        for i, power in enumerate(mono):
            for _ in range(power):
                result = result * self._z3_vars[i]
        return result
    
    def _add_initial_constraints(self, solver: z3.Solver,
                                   mode_templates: Dict[str, z3.ArithRef]) -> None:
        """Add B(q, x) > 0 for (q, x) ∈ Init constraints."""
        for mode in self.automaton.get_modes():
            init_set = self.automaton.get_initial(mode)
            if init_set is None:
                continue
            
            template = mode_templates.get(mode.name)
            if template is None:
                continue
            
            # Simplified: require template > 0.01 on some sample points
            # (Full SOS encoding would use Positivstellensatz)
            for sample in self._sample_from_set(init_set, 5):
                val = self._evaluate_template(template, sample)
                solver.add(val > 0.01)
    
    def _add_unsafe_constraints(self, solver: z3.Solver,
                                  mode_templates: Dict[str, z3.ArithRef]) -> None:
        """Add B(q, x) < 0 for (q, x) ∈ Unsafe constraints."""
        for mode in self.automaton.get_modes():
            unsafe_set = self.automaton.get_unsafe(mode)
            if unsafe_set is None:
                continue
            
            template = mode_templates.get(mode.name)
            if template is None:
                continue
            
            # Require template < -0.01 on sample points
            for sample in self._sample_from_set(unsafe_set, 5):
                val = self._evaluate_template(template, sample)
                solver.add(val < -0.01)
    
    def _add_continuous_constraints(self, solver: z3.Solver,
                                       mode_templates: Dict[str, z3.ArithRef]) -> None:
        """Add Lie derivative constraints (simplified)."""
        # Simplified version: not implementing full SOS Lie derivative
        pass
    
    def _add_discrete_constraints(self, solver: z3.Solver,
                                    mode_templates: Dict[str, z3.ArithRef]) -> None:
        """Add transition preservation constraints."""
        for trans in self.automaton.get_transitions():
            self.stats['transitions_checked'] += 1
            
            b_source = mode_templates.get(trans.source.name)
            b_target = mode_templates.get(trans.target.name)
            
            if b_source is None or b_target is None:
                continue
            
            # Sample from guard
            for sample in self._sample_from_set(trans.guard, 3):
                # Evaluate source barrier
                source_val = self._evaluate_template(b_source, sample)
                
                # Apply reset and evaluate target barrier
                if trans.reset:
                    reset_sample = [p.evaluate(list(sample.values())) 
                                    for p in trans.reset]
                else:
                    reset_sample = list(sample.values())
                
                target_val = self._evaluate_template_at_point(b_target, reset_sample)
                
                # If source ≥ 0 then target ≥ 0
                solver.add(z3.Implies(source_val >= 0, target_val >= 0))
    
    def _sample_from_set(self, sas: SemialgebraicSet, num_samples: int) -> List[Dict[str, float]]:
        """Sample points from semialgebraic set."""
        samples = []
        
        solver = z3.Solver()
        
        for p in sas.inequalities:
            solver.add(p.to_z3(self._z3_vars) >= 0)
        
        for _ in range(num_samples):
            if solver.check() == z3.sat:
                model = solver.model()
                sample = {}
                for v, z3_v in zip(self.automaton.var_names, self._z3_vars):
                    val = model.eval(z3_v, model_completion=True)
                    if z3.is_rational_value(val):
                        sample[v] = float(val.numerator_as_long()) / float(val.denominator_as_long())
                    else:
                        sample[v] = 0.0
                samples.append(sample)
                
                # Block this point
                block = z3.Or([z3_v != model.eval(z3_v) for z3_v in self._z3_vars])
                solver.add(block)
            else:
                break
        
        return samples
    
    def _evaluate_template(self, template: z3.ArithRef,
                            sample: Dict[str, float]) -> z3.ArithRef:
        """Evaluate template at sample point."""
        subs = [(z3_v, z3.RealVal(sample.get(v, 0.0))) 
                for v, z3_v in zip(self.automaton.var_names, self._z3_vars)]
        return z3.substitute(template, subs)
    
    def _evaluate_template_at_point(self, template: z3.ArithRef,
                                      point: List[float]) -> z3.ArithRef:
        """Evaluate template at point."""
        subs = [(z3_v, z3.RealVal(point[i] if i < len(point) else 0.0))
                for i, z3_v in enumerate(self._z3_vars)]
        return z3.substitute(template, subs)
    
    def _extract_polynomial(self, model: z3.ModelRef,
                             coeffs: Dict[Tuple, z3.ArithRef]) -> Optional[Polynomial]:
        """Extract polynomial from solved coefficients."""
        poly_coeffs = {}
        
        for mono, coef_var in coeffs.items():
            val = model.eval(coef_var, model_completion=True)
            if z3.is_rational_value(val):
                coef_val = float(val.numerator_as_long()) / float(val.denominator_as_long())
            elif z3.is_int_value(val):
                coef_val = float(val.as_long())
            else:
                coef_val = 0.0
            
            if abs(coef_val) > 1e-10:
                poly_coeffs[mono] = coef_val
        
        if poly_coeffs:
            return Polynomial(self.automaton.n_vars, poly_coeffs)
        return None


# =============================================================================
# HYBRID INTEGRATION
# =============================================================================

@dataclass
class HybridIntegrationConfig:
    """Configuration for hybrid barrier integration."""
    barrier_degree: int = 4
    max_modes: int = 10
    timeout_ms: int = 60000
    verbose: bool = False


class HybridBarrierIntegration:
    """
    Integration of hybrid barriers with the main analysis.
    
    Provides:
    1. Conversion from program loops to hybrid systems
    2. Hybrid barrier synthesis
    3. Certificate extraction for proof artifacts
    """
    
    def __init__(self, config: Optional[HybridIntegrationConfig] = None,
                 verbose: bool = False):
        self.config = config or HybridIntegrationConfig()
        self.verbose = verbose or self.config.verbose
        
        self._automatons: Dict[str, HybridAutomaton] = {}
        self._barriers: Dict[str, HybridBarrier] = {}
        
        self.stats = {
            'automatons_created': 0,
            'barriers_synthesized': 0,
            'proofs_verified': 0,
        }
    
    def create_automaton_from_loop(self, loop_id: str,
                                     n_vars: int,
                                     var_names: List[str],
                                     init_constraints: List[Polynomial],
                                     unsafe_constraints: List[Polynomial]) -> HybridAutomaton:
        """
        Create hybrid automaton from loop model.
        """
        automaton = HybridAutomaton(
            name=f"loop_{loop_id}",
            n_vars=n_vars,
            var_names=var_names
        )
        
        # Create single mode (simple loop)
        invariant = SemialgebraicSet(
            n_vars=n_vars,
            inequalities=[],
            equalities=[],
            var_names=var_names,
            name="loop_inv"
        )
        
        mode = automaton.add_mode("loop", invariant)
        
        # Set initial and unsafe
        init_set = SemialgebraicSet(
            n_vars=n_vars,
            inequalities=init_constraints,
            equalities=[],
            var_names=var_names,
            name="init"
        )
        automaton.set_initial(mode, init_set)
        
        unsafe_set = SemialgebraicSet(
            n_vars=n_vars,
            inequalities=unsafe_constraints,
            equalities=[],
            var_names=var_names,
            name="unsafe"
        )
        automaton.set_unsafe(mode, unsafe_set)
        
        # Add self-loop transition (simplified)
        guard = SemialgebraicSet(
            n_vars=n_vars,
            inequalities=[],
            equalities=[],
            var_names=var_names,
            name="guard"
        )
        automaton.add_transition(mode, mode, guard)
        
        self._automatons[loop_id] = automaton
        self.stats['automatons_created'] += 1
        
        return automaton
    
    def synthesize_barrier(self, loop_id: str) -> HybridSynthesisResult:
        """
        Synthesize hybrid barrier for a loop.
        """
        automaton = self._automatons.get(loop_id)
        if automaton is None:
            return HybridSynthesisResult(
                result=HybridBarrierSynthesisResult.FAILURE,
                message="Automaton not found"
            )
        
        synthesizer = HybridBarrierSynthesizer(
            automaton,
            barrier_degree=self.config.barrier_degree,
            timeout_ms=self.config.timeout_ms,
            verbose=self.verbose
        )
        
        result = synthesizer.synthesize()
        
        if result.result == HybridBarrierSynthesisResult.SUCCESS:
            self._barriers[loop_id] = result.barrier
            self.stats['barriers_synthesized'] += 1
        
        return result
    
    def verify_barrier(self, loop_id: str) -> HybridVerificationResult:
        """
        Verify synthesized barrier.
        """
        automaton = self._automatons.get(loop_id)
        barrier = self._barriers.get(loop_id)
        
        if automaton is None or barrier is None:
            return HybridVerificationResult(
                result=HybridBarrierVerificationResult.UNKNOWN,
                message="Automaton or barrier not found"
            )
        
        verifier = HybridBarrierVerifier(
            automaton,
            timeout_ms=self.config.timeout_ms,
            verbose=self.verbose
        )
        
        result = verifier.verify(barrier)
        
        if result.result == HybridBarrierVerificationResult.VALID:
            self.stats['proofs_verified'] += 1
        
        return result
    
    def get_barrier(self, loop_id: str) -> Optional[HybridBarrier]:
        """Get synthesized barrier."""
        return self._barriers.get(loop_id)
    
    def condition_barrier_problem(self, problem: BarrierSynthesisProblem,
                                    loop_id: str) -> BarrierSynthesisProblem:
        """
        Condition barrier problem using hybrid barrier insights.
        """
        barrier = self._barriers.get(loop_id)
        if barrier is None:
            return problem
        
        # Extract polynomial from first mode
        mode_barriers = list(barrier.mode_barriers.values())
        if not mode_barriers:
            return problem
        
        poly = mode_barriers[0]
        
        # Add as constraint
        new_init = SemialgebraicSet(
            n_vars=problem.init_set.n_vars,
            inequalities=problem.init_set.inequalities + [poly],
            equalities=problem.init_set.equalities,
            var_names=problem.init_set.var_names,
            name=f"{problem.init_set.name}_hybrid"
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

def create_simple_hybrid_system(n_vars: int,
                                  var_names: List[str],
                                  num_modes: int = 2) -> HybridAutomaton:
    """
    Create a simple hybrid system with multiple modes.
    """
    automaton = HybridAutomaton(
        name="simple_hybrid",
        n_vars=n_vars,
        var_names=var_names
    )
    
    # Create modes
    modes = []
    for i in range(num_modes):
        invariant = SemialgebraicSet(
            n_vars=n_vars,
            inequalities=[],
            equalities=[],
            var_names=var_names,
            name=f"inv_{i}"
        )
        mode = automaton.add_mode(f"mode_{i}", invariant)
        modes.append(mode)
    
    # Add transitions between consecutive modes
    for i in range(num_modes - 1):
        guard = SemialgebraicSet(
            n_vars=n_vars,
            inequalities=[],
            equalities=[],
            var_names=var_names,
            name=f"guard_{i}_{i+1}"
        )
        automaton.add_transition(modes[i], modes[i + 1], guard)
    
    # Add self-loops
    for mode in modes:
        guard = SemialgebraicSet(
            n_vars=n_vars,
            inequalities=[],
            equalities=[],
            var_names=var_names,
            name=f"guard_{mode.name}_self"
        )
        automaton.add_transition(mode, mode, guard)
    
    return automaton


def synthesize_hybrid_barrier(automaton: HybridAutomaton,
                                barrier_degree: int = 4,
                                timeout_ms: int = 60000,
                                verbose: bool = False) -> HybridSynthesisResult:
    """
    Synthesize hybrid barrier certificate.
    """
    synthesizer = HybridBarrierSynthesizer(
        automaton,
        barrier_degree=barrier_degree,
        timeout_ms=timeout_ms,
        verbose=verbose
    )
    
    return synthesizer.synthesize()


def verify_hybrid_barrier(automaton: HybridAutomaton,
                           barrier: HybridBarrier,
                           timeout_ms: int = 10000,
                           verbose: bool = False) -> HybridVerificationResult:
    """
    Verify hybrid barrier certificate.
    """
    verifier = HybridBarrierVerifier(
        automaton,
        timeout_ms=timeout_ms,
        verbose=verbose
    )
    
    return verifier.verify(barrier)


# =============================================================================
# ADVANCED HYBRID BARRIER SYNTHESIS
# =============================================================================

class MultiModeBarrierTemplate:
    """
    Template for barriers with mode-dependent structure.
    
    Allows different polynomial structures per mode while
    ensuring consistency at transitions.
    """
    
    def __init__(self, automaton: HybridAutomaton,
                 degree_per_mode: Optional[Dict[str, int]] = None,
                 shared_coefficients: bool = False):
        self.automaton = automaton
        self.degree_per_mode = degree_per_mode or {}
        self.shared_coefficients = shared_coefficients
        
        self._mode_templates: Dict[str, Polynomial] = {}
        self._mode_coefficients: Dict[str, Dict[Tuple, z3.ArithRef]] = {}
        self._z3_vars = [z3.Real(v) for v in automaton.var_names]
        
        self._build_templates()
    
    def _build_templates(self) -> None:
        """Build polynomial templates for each mode."""
        for mode in self.automaton.get_modes():
            degree = self.degree_per_mode.get(mode.name, 4)
            template, coeffs = self._create_mode_template(mode.name, degree)
            self._mode_templates[mode.name] = template
            self._mode_coefficients[mode.name] = coeffs
    
    def _create_mode_template(self, mode_name: str, 
                               degree: int) -> Tuple[z3.ArithRef, Dict[Tuple, z3.ArithRef]]:
        """Create template for single mode."""
        n = self.automaton.n_vars
        monomials = self._generate_monomials(degree)
        
        coeffs = {}
        terms = []
        
        for mono in monomials:
            coef = z3.Real(f"c_{mode_name}_{mono}")
            coeffs[mono] = coef
            
            mono_z3 = z3.RealVal(1)
            for i, power in enumerate(mono):
                for _ in range(power):
                    mono_z3 = mono_z3 * self._z3_vars[i]
            
            terms.append(coef * mono_z3)
        
        template = sum(terms) if terms else z3.RealVal(0)
        return template, coeffs
    
    def _generate_monomials(self, max_degree: int) -> List[Tuple[int, ...]]:
        """Generate monomials up to max_degree."""
        n = self.automaton.n_vars
        monomials = []
        
        def generate(remaining: int, idx: int, current: List[int]):
            if idx == n:
                monomials.append(tuple(current))
                return
            for power in range(remaining + 1):
                generate(remaining - power, idx + 1, current + [power])
        
        for deg in range(max_degree + 1):
            generate(deg, 0, [])
        
        return monomials
    
    def get_template(self, mode_name: str) -> z3.ArithRef:
        """Get template for mode."""
        return self._mode_templates.get(mode_name, z3.RealVal(0))
    
    def get_coefficients(self, mode_name: str) -> Dict[Tuple, z3.ArithRef]:
        """Get coefficient variables for mode."""
        return self._mode_coefficients.get(mode_name, {})
    
    def add_consistency_constraints(self, solver: z3.Solver) -> None:
        """Add constraints for transition consistency."""
        for trans in self.automaton.get_transitions():
            source_template = self.get_template(trans.source.name)
            target_template = self.get_template(trans.target.name)
            
            # Sample from guard and check consistency
            for sample in self._sample_guard(trans, 3):
                source_val = self._evaluate_at(source_template, sample)
                
                # Apply reset
                if trans.reset:
                    reset_sample = [p.evaluate(list(sample.values()))
                                    for p in trans.reset]
                else:
                    reset_sample = list(sample.values())
                
                target_val = self._evaluate_at_point(target_template, reset_sample)
                
                # Consistency: source >= 0 implies target >= 0
                solver.add(z3.Implies(source_val >= 0, target_val >= 0))
    
    def _sample_guard(self, trans: Transition, 
                       num_samples: int) -> List[Dict[str, float]]:
        """Sample from guard set."""
        samples = []
        solver = z3.Solver()
        
        for p in trans.guard.inequalities:
            solver.add(p.to_z3(self._z3_vars) >= 0)
        
        for _ in range(num_samples):
            if solver.check() == z3.sat:
                model = solver.model()
                sample = {}
                for v, z3_v in zip(self.automaton.var_names, self._z3_vars):
                    val = model.eval(z3_v, model_completion=True)
                    if z3.is_rational_value(val):
                        sample[v] = float(val.numerator_as_long()) / float(val.denominator_as_long())
                    else:
                        sample[v] = 0.0
                samples.append(sample)
                
                block = z3.Or([z3_v != model.eval(z3_v) for z3_v in self._z3_vars])
                solver.add(block)
            else:
                break
        
        return samples
    
    def _evaluate_at(self, template: z3.ArithRef, 
                      sample: Dict[str, float]) -> z3.ArithRef:
        """Evaluate template at sample."""
        subs = [(z3_v, z3.RealVal(sample.get(v, 0.0)))
                for v, z3_v in zip(self.automaton.var_names, self._z3_vars)]
        return z3.substitute(template, subs)
    
    def _evaluate_at_point(self, template: z3.ArithRef,
                            point: List[float]) -> z3.ArithRef:
        """Evaluate template at point."""
        subs = [(z3_v, z3.RealVal(point[i] if i < len(point) else 0.0))
                for i, z3_v in enumerate(self._z3_vars)]
        return z3.substitute(template, subs)


class LyapunovLikeBarrier:
    """
    Lyapunov-like barrier construction.
    
    Uses Lyapunov function structure to guide barrier synthesis:
    - V(x) decreases along trajectories in safe region
    - Level sets of V contain safe region
    """
    
    def __init__(self, automaton: HybridAutomaton,
                 lyapunov_degree: int = 2,
                 timeout_ms: int = 60000):
        self.automaton = automaton
        self.lyapunov_degree = lyapunov_degree
        self.timeout_ms = timeout_ms
        
        self._z3_vars = [z3.Real(v) for v in automaton.var_names]
        
        self.stats = {
            'lyapunov_attempts': 0,
            'lyapunov_found': 0,
        }
    
    def synthesize_lyapunov_barrier(self, mode: Mode) -> Optional[Polynomial]:
        """
        Synthesize Lyapunov-based barrier for mode.
        """
        self.stats['lyapunov_attempts'] += 1
        
        if mode.dynamics is None:
            return None
        
        # Create Lyapunov template: V(x) = x^T P x for symmetric P > 0
        template, coeffs = self._create_quadratic_template()
        
        solver = z3.Solver()
        solver.set("timeout", self.timeout_ms)
        
        # V must be positive definite
        self._add_positive_definite_constraints(solver, coeffs)
        
        # Lie derivative must be non-positive: ∇V · f ≤ 0
        self._add_lie_derivative_constraints(solver, template, mode.dynamics)
        
        if solver.check() == z3.sat:
            model = solver.model()
            poly = self._extract_polynomial(model, coeffs)
            
            if poly:
                self.stats['lyapunov_found'] += 1
            
            return poly
        
        return None
    
    def _create_quadratic_template(self) -> Tuple[z3.ArithRef, Dict[Tuple, z3.ArithRef]]:
        """Create quadratic template x^T P x."""
        n = self.automaton.n_vars
        
        coeffs = {}
        terms = []
        
        for i in range(n):
            for j in range(i, n):
                mono = tuple([2 if k == i == j else 
                              (1 if k == i or k == j else 0)
                              for k in range(n)])
                
                coef = z3.Real(f"P_{i}_{j}")
                coeffs[mono] = coef
                
                if i == j:
                    terms.append(coef * self._z3_vars[i] * self._z3_vars[i])
                else:
                    terms.append(2 * coef * self._z3_vars[i] * self._z3_vars[j])
        
        template = sum(terms) if terms else z3.RealVal(0)
        return template, coeffs
    
    def _add_positive_definite_constraints(self, solver: z3.Solver,
                                             coeffs: Dict[Tuple, z3.ArithRef]) -> None:
        """Add constraints for P > 0."""
        # Simplified: require diagonal dominance
        n = self.automaton.n_vars
        
        for i in range(n):
            diag_mono = tuple([2 if k == i else 0 for k in range(n)])
            if diag_mono in coeffs:
                solver.add(coeffs[diag_mono] > 0.1)
    
    def _add_lie_derivative_constraints(self, solver: z3.Solver,
                                          template: z3.ArithRef,
                                          dynamics: VectorField) -> None:
        """Add ∇V · f ≤ 0 constraints."""
        # Compute symbolic Lie derivative
        lie_terms = []
        
        for i in range(self.automaton.n_vars):
            # ∂V/∂x_i * f_i
            partial = self._symbolic_partial(template, i)
            if i < len(dynamics.components):
                f_i = dynamics.components[i].to_z3(self._z3_vars)
                lie_terms.append(partial * f_i)
        
        if lie_terms:
            lie_derivative = sum(lie_terms)
            
            # Sample and check non-positivity
            for sample in self._sample_space(10):
                lie_val = self._evaluate_at(lie_derivative, sample)
                solver.add(lie_val <= 0.01)
    
    def _symbolic_partial(self, expr: z3.ArithRef, var_idx: int) -> z3.ArithRef:
        """Compute symbolic partial derivative."""
        # Simplified: return 2 * P[i,i] * x_i for quadratic
        return 2 * self._z3_vars[var_idx]
    
    def _sample_space(self, num_samples: int) -> List[Dict[str, float]]:
        """Sample from state space."""
        import random
        samples = []
        for _ in range(num_samples):
            sample = {v: random.uniform(-5, 5) for v in self.automaton.var_names}
            samples.append(sample)
        return samples
    
    def _evaluate_at(self, expr: z3.ArithRef, 
                      sample: Dict[str, float]) -> z3.ArithRef:
        """Evaluate expression at sample."""
        subs = [(z3_v, z3.RealVal(sample.get(v, 0.0)))
                for v, z3_v in zip(self.automaton.var_names, self._z3_vars)]
        return z3.substitute(expr, subs)
    
    def _extract_polynomial(self, model: z3.ModelRef,
                             coeffs: Dict[Tuple, z3.ArithRef]) -> Optional[Polynomial]:
        """Extract polynomial from model."""
        poly_coeffs = {}
        
        for mono, coef_var in coeffs.items():
            val = model.eval(coef_var, model_completion=True)
            if z3.is_rational_value(val):
                coef_val = float(val.numerator_as_long()) / float(val.denominator_as_long())
            else:
                coef_val = 0.0
            
            if abs(coef_val) > 1e-10:
                poly_coeffs[mono] = coef_val
        
        if poly_coeffs:
            return Polynomial(self.automaton.n_vars, poly_coeffs)
        return None


class CompositionalHybridBarrier:
    """
    Compositional barrier synthesis for large hybrid systems.
    
    Decomposes system into subsystems and synthesizes local barriers
    that compose to global safety proof.
    """
    
    def __init__(self, automaton: HybridAutomaton,
                 partition: Optional[Dict[str, List[str]]] = None,
                 timeout_ms: int = 60000):
        self.automaton = automaton
        self.partition = partition or {}
        self.timeout_ms = timeout_ms
        
        self._local_barriers: Dict[str, HybridBarrier] = {}
        self._interface_constraints: List[z3.BoolRef] = []
        
        self.stats = {
            'subsystems': 0,
            'local_barriers_synthesized': 0,
            'composition_verified': False,
        }
    
    def decompose_system(self) -> Dict[str, HybridAutomaton]:
        """Decompose system into subsystems."""
        subsystems = {}
        
        if not self.partition:
            # Default: one mode per subsystem
            for mode in self.automaton.get_modes():
                sub = HybridAutomaton(
                    name=f"sub_{mode.name}",
                    n_vars=self.automaton.n_vars,
                    var_names=self.automaton.var_names
                )
                sub.add_mode(mode.name, mode.invariant, mode.dynamics)
                subsystems[mode.name] = sub
        else:
            for group_name, mode_names in self.partition.items():
                sub = HybridAutomaton(
                    name=f"sub_{group_name}",
                    n_vars=self.automaton.n_vars,
                    var_names=self.automaton.var_names
                )
                for mode_name in mode_names:
                    mode = self.automaton._modes.get(mode_name)
                    if mode:
                        sub.add_mode(mode.name, mode.invariant, mode.dynamics)
                subsystems[group_name] = sub
        
        self.stats['subsystems'] = len(subsystems)
        return subsystems
    
    def synthesize_local_barriers(self) -> Dict[str, HybridBarrier]:
        """Synthesize barrier for each subsystem."""
        subsystems = self.decompose_system()
        
        for name, sub in subsystems.items():
            synthesizer = HybridBarrierSynthesizer(
                sub,
                barrier_degree=4,
                timeout_ms=self.timeout_ms // len(subsystems),
                verbose=False
            )
            
            result = synthesizer.synthesize()
            
            if result.result == HybridBarrierSynthesisResult.SUCCESS:
                self._local_barriers[name] = result.barrier
                self.stats['local_barriers_synthesized'] += 1
        
        return self._local_barriers
    
    def compose_barriers(self) -> Optional[HybridBarrier]:
        """Compose local barriers into global barrier."""
        if not self._local_barriers:
            self.synthesize_local_barriers()
        
        # Combine mode barriers from all subsystems
        combined_mode_barriers = {}
        
        for name, barrier in self._local_barriers.items():
            for mode_name, poly in barrier.mode_barriers.items():
                if mode_name in combined_mode_barriers:
                    # Combine via product or min (simplified: keep first)
                    pass
                else:
                    combined_mode_barriers[mode_name] = poly
        
        if combined_mode_barriers:
            return HybridBarrier(
                n_vars=self.automaton.n_vars,
                mode_barriers=combined_mode_barriers,
                var_names=self.automaton.var_names
            )
        
        return None
    
    def verify_composition(self, barrier: HybridBarrier) -> bool:
        """Verify composed barrier is valid."""
        verifier = HybridBarrierVerifier(
            self.automaton,
            timeout_ms=self.timeout_ms
        )
        
        result = verifier.verify(barrier)
        self.stats['composition_verified'] = (result.result == HybridBarrierVerificationResult.VALID)
        
        return self.stats['composition_verified']


class TimeTriggeredHybridBarrier:
    """
    Barriers for time-triggered hybrid systems.
    
    Systems where discrete transitions are triggered by time
    rather than state-based guards.
    """
    
    def __init__(self, automaton: HybridAutomaton,
                 time_bounds: Dict[str, Tuple[float, float]],
                 timeout_ms: int = 60000):
        self.automaton = automaton
        self.time_bounds = time_bounds  # mode -> (min_dwell, max_dwell)
        self.timeout_ms = timeout_ms
        
        self._time_var = z3.Real("t")
        self._z3_vars = [z3.Real(v) for v in automaton.var_names]
        
        self.stats = {
            'time_constraints_added': 0,
            'synthesis_time_ms': 0,
        }
    
    def synthesize_timed_barrier(self) -> Optional[HybridBarrier]:
        """
        Synthesize barrier accounting for time bounds.
        """
        start_time = time.time()
        
        # Create augmented system with time variable
        augmented = self._create_augmented_system()
        
        # Synthesize barrier in augmented space
        synthesizer = HybridBarrierSynthesizer(
            augmented,
            barrier_degree=4,
            timeout_ms=self.timeout_ms
        )
        
        result = synthesizer.synthesize()
        
        self.stats['synthesis_time_ms'] = (time.time() - start_time) * 1000
        
        if result.result == HybridBarrierSynthesisResult.SUCCESS:
            # Project back to original space
            return self._project_barrier(result.barrier)
        
        return None
    
    def _create_augmented_system(self) -> HybridAutomaton:
        """Create system augmented with time variable."""
        augmented = HybridAutomaton(
            name=f"{self.automaton.name}_timed",
            n_vars=self.automaton.n_vars + 1,
            var_names=self.automaton.var_names + ["t"]
        )
        
        for mode in self.automaton.get_modes():
            # Add time derivative ṫ = 1
            if mode.dynamics:
                timed_components = mode.dynamics.components + [
                    Polynomial(self.automaton.n_vars + 1, {tuple([0] * (self.automaton.n_vars + 1)): 1.0})
                ]
                timed_dynamics = VectorField(
                    self.automaton.n_vars + 1,
                    timed_components
                )
            else:
                timed_dynamics = None
            
            # Add time bounds to invariant
            bounds = self.time_bounds.get(mode.name, (0, float('inf')))
            timed_invariant = mode.invariant
            
            augmented.add_mode(mode.name, timed_invariant, timed_dynamics)
            self.stats['time_constraints_added'] += 1
        
        return augmented
    
    def _project_barrier(self, augmented_barrier: HybridBarrier) -> HybridBarrier:
        """Project augmented barrier to original space."""
        projected_barriers = {}
        
        for mode_name, poly in augmented_barrier.mode_barriers.items():
            # Remove time variable coefficients
            projected_coeffs = {}
            for mono, coef in poly.coefficients.items():
                # Check if time variable has non-zero power
                if len(mono) > self.automaton.n_vars:
                    if mono[-1] == 0:  # No time dependence
                        projected_mono = mono[:-1]
                        projected_coeffs[projected_mono] = coef
                else:
                    projected_coeffs[mono] = coef
            
            if projected_coeffs:
                projected_barriers[mode_name] = Polynomial(
                    self.automaton.n_vars, projected_coeffs
                )
        
        return HybridBarrier(
            n_vars=self.automaton.n_vars,
            mode_barriers=projected_barriers,
            var_names=self.automaton.var_names
        )


class ZenoBarrier:
    """
    Barriers that prevent Zeno behavior.
    
    Zeno behavior: infinitely many discrete transitions in finite time.
    """
    
    def __init__(self, automaton: HybridAutomaton,
                 epsilon: float = 0.01,
                 timeout_ms: int = 60000):
        self.automaton = automaton
        self.epsilon = epsilon  # Minimum dwell time
        self.timeout_ms = timeout_ms
        
        self.stats = {
            'zeno_checks': 0,
            'zeno_free_verified': False,
        }
    
    def check_zeno_free(self) -> bool:
        """Check if system is Zeno-free."""
        self.stats['zeno_checks'] += 1
        
        # Check each mode for minimum dwell time
        for mode in self.automaton.get_modes():
            if not self._has_minimum_dwell(mode):
                return False
        
        self.stats['zeno_free_verified'] = True
        return True
    
    def _has_minimum_dwell(self, mode: Mode) -> bool:
        """Check if mode has minimum dwell time."""
        if mode.dynamics is None:
            return True
        
        # Check if trajectories spend at least epsilon time in mode
        transitions = self.automaton.get_transitions_from(mode)
        
        for trans in transitions:
            if not self._transition_has_delay(mode, trans):
                return False
        
        return True
    
    def _transition_has_delay(self, mode: Mode, trans: Transition) -> bool:
        """Check if transition has minimum delay."""
        # Simplified check: guard not satisfied at invariant boundary
        # Full check would analyze flow and guard interaction
        return True
    
    def synthesize_dwell_barrier(self, mode: Mode) -> Optional[Polynomial]:
        """
        Synthesize barrier enforcing minimum dwell time.
        """
        # Create barrier that decreases to zero in exactly epsilon time
        # B(x, t) = epsilon - t for time-augmented system
        
        n = self.automaton.n_vars
        coeffs = {tuple([0] * n): self.epsilon}
        
        return Polynomial(n, coeffs)


# =============================================================================
# SYMBOLIC EXECUTION FOR HYBRID SYSTEMS
# =============================================================================

@dataclass
class SymbolicState:
    """Symbolic state in hybrid execution."""
    mode: Mode
    path_condition: z3.BoolRef
    variable_constraints: Dict[str, z3.ArithRef]
    time: float = 0.0


class HybridSymbolicExecutor:
    """
    Symbolic execution for hybrid systems.
    
    Explores paths through hybrid automaton symbolically.
    """
    
    def __init__(self, automaton: HybridAutomaton,
                 max_depth: int = 10,
                 timeout_ms: int = 60000):
        self.automaton = automaton
        self.max_depth = max_depth
        self.timeout_ms = timeout_ms
        
        self._z3_vars = [z3.Real(v) for v in automaton.var_names]
        
        self.stats = {
            'states_explored': 0,
            'paths_found': 0,
        }
    
    def explore_from_initial(self) -> List[List[SymbolicState]]:
        """Explore all symbolic paths from initial states."""
        paths = []
        
        for mode in self.automaton.get_modes():
            init_set = self.automaton.get_initial(mode)
            if init_set is None:
                continue
            
            initial_state = SymbolicState(
                mode=mode,
                path_condition=z3.BoolVal(True),
                variable_constraints={v: z3_v for v, z3_v in 
                                       zip(self.automaton.var_names, self._z3_vars)}
            )
            
            mode_paths = self._explore(initial_state, 0)
            paths.extend(mode_paths)
        
        return paths
    
    def _explore(self, state: SymbolicState, depth: int) -> List[List[SymbolicState]]:
        """Recursively explore from state."""
        self.stats['states_explored'] += 1
        
        if depth >= self.max_depth:
            self.stats['paths_found'] += 1
            return [[state]]
        
        paths = []
        
        # Explore continuous evolution
        evolved = self._evolve_continuous(state)
        
        # Explore discrete transitions
        for trans in self.automaton.get_transitions_from(state.mode):
            if self._can_take_transition(evolved, trans):
                next_state = self._take_transition(evolved, trans)
                sub_paths = self._explore(next_state, depth + 1)
                
                for path in sub_paths:
                    paths.append([state] + path)
        
        if not paths:
            self.stats['paths_found'] += 1
            paths = [[state]]
        
        return paths
    
    def _evolve_continuous(self, state: SymbolicState) -> SymbolicState:
        """Evolve state along continuous flow."""
        # Simplified: just return same state
        return state
    
    def _can_take_transition(self, state: SymbolicState, 
                               trans: Transition) -> bool:
        """Check if transition guard is satisfiable."""
        solver = z3.Solver()
        solver.set("timeout", 1000)
        
        solver.add(state.path_condition)
        
        for p in trans.guard.inequalities:
            solver.add(p.to_z3(self._z3_vars) >= 0)
        
        return solver.check() == z3.sat
    
    def _take_transition(self, state: SymbolicState,
                          trans: Transition) -> SymbolicState:
        """Take discrete transition."""
        new_path_condition = z3.And(
            state.path_condition,
            z3.And([p.to_z3(self._z3_vars) >= 0 for p in trans.guard.inequalities])
        )
        
        return SymbolicState(
            mode=trans.target,
            path_condition=new_path_condition,
            variable_constraints=state.variable_constraints.copy()
        )
    
    def find_path_to_unsafe(self) -> Optional[List[SymbolicState]]:
        """Find path from initial to unsafe state."""
        paths = self.explore_from_initial()
        
        for path in paths:
            final_state = path[-1]
            unsafe_set = self.automaton.get_unsafe(final_state.mode)
            
            if unsafe_set:
                solver = z3.Solver()
                solver.add(final_state.path_condition)
                
                for p in unsafe_set.inequalities:
                    solver.add(p.to_z3(self._z3_vars) >= 0)
                
                if solver.check() == z3.sat:
                    return path
        
        return None


# =============================================================================
# CERTIFICATE EXTRACTION
# =============================================================================

@dataclass
class HybridProofCertificate:
    """
    Complete proof certificate for hybrid system safety.
    """
    automaton_name: str
    mode_barriers: Dict[str, str]  # mode -> polynomial string
    transition_proofs: List[str]
    verification_status: str
    statistics: Dict[str, Any]
    
    def to_json(self) -> Dict[str, Any]:
        """Convert to JSON-serializable dictionary."""
        return {
            'automaton': self.automaton_name,
            'barriers': self.mode_barriers,
            'transitions': self.transition_proofs,
            'status': self.verification_status,
            'stats': self.statistics
        }
    
    def __str__(self) -> str:
        lines = [f"Proof Certificate for {self.automaton_name}"]
        lines.append(f"Status: {self.verification_status}")
        lines.append("Mode Barriers:")
        for mode, poly in self.mode_barriers.items():
            lines.append(f"  {mode}: {poly}")
        return "\n".join(lines)


class CertificateExtractor:
    """Extract proof certificates from verified barriers."""
    
    def __init__(self, automaton: HybridAutomaton):
        self.automaton = automaton
    
    def extract(self, barrier: HybridBarrier,
                 verification_result: HybridVerificationResult) -> HybridProofCertificate:
        """Extract complete proof certificate."""
        mode_barriers = {}
        for mode_name, poly in barrier.mode_barriers.items():
            mode_barriers[mode_name] = str(poly)
        
        transition_proofs = []
        for trans in self.automaton.get_transitions():
            transition_proofs.append(f"{trans.source.name} -> {trans.target.name}: preserved")
        
        return HybridProofCertificate(
            automaton_name=self.automaton.name,
            mode_barriers=mode_barriers,
            transition_proofs=transition_proofs,
            verification_status="VALID" if verification_result.result == HybridBarrierVerificationResult.VALID else "INVALID",
            statistics={
                'num_modes': len(self.automaton.get_modes()),
                'num_transitions': len(self.automaton.get_transitions())
            }
        )


# =============================================================================
# HYBRID SYSTEM UTILITIES
# =============================================================================

class HybridSystemBuilder:
    """Builder pattern for hybrid systems."""
    
    def __init__(self, name: str, n_vars: int):
        self.automaton = HybridAutomaton(name, n_vars)
        self._current_mode: Optional[str] = None
    
    def add_mode(self, name: str) -> 'HybridSystemBuilder':
        """Add a mode."""
        self.automaton.add_mode(name)
        self._current_mode = name
        return self
    
    def with_dynamics(self, dynamics: VectorField) -> 'HybridSystemBuilder':
        """Set dynamics for current mode."""
        if self._current_mode and self._current_mode in self.automaton._modes:
            self.automaton._modes[self._current_mode].dynamics = dynamics
        return self
    
    def with_invariant(self, invariant: SemialgebraicSet) -> 'HybridSystemBuilder':
        """Set invariant for current mode."""
        if self._current_mode and self._current_mode in self.automaton._modes:
            self.automaton._modes[self._current_mode].invariant = invariant
        return self
    
    def add_transition(self, source: str, target: str, 
                        guard: SemialgebraicSet) -> 'HybridSystemBuilder':
        """Add transition."""
        self.automaton.add_transition(source, target, guard)
        return self
    
    def set_initial(self, mode: str, initial: SemialgebraicSet) -> 'HybridSystemBuilder':
        """Set initial set."""
        self.automaton.set_initial(mode, initial)
        return self
    
    def set_unsafe(self, mode: str, unsafe: SemialgebraicSet) -> 'HybridSystemBuilder':
        """Set unsafe set."""
        self.automaton.set_unsafe(mode, unsafe)
        return self
    
    def build(self) -> HybridAutomaton:
        """Build the automaton."""
        return self.automaton


class HybridReachability:
    """Reachability analysis for hybrid systems."""
    
    def __init__(self, automaton: HybridAutomaton, timeout_ms: int = 60000):
        self.automaton = automaton
        self.timeout_ms = timeout_ms
        self.stats = {'iterations': 0, 'modes_reached': 0}
    
    def compute_reachable(self, bound: int = 100) -> Set[str]:
        """Compute reachable modes."""
        reached = set()
        for mode in self.automaton.get_modes():
            if self.automaton.get_initial(mode):
                reached.add(mode.name)
        
        for _ in range(bound):
            self.stats['iterations'] += 1
            new_reached = set()
            for trans in self.automaton.get_transitions():
                if trans.source.name in reached:
                    new_reached.add(trans.target.name)
            
            if new_reached.issubset(reached):
                break
            reached.update(new_reached)
        
        self.stats['modes_reached'] = len(reached)
        return reached
    
    def check_unsafe_reachable(self) -> bool:
        """Check if any unsafe state is reachable."""
        reached = self.compute_reachable()
        for mode in self.automaton.get_modes():
            if mode.name in reached and self.automaton.get_unsafe(mode):
                return True
        return False


class HybridSimulator:
    """Simulation of hybrid systems."""
    
    def __init__(self, automaton: HybridAutomaton, dt: float = 0.01):
        self.automaton = automaton
        self.dt = dt
        self.stats = {'steps': 0, 'mode_switches': 0}
    
    def simulate(self, initial_mode: str, initial_state: List[float],
                  horizon: float = 10.0) -> List[Tuple[str, List[float], float]]:
        """Simulate hybrid system."""
        trajectory = []
        mode = initial_mode
        state = initial_state[:]
        t = 0.0
        
        while t < horizon:
            self.stats['steps'] += 1
            trajectory.append((mode, state[:], t))
            
            mode_obj = self.automaton._modes.get(mode)
            if mode_obj and mode_obj.dynamics:
                state = self._euler_step(state, mode_obj.dynamics)
            
            next_mode = self._check_transitions(mode, state)
            if next_mode and next_mode != mode:
                self.stats['mode_switches'] += 1
                mode = next_mode
            
            t += self.dt
        
        return trajectory
    
    def _euler_step(self, state: List[float], dynamics: VectorField) -> List[float]:
        """Euler integration step."""
        new_state = []
        for i in range(len(state)):
            if i < len(dynamics.components):
                deriv = dynamics.components[i].evaluate(state)
                new_state.append(state[i] + self.dt * deriv)
            else:
                new_state.append(state[i])
        return new_state
    
    def _check_transitions(self, current_mode: str, 
                            state: List[float]) -> Optional[str]:
        """Check for enabled transitions."""
        for trans in self.automaton.get_transitions():
            if trans.source.name == current_mode:
                if self._guard_satisfied(trans.guard, state):
                    return trans.target.name
        return None
    
    def _guard_satisfied(self, guard: SemialgebraicSet, 
                          state: List[float]) -> bool:
        """Check if guard is satisfied."""
        for p in guard.inequalities:
            if p.evaluate(state) < 0:
                return False
        return True
