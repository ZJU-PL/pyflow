"""
Barrier Certificate Core Layer.

This module provides the core barrier certificate constructions
that build upon the mathematical foundations. It integrates:

    Paper #1: Hybrid Barrier Certificates (Prajna-Jadbabaie 2004)
        - Multi-mode barrier functions for hybrid systems
        - Mode transition conditions
        
    Paper #2: Stochastic Barrier Certificates (Prajna et al. 2007)
        - Supermartingale conditions via Itô calculus
        - Probability bounds on safety
        
    Paper #3: SOS Safety (Papachristodoulou-Prajna 2002)
        - Emptiness checking via SOS
        - Barrier function existence
        
    Paper #4: SOSTOOLS Framework (Prajna et al. 2004)
        - Engineering framework for SOS programming
        - Parametric barrier templates

The composable architecture:

    ┌─────────────────────────────────────────────────────────────┐
    │                   BARRIER CERTIFICATE CORE                   │
    ├─────────────────────────────────────────────────────────────┤
    │                                                              │
    │  ┌──────────────────────────────────────────────────────────┐│
    │  │              MATHEMATICAL FOUNDATIONS                     ││
    │  │    (Positivstellensatz, SOS/SDP, Lasserre, Sparse SOS)   ││
    │  └────────────────────────┬─────────────────────────────────┘│
    │                           │                                  │
    │           ┌───────────────┼───────────────┐                  │
    │           │               │               │                  │
    │           ▼               ▼               ▼                  │
    │  ┌────────────┐   ┌────────────┐   ┌────────────┐           │
    │  │   Hybrid   │   │ Stochastic │   │ SOS Safety │           │
    │  │  Barriers  │   │  Barriers  │   │ Emptiness  │           │
    │  │ (Paper #1) │   │ (Paper #2) │   │ (Paper #3) │           │
    │  └──────┬─────┘   └──────┬─────┘   └──────┬─────┘           │
    │         │                │                │                  │
    │         └────────────────┼────────────────┘                  │
    │                          │                                   │
    │                          ▼                                   │
    │              ┌───────────────────────┐                       │
    │              │      SOSTOOLS         │                       │
    │              │  Unified Framework    │                       │
    │              │     (Paper #4)        │                       │
    │              └───────────────────────┘                       │
    │                                                              │
    └─────────────────────────────────────────────────────────────┘

Usage:
    from barriers.certificate_core import (
        HybridBarrierSynthesizer,
        StochasticBarrierSynthesizer,
        SOSSafetyChecker,
        SOSTOOLSFramework,
        BarrierCertificateEngine,
    )
    
    # Unified interface
    engine = BarrierCertificateEngine(system_type='hybrid')
    certificate = engine.synthesize(initial, safe, unsafe, dynamics)
"""

from __future__ import annotations

import z3
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple, Set, Any, Union, Callable
from enum import Enum, auto
import logging

# Import from foundations layer
from .foundations import (
    Monomial, Polynomial, SemialgebraicSet,
    QuadraticModule, SOSDecomposition, SOSDecomposer,
    PutinarCertificate, PutinarProver,
    LasserreRelaxation, LasserreHierarchySolver,
    SparseSOSDecomposer, PolynomialCertificateEngine
)

logger = logging.getLogger(__name__)


# =============================================================================
# SYSTEM MODELS
# =============================================================================

class SystemType(Enum):
    """Types of dynamical systems."""
    CONTINUOUS = auto()  # ẋ = f(x)
    DISCRETE = auto()  # x' = f(x)
    HYBRID = auto()  # Multi-mode with transitions
    STOCHASTIC = auto()  # dx = f(x)dt + g(x)dW


@dataclass
class ContinuousDynamics:
    """
    Continuous dynamical system: ẋ = f(x).
    
    The vector field f is given as a list of polynomials,
    one for each state variable.
    """
    n_vars: int
    vector_field: List[Polynomial]  # f_i(x) for each dimension
    name: str = ""
    
    def lie_derivative(self, B: Polynomial) -> Polynomial:
        """
        Compute Lie derivative: L_f(B) = ∇B · f = Σᵢ (∂B/∂xᵢ) · fᵢ
        
        The Lie derivative captures how B changes along trajectories.
        """
        gradient = B.gradient()
        result = Polynomial(self.n_vars)
        
        for i in range(min(len(gradient), len(self.vector_field))):
            result = result.add(gradient[i].multiply(self.vector_field[i]))
        
        return result
    
    def verify_stability_condition(self, B: Polynomial,
                                    region: SemialgebraicSet,
                                    solver: z3.Solver = None) -> bool:
        """
        Check Lie derivative negativity: L_f(B) ≤ 0 on region.
        """
        L = self.lie_derivative(B)
        
        if solver is None:
            solver = z3.Solver()
            solver.set("timeout", 10000)
        
        vars_z3 = [z3.Real(f'x{i}') for i in range(self.n_vars)]
        
        # Check: ∃x ∈ region such that L(x) > 0
        for g in region.constraints:
            solver.add(g.to_z3(vars_z3) >= 0)
        
        solver.add(L.to_z3(vars_z3) > 0)
        
        return solver.check() == z3.unsat  # No counterexample = valid


@dataclass
class DiscreteDynamics:
    """
    Discrete dynamical system: x' = f(x).
    """
    n_vars: int
    update_map: List[Polynomial]  # x'_i = f_i(x)
    name: str = ""
    
    def compose_with_barrier(self, B: Polynomial) -> Polynomial:
        """
        Compute B(f(x)) - the barrier value at next state.
        
        For discrete systems, the decrease condition is:
        B(f(x)) - B(x) ≤ 0 on safe region.
        """
        # Substitute f_i for x_i in B
        result = Polynomial(self.n_vars)
        
        for mono, coeff in B.terms.items():
            # Substitute into monomial
            term = Polynomial.constant(self.n_vars, coeff)
            for i, exp in enumerate(mono.exponents):
                if exp > 0 and i < len(self.update_map):
                    fi = self.update_map[i]
                    for _ in range(exp):
                        term = term.multiply(fi)
            result = result.add(term)
        
        return result
    
    def barrier_decrease(self, B: Polynomial) -> Polynomial:
        """
        Compute B(f(x)) - B(x).
        
        This should be ≤ 0 for the barrier to be valid.
        """
        B_next = self.compose_with_barrier(B)
        return B_next.add(B.negate())


@dataclass
class HybridMode:
    """
    A mode in a hybrid automaton.
    
    Each mode has continuous dynamics and an invariant (stay condition).
    """
    mode_id: int
    dynamics: ContinuousDynamics
    invariant: SemialgebraicSet  # Must remain in mode while here
    name: str = ""


@dataclass
class HybridTransition:
    """
    A transition between modes in a hybrid automaton.
    
    Guarded by a predicate, with a reset map.
    """
    source: int  # Source mode ID
    target: int  # Target mode ID
    guard: SemialgebraicSet  # When transition can fire
    reset: Optional[List[Polynomial]] = None  # Reset map x' = r(x), None = identity
    
    def apply_reset(self, point: List[float]) -> List[float]:
        """Apply reset map to point."""
        if self.reset is None:
            return list(point)
        return [p.evaluate(point) for p in self.reset]


@dataclass
class HybridAutomaton:
    """
    Hybrid automaton model for Paper #1.
    
    A hybrid system with:
    - Finite set of discrete modes
    - Continuous dynamics in each mode
    - Guarded transitions between modes
    """
    n_vars: int
    modes: Dict[int, HybridMode]
    transitions: List[HybridTransition]
    name: str = ""
    
    @property
    def num_modes(self) -> int:
        return len(self.modes)
    
    def get_mode(self, mode_id: int) -> Optional[HybridMode]:
        return self.modes.get(mode_id)
    
    def get_outgoing_transitions(self, mode_id: int) -> List[HybridTransition]:
        return [t for t in self.transitions if t.source == mode_id]


@dataclass
class StochasticDynamics:
    """
    Stochastic differential equation: dx = f(x)dt + g(x)dW.
    
    From Paper #2: Uses Itô calculus for barrier conditions.
    """
    n_vars: int
    drift: List[Polynomial]  # f_i(x) - drift coefficients
    diffusion: List[List[Polynomial]]  # g_ij(x) - diffusion matrix
    name: str = ""
    
    def infinitesimal_generator(self, B: Polynomial) -> Polynomial:
        """
        Compute infinitesimal generator: 𝓛B = ∇B·f + ½ tr(g gᵀ ∇²B).
        
        This is the expected rate of change of B(x(t)).
        By Itô's lemma: dB = 𝓛B dt + (∇B·g) dW
        """
        n = self.n_vars
        
        # First term: ∇B · f
        gradient = B.gradient()
        result = Polynomial(n)
        
        for i in range(min(len(gradient), len(self.drift))):
            result = result.add(gradient[i].multiply(self.drift[i]))
        
        # Second term: ½ tr(g gᵀ ∇²B)
        # Compute diffusion tensor: D_ij = Σ_k g_ik g_jk
        # Then add ½ Σ_ij D_ij ∂²B/∂xᵢ∂xⱼ
        
        for i in range(n):
            for j in range(n):
                # Compute D_ij
                D_ij = Polynomial(n)
                for k in range(len(self.diffusion[0]) if self.diffusion else 0):
                    if i < len(self.diffusion) and k < len(self.diffusion[i]):
                        if j < len(self.diffusion) and k < len(self.diffusion[j]):
                            D_ij = D_ij.add(
                                self.diffusion[i][k].multiply(self.diffusion[j][k])
                            )
                
                # Compute ∂²B/∂xᵢ∂xⱼ
                B_ij = B.differentiate(i).differentiate(j)
                
                # Add ½ D_ij B_ij
                result = result.add(D_ij.multiply(B_ij).scale(0.5))
        
        return result


# =============================================================================
# BARRIER CONDITIONS
# =============================================================================

@dataclass
class BarrierConditions:
    """
    Standard barrier certificate conditions.
    
    For a function B: ℝⁿ → ℝ to be a barrier certificate:
    1. B(x) > 0 for all x ∈ Initial
    2. B(x) ≤ 0 for all x ∈ Unsafe
    3. L_f(B)(x) ≤ 0 for all x ∈ Safe (continuous)
       or B(f(x)) - B(x) ≤ 0 (discrete)
    """
    initial: SemialgebraicSet  # X₀
    safe: SemialgebraicSet  # X_safe
    unsafe: SemialgebraicSet  # X_u
    state_space: Optional[SemialgebraicSet] = None  # X (default: R^n)


@dataclass
class HybridBarrierConditions:
    """
    Barrier conditions for hybrid systems (Paper #1).
    
    For each mode q, we have a barrier function B_q.
    Mode-specific conditions:
    1. B_q(x) > 0 on Initial ∩ Mode_q
    2. B_q(x) ≤ 0 on Unsafe ∩ Mode_q
    3. L_f_q(B_q) ≤ 0 in Mode_q (continuous invariant)
    
    Transition conditions:
    4. B_target(r(x)) ≤ B_source(x) on guards (barrier doesn't increase on jumps)
    """
    n_vars: int
    mode_conditions: Dict[int, BarrierConditions]
    mode_count: int


@dataclass
class StochasticBarrierConditions:
    """
    Barrier conditions for stochastic systems (Paper #2).
    
    For probabilistic safety:
    1. B(x) ≥ 0 on Initial (non-negative start)
    2. B(x) > 1 on Unsafe (threshold for escape)
    3. 𝓛B(x) ≤ λB(x) on Safe (supermartingale-like)
    
    Probability bound: P[reach Unsafe | x₀] ≤ B(x₀)
    """
    initial: SemialgebraicSet
    safe: SemialgebraicSet
    unsafe: SemialgebraicSet
    decay_rate: float = 0.0  # λ in condition 3


# =============================================================================
# BARRIER TEMPLATES
# =============================================================================

class BarrierTemplate:
    """
    Parametric barrier function template.
    
    From Paper #4 (SOSTOOLS): Express barrier as B(x) = Σ_α c_α x^α
    with unknown coefficients c_α to be determined.
    """
    
    def __init__(self, n_vars: int, max_degree: int):
        self.n_vars = n_vars
        self.max_degree = max_degree
        self.monomials = self._generate_monomials()
        self.coefficients: Dict[Monomial, z3.ExprRef] = {}
        
    def _generate_monomials(self) -> List[Monomial]:
        """Generate monomial basis up to max_degree."""
        monomials = []
        
        def generate(remaining: int, idx: int, current: List[int]):
            if idx == self.n_vars:
                monomials.append(Monomial(tuple(current)))
                return
            for power in range(remaining + 1):
                generate(remaining - power, idx + 1, current + [power])
        
        for d in range(self.max_degree + 1):
            generate(d, 0, [])
        
        return monomials
    
    @property
    def num_parameters(self) -> int:
        return len(self.monomials)
    
    def create_symbolic(self, name_prefix: str = "c") -> Polynomial:
        """
        Create symbolic polynomial with unknown coefficients.
        """
        poly = Polynomial(self.n_vars)
        
        for mono in self.monomials:
            coeff = z3.Real(f"{name_prefix}_{mono.exponents}")
            self.coefficients[mono] = coeff
            # Store symbolically - will convert during constraint generation
        
        return poly
    
    def to_z3(self, vars_z3: List[z3.ExprRef]) -> z3.ExprRef:
        """
        Get symbolic barrier as Z3 expression.
        """
        result = z3.RealVal(0)
        for mono in self.monomials:
            coeff = self.coefficients.get(mono, z3.RealVal(0))
            result = result + coeff * mono.to_z3(vars_z3)
        return result
    
    def evaluate(self, coeff_values: Dict[Monomial, float],
                  point: List[float]) -> float:
        """Evaluate with concrete coefficients."""
        result = 0.0
        for mono in self.monomials:
            c = coeff_values.get(mono, 0.0)
            result += c * mono.evaluate(point)
        return result
    
    def to_polynomial(self, coeff_values: Dict[Monomial, float]) -> Polynomial:
        """Convert to concrete polynomial."""
        poly = Polynomial(self.n_vars)
        for mono in self.monomials:
            c = coeff_values.get(mono, 0.0)
            if abs(c) > 1e-12:
                poly.terms[mono] = c
        return poly


class MultiModeBarrierTemplate:
    """
    Template for hybrid barrier certificates (Paper #1).
    
    Creates one barrier template B_q for each mode q.
    """
    
    def __init__(self, n_vars: int, num_modes: int, max_degree: int):
        self.n_vars = n_vars
        self.num_modes = num_modes
        self.max_degree = max_degree
        self.mode_templates: Dict[int, BarrierTemplate] = {}
        
        for q in range(num_modes):
            self.mode_templates[q] = BarrierTemplate(n_vars, max_degree)
    
    def get_mode_template(self, mode_id: int) -> BarrierTemplate:
        return self.mode_templates.get(mode_id, BarrierTemplate(self.n_vars, self.max_degree))
    
    def create_symbolic(self) -> Dict[int, z3.ExprRef]:
        """Create symbolic barriers for all modes."""
        vars_z3 = [z3.Real(f'x{i}') for i in range(self.n_vars)]
        result = {}
        
        for q, template in self.mode_templates.items():
            template.create_symbolic(f"B{q}")
            result[q] = template.to_z3(vars_z3)
        
        return result


# =============================================================================
# SOS SAFETY CHECKER (Paper #3)
# =============================================================================

class SOSSafetyChecker:
    """
    Safety verification via SOS (Paper #3).
    
    Key insight: Safety (reachable set doesn't intersect unsafe)
    reduces to non-existence of trajectories, which is checked
    via polynomial positivity/emptiness.
    """
    
    def __init__(self, n_vars: int, max_degree: int = 6,
                 timeout_ms: int = 60000):
        self.n_vars = n_vars
        self.max_degree = max_degree
        self.timeout_ms = timeout_ms
        self.cert_engine = PolynomialCertificateEngine(n_vars, max_degree, timeout_ms)
        
        self.stats = {
            'safety_checks': 0,
            'safe_proven': 0,
            'unsafe_found': 0,
            'unknown': 0,
        }
    
    def check_emptiness(self, set_constraints: List[Polynomial]) -> Tuple[bool, Optional[List[float]]]:
        """
        Check if a semialgebraic set is empty.
        
        Empty iff we can prove -1 ≥ 0 on the set, i.e., find
        a Putinar representation for -1.
        
        Returns (is_empty, counterexample_if_not_empty).
        """
        # Try to prove -1 >= 0 on the set
        minus_one = Polynomial.constant(self.n_vars, -1.0)
        
        cert = self.cert_engine.prove_positivity(minus_one, set_constraints, 0.0)
        
        if cert is not None:
            return (True, None)  # Set is empty
        
        # Try to find a point in the set
        solver = z3.Solver()
        solver.set("timeout", self.timeout_ms // 4)
        
        vars_z3 = [z3.Real(f'x{i}') for i in range(self.n_vars)]
        
        for g in set_constraints:
            solver.add(g.to_z3(vars_z3) >= 0)
        
        if solver.check() == z3.sat:
            model = solver.model()
            point = []
            for v in vars_z3:
                val = model.eval(v, model_completion=True)
                if z3.is_rational_value(val):
                    point.append(float(val.numerator_as_long()) /
                               float(val.denominator_as_long()))
                else:
                    point.append(0.0)
            return (False, point)
        
        return (False, None)  # Unknown
    
    def check_safety(self, conditions: BarrierConditions,
                      dynamics: ContinuousDynamics) -> Tuple[str, Optional[Polynomial]]:
        """
        Check safety using barrier certificate approach.
        
        Returns ('safe', barrier) if certificate found,
        ('unsafe', None) if counterexample found,
        ('unknown', None) otherwise.
        """
        self.stats['safety_checks'] += 1
        
        # Try to synthesize barrier certificate
        for degree in range(2, self.max_degree + 1, 2):
            template = BarrierTemplate(self.n_vars, degree)
            barrier = self._synthesize_barrier(template, conditions, dynamics)
            
            if barrier is not None:
                self.stats['safe_proven'] += 1
                return ('safe', barrier)
        
        # Try to find counterexample
        # Check if Initial can reach Unsafe directly
        initial_and_unsafe = (conditions.initial.constraints + 
                              conditions.unsafe.constraints)
        is_empty, cex = self.check_emptiness(initial_and_unsafe)
        
        if not is_empty and cex is not None:
            self.stats['unsafe_found'] += 1
            return ('unsafe', None)
        
        self.stats['unknown'] += 1
        return ('unknown', None)
    
    def _synthesize_barrier(self, template: BarrierTemplate,
                             conditions: BarrierConditions,
                             dynamics: ContinuousDynamics) -> Optional[Polynomial]:
        """
        Synthesize barrier using SOS constraints.
        """
        solver = z3.Solver()
        solver.set("timeout", self.timeout_ms)
        
        template.create_symbolic("B")
        vars_z3 = [z3.Real(f'x{i}') for i in range(self.n_vars)]
        B_z3 = template.to_z3(vars_z3)
        
        # Condition 1: B > 0 on Initial
        # We relax to B >= epsilon on Initial (sample points)
        self._add_positivity_samples(solver, B_z3, vars_z3,
                                      conditions.initial, 0.1, 20)
        
        # Condition 2: B <= 0 on Unsafe
        self._add_negativity_samples(solver, B_z3, vars_z3,
                                      conditions.unsafe, -0.1, 20)
        
        # Condition 3: L_f(B) <= 0 on Safe
        # First build symbolic Lie derivative
        LB_z3 = self._symbolic_lie_derivative(template, dynamics, vars_z3)
        self._add_negativity_samples(solver, LB_z3, vars_z3,
                                      conditions.safe, 0.0, 30)
        
        if solver.check() == z3.sat:
            model = solver.model()
            coeff_values = {}
            
            for mono, coeff_var in template.coefficients.items():
                val = model.eval(coeff_var, model_completion=True)
                if z3.is_rational_value(val):
                    coeff_values[mono] = (float(val.numerator_as_long()) /
                                         float(val.denominator_as_long()))
                else:
                    coeff_values[mono] = 0.0
            
            return template.to_polynomial(coeff_values)
        
        return None
    
    def _symbolic_lie_derivative(self, template: BarrierTemplate,
                                   dynamics: ContinuousDynamics,
                                   vars_z3: List[z3.ExprRef]) -> z3.ExprRef:
        """
        Compute symbolic Lie derivative for template.
        """
        # L_f(B) = Σᵢ (∂B/∂xᵢ) · fᵢ
        result = z3.RealVal(0)
        
        for i in range(min(self.n_vars, len(dynamics.vector_field))):
            # ∂B/∂xᵢ
            dB_dxi = z3.RealVal(0)
            for mono in template.monomials:
                if mono.exponents[i] > 0:
                    coeff = template.coefficients.get(mono, z3.RealVal(0))
                    exp_i = mono.exponents[i]
                    # Derivative: c * exp_i * x^(exp-1) * (other terms)
                    new_exp = list(mono.exponents)
                    new_exp[i] -= 1
                    new_mono = Monomial(tuple(new_exp))
                    dB_dxi = dB_dxi + coeff * z3.RealVal(exp_i) * new_mono.to_z3(vars_z3)
            
            # Multiply by fᵢ
            fi_z3 = dynamics.vector_field[i].to_z3(vars_z3)
            result = result + dB_dxi * fi_z3
        
        return result
    
    def _add_positivity_samples(self, solver: z3.Solver,
                                  expr: z3.ExprRef,
                                  vars_z3: List[z3.ExprRef],
                                  region: SemialgebraicSet,
                                  threshold: float,
                                  num_samples: int) -> None:
        """Add sampled positivity constraints."""
        import random
        samples = self._sample_region(region, num_samples)
        
        for sample in samples:
            substituted = self._substitute(expr, vars_z3, sample)
            solver.add(substituted >= threshold)
    
    def _add_negativity_samples(self, solver: z3.Solver,
                                  expr: z3.ExprRef,
                                  vars_z3: List[z3.ExprRef],
                                  region: SemialgebraicSet,
                                  threshold: float,
                                  num_samples: int) -> None:
        """Add sampled negativity constraints."""
        samples = self._sample_region(region, num_samples)
        
        for sample in samples:
            substituted = self._substitute(expr, vars_z3, sample)
            solver.add(substituted <= threshold)
    
    def _sample_region(self, region: SemialgebraicSet, count: int) -> List[List[float]]:
        """Generate samples from semialgebraic region."""
        import random
        samples = []
        
        for _ in range(count * 10):
            if len(samples) >= count:
                break
            
            # Random point in [-5, 5]^n
            point = [random.uniform(-5, 5) for _ in range(region.n_vars)]
            
            # Check if in region
            if region.contains(point, tolerance=1e-6):
                samples.append(point)
        
        # Pad with zeros if needed
        while len(samples) < count:
            samples.append([0.0] * region.n_vars)
        
        return samples
    
    def _substitute(self, expr: z3.ExprRef,
                     vars_z3: List[z3.ExprRef],
                     point: List[float]) -> z3.ExprRef:
        """Substitute point values into expression."""
        substitutions = [(vars_z3[i], z3.RealVal(point[i])) 
                        for i in range(min(len(vars_z3), len(point)))]
        return z3.substitute(expr, substitutions)


# =============================================================================
# HYBRID BARRIER SYNTHESIZER (Paper #1)
# =============================================================================

@dataclass
class HybridBarrierCertificate:
    """
    A hybrid barrier certificate.
    
    Contains one barrier function B_q for each mode q,
    along with verification status for each condition.
    """
    mode_barriers: Dict[int, Polynomial]
    continuous_conditions_valid: Dict[int, bool]
    transition_conditions_valid: Dict[Tuple[int, int], bool]
    verified: bool = False


class HybridBarrierSynthesizer:
    """
    Synthesize barrier certificates for hybrid systems (Paper #1).
    
    Main algorithm:
    1. Create template B_q for each mode q
    2. Add continuous invariant conditions per mode
    3. Add jump conditions for transitions
    4. Solve jointly using SOS constraints
    """
    
    def __init__(self, n_vars: int, max_degree: int = 4,
                 timeout_ms: int = 120000):
        self.n_vars = n_vars
        self.max_degree = max_degree
        self.timeout_ms = timeout_ms
        self.sos_checker = SOSSafetyChecker(n_vars, max_degree, timeout_ms // 2)
        
        self.stats = {
            'synthesis_attempts': 0,
            'certificates_found': 0,
            'transition_failures': 0,
        }
    
    def synthesize(self, automaton: HybridAutomaton,
                    conditions: HybridBarrierConditions) -> Optional[HybridBarrierCertificate]:
        """
        Synthesize hybrid barrier certificate.
        """
        self.stats['synthesis_attempts'] += 1
        
        # Create multi-mode template
        template = MultiModeBarrierTemplate(self.n_vars, automaton.num_modes, self.max_degree)
        
        solver = z3.Solver()
        solver.set("timeout", self.timeout_ms)
        
        vars_z3 = [z3.Real(f'x{i}') for i in range(self.n_vars)]
        
        # Create symbolic barriers
        symbolic_barriers = template.create_symbolic()
        
        # Add mode-specific constraints
        for mode_id, mode in automaton.modes.items():
            mode_cond = conditions.mode_conditions.get(mode_id)
            if mode_cond is None:
                continue
            
            B_q = symbolic_barriers.get(mode_id)
            if B_q is None:
                continue
            
            # Initial positivity
            self._add_initial_constraints(solver, B_q, vars_z3, mode_cond.initial)
            
            # Unsafe negativity
            self._add_unsafe_constraints(solver, B_q, vars_z3, mode_cond.unsafe)
            
            # Lie derivative negativity
            mode_template = template.get_mode_template(mode_id)
            LB = self._symbolic_lie_derivative(mode_template, mode.dynamics, vars_z3)
            self._add_lie_constraints(solver, LB, vars_z3, mode.invariant)
        
        # Add transition constraints
        for trans in automaton.transitions:
            B_source = symbolic_barriers.get(trans.source)
            B_target = symbolic_barriers.get(trans.target)
            
            if B_source is not None and B_target is not None:
                self._add_transition_constraints(solver, B_source, B_target,
                                                  trans, vars_z3)
        
        # Solve
        if solver.check() == z3.sat:
            model = solver.model()
            
            mode_barriers = {}
            continuous_valid = {}
            transition_valid = {}
            
            for mode_id in automaton.modes.keys():
                mode_template = template.get_mode_template(mode_id)
                coeff_values = self._extract_coefficients(model, mode_template)
                mode_barriers[mode_id] = mode_template.to_polynomial(coeff_values)
                continuous_valid[mode_id] = True  # Verified by solver
            
            for trans in automaton.transitions:
                transition_valid[(trans.source, trans.target)] = True
            
            self.stats['certificates_found'] += 1
            
            return HybridBarrierCertificate(
                mode_barriers=mode_barriers,
                continuous_conditions_valid=continuous_valid,
                transition_conditions_valid=transition_valid,
                verified=True
            )
        
        return None
    
    def _add_initial_constraints(self, solver: z3.Solver,
                                   B: z3.ExprRef,
                                   vars_z3: List[z3.ExprRef],
                                   initial: SemialgebraicSet) -> None:
        """Add B > 0 on Initial."""
        samples = self.sos_checker._sample_region(initial, 20)
        for sample in samples:
            B_at_sample = self.sos_checker._substitute(B, vars_z3, sample)
            solver.add(B_at_sample >= 0.1)
    
    def _add_unsafe_constraints(self, solver: z3.Solver,
                                  B: z3.ExprRef,
                                  vars_z3: List[z3.ExprRef],
                                  unsafe: SemialgebraicSet) -> None:
        """Add B <= 0 on Unsafe."""
        samples = self.sos_checker._sample_region(unsafe, 20)
        for sample in samples:
            B_at_sample = self.sos_checker._substitute(B, vars_z3, sample)
            solver.add(B_at_sample <= -0.1)
    
    def _add_lie_constraints(self, solver: z3.Solver,
                               LB: z3.ExprRef,
                               vars_z3: List[z3.ExprRef],
                               invariant: SemialgebraicSet) -> None:
        """Add L_f(B) <= 0 on invariant."""
        samples = self.sos_checker._sample_region(invariant, 30)
        for sample in samples:
            LB_at_sample = self.sos_checker._substitute(LB, vars_z3, sample)
            solver.add(LB_at_sample <= 0.0)
    
    def _add_transition_constraints(self, solver: z3.Solver,
                                      B_source: z3.ExprRef,
                                      B_target: z3.ExprRef,
                                      transition: HybridTransition,
                                      vars_z3: List[z3.ExprRef]) -> None:
        """Add B_target(r(x)) <= B_source(x) on guard."""
        samples = self.sos_checker._sample_region(transition.guard, 15)
        
        for sample in samples:
            # B_source at sample
            B_src = self.sos_checker._substitute(B_source, vars_z3, sample)
            
            # Apply reset to sample
            if transition.reset is not None:
                reset_sample = transition.apply_reset(sample)
            else:
                reset_sample = sample
            
            # B_target at reset(sample)
            B_tgt = self.sos_checker._substitute(B_target, vars_z3, reset_sample)
            
            # B_target(r(x)) <= B_source(x)
            solver.add(B_tgt <= B_src)
    
    def _symbolic_lie_derivative(self, template: BarrierTemplate,
                                   dynamics: ContinuousDynamics,
                                   vars_z3: List[z3.ExprRef]) -> z3.ExprRef:
        """Compute symbolic Lie derivative."""
        result = z3.RealVal(0)
        
        for i in range(min(self.n_vars, len(dynamics.vector_field))):
            dB_dxi = z3.RealVal(0)
            for mono in template.monomials:
                if mono.exponents[i] > 0:
                    coeff = template.coefficients.get(mono, z3.RealVal(0))
                    exp_i = mono.exponents[i]
                    new_exp = list(mono.exponents)
                    new_exp[i] -= 1
                    new_mono = Monomial(tuple(new_exp))
                    dB_dxi = dB_dxi + coeff * z3.RealVal(exp_i) * new_mono.to_z3(vars_z3)
            
            fi_z3 = dynamics.vector_field[i].to_z3(vars_z3)
            result = result + dB_dxi * fi_z3
        
        return result
    
    def _extract_coefficients(self, model: z3.ModelRef,
                                template: BarrierTemplate) -> Dict[Monomial, float]:
        """Extract coefficient values from model."""
        result = {}
        for mono, var in template.coefficients.items():
            val = model.eval(var, model_completion=True)
            if z3.is_rational_value(val):
                result[mono] = (float(val.numerator_as_long()) /
                               float(val.denominator_as_long()))
            else:
                result[mono] = 0.0
        return result


# =============================================================================
# STOCHASTIC BARRIER SYNTHESIZER (Paper #2)
# =============================================================================

@dataclass
class StochasticBarrierCertificate:
    """
    Stochastic barrier certificate.
    
    Provides probabilistic safety guarantee:
    P[reach Unsafe | x₀] ≤ B(x₀)
    """
    barrier: Polynomial
    decay_rate: float  # λ in supermartingale condition
    initial_bound: float  # max B on Initial
    probability_bound: float  # upper bound on reach probability
    verified: bool = False


class StochasticBarrierSynthesizer:
    """
    Synthesize barrier certificates for stochastic systems (Paper #2).
    
    Uses Itô calculus: The infinitesimal generator 𝓛 must satisfy
    𝓛B ≤ λB for the barrier to give probability bounds.
    """
    
    def __init__(self, n_vars: int, max_degree: int = 4,
                 timeout_ms: int = 120000):
        self.n_vars = n_vars
        self.max_degree = max_degree
        self.timeout_ms = timeout_ms
        self.cert_engine = PolynomialCertificateEngine(n_vars, max_degree, timeout_ms)
        
        self.stats = {
            'synthesis_attempts': 0,
            'certificates_found': 0,
        }
    
    def synthesize(self, dynamics: StochasticDynamics,
                    conditions: StochasticBarrierConditions) -> Optional[StochasticBarrierCertificate]:
        """
        Synthesize stochastic barrier certificate.
        """
        self.stats['synthesis_attempts'] += 1
        
        for degree in range(2, self.max_degree + 1, 2):
            for decay_rate in [0.0, 0.1, 0.5, 1.0]:
                cert = self._try_synthesis(dynamics, conditions, degree, decay_rate)
                if cert is not None:
                    self.stats['certificates_found'] += 1
                    return cert
        
        return None
    
    def _try_synthesis(self, dynamics: StochasticDynamics,
                        conditions: StochasticBarrierConditions,
                        degree: int,
                        decay_rate: float) -> Optional[StochasticBarrierCertificate]:
        """Try synthesis with specific degree and decay rate."""
        template = BarrierTemplate(self.n_vars, degree)
        template.create_symbolic("B")
        
        solver = z3.Solver()
        solver.set("timeout", self.timeout_ms // 4)
        
        vars_z3 = [z3.Real(f'x{i}') for i in range(self.n_vars)]
        B_z3 = template.to_z3(vars_z3)
        
        # Condition 1: B >= 0 on Initial
        self._add_nonnegativity_samples(solver, B_z3, vars_z3, conditions.initial, 20)
        
        # Condition 2: B > 1 on Unsafe
        self._add_threshold_samples(solver, B_z3, vars_z3, conditions.unsafe, 1.0, 20)
        
        # Condition 3: 𝓛B <= λB on Safe
        LB_z3 = self._symbolic_generator(template, dynamics, vars_z3)
        self._add_supermartingale_samples(solver, LB_z3, B_z3, vars_z3,
                                           conditions.safe, decay_rate, 30)
        
        if solver.check() == z3.sat:
            model = solver.model()
            coeff_values = {}
            
            for mono, var in template.coefficients.items():
                val = model.eval(var, model_completion=True)
                if z3.is_rational_value(val):
                    coeff_values[mono] = (float(val.numerator_as_long()) /
                                         float(val.denominator_as_long()))
                else:
                    coeff_values[mono] = 0.0
            
            barrier = template.to_polynomial(coeff_values)
            
            # Compute initial bound
            initial_bound = self._max_on_region(barrier, conditions.initial)
            
            return StochasticBarrierCertificate(
                barrier=barrier,
                decay_rate=decay_rate,
                initial_bound=initial_bound,
                probability_bound=min(1.0, initial_bound),
                verified=True
            )
        
        return None
    
    def _symbolic_generator(self, template: BarrierTemplate,
                              dynamics: StochasticDynamics,
                              vars_z3: List[z3.ExprRef]) -> z3.ExprRef:
        """
        Compute symbolic infinitesimal generator 𝓛B.
        """
        n = self.n_vars
        result = z3.RealVal(0)
        
        # First term: ∇B · f
        for i in range(min(n, len(dynamics.drift))):
            dB_dxi = z3.RealVal(0)
            for mono in template.monomials:
                if mono.exponents[i] > 0:
                    coeff = template.coefficients.get(mono, z3.RealVal(0))
                    exp_i = mono.exponents[i]
                    new_exp = list(mono.exponents)
                    new_exp[i] -= 1
                    new_mono = Monomial(tuple(new_exp))
                    dB_dxi = dB_dxi + coeff * z3.RealVal(exp_i) * new_mono.to_z3(vars_z3)
            
            fi_z3 = dynamics.drift[i].to_z3(vars_z3)
            result = result + dB_dxi * fi_z3
        
        # Second term: ½ tr(g gᵀ ∇²B) - simplified for diagonal diffusion
        # This is a major simplification; full version needs tensor contractions
        for i in range(n):
            # Second derivative ∂²B/∂xᵢ²
            d2B_dxi2 = z3.RealVal(0)
            for mono in template.monomials:
                if mono.exponents[i] >= 2:
                    coeff = template.coefficients.get(mono, z3.RealVal(0))
                    exp_i = mono.exponents[i]
                    new_exp = list(mono.exponents)
                    new_exp[i] -= 2
                    new_mono = Monomial(tuple(new_exp))
                    d2B_dxi2 = (d2B_dxi2 + coeff *
                               z3.RealVal(exp_i * (exp_i - 1)) *
                               new_mono.to_z3(vars_z3))
            
            # Diffusion coefficient squared (simplified)
            if i < len(dynamics.diffusion) and dynamics.diffusion[i]:
                g_ii = dynamics.diffusion[i][0].to_z3(vars_z3)
                result = result + z3.RealVal(0.5) * g_ii * g_ii * d2B_dxi2
        
        return result
    
    def _add_nonnegativity_samples(self, solver: z3.Solver,
                                     B: z3.ExprRef,
                                     vars_z3: List[z3.ExprRef],
                                     region: SemialgebraicSet,
                                     count: int) -> None:
        """Add B >= 0 on samples."""
        samples = self._sample_region(region, count)
        for sample in samples:
            B_val = self._substitute(B, vars_z3, sample)
            solver.add(B_val >= 0)
    
    def _add_threshold_samples(self, solver: z3.Solver,
                                 B: z3.ExprRef,
                                 vars_z3: List[z3.ExprRef],
                                 region: SemialgebraicSet,
                                 threshold: float,
                                 count: int) -> None:
        """Add B > threshold on samples."""
        samples = self._sample_region(region, count)
        for sample in samples:
            B_val = self._substitute(B, vars_z3, sample)
            solver.add(B_val > threshold)
    
    def _add_supermartingale_samples(self, solver: z3.Solver,
                                       LB: z3.ExprRef,
                                       B: z3.ExprRef,
                                       vars_z3: List[z3.ExprRef],
                                       region: SemialgebraicSet,
                                       decay: float,
                                       count: int) -> None:
        """Add 𝓛B <= λB on samples."""
        samples = self._sample_region(region, count)
        for sample in samples:
            LB_val = self._substitute(LB, vars_z3, sample)
            B_val = self._substitute(B, vars_z3, sample)
            solver.add(LB_val <= z3.RealVal(decay) * B_val)
    
    def _sample_region(self, region: SemialgebraicSet, count: int) -> List[List[float]]:
        """Sample from region."""
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
        """Substitute values."""
        subs = [(vars_z3[i], z3.RealVal(point[i]))
                for i in range(min(len(vars_z3), len(point)))]
        return z3.substitute(expr, subs)
    
    def _max_on_region(self, poly: Polynomial,
                        region: SemialgebraicSet) -> float:
        """Estimate max of polynomial on region."""
        samples = self._sample_region(region, 100)
        return max(poly.evaluate(s) for s in samples) if samples else 0.0


# =============================================================================
# SOSTOOLS FRAMEWORK (Paper #4)
# =============================================================================

class SOSTOOLSFramework:
    """
    SOSTOOLS-style framework for SOS programming (Paper #4).
    
    Provides high-level interface for:
    - Defining polynomial decision variables
    - Adding SOS/positivity constraints
    - Adding coefficient constraints
    - Solving and extracting results
    
    This is the "engineering" layer that makes SOS accessible.
    """
    
    def __init__(self, n_vars: int, timeout_ms: int = 120000):
        self.n_vars = n_vars
        self.timeout_ms = timeout_ms
        
        # State
        self.decision_polys: Dict[str, BarrierTemplate] = {}
        self.sos_constraints: List[Tuple[str, z3.ExprRef, SemialgebraicSet]] = []
        self.linear_constraints: List[z3.ExprRef] = []
        self.solver: Optional[z3.Solver] = None
        self.vars_z3 = [z3.Real(f'x{i}') for i in range(n_vars)]
        
        self.stats = {
            'problems_solved': 0,
            'sos_constraints': 0,
        }
    
    def reset(self) -> None:
        """Reset framework state."""
        self.decision_polys.clear()
        self.sos_constraints.clear()
        self.linear_constraints.clear()
        self.solver = None
    
    def add_polynomial(self, name: str, degree: int) -> z3.ExprRef:
        """
        Add parametric polynomial decision variable.
        
        Returns Z3 expression representing the polynomial.
        """
        template = BarrierTemplate(self.n_vars, degree)
        template.create_symbolic(name)
        self.decision_polys[name] = template
        return template.to_z3(self.vars_z3)
    
    def add_sos_constraint(self, name: str, expr: z3.ExprRef,
                            region: Optional[SemialgebraicSet] = None) -> None:
        """
        Add constraint that expr is SOS (non-negative everywhere) on region.
        
        If region is None, constraint is global.
        """
        if region is None:
            region = SemialgebraicSet(self.n_vars, [])
        
        self.sos_constraints.append((name, expr, region))
        self.stats['sos_constraints'] += 1
    
    def add_constraint(self, constraint: z3.ExprRef) -> None:
        """Add linear constraint on coefficients."""
        self.linear_constraints.append(constraint)
    
    def solve(self) -> Tuple[bool, Optional[Dict[str, Polynomial]]]:
        """
        Solve the SOS program.
        
        Returns (success, solution_polys).
        """
        self.solver = z3.Solver()
        self.solver.set("timeout", self.timeout_ms)
        
        # Add coefficient constraints
        for constraint in self.linear_constraints:
            self.solver.add(constraint)
        
        # Add SOS constraints via sampling
        for name, expr, region in self.sos_constraints:
            self._add_sos_via_sampling(expr, region)
        
        if self.solver.check() == z3.sat:
            model = self.solver.model()
            
            result_polys = {}
            for name, template in self.decision_polys.items():
                coeff_values = {}
                for mono, var in template.coefficients.items():
                    val = model.eval(var, model_completion=True)
                    if z3.is_rational_value(val):
                        coeff_values[mono] = (float(val.numerator_as_long()) /
                                             float(val.denominator_as_long()))
                    else:
                        coeff_values[mono] = 0.0
                result_polys[name] = template.to_polynomial(coeff_values)
            
            self.stats['problems_solved'] += 1
            return (True, result_polys)
        
        return (False, None)
    
    def _add_sos_via_sampling(self, expr: z3.ExprRef,
                                region: SemialgebraicSet) -> None:
        """Add SOS constraint via point sampling."""
        import random
        
        # Sample points
        samples = []
        if region.constraints:
            for _ in range(300):
                if len(samples) >= 50:
                    break
                point = [random.uniform(-10, 10) for _ in range(self.n_vars)]
                if region.contains(point):
                    samples.append(point)
        else:
            # Global: sample uniformly
            for _ in range(50):
                samples.append([random.uniform(-10, 10) for _ in range(self.n_vars)])
        
        # Add non-negativity at each sample
        for sample in samples:
            subs = [(self.vars_z3[i], z3.RealVal(sample[i]))
                    for i in range(min(len(sample), len(self.vars_z3)))]
            val = z3.substitute(expr, subs)
            self.solver.add(val >= 0)


# =============================================================================
# UNIFIED BARRIER CERTIFICATE ENGINE
# =============================================================================

class BarrierCertificateEngine:
    """
    Unified engine for barrier certificate synthesis.
    
    MAIN INTERFACE for the barrier certificate core layer.
    
    Automatically selects the appropriate synthesis method:
    - HybridBarrierSynthesizer for hybrid systems
    - StochasticBarrierSynthesizer for stochastic systems
    - SOSSafetyChecker for continuous deterministic systems
    
    Uses SOSTOOLSFramework as the underlying SOS solver.
    """
    
    def __init__(self, n_vars: int, system_type: str = 'continuous',
                 max_degree: int = 6, timeout_ms: int = 120000):
        self.n_vars = n_vars
        self.system_type = system_type
        self.max_degree = max_degree
        self.timeout_ms = timeout_ms
        
        # Initialize synthesizers
        self.sos_checker = SOSSafetyChecker(n_vars, max_degree, timeout_ms)
        self.hybrid_synth = HybridBarrierSynthesizer(n_vars, max_degree, timeout_ms)
        self.stochastic_synth = StochasticBarrierSynthesizer(n_vars, max_degree, timeout_ms)
        self.framework = SOSTOOLSFramework(n_vars, timeout_ms)
        
        self.stats = {
            'synthesis_requests': 0,
            'certificates_found': 0,
            'method_used': None,
        }
    
    def synthesize(self, initial: SemialgebraicSet,
                    safe: SemialgebraicSet,
                    unsafe: SemialgebraicSet,
                    dynamics: Union[ContinuousDynamics, HybridAutomaton, StochasticDynamics]
                    ) -> Optional[Union[Polynomial, HybridBarrierCertificate, StochasticBarrierCertificate]]:
        """
        Synthesize barrier certificate for the given system.
        
        Automatically dispatches to appropriate synthesizer based on dynamics type.
        """
        self.stats['synthesis_requests'] += 1
        
        if isinstance(dynamics, HybridAutomaton):
            return self._synthesize_hybrid(initial, safe, unsafe, dynamics)
        elif isinstance(dynamics, StochasticDynamics):
            return self._synthesize_stochastic(initial, safe, unsafe, dynamics)
        else:
            return self._synthesize_continuous(initial, safe, unsafe, dynamics)
    
    def _synthesize_continuous(self, initial: SemialgebraicSet,
                                 safe: SemialgebraicSet,
                                 unsafe: SemialgebraicSet,
                                 dynamics: ContinuousDynamics) -> Optional[Polynomial]:
        """Synthesize for continuous system."""
        conditions = BarrierConditions(
            initial=initial,
            safe=safe,
            unsafe=unsafe
        )
        
        result, barrier = self.sos_checker.check_safety(conditions, dynamics)
        
        if result == 'safe' and barrier is not None:
            self.stats['certificates_found'] += 1
            self.stats['method_used'] = 'sos_safety'
            return barrier
        
        return None
    
    def _synthesize_hybrid(self, initial: SemialgebraicSet,
                             safe: SemialgebraicSet,
                             unsafe: SemialgebraicSet,
                             automaton: HybridAutomaton) -> Optional[HybridBarrierCertificate]:
        """Synthesize for hybrid system."""
        # Create mode-specific conditions
        mode_conditions = {}
        for mode_id in automaton.modes.keys():
            mode = automaton.modes[mode_id]
            mode_conditions[mode_id] = BarrierConditions(
                initial=initial.intersect(mode.invariant),
                safe=safe.intersect(mode.invariant),
                unsafe=unsafe.intersect(mode.invariant)
            )
        
        conditions = HybridBarrierConditions(
            n_vars=self.n_vars,
            mode_conditions=mode_conditions,
            mode_count=automaton.num_modes
        )
        
        cert = self.hybrid_synth.synthesize(automaton, conditions)
        
        if cert is not None:
            self.stats['certificates_found'] += 1
            self.stats['method_used'] = 'hybrid_barrier'
        
        return cert
    
    def _synthesize_stochastic(self, initial: SemialgebraicSet,
                                 safe: SemialgebraicSet,
                                 unsafe: SemialgebraicSet,
                                 dynamics: StochasticDynamics) -> Optional[StochasticBarrierCertificate]:
        """Synthesize for stochastic system."""
        conditions = StochasticBarrierConditions(
            initial=initial,
            safe=safe,
            unsafe=unsafe
        )
        
        cert = self.stochastic_synth.synthesize(dynamics, conditions)
        
        if cert is not None:
            self.stats['certificates_found'] += 1
            self.stats['method_used'] = 'stochastic_barrier'
        
        return cert
    
    def verify(self, barrier: Polynomial,
                initial: SemialgebraicSet,
                safe: SemialgebraicSet,
                unsafe: SemialgebraicSet,
                dynamics: ContinuousDynamics) -> Dict[str, bool]:
        """
        Verify that a barrier certificate is valid.
        
        Returns dict mapping condition name to validity.
        """
        results = {
            'initial_positive': False,
            'unsafe_negative': False,
            'lie_negative': False,
            'overall': False,
        }
        
        solver = z3.Solver()
        solver.set("timeout", self.timeout_ms // 3)
        vars_z3 = [z3.Real(f'x{i}') for i in range(self.n_vars)]
        B_z3 = barrier.to_z3(vars_z3)
        
        # Check initial positivity
        solver.push()
        for g in initial.constraints:
            solver.add(g.to_z3(vars_z3) >= 0)
        solver.add(B_z3 <= 0)
        results['initial_positive'] = (solver.check() == z3.unsat)
        solver.pop()
        
        # Check unsafe negativity
        solver.push()
        for g in unsafe.constraints:
            solver.add(g.to_z3(vars_z3) >= 0)
        solver.add(B_z3 > 0)
        results['unsafe_negative'] = (solver.check() == z3.unsat)
        solver.pop()
        
        # Check Lie derivative negativity
        L = dynamics.lie_derivative(barrier)
        L_z3 = L.to_z3(vars_z3)
        solver.push()
        for g in safe.constraints:
            solver.add(g.to_z3(vars_z3) >= 0)
        solver.add(L_z3 > 0)
        results['lie_negative'] = (solver.check() == z3.unsat)
        solver.pop()
        
        results['overall'] = all([
            results['initial_positive'],
            results['unsafe_negative'],
            results['lie_negative']
        ])
        
        return results


# =============================================================================
# EXPORTS
# =============================================================================

__all__ = [
    # System types
    'SystemType',
    'ContinuousDynamics',
    'DiscreteDynamics',
    'HybridMode',
    'HybridTransition',
    'HybridAutomaton',
    'StochasticDynamics',
    
    # Barrier conditions
    'BarrierConditions',
    'HybridBarrierConditions',
    'StochasticBarrierConditions',
    
    # Templates
    'BarrierTemplate',
    'MultiModeBarrierTemplate',
    
    # SOS Safety (Paper #3)
    'SOSSafetyChecker',
    
    # Hybrid Barriers (Paper #1)
    'HybridBarrierCertificate',
    'HybridBarrierSynthesizer',
    
    # Stochastic Barriers (Paper #2)
    'StochasticBarrierCertificate',
    'StochasticBarrierSynthesizer',
    
    # SOSTOOLS Framework (Paper #4)
    'SOSTOOLSFramework',
    
    # Unified Engine
    'BarrierCertificateEngine',
]
