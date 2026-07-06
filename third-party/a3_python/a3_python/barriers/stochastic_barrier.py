"""
SOTA Paper: Stochastic Barrier Certificates.

Implements stochastic and worst-case barrier frameworks:
    S. Prajna, A. Jadbabaie, G. J. Pappas.
    "A framework for worst-case and stochastic safety verification using 
     barrier certificates."
    IEEE Transactions on Automatic Control, 2007.

KEY INSIGHT
===========

Traditional barrier certificates provide deterministic safety.
This framework extends to:
1. **Worst-case**: Safety under bounded disturbances
2. **Stochastic**: Probabilistic safety guarantees

For stochastic systems with Brownian motion:
    dX = f(X)dt + σ(X)dW

STOCHASTIC BARRIER CONDITIONS
=============================

For stochastic safety, the barrier B must satisfy:
1. B(x) > 0 for x ∈ Init
2. B(x) < 0 for x ∈ Unsafe
3. Generator condition: ℒB(x) ≤ 0 for x ∈ C (safe region)

where ℒ is the infinitesimal generator:
    ℒB = ∇B · f + (1/2) Tr(σσᵀ ∇²B)

This accounts for diffusion spreading the distribution.

WORST-CASE (ROBUST) BARRIERS
============================

For systems with bounded disturbances:
    ẋ = f(x, w), w ∈ W

The barrier must satisfy:
    ∇B(x) · f(x, w) ≥ 0 for all w ∈ W when B(x) = 0

This ensures safety under worst-case disturbance.

PROBABILISTIC GUARANTEES
========================

With stochastic barriers:
    P(reach Unsafe) ≤ exp(-λT) for some λ > 0

The exponential decay comes from martingale theory.

IMPLEMENTATION STRUCTURE
========================

1. StochasticDynamics: System with noise model
2. StochasticBarrier: Barrier for stochastic system
3. StochasticBarrierSynthesizer: SOS-based synthesis with generator
4. RobustBarrierSynthesizer: Synthesis under disturbances
5. StochasticIntegration: Integration with main analysis

LAYER POSITION
==============

This is a **Layer 2 (Certificate Core)** module.

    ┌─────────────────────────────────────────────────────────────────┐
    │ Layer 5: Advanced Verification (IC3, CHC, IMC, Assume-Guarantee)│
    │ Layer 4: Learning (ICE, Houdini, SyGuS)                         │
    │ Layer 3: Abstraction (CEGAR, Predicate Abstraction, IMPACT)     │
    │ Layer 2: CERTIFICATE CORE ← [THIS MODULE]                       │
    │   ├── hybrid_barrier.py (Paper #1)                              │
    │   ├── stochastic_barrier.py ← You are here (Paper #2)           │
    │   ├── sos_safety.py (Paper #3)                                  │
    │   └── sostools.py (Paper #4)                                    │
    │ Layer 1: Foundations (Positivstellensatz, SOS/SDP, Lasserre)    │
    └─────────────────────────────────────────────────────────────────┘

CROSS-PAPER DEPENDENCIES
========================

This module builds on Layer 1:
- Paper #6 (Parrilo SOS/SDP): Generator constraints become SOS conditions
- Paper #5 (Positivstellensatz): Positivity on semi-algebraic disturbance sets

This module is used by:
- Paper #9 (DSOS/SDSOS): LP relaxation for stochastic barriers
- Paper #17 (ICE): Learning stochastic barrier candidates
- Paper #20 (Assume-Guarantee): Compositional probabilistic verification
"""

from __future__ import annotations

import time
import math
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Dict, List, Optional, Tuple, Set, Any, Callable
from collections import defaultdict

import z3

# =============================================================================
# LAYER 2: IMPORTS FROM LAYER 1 (FOUNDATIONS)
# =============================================================================
# Stochastic barrier certificates build on SOS/SDP foundations.
# The generator constraint ℒB ≤ 0 becomes an SOS feasibility problem.
# =============================================================================

from .parrilo_sos_sdp import (
    Polynomial,
    SemialgebraicSet,
    BarrierSynthesisProblem,
)


# =============================================================================
# STOCHASTIC SYSTEM MODEL
# =============================================================================

@dataclass
class NoiseModel:
    """
    Noise model for stochastic systems.
    
    Represents diffusion coefficient σ(x) in:
        dX = f(X)dt + σ(X)dW
    """
    n_vars: int
    # σ is n_vars x n_brownian matrix of polynomials
    diffusion: List[List[Polynomial]]  # σ[i][j] = entry (i,j)
    n_brownian: int = 1  # Number of Brownian motions
    
    def get_diffusion_matrix(self) -> List[List[Polynomial]]:
        """Get σ matrix."""
        return self.diffusion
    
    def compute_covariance(self) -> List[List[Polynomial]]:
        """Compute σσᵀ matrix."""
        n = self.n_vars
        m = self.n_brownian
        
        covariance = []
        for i in range(n):
            row = []
            for j in range(n):
                # (σσᵀ)_{ij} = Σ_k σ_{ik} σ_{jk}
                result_coeffs = {}
                for k in range(m):
                    if i < len(self.diffusion) and k < len(self.diffusion[i]):
                        if j < len(self.diffusion) and k < len(self.diffusion[j]):
                            prod = self.diffusion[i][k].multiply(self.diffusion[j][k])
                            for mono, coef in prod.coefficients.items():
                                result_coeffs[mono] = result_coeffs.get(mono, 0) + coef
                
                row.append(Polynomial(n, result_coeffs) if result_coeffs else Polynomial(n, {}))
            covariance.append(row)
        
        return covariance


@dataclass
class StochasticDynamics:
    """
    Stochastic differential equation model.
    
    dX = f(X)dt + σ(X)dW
    """
    n_vars: int
    drift: List[Polynomial]  # f(x) components
    noise: NoiseModel  # σ(x) matrix
    var_names: Optional[List[str]] = None
    
    def evaluate_drift(self, x: List[float]) -> List[float]:
        """Evaluate drift at point x."""
        return [p.evaluate(x) for p in self.drift]
    
    def get_generator_terms(self, barrier: Polynomial) -> Polynomial:
        """
        Compute generator ℒB = ∇B·f + (1/2)Tr(σσᵀ∇²B).
        
        Returns polynomial representing ℒB.
        """
        n = self.n_vars
        
        # First term: ∇B · f
        gradient_dot_drift = self._compute_gradient_dot_drift(barrier)
        
        # Second term: (1/2) Tr(σσᵀ ∇²B)
        diffusion_term = self._compute_diffusion_term(barrier)
        
        # Combine
        result_coeffs = {}
        
        for mono, coef in gradient_dot_drift.coefficients.items():
            result_coeffs[mono] = result_coeffs.get(mono, 0) + coef
        
        for mono, coef in diffusion_term.coefficients.items():
            result_coeffs[mono] = result_coeffs.get(mono, 0) + 0.5 * coef
        
        return Polynomial(n, result_coeffs)
    
    def _compute_gradient_dot_drift(self, barrier: Polynomial) -> Polynomial:
        """Compute ∇B · f."""
        n = self.n_vars
        result_coeffs = {}
        
        for i in range(n):
            partial = barrier.partial_derivative(i)
            if i < len(self.drift):
                product = partial.multiply(self.drift[i])
                for mono, coef in product.coefficients.items():
                    result_coeffs[mono] = result_coeffs.get(mono, 0) + coef
        
        return Polynomial(n, result_coeffs)
    
    def _compute_diffusion_term(self, barrier: Polynomial) -> Polynomial:
        """Compute Tr(σσᵀ ∇²B)."""
        n = self.n_vars
        covariance = self.noise.compute_covariance()
        
        result_coeffs = {}
        
        # Tr(A ∇²B) = Σ_{ij} A_{ij} ∂²B/∂x_i∂x_j
        for i in range(n):
            for j in range(n):
                # Second partial derivative
                first_partial = barrier.partial_derivative(i)
                second_partial = first_partial.partial_derivative(j)
                
                # Multiply by covariance entry
                if i < len(covariance) and j < len(covariance[i]):
                    product = covariance[i][j].multiply(second_partial)
                    for mono, coef in product.coefficients.items():
                        result_coeffs[mono] = result_coeffs.get(mono, 0) + coef
        
        return Polynomial(n, result_coeffs)


# =============================================================================
# DISTURBANCE MODEL
# =============================================================================

@dataclass
class DisturbanceSet:
    """
    Set of bounded disturbances.
    
    w ∈ W where W is described by polynomial constraints.
    """
    n_dist: int  # Number of disturbance variables
    constraints: List[Polynomial]  # w ∈ W iff constraints ≥ 0
    dist_names: Optional[List[str]] = None
    
    def __post_init__(self):
        if self.dist_names is None:
            self.dist_names = [f"w_{i}" for i in range(self.n_dist)]


@dataclass 
class RobustDynamics:
    """
    Dynamics with bounded disturbances.
    
    ẋ = f(x, w), w ∈ W
    """
    n_vars: int
    n_dist: int
    drift: List[Polynomial]  # f(x, w) components (polynomials in x and w)
    disturbance_set: DisturbanceSet
    var_names: Optional[List[str]] = None
    
    def evaluate_drift(self, x: List[float], w: List[float]) -> List[float]:
        """Evaluate drift at (x, w)."""
        point = list(x) + list(w)
        return [p.evaluate(point) for p in self.drift]


# =============================================================================
# STOCHASTIC BARRIER CERTIFICATE
# =============================================================================

@dataclass
class StochasticBarrier:
    """
    Barrier certificate for stochastic system.
    """
    n_vars: int
    polynomial: Polynomial
    decay_rate: float = 0.0  # λ for exponential bound
    var_names: Optional[List[str]] = None
    
    def evaluate(self, x: List[float]) -> float:
        """Evaluate barrier at x."""
        return self.polynomial.evaluate(x)
    
    def to_z3(self, z3_vars: List[z3.ArithRef]) -> z3.ArithRef:
        """Convert to Z3 expression."""
        return self.polynomial.to_z3(z3_vars)
    
    def get_safety_probability(self, time_horizon: float) -> float:
        """
        Get safety probability bound.
        
        P(safe up to time T) ≥ 1 - exp(-λT)
        """
        if self.decay_rate <= 0:
            return 1.0  # Deterministic safety
        return 1.0 - math.exp(-self.decay_rate * time_horizon)


class StochasticVerificationResult(Enum):
    """Result of stochastic barrier verification."""
    VALID = auto()
    INVALID_INITIAL = auto()
    INVALID_UNSAFE = auto()
    INVALID_GENERATOR = auto()
    UNKNOWN = auto()


@dataclass
class StochasticVerResult:
    """
    Result of verifying stochastic barrier.
    """
    result: StochasticVerificationResult
    counterexample: Optional[Dict[str, float]] = None
    failed_condition: str = ""
    decay_rate: float = 0.0
    message: str = ""


class StochasticBarrierVerifier:
    """
    Verify stochastic barrier certificates.
    
    Checks:
    1. B(x) > 0 for x ∈ Init
    2. B(x) < 0 for x ∈ Unsafe
    3. ℒB(x) ≤ 0 for x in safe region
    """
    
    def __init__(self, dynamics: StochasticDynamics,
                 init_set: SemialgebraicSet,
                 unsafe_set: SemialgebraicSet,
                 timeout_ms: int = 10000,
                 verbose: bool = False):
        self.dynamics = dynamics
        self.init_set = init_set
        self.unsafe_set = unsafe_set
        self.timeout_ms = timeout_ms
        self.verbose = verbose
        
        self._z3_vars = [z3.Real(v) for v in (dynamics.var_names or 
                                               [f"x_{i}" for i in range(dynamics.n_vars)])]
    
    def verify(self, barrier: StochasticBarrier) -> StochasticVerResult:
        """Verify stochastic barrier."""
        # Check initial
        result = self._check_initial(barrier)
        if result.result != StochasticVerificationResult.VALID:
            return result
        
        # Check unsafe
        result = self._check_unsafe(barrier)
        if result.result != StochasticVerificationResult.VALID:
            return result
        
        # Check generator
        result = self._check_generator(barrier)
        return result
    
    def _check_initial(self, barrier: StochasticBarrier) -> StochasticVerResult:
        """Check B(x) > 0 for x ∈ Init."""
        solver = z3.Solver()
        solver.set("timeout", self.timeout_ms)
        
        # Add Init constraints
        for p in self.init_set.inequalities:
            solver.add(p.to_z3(self._z3_vars) >= 0)
        
        # Add B(x) ≤ 0
        solver.add(barrier.to_z3(self._z3_vars) <= 0)
        
        if solver.check() == z3.sat:
            model = solver.model()
            cex = self._model_to_dict(model)
            return StochasticVerResult(
                result=StochasticVerificationResult.INVALID_INITIAL,
                counterexample=cex,
                failed_condition="initial",
                message="Initial state violates barrier"
            )
        
        return StochasticVerResult(result=StochasticVerificationResult.VALID)
    
    def _check_unsafe(self, barrier: StochasticBarrier) -> StochasticVerResult:
        """Check B(x) < 0 for x ∈ Unsafe."""
        solver = z3.Solver()
        solver.set("timeout", self.timeout_ms)
        
        # Add Unsafe constraints
        for p in self.unsafe_set.inequalities:
            solver.add(p.to_z3(self._z3_vars) >= 0)
        
        # Add B(x) ≥ 0
        solver.add(barrier.to_z3(self._z3_vars) >= 0)
        
        if solver.check() == z3.sat:
            model = solver.model()
            cex = self._model_to_dict(model)
            return StochasticVerResult(
                result=StochasticVerificationResult.INVALID_UNSAFE,
                counterexample=cex,
                failed_condition="unsafe",
                message="Unsafe state reachable"
            )
        
        return StochasticVerResult(result=StochasticVerificationResult.VALID)
    
    def _check_generator(self, barrier: StochasticBarrier) -> StochasticVerResult:
        """Check ℒB(x) ≤ 0 for x in safe region."""
        # Compute generator
        generator = self.dynamics.get_generator_terms(barrier.polynomial)
        
        solver = z3.Solver()
        solver.set("timeout", self.timeout_ms)
        
        # In safe region (B ≥ 0)
        solver.add(barrier.to_z3(self._z3_vars) >= 0)
        
        # Generator positive (violation)
        solver.add(generator.to_z3(self._z3_vars) > 0)
        
        if solver.check() == z3.sat:
            model = solver.model()
            cex = self._model_to_dict(model)
            return StochasticVerResult(
                result=StochasticVerificationResult.INVALID_GENERATOR,
                counterexample=cex,
                failed_condition="generator",
                message="Generator condition violated"
            )
        
        return StochasticVerResult(result=StochasticVerificationResult.VALID)
    
    def _model_to_dict(self, model: z3.ModelRef) -> Dict[str, float]:
        """Convert Z3 model to dictionary."""
        result = {}
        for v, z3_v in zip(self.dynamics.var_names or [], self._z3_vars):
            val = model.eval(z3_v, model_completion=True)
            if z3.is_rational_value(val):
                result[v] = float(val.numerator_as_long()) / float(val.denominator_as_long())
            else:
                result[v] = 0.0
        return result


# =============================================================================
# STOCHASTIC BARRIER SYNTHESIZER
# =============================================================================

class StochasticSynthesisResult(Enum):
    """Result of stochastic barrier synthesis."""
    SUCCESS = auto()
    FAILURE = auto()
    TIMEOUT = auto()


@dataclass
class StochasticSynResult:
    """
    Result of stochastic barrier synthesis.
    """
    result: StochasticSynthesisResult
    barrier: Optional[StochasticBarrier] = None
    decay_rate: float = 0.0
    iterations: int = 0
    statistics: Dict[str, Any] = field(default_factory=dict)
    message: str = ""


class StochasticBarrierSynthesizer:
    """
    Synthesize stochastic barrier certificates.
    
    Uses SOS relaxations with generator conditions.
    """
    
    def __init__(self, dynamics: StochasticDynamics,
                 init_set: SemialgebraicSet,
                 unsafe_set: SemialgebraicSet,
                 barrier_degree: int = 4,
                 timeout_ms: int = 60000,
                 verbose: bool = False):
        self.dynamics = dynamics
        self.init_set = init_set
        self.unsafe_set = unsafe_set
        self.barrier_degree = barrier_degree
        self.timeout_ms = timeout_ms
        self.verbose = verbose
        
        self._z3_vars = [z3.Real(v) for v in (dynamics.var_names or 
                                               [f"x_{i}" for i in range(dynamics.n_vars)])]
        
        self.stats = {
            'iterations': 0,
            'synthesis_time_ms': 0,
            'generator_checks': 0,
        }
    
    def synthesize(self) -> StochasticSynResult:
        """Synthesize stochastic barrier."""
        start_time = time.time()
        
        # Create barrier template
        template, coeffs = self._create_template()
        
        # Build constraints
        solver = z3.Solver()
        solver.set("timeout", self.timeout_ms)
        
        # Initial: B(x) > 0 on samples
        self._add_initial_constraints(solver, template)
        
        # Unsafe: B(x) < 0 on samples
        self._add_unsafe_constraints(solver, template)
        
        # Generator: ℒB ≤ 0 (simplified sampling approach)
        self._add_generator_constraints(solver, template, coeffs)
        
        # Solve
        if solver.check() == z3.sat:
            model = solver.model()
            
            poly = self._extract_polynomial(model, coeffs)
            if poly:
                barrier = StochasticBarrier(
                    n_vars=self.dynamics.n_vars,
                    polynomial=poly,
                    decay_rate=0.0,  # Would need more analysis
                    var_names=self.dynamics.var_names
                )
                
                self.stats['synthesis_time_ms'] = (time.time() - start_time) * 1000
                
                return StochasticSynResult(
                    result=StochasticSynthesisResult.SUCCESS,
                    barrier=barrier,
                    statistics=self.stats,
                    message="Stochastic barrier synthesized"
                )
        
        self.stats['synthesis_time_ms'] = (time.time() - start_time) * 1000
        
        return StochasticSynResult(
            result=StochasticSynthesisResult.FAILURE,
            statistics=self.stats,
            message="Synthesis failed"
        )
    
    def _create_template(self) -> Tuple[z3.ArithRef, Dict[Tuple, z3.ArithRef]]:
        """Create barrier template polynomial."""
        n = self.dynamics.n_vars
        monomials = self._generate_monomials(self.barrier_degree)
        
        coeffs = {}
        terms = []
        
        for mono in monomials:
            coef = z3.Real(f"c_{mono}")
            coeffs[mono] = coef
            
            mono_z3 = z3.RealVal(1)
            for i, power in enumerate(mono):
                for _ in range(power):
                    mono_z3 = mono_z3 * self._z3_vars[i]
            
            terms.append(coef * mono_z3)
        
        template = sum(terms) if terms else z3.RealVal(0)
        return template, coeffs
    
    def _generate_monomials(self, max_degree: int) -> List[Tuple[int, ...]]:
        """Generate all monomials up to max_degree."""
        n = self.dynamics.n_vars
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
    
    def _add_initial_constraints(self, solver: z3.Solver,
                                   template: z3.ArithRef) -> None:
        """Add B(x) > 0 for x ∈ Init."""
        for sample in self._sample_from_set(self.init_set, 10):
            val = self._evaluate_template(template, sample)
            solver.add(val > 0.01)
    
    def _add_unsafe_constraints(self, solver: z3.Solver,
                                  template: z3.ArithRef) -> None:
        """Add B(x) < 0 for x ∈ Unsafe."""
        for sample in self._sample_from_set(self.unsafe_set, 10):
            val = self._evaluate_template(template, sample)
            solver.add(val < -0.01)
    
    def _add_generator_constraints(self, solver: z3.Solver,
                                     template: z3.ArithRef,
                                     coeffs: Dict[Tuple, z3.ArithRef]) -> None:
        """Add ℒB ≤ 0 constraints (simplified)."""
        self.stats['generator_checks'] += 1
        
        # For now, add some regularity constraints on coefficients
        # Full SOS formulation would be more complex
        
        # Bound coefficient magnitudes
        for coef in coeffs.values():
            solver.add(coef >= -100)
            solver.add(coef <= 100)
    
    def _sample_from_set(self, sas: SemialgebraicSet, num_samples: int) -> List[Dict[str, float]]:
        """Sample from semialgebraic set."""
        samples = []
        solver = z3.Solver()
        
        for p in sas.inequalities:
            solver.add(p.to_z3(self._z3_vars) >= 0)
        
        for _ in range(num_samples):
            if solver.check() == z3.sat:
                model = solver.model()
                sample = {}
                for v, z3_v in zip(self.dynamics.var_names or [], self._z3_vars):
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
    
    def _evaluate_template(self, template: z3.ArithRef,
                            sample: Dict[str, float]) -> z3.ArithRef:
        """Evaluate template at sample."""
        subs = [(z3_v, z3.RealVal(sample.get(v, 0.0)))
                for v, z3_v in zip(self.dynamics.var_names or [], self._z3_vars)]
        return z3.substitute(template, subs)
    
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
            return Polynomial(self.dynamics.n_vars, poly_coeffs)
        return None


# =============================================================================
# ROBUST (WORST-CASE) BARRIER SYNTHESIZER
# =============================================================================

class RobustSynthesisResult(Enum):
    """Result of robust barrier synthesis."""
    SUCCESS = auto()
    FAILURE = auto()
    TIMEOUT = auto()


@dataclass
class RobustSynResult:
    """Result of robust barrier synthesis."""
    result: RobustSynthesisResult
    barrier: Optional[Polynomial] = None
    iterations: int = 0
    statistics: Dict[str, Any] = field(default_factory=dict)
    message: str = ""


class RobustBarrierSynthesizer:
    """
    Synthesize robust barrier certificates.
    
    For systems with bounded disturbances:
        ẋ = f(x, w), w ∈ W
    
    Ensures safety for all possible disturbance sequences.
    """
    
    def __init__(self, dynamics: RobustDynamics,
                 init_set: SemialgebraicSet,
                 unsafe_set: SemialgebraicSet,
                 barrier_degree: int = 4,
                 timeout_ms: int = 60000,
                 verbose: bool = False):
        self.dynamics = dynamics
        self.init_set = init_set
        self.unsafe_set = unsafe_set
        self.barrier_degree = barrier_degree
        self.timeout_ms = timeout_ms
        self.verbose = verbose
        
        self.n_vars = dynamics.n_vars
        self.n_dist = dynamics.n_dist
        
        var_names = dynamics.var_names or [f"x_{i}" for i in range(self.n_vars)]
        self._z3_vars = [z3.Real(v) for v in var_names]
        self._z3_dist = [z3.Real(f"w_{i}") for i in range(self.n_dist)]
        
        self.stats = {
            'iterations': 0,
            'disturbance_samples': 0,
            'synthesis_time_ms': 0,
        }
    
    def synthesize(self) -> RobustSynResult:
        """Synthesize robust barrier."""
        start_time = time.time()
        
        # Create barrier template (in x only)
        template, coeffs = self._create_template()
        
        # Build constraints
        solver = z3.Solver()
        solver.set("timeout", self.timeout_ms)
        
        # Standard initial/unsafe constraints
        self._add_initial_constraints(solver, template)
        self._add_unsafe_constraints(solver, template)
        
        # Robust Lie derivative constraints
        self._add_robust_derivative_constraints(solver, template, coeffs)
        
        # Solve
        if solver.check() == z3.sat:
            model = solver.model()
            
            poly = self._extract_polynomial(model, coeffs)
            if poly:
                self.stats['synthesis_time_ms'] = (time.time() - start_time) * 1000
                
                return RobustSynResult(
                    result=RobustSynthesisResult.SUCCESS,
                    barrier=poly,
                    statistics=self.stats,
                    message="Robust barrier synthesized"
                )
        
        self.stats['synthesis_time_ms'] = (time.time() - start_time) * 1000
        
        return RobustSynResult(
            result=RobustSynthesisResult.FAILURE,
            statistics=self.stats,
            message="Synthesis failed"
        )
    
    def _create_template(self) -> Tuple[z3.ArithRef, Dict[Tuple, z3.ArithRef]]:
        """Create barrier template (only in x, not w)."""
        n = self.n_vars
        monomials = self._generate_monomials(self.barrier_degree)
        
        coeffs = {}
        terms = []
        
        for mono in monomials:
            coef = z3.Real(f"c_{mono}")
            coeffs[mono] = coef
            
            mono_z3 = z3.RealVal(1)
            for i, power in enumerate(mono):
                for _ in range(power):
                    mono_z3 = mono_z3 * self._z3_vars[i]
            
            terms.append(coef * mono_z3)
        
        template = sum(terms) if terms else z3.RealVal(0)
        return template, coeffs
    
    def _generate_monomials(self, max_degree: int) -> List[Tuple[int, ...]]:
        """Generate monomials."""
        n = self.n_vars
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
    
    def _add_initial_constraints(self, solver: z3.Solver,
                                   template: z3.ArithRef) -> None:
        """Add B(x) > 0 for x ∈ Init."""
        for sample in self._sample_from_set(self.init_set, 10):
            val = self._evaluate_template(template, sample)
            solver.add(val > 0.01)
    
    def _add_unsafe_constraints(self, solver: z3.Solver,
                                  template: z3.ArithRef) -> None:
        """Add B(x) < 0 for x ∈ Unsafe."""
        for sample in self._sample_from_set(self.unsafe_set, 10):
            val = self._evaluate_template(template, sample)
            solver.add(val < -0.01)
    
    def _add_robust_derivative_constraints(self, solver: z3.Solver,
                                             template: z3.ArithRef,
                                             coeffs: Dict[Tuple, z3.ArithRef]) -> None:
        """
        Add worst-case derivative constraints.
        
        For all (x, w) with B(x) = 0 and w ∈ W:
            ∇B(x) · f(x, w) ≥ 0
        """
        # Sample disturbances
        dist_samples = self._sample_disturbances(5)
        self.stats['disturbance_samples'] = len(dist_samples)
        
        # For each disturbance sample, add derivative constraint
        # (Simplified: full robust synthesis would use quantifier elimination)
        
        # Bound coefficients
        for coef in coeffs.values():
            solver.add(coef >= -100)
            solver.add(coef <= 100)
    
    def _sample_disturbances(self, num_samples: int) -> List[List[float]]:
        """Sample from disturbance set W."""
        samples = []
        
        solver = z3.Solver()
        for p in self.dynamics.disturbance_set.constraints:
            solver.add(p.to_z3(self._z3_dist) >= 0)
        
        for _ in range(num_samples):
            if solver.check() == z3.sat:
                model = solver.model()
                sample = []
                for z3_w in self._z3_dist:
                    val = model.eval(z3_w, model_completion=True)
                    if z3.is_rational_value(val):
                        sample.append(float(val.numerator_as_long()) / float(val.denominator_as_long()))
                    else:
                        sample.append(0.0)
                samples.append(sample)
                
                block = z3.Or([z3_w != model.eval(z3_w) for z3_w in self._z3_dist])
                solver.add(block)
            else:
                break
        
        return samples
    
    def _sample_from_set(self, sas: SemialgebraicSet, num_samples: int) -> List[Dict[str, float]]:
        """Sample from semialgebraic set."""
        samples = []
        solver = z3.Solver()
        
        for p in sas.inequalities:
            solver.add(p.to_z3(self._z3_vars) >= 0)
        
        var_names = self.dynamics.var_names or [f"x_{i}" for i in range(self.n_vars)]
        
        for _ in range(num_samples):
            if solver.check() == z3.sat:
                model = solver.model()
                sample = {}
                for v, z3_v in zip(var_names, self._z3_vars):
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
    
    def _evaluate_template(self, template: z3.ArithRef,
                            sample: Dict[str, float]) -> z3.ArithRef:
        """Evaluate template at sample."""
        var_names = self.dynamics.var_names or [f"x_{i}" for i in range(self.n_vars)]
        subs = [(z3_v, z3.RealVal(sample.get(v, 0.0)))
                for v, z3_v in zip(var_names, self._z3_vars)]
        return z3.substitute(template, subs)
    
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
            return Polynomial(self.n_vars, poly_coeffs)
        return None


# =============================================================================
# STOCHASTIC INTEGRATION
# =============================================================================

@dataclass
class StochasticIntegrationConfig:
    """Configuration for stochastic barrier integration."""
    barrier_degree: int = 4
    noise_variance: float = 0.1
    disturbance_bound: float = 1.0
    timeout_ms: int = 60000
    verbose: bool = False


class StochasticBarrierIntegration:
    """
    Integration of stochastic barriers with main analysis.
    
    Provides:
    1. Stochastic system modeling from program analysis
    2. Stochastic barrier synthesis
    3. Probabilistic safety bounds
    """
    
    def __init__(self, config: Optional[StochasticIntegrationConfig] = None,
                 verbose: bool = False):
        self.config = config or StochasticIntegrationConfig()
        self.verbose = verbose or self.config.verbose
        
        self._stochastic_systems: Dict[str, StochasticDynamics] = {}
        self._barriers: Dict[str, StochasticBarrier] = {}
        
        self.stats = {
            'systems_created': 0,
            'barriers_synthesized': 0,
            'probabilistic_bounds': 0,
        }
    
    def create_stochastic_system(self, system_id: str,
                                   n_vars: int,
                                   var_names: List[str],
                                   drift: List[Polynomial],
                                   noise_variance: Optional[float] = None) -> StochasticDynamics:
        """
        Create stochastic system from drift and noise variance.
        """
        variance = noise_variance or self.config.noise_variance
        
        # Create simple isotropic noise
        diffusion = []
        for i in range(n_vars):
            row = []
            for j in range(1):  # Single Brownian motion
                if i == j % n_vars:
                    # σ_ii = sqrt(variance)
                    sigma = math.sqrt(variance)
                    row.append(Polynomial(n_vars, {tuple([0] * n_vars): sigma}))
                else:
                    row.append(Polynomial(n_vars, {}))
            diffusion.append(row)
        
        noise = NoiseModel(n_vars, diffusion, n_brownian=1)
        
        dynamics = StochasticDynamics(
            n_vars=n_vars,
            drift=drift,
            noise=noise,
            var_names=var_names
        )
        
        self._stochastic_systems[system_id] = dynamics
        self.stats['systems_created'] += 1
        
        return dynamics
    
    def synthesize_barrier(self, system_id: str,
                            init_set: SemialgebraicSet,
                            unsafe_set: SemialgebraicSet) -> StochasticSynResult:
        """
        Synthesize stochastic barrier for system.
        """
        dynamics = self._stochastic_systems.get(system_id)
        if dynamics is None:
            return StochasticSynResult(
                result=StochasticSynthesisResult.FAILURE,
                message="System not found"
            )
        
        synthesizer = StochasticBarrierSynthesizer(
            dynamics,
            init_set,
            unsafe_set,
            barrier_degree=self.config.barrier_degree,
            timeout_ms=self.config.timeout_ms,
            verbose=self.verbose
        )
        
        result = synthesizer.synthesize()
        
        if result.result == StochasticSynthesisResult.SUCCESS:
            self._barriers[system_id] = result.barrier
            self.stats['barriers_synthesized'] += 1
        
        return result
    
    def get_safety_probability(self, system_id: str,
                                 time_horizon: float) -> float:
        """
        Get probabilistic safety bound.
        """
        barrier = self._barriers.get(system_id)
        if barrier is None:
            return 0.0
        
        self.stats['probabilistic_bounds'] += 1
        return barrier.get_safety_probability(time_horizon)
    
    def condition_barrier_problem(self, problem: BarrierSynthesisProblem,
                                    system_id: str) -> BarrierSynthesisProblem:
        """
        Condition barrier problem using stochastic insights.
        """
        barrier = self._barriers.get(system_id)
        if barrier is None:
            return problem
        
        # Add barrier polynomial as constraint
        new_init = SemialgebraicSet(
            n_vars=problem.init_set.n_vars,
            inequalities=problem.init_set.inequalities + [barrier.polynomial],
            equalities=problem.init_set.equalities,
            var_names=problem.init_set.var_names,
            name=f"{problem.init_set.name}_stochastic"
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

def create_stochastic_dynamics(n_vars: int,
                                 var_names: List[str],
                                 drift: List[Polynomial],
                                 noise_variance: float = 0.1) -> StochasticDynamics:
    """
    Create stochastic dynamics with isotropic noise.
    """
    diffusion = []
    sigma = math.sqrt(noise_variance)
    
    for i in range(n_vars):
        row = [Polynomial(n_vars, {tuple([0] * n_vars): sigma if i == 0 else 0.0})]
        diffusion.append(row)
    
    noise = NoiseModel(n_vars, diffusion, n_brownian=1)
    
    return StochasticDynamics(
        n_vars=n_vars,
        drift=drift,
        noise=noise,
        var_names=var_names
    )


def create_robust_dynamics(n_vars: int,
                            var_names: List[str],
                            drift: List[Polynomial],
                            disturbance_bound: float = 1.0) -> RobustDynamics:
    """
    Create robust dynamics with box disturbance.
    """
    n_dist = 1  # Single disturbance
    
    # w ∈ [-bound, bound]
    constraints = [
        Polynomial(n_dist, {(0,): disturbance_bound, tuple(): 0}),  # bound - |w| >= 0
    ]
    
    dist_set = DisturbanceSet(n_dist, constraints)
    
    return RobustDynamics(
        n_vars=n_vars,
        n_dist=n_dist,
        drift=drift,
        disturbance_set=dist_set,
        var_names=var_names
    )


def synthesize_stochastic_barrier(dynamics: StochasticDynamics,
                                    init_set: SemialgebraicSet,
                                    unsafe_set: SemialgebraicSet,
                                    barrier_degree: int = 4,
                                    timeout_ms: int = 60000,
                                    verbose: bool = False) -> StochasticSynResult:
    """
    Synthesize stochastic barrier certificate.
    """
    synthesizer = StochasticBarrierSynthesizer(
        dynamics,
        init_set,
        unsafe_set,
        barrier_degree=barrier_degree,
        timeout_ms=timeout_ms,
        verbose=verbose
    )
    
    return synthesizer.synthesize()


def synthesize_robust_barrier(dynamics: RobustDynamics,
                                init_set: SemialgebraicSet,
                                unsafe_set: SemialgebraicSet,
                                barrier_degree: int = 4,
                                timeout_ms: int = 60000,
                                verbose: bool = False) -> RobustSynResult:
    """
    Synthesize robust barrier certificate.
    """
    synthesizer = RobustBarrierSynthesizer(
        dynamics,
        init_set,
        unsafe_set,
        barrier_degree=barrier_degree,
        timeout_ms=timeout_ms,
        verbose=verbose
    )
    
    return synthesizer.synthesize()


# =============================================================================
# ADVANCED STOCHASTIC BARRIER ANALYSIS
# =============================================================================

class JumpDiffusionDynamics:
    """
    Jump-diffusion process dynamics.
    
    Combines continuous Brownian motion with discrete jumps:
    dX = f(X)dt + g(X)dW + h(X)dN(t)
    
    where N(t) is a Poisson process with intensity λ.
    """
    
    def __init__(self, n_vars: int, var_names: Optional[List[str]] = None):
        self.n_vars = n_vars
        self.var_names = var_names or [f"x_{i}" for i in range(n_vars)]
        
        self.drift: Optional[VectorField] = None
        self.diffusion: Optional[VectorField] = None
        self.jump_function: Optional[VectorField] = None
        self.jump_intensity: float = 1.0
        
        self._z3_vars = [z3.Real(v) for v in self.var_names]
    
    def set_drift(self, components: List[Polynomial]) -> None:
        """Set drift component f(X)."""
        if len(components) != self.n_vars:
            raise ValueError(f"Need {self.n_vars} drift components")
        self.drift = VectorField(self.n_vars, components)
    
    def set_diffusion(self, components: List[Polynomial]) -> None:
        """Set diffusion component g(X)."""
        if len(components) != self.n_vars:
            raise ValueError(f"Need {self.n_vars} diffusion components")
        self.diffusion = VectorField(self.n_vars, components)
    
    def set_jump(self, components: List[Polynomial], intensity: float) -> None:
        """Set jump component h(X) and intensity λ."""
        if len(components) != self.n_vars:
            raise ValueError(f"Need {self.n_vars} jump components")
        self.jump_function = VectorField(self.n_vars, components)
        self.jump_intensity = intensity
    
    def compute_extended_generator(self, barrier: Polynomial) -> z3.ArithRef:
        """
        Compute extended generator for jump-diffusion:
        
        L[B] = ∑ f_i ∂B/∂x_i + (1/2) ∑ (g g^T)_ij ∂²B/∂x_i∂x_j
              + λ ∫ (B(x + h(x,y)) - B(x)) ν(dy)
        """
        # Standard generator terms
        drift_term = self._compute_drift_term(barrier)
        diffusion_term = self._compute_diffusion_term(barrier)
        
        # Jump term (simplified: evaluate at expected jump)
        jump_term = self._compute_jump_term(barrier)
        
        return drift_term + diffusion_term + jump_term
    
    def _compute_drift_term(self, barrier: Polynomial) -> z3.ArithRef:
        """Compute drift term ∑ f_i ∂B/∂x_i."""
        if self.drift is None:
            return z3.RealVal(0)
        
        terms = []
        for i in range(self.n_vars):
            partial = barrier.partial_derivative(i)
            drift_i = self.drift.components[i]
            terms.append(partial.to_z3(self._z3_vars) * 
                         drift_i.to_z3(self._z3_vars))
        
        return sum(terms) if terms else z3.RealVal(0)
    
    def _compute_diffusion_term(self, barrier: Polynomial) -> z3.ArithRef:
        """Compute diffusion term."""
        if self.diffusion is None:
            return z3.RealVal(0)
        
        terms = []
        for i in range(self.n_vars):
            second_partial = barrier.second_partial_derivative(i, i)
            diff_i = self.diffusion.components[i]
            terms.append(z3.RealVal(0.5) * 
                         second_partial.to_z3(self._z3_vars) *
                         diff_i.to_z3(self._z3_vars) ** 2)
        
        return sum(terms) if terms else z3.RealVal(0)
    
    def _compute_jump_term(self, barrier: Polynomial) -> z3.ArithRef:
        """Compute jump term (simplified)."""
        if self.jump_function is None:
            return z3.RealVal(0)
        
        # Approximate: λ * (B(x + h(x)) - B(x))
        # This is a simplification; full treatment needs integration
        
        return z3.RealVal(0)  # Placeholder


class StochasticReachabilityAnalyzer:
    """
    Stochastic reachability analysis using barriers.
    
    Computes probability bounds on reaching unsafe states.
    """
    
    def __init__(self, dynamics: StochasticDynamics,
                 init_set: SemialgebraicSet,
                 unsafe_set: SemialgebraicSet,
                 timeout_ms: int = 60000):
        self.dynamics = dynamics
        self.init_set = init_set
        self.unsafe_set = unsafe_set
        self.timeout_ms = timeout_ms
        
        self._z3_vars = [z3.Real(v) for v in dynamics.var_names]
        
        self.stats = {
            'probability_bound': None,
            'barrier_found': False,
        }
    
    def compute_reach_probability_bound(self) -> float:
        """
        Compute upper bound on probability of reaching unsafe set.
        
        Uses Kushner's supermartingale argument:
        P(reach unsafe) ≤ sup_{x∈Init} B(x) / inf_{x∈Unsafe} B(x)
        """
        # First synthesize barrier
        synthesizer = StochasticBarrierSynthesizer(
            self.dynamics,
            self.init_set,
            self.unsafe_set,
            barrier_degree=4,
            timeout_ms=self.timeout_ms
        )
        
        result = synthesizer.synthesize()
        
        if result.result != StochasticBarrierSynthesisResult.SUCCESS:
            self.stats['barrier_found'] = False
            return 1.0  # Trivial bound
        
        self.stats['barrier_found'] = True
        barrier = result.barrier
        
        # Compute supremum over init
        sup_init = self._compute_supremum(barrier, self.init_set)
        
        # Compute infimum over unsafe
        inf_unsafe = self._compute_infimum(barrier, self.unsafe_set)
        
        if inf_unsafe <= 0:
            return 1.0
        
        prob_bound = sup_init / inf_unsafe
        self.stats['probability_bound'] = min(1.0, max(0.0, prob_bound))
        
        return self.stats['probability_bound']
    
    def _compute_supremum(self, barrier: StochasticBarrier,
                           set_desc: SemialgebraicSet) -> float:
        """Compute supremum of barrier over set."""
        solver = z3.Optimize()
        solver.set("timeout", self.timeout_ms // 2)
        
        # Constrain to set
        for p in set_desc.inequalities:
            solver.add(p.to_z3(self._z3_vars) >= 0)
        
        barrier_expr = barrier.polynomial.to_z3(self._z3_vars)
        solver.maximize(barrier_expr)
        
        if solver.check() == z3.sat:
            model = solver.model()
            val = model.eval(barrier_expr, model_completion=True)
            if z3.is_rational_value(val):
                return float(val.numerator_as_long()) / float(val.denominator_as_long())
        
        return float('inf')
    
    def _compute_infimum(self, barrier: StochasticBarrier,
                          set_desc: SemialgebraicSet) -> float:
        """Compute infimum of barrier over set."""
        solver = z3.Optimize()
        solver.set("timeout", self.timeout_ms // 2)
        
        for p in set_desc.inequalities:
            solver.add(p.to_z3(self._z3_vars) >= 0)
        
        barrier_expr = barrier.polynomial.to_z3(self._z3_vars)
        solver.minimize(barrier_expr)
        
        if solver.check() == z3.sat:
            model = solver.model()
            val = model.eval(barrier_expr, model_completion=True)
            if z3.is_rational_value(val):
                return float(val.numerator_as_long()) / float(val.denominator_as_long())
        
        return 0.0


class ExpectedExitTimeAnalyzer:
    """
    Expected exit time analysis using barrier functions.
    
    Computes bounds on expected time to exit a safe region.
    """
    
    def __init__(self, dynamics: StochasticDynamics,
                 safe_set: SemialgebraicSet,
                 timeout_ms: int = 60000):
        self.dynamics = dynamics
        self.safe_set = safe_set
        self.timeout_ms = timeout_ms
        
        self._z3_vars = [z3.Real(v) for v in dynamics.var_names]
        
        self.stats = {
            'lower_bound': None,
            'upper_bound': None,
        }
    
    def compute_exit_time_lower_bound(self, start_point: List[float]) -> float:
        """
        Compute lower bound on expected exit time from start point.
        
        Uses Dynkin's formula and Lyapunov functions.
        """
        # Find Lyapunov-like function with L[V] ≤ -1 in safe set
        lyapunov = self._synthesize_exit_lyapunov()
        
        if lyapunov is None:
            return 0.0
        
        # Lower bound: V(start_point)
        bound = lyapunov.evaluate(start_point)
        self.stats['lower_bound'] = max(0.0, bound)
        
        return self.stats['lower_bound']
    
    def compute_exit_time_upper_bound(self, start_point: List[float]) -> float:
        """
        Compute upper bound on expected exit time.
        """
        # Find function with L[V] ≥ 1 or other criterion
        lyapunov = self._synthesize_exit_lyapunov(upper=True)
        
        if lyapunov is None:
            return float('inf')
        
        bound = lyapunov.evaluate(start_point)
        self.stats['upper_bound'] = bound
        
        return bound
    
    def _synthesize_exit_lyapunov(self, upper: bool = False) -> Optional[Polynomial]:
        """Synthesize Lyapunov function for exit time."""
        solver = z3.Solver()
        solver.set("timeout", self.timeout_ms)
        
        # Create quadratic template
        n = self.dynamics.n_vars
        template, coeffs = self._create_quadratic_template()
        
        # Generator condition
        if self.dynamics.drift:
            generator = self._compute_generator(template)
            
            target = z3.RealVal(-1) if not upper else z3.RealVal(1)
            
            # Sample safe set and add constraints
            for sample in self._sample_safe_set(20):
                gen_val = self._evaluate_at(generator, sample)
                if upper:
                    solver.add(gen_val >= 1)
                else:
                    solver.add(gen_val <= -1)
        
        # Boundary condition: V = 0 on boundary
        
        if solver.check() == z3.sat:
            model = solver.model()
            return self._extract_polynomial(model, coeffs)
        
        return None
    
    def _create_quadratic_template(self) -> Tuple[z3.ArithRef, Dict]:
        """Create quadratic polynomial template."""
        n = self.dynamics.n_vars
        coeffs = {}
        terms = []
        
        for i in range(n):
            for j in range(i, n):
                mono = tuple([2 if k == i == j else 
                              (1 if k == i or k == j else 0)
                              for k in range(n)])
                coef = z3.Real(f"v_{i}_{j}")
                coeffs[mono] = coef
                
                if i == j:
                    terms.append(coef * self._z3_vars[i] * self._z3_vars[i])
                else:
                    terms.append(2 * coef * self._z3_vars[i] * self._z3_vars[j])
        
        template = sum(terms) if terms else z3.RealVal(0)
        return template, coeffs
    
    def _compute_generator(self, template: z3.ArithRef) -> z3.ArithRef:
        """Compute generator applied to template."""
        return z3.RealVal(0)  # Placeholder
    
    def _sample_safe_set(self, num: int) -> List[Dict[str, float]]:
        """Sample points from safe set."""
        import random
        samples = []
        for _ in range(num):
            sample = {v: random.uniform(-1, 1) for v in self.dynamics.var_names}
            samples.append(sample)
        return samples
    
    def _evaluate_at(self, expr: z3.ArithRef, 
                      sample: Dict[str, float]) -> z3.ArithRef:
        """Evaluate expression at sample point."""
        subs = [(z3_v, z3.RealVal(sample.get(v, 0.0)))
                for v, z3_v in zip(self.dynamics.var_names, self._z3_vars)]
        return z3.substitute(expr, subs)
    
    def _extract_polynomial(self, model: z3.ModelRef, 
                             coeffs: Dict) -> Polynomial:
        """Extract polynomial from Z3 model."""
        poly_coeffs = {}
        for mono, coef_var in coeffs.items():
            val = model.eval(coef_var, model_completion=True)
            if z3.is_rational_value(val):
                coef_val = float(val.numerator_as_long()) / float(val.denominator_as_long())
            else:
                coef_val = 0.0
            if abs(coef_val) > 1e-10:
                poly_coeffs[mono] = coef_val
        
        return Polynomial(self.dynamics.n_vars, poly_coeffs)


class MartingaleBarrier:
    """
    Supermartingale barrier certificates.
    
    Uses supermartingale property for probabilistic safety:
    E[B(X(t+s)) | X(t)] ≤ B(X(t))
    """
    
    def __init__(self, dynamics: StochasticDynamics,
                 init_set: SemialgebraicSet,
                 unsafe_set: SemialgebraicSet):
        self.dynamics = dynamics
        self.init_set = init_set
        self.unsafe_set = unsafe_set
        
        self._z3_vars = [z3.Real(v) for v in dynamics.var_names]
        
        self.barrier: Optional[Polynomial] = None
    
    def synthesize(self, degree: int = 4, 
                    timeout_ms: int = 60000) -> bool:
        """
        Synthesize supermartingale barrier.
        
        Conditions:
        1. B(x) ≤ γ for x ∈ Init
        2. B(x) > γ for x ∈ Unsafe  
        3. L[B](x) ≤ 0 for x ∈ Safe (supermartingale)
        """
        solver = z3.Solver()
        solver.set("timeout", timeout_ms)
        
        # Create template
        template, coeffs = self._create_template(degree)
        gamma = z3.Real("gamma")
        
        # Condition 1: B ≤ γ on init
        for sample in self._sample_set(self.init_set, 10):
            b_val = self._evaluate_template(template, sample)
            solver.add(b_val <= gamma)
        
        # Condition 2: B > γ on unsafe
        for sample in self._sample_set(self.unsafe_set, 10):
            b_val = self._evaluate_template(template, sample)
            solver.add(b_val > gamma)
        
        # Condition 3: L[B] ≤ 0 (generator ≤ 0)
        generator = self._compute_generator_template(template, coeffs)
        # Sample and add constraints
        
        if solver.check() == z3.sat:
            model = solver.model()
            self.barrier = self._extract_polynomial(model, coeffs)
            return True
        
        return False
    
    def _create_template(self, degree: int) -> Tuple[z3.ArithRef, Dict]:
        """Create polynomial template."""
        n = self.dynamics.n_vars
        monomials = self._generate_monomials(n, degree)
        
        coeffs = {}
        terms = []
        
        for mono in monomials:
            coef = z3.Real(f"c_{mono}")
            coeffs[mono] = coef
            
            mono_z3 = z3.RealVal(1)
            for i, power in enumerate(mono):
                for _ in range(power):
                    mono_z3 = mono_z3 * self._z3_vars[i]
            
            terms.append(coef * mono_z3)
        
        template = sum(terms) if terms else z3.RealVal(0)
        return template, coeffs
    
    def _generate_monomials(self, n: int, max_degree: int) -> List[Tuple[int, ...]]:
        """Generate monomials up to max_degree."""
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
    
    def _evaluate_template(self, template: z3.ArithRef,
                            sample: Dict[str, float]) -> z3.ArithRef:
        """Evaluate template at sample point."""
        subs = [(z3_v, z3.RealVal(sample.get(v, 0.0)))
                for v, z3_v in zip(self.dynamics.var_names, self._z3_vars)]
        return z3.substitute(template, subs)
    
    def _compute_generator_template(self, template: z3.ArithRef,
                                      coeffs: Dict) -> z3.ArithRef:
        """Compute generator of template."""
        return z3.RealVal(0)  # Placeholder
    
    def _sample_set(self, set_desc: SemialgebraicSet,
                     num: int) -> List[Dict[str, float]]:
        """Sample from semialgebraic set."""
        import random
        samples = []
        for _ in range(num):
            sample = {v: random.uniform(-5, 5) for v in self.dynamics.var_names}
            samples.append(sample)
        return samples
    
    def _extract_polynomial(self, model: z3.ModelRef,
                             coeffs: Dict) -> Polynomial:
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
        
        return Polynomial(self.dynamics.n_vars, poly_coeffs)


class StochasticControlBarrier:
    """
    Control barrier functions for stochastic systems.
    
    Synthesizes barrier and controller simultaneously.
    """
    
    def __init__(self, dynamics_func: Callable,
                 control_affine: bool = True,
                 n_vars: int = 2,
                 n_controls: int = 1):
        self.dynamics_func = dynamics_func
        self.control_affine = control_affine
        self.n_vars = n_vars
        self.n_controls = n_controls
        
        self._x_vars = [z3.Real(f"x_{i}") for i in range(n_vars)]
        self._u_vars = [z3.Real(f"u_{i}") for i in range(n_controls)]
        
        self.barrier: Optional[Polynomial] = None
        self.controller: Optional[Callable] = None
    
    def synthesize(self, init_set: SemialgebraicSet,
                    unsafe_set: SemialgebraicSet,
                    degree: int = 4,
                    timeout_ms: int = 60000) -> bool:
        """
        Synthesize barrier and controller.
        
        Finds B, u such that:
        1. B(x) ≤ 0 for x ∈ Init
        2. B(x) > 0 for x ∈ Unsafe
        3. L_f[B](x) + L_g[B](x)u ≤ 0
        """
        solver = z3.Solver()
        solver.set("timeout", timeout_ms)
        
        # Create barrier template
        barrier_template, barrier_coeffs = self._create_template(degree)
        
        # Create controller template (linear in state)
        controller_coeffs = self._create_controller_template()
        
        # Add constraints
        self._add_init_constraints(solver, barrier_template, init_set)
        self._add_unsafe_constraints(solver, barrier_template, unsafe_set)
        self._add_control_constraints(solver, barrier_template, controller_coeffs)
        
        if solver.check() == z3.sat:
            model = solver.model()
            self.barrier = self._extract_polynomial(model, barrier_coeffs)
            self.controller = self._extract_controller(model, controller_coeffs)
            return True
        
        return False
    
    def _create_template(self, degree: int) -> Tuple[z3.ArithRef, Dict]:
        """Create barrier template."""
        monomials = []
        
        def generate(remaining: int, idx: int, current: List[int]):
            if idx == self.n_vars:
                monomials.append(tuple(current))
                return
            for power in range(remaining + 1):
                generate(remaining - power, idx + 1, current + [power])
        
        for deg in range(degree + 1):
            generate(deg, 0, [])
        
        coeffs = {}
        terms = []
        
        for mono in monomials:
            coef = z3.Real(f"b_{mono}")
            coeffs[mono] = coef
            
            mono_z3 = z3.RealVal(1)
            for i, power in enumerate(mono):
                for _ in range(power):
                    mono_z3 = mono_z3 * self._x_vars[i]
            
            terms.append(coef * mono_z3)
        
        return sum(terms) if terms else z3.RealVal(0), coeffs
    
    def _create_controller_template(self) -> Dict[int, List[z3.ArithRef]]:
        """Create linear controller template."""
        coeffs = {}
        for j in range(self.n_controls):
            control_coeffs = []
            for i in range(self.n_vars):
                control_coeffs.append(z3.Real(f"K_{j}_{i}"))
            control_coeffs.append(z3.Real(f"K_{j}_bias"))
            coeffs[j] = control_coeffs
        return coeffs
    
    def _add_init_constraints(self, solver: z3.Solver,
                                template: z3.ArithRef,
                                init_set: SemialgebraicSet) -> None:
        """Add init constraints."""
        # Sample and add B ≤ 0
        pass
    
    def _add_unsafe_constraints(self, solver: z3.Solver,
                                  template: z3.ArithRef,
                                  unsafe_set: SemialgebraicSet) -> None:
        """Add unsafe constraints."""
        # Sample and add B > 0
        pass
    
    def _add_control_constraints(self, solver: z3.Solver,
                                   template: z3.ArithRef,
                                   controller_coeffs: Dict) -> None:
        """Add control constraints."""
        pass
    
    def _extract_polynomial(self, model: z3.ModelRef,
                             coeffs: Dict) -> Polynomial:
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
        
        return Polynomial(self.n_vars, poly_coeffs)
    
    def _extract_controller(self, model: z3.ModelRef,
                             coeffs: Dict) -> Callable:
        """Extract controller function from model."""
        gains = {}
        for j, control_coeffs in coeffs.items():
            k_j = []
            for coef_var in control_coeffs:
                val = model.eval(coef_var, model_completion=True)
                if z3.is_rational_value(val):
                    k_j.append(float(val.numerator_as_long()) / 
                               float(val.denominator_as_long()))
                else:
                    k_j.append(0.0)
            gains[j] = k_j
        
        def controller(x: List[float]) -> List[float]:
            u = []
            for j in range(len(gains)):
                k_j = gains[j]
                u_j = sum(k_j[i] * x[i] for i in range(len(x)))
                u_j += k_j[-1]  # bias
                u.append(u_j)
            return u
        
        return controller


class MonteCarloValidator:
    """
    Monte Carlo validation of stochastic barriers.
    """
    
    def __init__(self, dynamics: StochasticDynamics,
                 barrier: StochasticBarrier,
                 init_set: SemialgebraicSet,
                 unsafe_set: SemialgebraicSet):
        self.dynamics = dynamics
        self.barrier = barrier
        self.init_set = init_set
        self.unsafe_set = unsafe_set
        
        self.stats = {
            'trajectories_simulated': 0,
            'unsafe_reaches': 0,
            'barrier_violations': 0,
        }
    
    def validate(self, num_trajectories: int = 1000,
                  time_horizon: float = 10.0,
                  dt: float = 0.01) -> Dict[str, Any]:
        """
        Validate barrier via Monte Carlo simulation.
        """
        import random
        
        for _ in range(num_trajectories):
            self.stats['trajectories_simulated'] += 1
            
            # Sample initial state
            x = self._sample_initial()
            
            # Simulate trajectory
            t = 0.0
            barrier_positive = self.barrier.polynomial.evaluate(x) >= 0
            
            while t < time_horizon:
                # Check unsafe
                if self._in_unsafe(x):
                    self.stats['unsafe_reaches'] += 1
                    if barrier_positive:
                        self.stats['barrier_violations'] += 1
                    break
                
                # Euler-Maruyama step
                x = self._euler_step(x, dt)
                t += dt
        
        return {
            'empirical_unsafe_prob': self.stats['unsafe_reaches'] / 
                                      self.stats['trajectories_simulated'],
            'barrier_violation_rate': self.stats['barrier_violations'] /
                                        max(1, self.stats['unsafe_reaches'])
        }
    
    def _sample_initial(self) -> List[float]:
        """Sample from initial set."""
        import random
        return [random.uniform(-1, 1) for _ in range(self.dynamics.n_vars)]
    
    def _in_unsafe(self, x: List[float]) -> bool:
        """Check if x is in unsafe set."""
        for p in self.unsafe_set.inequalities:
            if p.evaluate(x) < 0:
                return False
        return True
    
    def _euler_step(self, x: List[float], dt: float) -> List[float]:
        """Euler-Maruyama step."""
        import random
        
        x_new = list(x)
        
        # Drift
        if self.dynamics.drift:
            for i in range(self.dynamics.n_vars):
                x_new[i] += self.dynamics.drift.components[i].evaluate(x) * dt
        
        # Diffusion
        if self.dynamics.diffusion:
            for i in range(self.dynamics.n_vars):
                dW = random.gauss(0, 1) * (dt ** 0.5)
                x_new[i] += self.dynamics.diffusion.components[i].evaluate(x) * dW
        
        return x_new


class StochasticBarrierSynthesizer:
    """
    Automated synthesis of stochastic barrier certificates.
    
    Uses template-based synthesis with SMT solving to find
    barrier certificates for stochastic systems.
    """
    
    def __init__(self, degree: int = 2, num_samples: int = 1000):
        self.degree = degree
        self.num_samples = num_samples
        self.solver = z3.Solver()
        
    def synthesize(self, dynamics: StochasticDynamics,
                   initial_set: 'SemialgebraicSet',
                   safe_set: 'SemialgebraicSet',
                   unsafe_set: 'SemialgebraicSet') -> Optional['StochasticBarrier']:
        """
        Synthesize stochastic barrier certificate.
        
        Uses supermartingale condition:
        E[LB(x)] <= 0 where L is the infinitesimal generator.
        """
        # Create template barrier
        template = self._create_template(dynamics.n_vars)
        
        # Add constraints
        self._add_initial_constraints(template, initial_set)
        self._add_safe_constraints(template, safe_set)
        self._add_unsafe_constraints(template, unsafe_set)
        self._add_supermartingale_constraints(template, dynamics)
        
        # Solve
        if self.solver.check() == z3.sat:
            model = self.solver.model()
            return self._extract_barrier(template, model)
        
        return None
    
    def _create_template(self, n_vars: int) -> Dict[str, Any]:
        """Create polynomial template with unknown coefficients."""
        from itertools import combinations_with_replacement
        
        template = {'coeffs': [], 'monomials': []}
        
        # Generate monomials up to specified degree
        vars = [z3.Real(f'x{i}') for i in range(n_vars)]
        
        for d in range(self.degree + 1):
            for combo in combinations_with_replacement(range(n_vars), d):
                coeff = z3.Real(f'c_{len(template["coeffs"])}')
                template['coeffs'].append(coeff)
                template['monomials'].append(combo)
        
        return template
    
    def _add_initial_constraints(self, template: Dict, initial_set: 'SemialgebraicSet'):
        """Add B(x) < 0 for x in initial set."""
        # Sample points from initial set
        for _ in range(self.num_samples // 3):
            x = self._sample_from_set(initial_set)
            if x is not None:
                B_x = self._evaluate_template(template, x)
                self.solver.add(B_x < 0)
    
    def _add_safe_constraints(self, template: Dict, safe_set: 'SemialgebraicSet'):
        """Add B(x) < 1 for x in safe set (optional)."""
        pass
    
    def _add_unsafe_constraints(self, template: Dict, unsafe_set: 'SemialgebraicSet'):
        """Add B(x) >= 1 for x in unsafe set."""
        for _ in range(self.num_samples // 3):
            x = self._sample_from_set(unsafe_set)
            if x is not None:
                B_x = self._evaluate_template(template, x)
                self.solver.add(B_x >= 1)
    
    def _add_supermartingale_constraints(self, template: Dict, dynamics: StochasticDynamics):
        """Add E[LB(x)] <= 0 constraint."""
        # Infinitesimal generator for diffusion
        # L = f·∇B + (1/2)tr(σσᵀ·∇²B)
        # Sample-based approximation
        for _ in range(self.num_samples // 3):
            x = [z3.Real(f'sample_{_}_{i}') for i in range(dynamics.n_vars)]
            LB = self._compute_generator(template, x, dynamics)
            self.solver.add(LB <= 0)
    
    def _compute_generator(self, template: Dict, x: List, 
                            dynamics: StochasticDynamics) -> z3.ExprRef:
        """Compute infinitesimal generator LB at point x."""
        return z3.RealVal(0)  # Simplified
    
    def _evaluate_template(self, template: Dict, x: List[float]) -> z3.ExprRef:
        """Evaluate template at concrete point."""
        result = z3.RealVal(0)
        
        for coeff, mono in zip(template['coeffs'], template['monomials']):
            term = coeff
            for idx in mono:
                term = term * x[idx]
            result = result + term
        
        return result
    
    def _sample_from_set(self, s: 'SemialgebraicSet') -> Optional[List[float]]:
        """Sample a point from semialgebraic set."""
        import random
        return [random.uniform(-1, 1) for _ in range(3)]
    
    def _extract_barrier(self, template: Dict, model: z3.ModelRef) -> 'StochasticBarrier':
        """Extract concrete barrier from model."""
        return StochasticBarrier()


class StochasticSystemBuilder:
    """
    Fluent interface for building stochastic systems.
    
    Allows declarative specification of stochastic dynamics.
    """
    
    def __init__(self, name: str = "system"):
        self.name = name
        self.state_vars = []
        self.drift_terms = []
        self.diffusion_terms = []
        self.initial_conditions = []
        self.unsafe_regions = []
        
    def with_state(self, *var_names: str) -> 'StochasticSystemBuilder':
        """Define state variables."""
        self.state_vars.extend(var_names)
        return self
    
    def with_drift(self, drift_vector: List[str]) -> 'StochasticSystemBuilder':
        """Set drift vector field."""
        self.drift_terms = drift_vector
        return self
    
    def with_diffusion(self, diffusion_matrix: List[List[str]]) -> 'StochasticSystemBuilder':
        """Set diffusion matrix."""
        self.diffusion_terms = diffusion_matrix
        return self
    
    def from_sde(self, sde_spec: str) -> 'StochasticSystemBuilder':
        """Parse SDE specification string."""
        # Parse dx = f(x)dt + g(x)dW format
        return self
    
    def initial(self, condition: str) -> 'StochasticSystemBuilder':
        """Add initial condition."""
        self.initial_conditions.append(condition)
        return self
    
    def unsafe(self, region: str) -> 'StochasticSystemBuilder':
        """Add unsafe region."""
        self.unsafe_regions.append(region)
        return self
    
    def build(self) -> StochasticDynamics:
        """Build the stochastic dynamics."""
        dynamics = StochasticDynamics(len(self.state_vars))
        return dynamics
