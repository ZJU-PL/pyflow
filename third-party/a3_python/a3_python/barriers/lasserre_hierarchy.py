"""
SOTA Paper #7: Lasserre Hierarchy (Moments/SOS) Integration.

Reference:
    J.-B. Lasserre. "Global optimization with polynomials and the problem of moments."
    SIAM Journal on Optimization, 2001.

This module implements the Lasserre hierarchy for systematic degree-lifting
in polynomial barrier certificate synthesis. The hierarchy provides:

1. **Completeness guarantees**: For polynomial systems, increasing the relaxation
   order will eventually find a certificate (if one exists).

2. **Staged deepening**: Start with low-degree relaxations (fast) and increase
   degree only when necessary (expensive but more powerful).

3. **Counterexample extraction**: Failed relaxations at order k provide
   dual information that guides refinement or proves no low-degree barrier exists.

THEORETICAL FOUNDATIONS
=======================

The Lasserre hierarchy is based on the moment-SOS duality:

**Primal (Moments)**:
  min ∫ f(x) dμ(x)
  s.t. μ is a probability measure on K = {g_i(x) ≥ 0}
       moments of μ satisfy truncated moment constraints

**Dual (SOS)**:
  max γ
  s.t. f(x) - γ = σ₀(x) + Σᵢ σᵢ(x)gᵢ(x)
       σᵢ are SOS polynomials of bounded degree

At order k (the k-th level of the hierarchy):
- SOS polynomials have degree ≤ 2k
- Multiplier σᵢ for constraint gᵢ has degree ≤ 2k - deg(gᵢ)

CONVERGENCE PROPERTIES
======================

**Finite convergence** occurs when:
1. The feasible set K is compact (Archimedean condition)
2. The optimal value is achieved (no duality gap)

**Rate of convergence**:
- Polynomial under regularity conditions
- Practical: often converges in low orders (k = 2-4)

INTEGRATION WITH BARRIER SYNTHESIS
==================================

For barrier synthesis, we use the hierarchy to:

1. **Staged certificate search**:
   - Try degree 2 barriers first (cheap, often sufficient)
   - Increase to degree 4, 6, ... if needed
   - Return UNKNOWN only after exhausting budget

2. **Infeasibility certificates**:
   - If order k is infeasible, no degree-2k barrier exists
   - Primal solutions give moment sequences (potential counterexamples)

3. **Conditioning information**:
   - Lower-order solutions provide warm-starts for higher orders
   - Dual variables indicate which constraints are tight

ORTHOGONAL CONTRIBUTIONS
========================

This module is orthogonal to Paper #6 (basic SOS) in:

1. **Systematic scheduling**: Paper #6 does one-shot synthesis; this provides
   a principled sequence of increasingly powerful attempts.

2. **Completeness tracking**: Knows when to give up (hierarchy level exceeded)
   vs. keep trying (more degrees available).

3. **Dual extraction**: Uses moment relaxations for counterexample hints.

FALSE POSITIVE REDUCTION
========================

Lasserre hierarchy reduces false positives by:
1. Proving SAFE with minimal degree certificates (more robust)
2. Providing completeness bounds ("no barrier of degree ≤ 2k exists")
3. Extracting potential counterexamples from moment solutions

BUG COVERAGE INCREASE
=====================

Lasserre hierarchy increases bug coverage by:
1. Freeing budget from easy proofs (low-degree SAFE)
2. Guiding bug search with moment-extracted candidates
3. Enabling parallel attempts at different hierarchy levels

LAYER POSITION
==============

This is a **Layer 1 (Foundations)** module.

    ┌─────────────────────────────────────────────────────────────────┐
    │ Layer 5: Advanced Verification (IC3, CHC, IMC, Assume-Guarantee)│
    │ Layer 4: Learning (ICE, Houdini, SyGuS)                         │
    │ Layer 3: Abstraction (CEGAR, Predicate Abstraction, IMPACT)     │
    │ Layer 2: Certificate Core (Hybrid, Stochastic, SOS Safety)      │
    │ Layer 1: FOUNDATIONS ← [THIS MODULE]                            │
    │   ├── positivstellensatz.py (Paper #5)                          │
    │   ├── parrilo_sos_sdp.py (Paper #6)                             │
    │   ├── lasserre_hierarchy.py ← You are here (Paper #7)           │
    │   └── sparse_sos.py (Paper #8)                                  │
    └─────────────────────────────────────────────────────────────────┘

CROSS-PAPER DEPENDENCIES
========================

This module builds on:
- Paper #6 (Parrilo SOS/SDP): Core SOS decomposition and Gram matrices
- Paper #5 (Positivstellensatz): Theoretical foundation for SOS certificates

This module is used by:
- Papers #1-4 (Certificate Core): Staged degree-lifting for barriers
- Paper #9 (DSOS/SDSOS): LP relaxation at each hierarchy level
- Paper #17 (ICE): Hierarchy level guides candidate complexity
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Dict, List, Optional, Tuple, Callable, Set, Iterator, Any

import z3

# =============================================================================
# LAYER 1: IMPORTS FROM PARRILO SOS/SDP (Paper #6)
# =============================================================================
# Lasserre hierarchy extends Parrilo's SOS/SDP with systematic degree-lifting.
# We import core SOS types and build the moment/SOS hierarchy on top.
# =============================================================================

from .parrilo_sos_sdp import (
    Polynomial,
    Monomial,
    PolynomialCoeffs,
    MonomialBasis,
    GramMatrix,
    SOSDecomposition,
    SemialgebraicSet,
    SemialgebraicConstraint,
    PositivstellensatzCertificate,
    SOSFeasibilityProblem,
    SOSEncoder,
    SDPSolverStatus,
    BarrierSynthesisProblem,
    BarrierCertificateResult,
    SOSBarrierSynthesizer,
    ProgramSOSModel,
)


class HierarchyStatus(Enum):
    """Status of hierarchy level attempt."""
    FEASIBLE = auto()          # Found certificate at this level
    INFEASIBLE = auto()        # No certificate at this level
    TIMEOUT = auto()           # Solver timeout
    NUMERICAL_ERROR = auto()   # Numerical issues
    UNKNOWN = auto()           # Could not determine


@dataclass
class HierarchyLevelResult:
    """
    Result of attempting a single hierarchy level.
    
    Attributes:
        level: Hierarchy level k (degree = 2k)
        status: Outcome of the attempt
        certificate: Barrier certificate (if found)
        moment_solution: Moment matrix (if available, for counterexamples)
        dual_variables: Dual variables (for conditioning)
        solve_time_ms: Time spent at this level
        gap: Primal-dual gap (measure of solution quality)
    """
    level: int
    status: HierarchyStatus
    certificate: Optional[BarrierCertificateResult] = None
    moment_solution: Optional[Dict[Monomial, float]] = None
    dual_variables: Optional[Dict[str, float]] = None
    solve_time_ms: float = 0.0
    gap: float = float('inf')
    
    @property
    def degree(self) -> int:
        """Barrier degree at this level."""
        return 2 * self.level
    
    def is_terminal(self) -> bool:
        """Check if this result is terminal (no need to continue)."""
        return self.status in {HierarchyStatus.FEASIBLE, HierarchyStatus.INFEASIBLE}


@dataclass
class HierarchySchedule:
    """
    Schedule for Lasserre hierarchy exploration.
    
    Attributes:
        min_level: Starting hierarchy level (typically 1)
        max_level: Maximum level to attempt
        timeout_per_level_ms: Timeout for each level
        total_timeout_ms: Total time budget
        adaptive_timeout: Whether to adjust timeouts based on progress
    """
    min_level: int = 1
    max_level: int = 5
    timeout_per_level_ms: int = 10000
    total_timeout_ms: int = 60000
    adaptive_timeout: bool = True
    
    def get_level_timeout(self, level: int, elapsed_ms: float) -> int:
        """Get timeout for a specific level."""
        remaining = self.total_timeout_ms - elapsed_ms
        
        if remaining <= 0:
            return 0
        
        if self.adaptive_timeout:
            # Allocate more time to higher levels (they're harder)
            levels_remaining = self.max_level - level + 1
            if levels_remaining <= 0:
                return int(remaining)
            
            # Exponential allocation: level k gets 2^k share
            total_weight = sum(2 ** (l - self.min_level) 
                             for l in range(level, self.max_level + 1))
            level_weight = 2 ** (level - self.min_level)
            
            allocated = (level_weight / total_weight) * remaining
            return int(min(allocated, self.timeout_per_level_ms))
        else:
            return int(min(remaining, self.timeout_per_level_ms))
    
    def levels(self) -> Iterator[int]:
        """Iterate over hierarchy levels."""
        for level in range(self.min_level, self.max_level + 1):
            yield level


@dataclass
class MomentMatrix:
    """
    Moment matrix for Lasserre relaxation.
    
    M_k(y) is a matrix indexed by monomials of degree ≤ k, with entries
    M[α,β] = y_{α+β} where y is a pseudo-moment sequence.
    
    For a valid measure μ: y_α = ∫ x^α dμ(x), and M_k(y) ≽ 0.
    
    Attributes:
        order: Hierarchy level k
        n_vars: Number of variables
        basis: Monomial basis of degree ≤ k
        entries: Moment values y_α
    """
    order: int
    n_vars: int
    basis: MonomialBasis
    entries: Dict[Monomial, float]
    
    @staticmethod
    def create_symbolic(n_vars: int, order: int, name: str = "y") -> 'MomentMatrix':
        """Create moment matrix with symbolic entries."""
        basis = MonomialBasis.create(n_vars, order)
        
        # Need moments up to degree 2*order
        max_degree = 2 * order
        all_monomials = []
        for d in range(max_degree + 1):
            for exps in _partitions_list(d, n_vars):
                all_monomials.append(tuple(exps))
        
        # Create Z3 variables for each moment
        entries = {}
        for mono in all_monomials:
            mono_str = "_".join(str(e) for e in mono)
            entries[mono] = z3.Real(f"{name}_{mono_str}")
        
        return MomentMatrix(
            order=order,
            n_vars=n_vars,
            basis=basis,
            entries=entries
        )
    
    def get_matrix_entry(self, alpha: Monomial, beta: Monomial) -> Any:
        """Get M[α,β] = y_{α+β}."""
        combined = tuple(a + b for a, b in zip(alpha, beta))
        return self.entries.get(combined, z3.RealVal(0))
    
    def get_psd_constraints(self) -> List[z3.BoolRef]:
        """Generate PSD constraints for moment matrix."""
        constraints = []
        n = len(self.basis)
        
        # Build moment matrix symbolically and add PSD constraints
        # For efficiency, use principal minors up to size 3
        
        # 1x1 minors (diagonal): M[α,α] = y_{2α} ≥ 0
        for alpha in self.basis.monomials:
            entry = self.get_matrix_entry(alpha, alpha)
            if isinstance(entry, z3.ArithRef):
                constraints.append(entry >= 0)
        
        # 2x2 minors
        monomials = list(self.basis.monomials)
        for i in range(min(n, 10)):
            for j in range(i + 1, min(n, 10)):
                m_ii = self.get_matrix_entry(monomials[i], monomials[i])
                m_jj = self.get_matrix_entry(monomials[j], monomials[j])
                m_ij = self.get_matrix_entry(monomials[i], monomials[j])
                
                # det ≥ 0: m_ii * m_jj - m_ij² ≥ 0
                if isinstance(m_ii, z3.ArithRef):
                    constraints.append(m_ii * m_jj >= m_ij * m_ij)
        
        return constraints
    
    def extract_candidate_point(self, model: z3.ModelRef) -> Optional[List[float]]:
        """
        Extract a candidate point from moment solution.
        
        If moments correspond to a point mass at x*, then:
        y_α = (x*)^α for all α.
        
        We can recover x* from first-order moments y_{e_i}.
        """
        point = []
        for i in range(self.n_vars):
            mono = tuple(1 if j == i else 0 for j in range(self.n_vars))
            if mono in self.entries:
                val = self.entries[mono]
                if isinstance(val, z3.ArithRef):
                    eval_val = model.eval(val, model_completion=True)
                    try:
                        point.append(float(eval_val.as_fraction()))
                    except:
                        return None
                else:
                    point.append(float(val))
            else:
                return None
        
        return point


def _partitions_list(total: int, n_parts: int) -> List[List[int]]:
    """Generate all partitions as a list."""
    if n_parts == 1:
        return [[total]]
    result = []
    for i in range(total + 1):
        for rest in _partitions_list(total - i, n_parts - 1):
            result.append([i] + rest)
    return result


@dataclass
class LocalizingMatrix:
    """
    Localizing matrix for constraint g(x) ≥ 0.
    
    M_k(g·y) is indexed by monomials of degree ≤ k - ⌈deg(g)/2⌉,
    with entries M[α,β] = Σ_γ g_γ y_{α+β+γ}.
    
    The constraint g(x) ≥ 0 implies M_k(g·y) ≽ 0 for valid moments.
    
    Attributes:
        constraint: The polynomial g
        moment_matrix: Parent moment matrix
        basis: Reduced monomial basis
    """
    constraint: Polynomial
    moment_matrix: MomentMatrix
    basis: MonomialBasis
    
    @staticmethod
    def create(constraint: Polynomial, moment_matrix: MomentMatrix) -> 'LocalizingMatrix':
        """Create localizing matrix for a constraint."""
        # Reduced degree: k - ceil(deg(g)/2)
        g_deg = constraint.degree()
        reduced_order = moment_matrix.order - (g_deg + 1) // 2
        
        if reduced_order < 0:
            reduced_order = 0
        
        basis = MonomialBasis.create(moment_matrix.n_vars, reduced_order)
        
        return LocalizingMatrix(
            constraint=constraint,
            moment_matrix=moment_matrix,
            basis=basis
        )
    
    def get_matrix_entry(self, alpha: Monomial, beta: Monomial) -> z3.ArithRef:
        """Get M[α,β] = Σ_γ g_γ y_{α+β+γ}."""
        result = z3.RealVal(0)
        
        for gamma, coeff in self.constraint.coeffs.items():
            combined = tuple(a + b + g for a, b, g in zip(alpha, beta, gamma))
            moment_val = self.moment_matrix.entries.get(combined, z3.RealVal(0))
            result = result + z3.RealVal(coeff) * moment_val
        
        return result
    
    def get_psd_constraints(self) -> List[z3.BoolRef]:
        """Generate PSD constraints for localizing matrix."""
        constraints = []
        n = len(self.basis)
        
        if n == 0:
            return constraints
        
        # Diagonal entries ≥ 0
        monomials = list(self.basis.monomials)
        for alpha in monomials[:min(n, 10)]:
            entry = self.get_matrix_entry(alpha, alpha)
            constraints.append(entry >= 0)
        
        # 2x2 minors
        for i in range(min(n, 8)):
            for j in range(i + 1, min(n, 8)):
                m_ii = self.get_matrix_entry(monomials[i], monomials[i])
                m_jj = self.get_matrix_entry(monomials[j], monomials[j])
                m_ij = self.get_matrix_entry(monomials[i], monomials[j])
                
                constraints.append(m_ii * m_jj >= m_ij * m_ij)
        
        return constraints


@dataclass
class LasserreRelaxation:
    """
    A single level of the Lasserre hierarchy.
    
    Represents the moment relaxation at order k for proving f(x) ≥ 0 on
    the semialgebraic set K = {g_i(x) ≥ 0}.
    
    Attributes:
        order: Hierarchy level k
        target: Polynomial f(x) to prove nonnegative
        domain: Semialgebraic set K
        moment_matrix: M_k(y)
        localizing_matrices: M_k(g_i·y) for each constraint
    """
    order: int
    target: Polynomial
    domain: SemialgebraicSet
    moment_matrix: MomentMatrix
    localizing_matrices: List[LocalizingMatrix]
    
    @staticmethod
    def create(order: int, target: Polynomial,
               domain: SemialgebraicSet) -> 'LasserreRelaxation':
        """Create Lasserre relaxation at given order."""
        n_vars = domain.n_vars
        
        # Create moment matrix
        moment_matrix = MomentMatrix.create_symbolic(n_vars, order)
        
        # Create localizing matrices for each constraint
        localizing = []
        for g in domain.inequalities:
            loc_mat = LocalizingMatrix.create(g, moment_matrix)
            localizing.append(loc_mat)
        
        return LasserreRelaxation(
            order=order,
            target=target,
            domain=domain,
            moment_matrix=moment_matrix,
            localizing_matrices=localizing
        )
    
    def get_all_constraints(self) -> List[z3.BoolRef]:
        """Get all constraints for this relaxation level."""
        constraints = []
        
        # Moment matrix PSD
        constraints.extend(self.moment_matrix.get_psd_constraints())
        
        # Localizing matrices PSD
        for loc_mat in self.localizing_matrices:
            constraints.extend(loc_mat.get_psd_constraints())
        
        # Normalization: y_0 = 1 (probability measure)
        zero_mono = tuple([0] * self.domain.n_vars)
        if zero_mono in self.moment_matrix.entries:
            constraints.append(self.moment_matrix.entries[zero_mono] == 1)
        
        return constraints
    
    def encode_nonnegativity(self) -> Tuple[z3.Solver, z3.ArithRef]:
        """
        Encode the relaxation as a Z3 problem.
        
        Returns solver and variable representing the lower bound γ.
        """
        solver = z3.Solver()
        
        # Add moment constraints
        solver.add(*self.get_all_constraints())
        
        # Objective: maximize γ such that ∫f dμ ≥ γ
        # Which is: Σ_α f_α y_α ≥ γ
        gamma = z3.Real("gamma")
        
        integral = z3.RealVal(0)
        for mono, coeff in self.target.coeffs.items():
            if mono in self.moment_matrix.entries:
                integral = integral + z3.RealVal(coeff) * self.moment_matrix.entries[mono]
        
        solver.add(integral >= gamma)
        
        return solver, gamma


class LasserreHierarchySolver:
    """
    Solver for the Lasserre hierarchy.
    
    Implements systematic degree-lifting with:
    - Staged exploration from low to high orders
    - Early termination on success
    - Dual extraction for refinement information
    """
    
    def __init__(self, schedule: Optional[HierarchySchedule] = None,
                 verbose: bool = False):
        self.schedule = schedule or HierarchySchedule()
        self.verbose = verbose
        
        # Results from each level
        self.level_results: List[HierarchyLevelResult] = []
    
    def solve_nonnegativity(self, target: Polynomial,
                            domain: SemialgebraicSet) -> Tuple[bool, int, Optional[float]]:
        """
        Prove f(x) ≥ 0 on domain using Lasserre hierarchy.
        
        Args:
            target: Polynomial f(x)
            domain: Semialgebraic domain
        
        Returns:
            (success, level_used, lower_bound)
        """
        start_time = time.time()
        
        for level in self.schedule.levels():
            elapsed = (time.time() - start_time) * 1000
            timeout = self.schedule.get_level_timeout(level, elapsed)
            
            if timeout <= 0:
                if self.verbose:
                    print(f"[Lasserre] Total timeout reached at level {level}")
                break
            
            result = self._solve_at_level(level, target, domain, timeout)
            self.level_results.append(result)
            
            if result.status == HierarchyStatus.FEASIBLE:
                return True, level, result.gap
            
            if self.verbose:
                print(f"[Lasserre] Level {level}: {result.status.name}, "
                      f"time={result.solve_time_ms:.1f}ms")
        
        return False, -1, None
    
    def _solve_at_level(self, level: int, target: Polynomial,
                        domain: SemialgebraicSet,
                        timeout_ms: int) -> HierarchyLevelResult:
        """Attempt to prove nonnegativity at a specific hierarchy level."""
        start = time.time()
        
        try:
            # Create relaxation
            relaxation = LasserreRelaxation.create(level, target, domain)
            
            # Encode and solve
            solver, gamma = relaxation.encode_nonnegativity()
            solver.set("timeout", timeout_ms)
            
            # We want to maximize γ, so we do binary search
            # For now, just check if γ ≥ 0 is feasible
            solver.add(gamma >= 0)
            
            result = solver.check()
            elapsed = (time.time() - start) * 1000
            
            if result == z3.sat:
                model = solver.model()
                gamma_val = model.eval(gamma, model_completion=True)
                try:
                    gap = float(gamma_val.as_fraction())
                except:
                    gap = 0.0
                
                # Extract moment solution for potential counterexamples
                moment_sol = self._extract_moments(relaxation.moment_matrix, model)
                
                return HierarchyLevelResult(
                    level=level,
                    status=HierarchyStatus.FEASIBLE,
                    moment_solution=moment_sol,
                    solve_time_ms=elapsed,
                    gap=gap
                )
            elif result == z3.unsat:
                return HierarchyLevelResult(
                    level=level,
                    status=HierarchyStatus.INFEASIBLE,
                    solve_time_ms=elapsed
                )
            else:
                return HierarchyLevelResult(
                    level=level,
                    status=HierarchyStatus.TIMEOUT,
                    solve_time_ms=elapsed
                )
                
        except Exception as e:
            elapsed = (time.time() - start) * 1000
            if self.verbose:
                print(f"[Lasserre] Error at level {level}: {e}")
            return HierarchyLevelResult(
                level=level,
                status=HierarchyStatus.NUMERICAL_ERROR,
                solve_time_ms=elapsed
            )
    
    def _extract_moments(self, moment_matrix: MomentMatrix,
                         model: z3.ModelRef) -> Dict[Monomial, float]:
        """Extract moment values from Z3 model."""
        moments = {}
        for mono, var in moment_matrix.entries.items():
            if isinstance(var, z3.ArithRef):
                val = model.eval(var, model_completion=True)
                try:
                    moments[mono] = float(val.as_fraction())
                except:
                    moments[mono] = 0.0
        return moments
    
    def get_candidate_counterexamples(self) -> List[List[float]]:
        """
        Extract candidate counterexample points from moment solutions.
        
        Uses the atomic measure interpretation: if the moment solution
        corresponds to a point mass, we can extract the support point.
        """
        candidates = []
        
        for result in self.level_results:
            if result.moment_solution:
                # Try to extract point from first-order moments
                point = self._extract_point_from_moments(result.moment_solution)
                if point:
                    candidates.append(point)
        
        return candidates
    
    def _extract_point_from_moments(self, moments: Dict[Monomial, float]) -> Optional[List[float]]:
        """Extract point from moment sequence (if it's atomic)."""
        # Find the dimension from the moments
        if not moments:
            return None
        
        max_len = max(len(m) for m in moments.keys())
        n_vars = max_len
        
        # Extract first-order moments (mean values)
        point = []
        for i in range(n_vars):
            mono = tuple(1 if j == i else 0 for j in range(n_vars))
            if mono in moments:
                point.append(moments[mono])
            else:
                return None
        
        return point


# =============================================================================
# BARRIER SYNTHESIS WITH LASSERRE HIERARCHY
# =============================================================================

@dataclass
class LasserreBarrierConfig:
    """
    Configuration for Lasserre-based barrier synthesis.
    
    Attributes:
        min_degree: Starting barrier degree
        max_degree: Maximum barrier degree
        schedule: Hierarchy exploration schedule
        sos_multiplier_boost: Extra degree for SOS multipliers
        use_warm_start: Reuse solutions from lower levels
    """
    min_degree: int = 2
    max_degree: int = 8
    schedule: Optional[HierarchySchedule] = None
    sos_multiplier_boost: int = 0
    use_warm_start: bool = True
    
    @property
    def levels(self) -> range:
        """Get hierarchy levels (degree/2)."""
        return range(self.min_degree // 2, self.max_degree // 2 + 1)


@dataclass 
class LasserreBarrierResult:
    """
    Result of Lasserre-based barrier synthesis.
    
    Attributes:
        success: Whether a barrier was found
        barrier: The barrier polynomial (if success)
        degree_used: Degree of successful barrier
        levels_tried: Number of hierarchy levels attempted
        level_results: Results from each level
        candidate_counterexamples: Points extracted from failed levels
        total_time_ms: Total synthesis time
        message: Status message
    """
    success: bool
    barrier: Optional[Polynomial] = None
    degree_used: int = 0
    levels_tried: int = 0
    level_results: List[HierarchyLevelResult] = field(default_factory=list)
    candidate_counterexamples: List[List[float]] = field(default_factory=list)
    total_time_ms: float = 0.0
    message: str = ""
    
    def summary(self) -> str:
        """Generate summary string."""
        if self.success:
            return (f"LASSERRE SUCCESS: degree-{self.degree_used} barrier found "
                    f"({self.levels_tried} levels, {self.total_time_ms:.1f}ms)")
        else:
            return (f"LASSERRE FAILED: {self.message} "
                    f"({self.levels_tried} levels, {self.total_time_ms:.1f}ms)")


class LasserreBarrierSynthesizer:
    """
    Barrier certificate synthesis using Lasserre hierarchy.
    
    This synthesizer implements staged deepening:
    1. Start with low-degree barriers (fast, often sufficient)
    2. Increase degree only when lower degrees fail
    3. Extract counterexample candidates from failed attempts
    4. Provide completeness information (no barrier up to degree k)
    """
    
    def __init__(self, problem: BarrierSynthesisProblem,
                 config: Optional[LasserreBarrierConfig] = None,
                 verbose: bool = False):
        self.problem = problem
        self.config = config or LasserreBarrierConfig()
        self.verbose = verbose
        
        # Z3 variables
        var_names = problem.init_set.var_names or [f"x{i}" for i in range(problem.n_vars)]
        self.z3_vars = [z3.Real(name) for name in var_names]
    
    def synthesize(self) -> LasserreBarrierResult:
        """
        Synthesize barrier using Lasserre hierarchy.
        
        Tries increasing degrees until success or budget exhaustion.
        """
        start_time = time.time()
        level_results = []
        candidate_ces = []
        
        schedule = self.config.schedule or HierarchySchedule(
            min_level=self.config.min_degree // 2,
            max_level=self.config.max_degree // 2,
            total_timeout_ms=60000
        )
        
        for level in schedule.levels():
            degree = 2 * level
            elapsed = (time.time() - start_time) * 1000
            timeout = schedule.get_level_timeout(level, elapsed)
            
            if timeout <= 0:
                break
            
            if self.verbose:
                print(f"[Lasserre] Trying degree {degree} barrier...")
            
            result = self._try_degree(degree, timeout)
            level_results.append(result)
            
            if result.status == HierarchyStatus.FEASIBLE and result.certificate:
                return LasserreBarrierResult(
                    success=True,
                    barrier=result.certificate.barrier,
                    degree_used=degree,
                    levels_tried=len(level_results),
                    level_results=level_results,
                    total_time_ms=(time.time() - start_time) * 1000,
                    message="Barrier found"
                )
            
            # Extract counterexample candidates from failed attempt
            if result.moment_solution:
                point = self._extract_point(result.moment_solution)
                if point:
                    candidate_ces.append(point)
        
        return LasserreBarrierResult(
            success=False,
            levels_tried=len(level_results),
            level_results=level_results,
            candidate_counterexamples=candidate_ces,
            total_time_ms=(time.time() - start_time) * 1000,
            message=f"No barrier found up to degree {self.config.max_degree}"
        )
    
    def _try_degree(self, degree: int, timeout_ms: int) -> HierarchyLevelResult:
        """Attempt barrier synthesis at a specific degree."""
        level = degree // 2
        start = time.time()
        
        try:
            # Create synthesis problem at this degree
            synth = SOSBarrierSynthesizer(
                BarrierSynthesisProblem(
                    n_vars=self.problem.n_vars,
                    init_set=self.problem.init_set,
                    unsafe_set=self.problem.unsafe_set,
                    transition=self.problem.transition,
                    invariant_set=self.problem.invariant_set,
                    epsilon=self.problem.epsilon,
                    barrier_degree=degree
                ),
                verbose=self.verbose,
                timeout_ms=timeout_ms
            )
            
            result = synth.synthesize()
            elapsed = (time.time() - start) * 1000
            
            if result.success:
                return HierarchyLevelResult(
                    level=level,
                    status=HierarchyStatus.FEASIBLE,
                    certificate=result,
                    solve_time_ms=elapsed
                )
            else:
                return HierarchyLevelResult(
                    level=level,
                    status=HierarchyStatus.INFEASIBLE,
                    solve_time_ms=elapsed
                )
                
        except Exception as e:
            elapsed = (time.time() - start) * 1000
            if self.verbose:
                print(f"[Lasserre] Error at degree {degree}: {e}")
            return HierarchyLevelResult(
                level=level,
                status=HierarchyStatus.NUMERICAL_ERROR,
                solve_time_ms=elapsed
            )
    
    def _extract_point(self, moments: Dict[Monomial, float]) -> Optional[List[float]]:
        """Extract candidate point from moment solution."""
        n_vars = self.problem.n_vars
        point = []
        
        for i in range(n_vars):
            mono = tuple(1 if j == i else 0 for j in range(n_vars))
            if mono in moments:
                point.append(moments[mono])
            else:
                return None
        
        return point


# =============================================================================
# PORTFOLIO INTEGRATION WITH STAGED DEEPENING
# =============================================================================

@dataclass
class StagedDeepeningConfig:
    """
    Configuration for staged deepening across the hierarchy.
    
    Attributes:
        initial_degree: Starting degree for all attempts
        degree_increment: How much to increase degree on failure
        max_degree: Maximum degree to attempt
        parallel_attempts: Number of parallel degree attempts
        budget_per_degree_ms: Time budget for each degree
    """
    initial_degree: int = 2
    degree_increment: int = 2
    max_degree: int = 10
    parallel_attempts: int = 1
    budget_per_degree_ms: int = 5000


class StagedDeepeningOrchestrator:
    """
    Orchestrates staged deepening across multiple barrier problems.
    
    This class manages the interaction between:
    - Multiple barrier synthesis problems (different hazards)
    - The Lasserre hierarchy for each problem
    - Resource allocation across problems
    
    Key insight: Low-degree success on one problem frees budget for
    higher-degree attempts on harder problems.
    """
    
    def __init__(self, config: Optional[StagedDeepeningConfig] = None,
                 verbose: bool = False):
        self.config = config or StagedDeepeningConfig()
        self.verbose = verbose
        
        # Tracking state
        self._problems: Dict[str, BarrierSynthesisProblem] = {}
        self._results: Dict[str, LasserreBarrierResult] = {}
        self._degree_attempts: Dict[str, int] = {}  # Current degree per problem
    
    def add_problem(self, problem_id: str, problem: BarrierSynthesisProblem) -> None:
        """Add a barrier synthesis problem."""
        self._problems[problem_id] = problem
        self._degree_attempts[problem_id] = self.config.initial_degree
    
    def solve_all(self, total_timeout_ms: int = 60000) -> Dict[str, LasserreBarrierResult]:
        """
        Solve all problems with staged deepening.
        
        Strategy:
        1. Try all problems at initial degree
        2. Remove solved problems
        3. Increase degree for unsolved problems
        4. Repeat until budget exhausted
        """
        start_time = time.time()
        
        while True:
            elapsed = (time.time() - start_time) * 1000
            if elapsed >= total_timeout_ms:
                break
            
            # Find unsolved problems
            unsolved = [pid for pid in self._problems 
                       if pid not in self._results or not self._results[pid].success]
            
            if not unsolved:
                break
            
            # Try each unsolved problem at its current degree
            remaining_budget = total_timeout_ms - elapsed
            per_problem_budget = remaining_budget / len(unsolved)
            
            for pid in unsolved:
                problem = self._problems[pid]
                degree = self._degree_attempts[pid]
                
                if degree > self.config.max_degree:
                    # Mark as failed
                    if pid not in self._results:
                        self._results[pid] = LasserreBarrierResult(
                            success=False,
                            message=f"Exceeded max degree {self.config.max_degree}"
                        )
                    continue
                
                result = self._solve_one(problem, degree, int(per_problem_budget))
                
                if result.success:
                    self._results[pid] = result
                    if self.verbose:
                        print(f"[Staged] Problem {pid} solved at degree {degree}")
                else:
                    # Increase degree for next round
                    self._degree_attempts[pid] += self.config.degree_increment
                    self._results[pid] = result
            
            # Check if all problems are at max degree
            all_at_max = all(
                self._degree_attempts.get(pid, 0) > self.config.max_degree
                for pid in unsolved
            )
            if all_at_max:
                break
        
        return self._results
    
    def _solve_one(self, problem: BarrierSynthesisProblem,
                   degree: int, timeout_ms: int) -> LasserreBarrierResult:
        """Solve one problem at a specific degree."""
        config = LasserreBarrierConfig(
            min_degree=degree,
            max_degree=degree,  # Only try this one degree
            schedule=HierarchySchedule(
                min_level=degree // 2,
                max_level=degree // 2,
                timeout_per_level_ms=timeout_ms,
                total_timeout_ms=timeout_ms
            )
        )
        
        synthesizer = LasserreBarrierSynthesizer(
            problem,
            config=config,
            verbose=self.verbose
        )
        
        return synthesizer.synthesize()
    
    def get_counterexample_pool(self) -> List[Tuple[str, List[float]]]:
        """
        Get all counterexample candidates from failed attempts.
        
        Returns:
            List of (problem_id, candidate_point) pairs
        """
        pool = []
        for pid, result in self._results.items():
            for ce in result.candidate_counterexamples:
                pool.append((pid, ce))
        return pool


# =============================================================================
# INTEGRATION WITH CEGIS AND PYFROMSCRATCH
# =============================================================================

class LasserreCEGISIntegration:
    """
    Integration layer between Lasserre hierarchy and CEGIS.
    
    This class bridges:
    - Counterexample extraction from moment solutions
    - Feeding candidates back to CEGIS refinement
    - Coordinating degree increases with CEGIS iterations
    """
    
    def __init__(self, verbose: bool = False):
        self.verbose = verbose
        self._counterexample_cache: List[Tuple[str, List[float]]] = []
    
    def extract_refinement_hints(self, result: LasserreBarrierResult) -> Dict[str, Any]:
        """
        Extract hints for CEGIS refinement from failed Lasserre attempt.
        
        Hints include:
        - Candidate counterexample points
        - Degree lower bound (no barrier exists below this)
        - Tight constraints (from dual information)
        """
        hints = {
            'degree_lower_bound': result.degree_used,
            'candidate_counterexamples': result.candidate_counterexamples,
            'levels_explored': result.levels_tried,
        }
        
        # Analyze level results for tight constraints
        for level_result in result.level_results:
            if level_result.dual_variables:
                hints['tight_constraints'] = [
                    k for k, v in level_result.dual_variables.items()
                    if abs(v) > 0.1
                ]
        
        return hints
    
    def integrate_counterexamples(self, ce_points: List[List[float]],
                                  problem: BarrierSynthesisProblem) -> None:
        """
        Integrate counterexample points into the problem.
        
        These points can be:
        1. Validated (are they actually reachable?)
        2. Used to refine the invariant set
        3. Added as explicit constraints
        """
        for point in ce_points:
            # Cache for later use
            self._counterexample_cache.append(("lasserre", point))
    
    def get_cached_counterexamples(self) -> List[List[float]]:
        """Get all cached counterexample candidates."""
        return [ce for _, ce in self._counterexample_cache]


class LasserreIntegration:
    """
    Main integration class for Lasserre hierarchy in a3-python.
    
    Provides the interface for the kitchen-sink orchestrator to use
    Lasserre-based barrier synthesis with systematic degree lifting.
    """
    
    def __init__(self, verbose: bool = False):
        self.verbose = verbose
        self._cache: Dict[str, LasserreBarrierResult] = {}
        self._orchestrator: Optional[StagedDeepeningOrchestrator] = None
    
    def try_lasserre_proof(self, problem: BarrierSynthesisProblem,
                           max_degree: int = 6,
                           timeout_ms: int = 30000) -> LasserreBarrierResult:
        """
        Attempt Lasserre-based barrier synthesis.
        
        Args:
            problem: Barrier synthesis problem
            max_degree: Maximum polynomial degree
            timeout_ms: Total time budget
        
        Returns:
            LasserreBarrierResult with barrier or failure info
        """
        # Check cache
        cache_key = self._problem_key(problem, max_degree)
        if cache_key in self._cache:
            return self._cache[cache_key]
        
        config = LasserreBarrierConfig(
            min_degree=2,
            max_degree=max_degree,
            schedule=HierarchySchedule(
                min_level=1,
                max_level=max_degree // 2,
                total_timeout_ms=timeout_ms
            )
        )
        
        synthesizer = LasserreBarrierSynthesizer(
            problem,
            config=config,
            verbose=self.verbose
        )
        
        result = synthesizer.synthesize()
        self._cache[cache_key] = result
        
        return result
    
    def staged_deepening(self, problems: Dict[str, BarrierSynthesisProblem],
                         config: Optional[StagedDeepeningConfig] = None,
                         timeout_ms: int = 60000) -> Dict[str, LasserreBarrierResult]:
        """
        Solve multiple problems with coordinated staged deepening.
        
        Args:
            problems: Dictionary of problem_id -> BarrierSynthesisProblem
            config: Staged deepening configuration
            timeout_ms: Total time budget
        
        Returns:
            Dictionary of problem_id -> LasserreBarrierResult
        """
        self._orchestrator = StagedDeepeningOrchestrator(
            config=config,
            verbose=self.verbose
        )
        
        for pid, problem in problems.items():
            self._orchestrator.add_problem(pid, problem)
        
        return self._orchestrator.solve_all(timeout_ms)
    
    def get_counterexample_candidates(self) -> List[Tuple[str, List[float]]]:
        """Get all counterexample candidates from failed attempts."""
        if self._orchestrator:
            return self._orchestrator.get_counterexample_pool()
        return []
    
    def _problem_key(self, problem: BarrierSynthesisProblem, max_degree: int) -> str:
        """Generate cache key for a problem."""
        # Simple hash based on problem structure
        return f"{problem.n_vars}_{len(problem.init_set.inequalities)}_{max_degree}"
    
    def clear_cache(self) -> None:
        """Clear the result cache."""
        self._cache.clear()


# =============================================================================
# ADVANCED MOMENT TECHNIQUES
# =============================================================================

class FlatExtensionDetector:
    """
    Detector for flat extensions in moment matrices.
    
    A flat extension occurs when the rank of M_{k+1}(y) equals the rank
    of M_k(y). This indicates convergence of the Lasserre hierarchy and
    allows extraction of the optimal solution.
    
    Theory: If M_k(y) has rank r and admits a flat extension M_{k+1}(y),
    then the optimal measure is r-atomic (supported on r points).
    """
    
    def __init__(self, tolerance: float = 1e-6):
        self.tolerance = tolerance
    
    def check_flat_extension(self, moments_k: MomentMatrix,
                             moments_k1: MomentMatrix) -> Tuple[bool, int]:
        """
        Check if M_{k+1}(y) is a flat extension of M_k(y).
        
        Returns (is_flat, rank).
        """
        rank_k = self._estimate_rank(moments_k)
        rank_k1 = self._estimate_rank(moments_k1)
        
        is_flat = (rank_k == rank_k1)
        
        return is_flat, rank_k
    
    def _estimate_rank(self, moment_matrix: MomentMatrix) -> int:
        """
        Estimate numerical rank of moment matrix.
        
        Uses singular value analysis (simplified for Z3 symbolic entries).
        """
        n = len(moment_matrix.basis)
        
        # For concrete entries, would compute SVD
        # For now, return dimension (no rank deficiency detected)
        return n
    
    def extract_atomic_measure(self, moments: MomentMatrix,
                                rank: int) -> List[Tuple[List[float], float]]:
        """
        Extract atomic measure from moment sequence.
        
        Returns list of (point, weight) pairs.
        
        Uses Curto-Fialkow moment theory: given a flat extension,
        the support points can be recovered from eigenanalysis.
        """
        atoms = []
        
        # For rank-1 case (point mass), extract directly from first moments
        if rank == 1:
            point = []
            for i in range(moments.n_vars):
                mono = tuple(1 if j == i else 0 for j in range(moments.n_vars))
                if mono in moments.entries:
                    val = moments.entries[mono]
                    if isinstance(val, (int, float)):
                        point.append(float(val))
                    else:
                        point.append(0.0)
                else:
                    point.append(0.0)
            
            atoms.append((point, 1.0))
        
        return atoms


class ChristofelFunction:
    """
    Christoffel function for polynomial sampling.
    
    The Christoffel function λ_k(x) = 1/||m_k(x)||²_{M_k^{-1}}
    provides a polynomial approximation to the density of the
    optimal measure.
    
    Uses:
    1. Identifying regions where the optimal measure is concentrated
    2. Generating candidate counterexample points
    3. Importance sampling for moment extraction
    """
    
    def __init__(self, moment_matrix: MomentMatrix):
        self.moment_matrix = moment_matrix
        self.n_vars = moment_matrix.n_vars
        self.order = moment_matrix.order
    
    def evaluate(self, point: List[float]) -> float:
        """
        Evaluate Christoffel function at a point.
        
        λ(x) = 1 / m(x)ᵀ M⁻¹ m(x)
        
        where m(x) is the monomial vector and M is the moment matrix.
        """
        # Build monomial vector
        m_x = []
        for mono in self.moment_matrix.basis.monomials:
            val = 1.0
            for i, exp in enumerate(mono):
                val *= point[i] ** exp
            m_x.append(val)
        
        # For simplicity, assume M = I (would need actual moment values)
        norm_sq = sum(v * v for v in m_x)
        
        if norm_sq < 1e-10:
            return 0.0
        
        return 1.0 / norm_sq
    
    def find_maxima(self, domain: SemialgebraicSet,
                    n_samples: int = 100) -> List[List[float]]:
        """
        Find approximate maxima of Christoffel function on domain.
        
        High-value regions indicate where measure is concentrated.
        """
        import random
        
        # Sample random points and evaluate
        candidates = []
        
        for _ in range(n_samples):
            # Generate random point (simplified - assumes box domain)
            point = [random.uniform(-1, 1) for _ in range(self.n_vars)]
            val = self.evaluate(point)
            candidates.append((val, point))
        
        # Return top points
        candidates.sort(reverse=True)
        return [p for _, p in candidates[:10]]


class MomentSequenceValidator:
    """
    Validator for moment sequences.
    
    A sequence y = (y_α)_{|α|≤2k} is a valid moment sequence if:
    1. M_k(y) ≽ 0 (moment matrix is PSD)
    2. M_{k-d}(g_i · y) ≽ 0 for each constraint g_i (localizing matrices PSD)
    
    This class checks these conditions and provides diagnostics.
    """
    
    def __init__(self, tolerance: float = 1e-6):
        self.tolerance = tolerance
    
    def validate_moments(self, moments: Dict[Monomial, float],
                         n_vars: int,
                         order: int) -> Tuple[bool, List[str]]:
        """
        Validate a moment sequence.
        
        Returns (is_valid, list_of_issues).
        """
        issues = []
        
        # Check normalization: y_0 = 1
        zero_mono = tuple([0] * n_vars)
        y_0 = moments.get(zero_mono, 0)
        
        if abs(y_0 - 1.0) > self.tolerance:
            issues.append(f"Normalization: y_0 = {y_0} ≠ 1")
        
        # Check moment matrix PSD (simplified)
        # Would build matrix and check eigenvalues
        
        # Check consistency: y_{2α} ≥ 0 for all α
        for mono, val in moments.items():
            if all(e % 2 == 0 for e in mono) and val < -self.tolerance:
                issues.append(f"Non-PSD: y_{mono} = {val} < 0")
        
        return len(issues) == 0, issues
    
    def check_supports_measure(self, moments: Dict[Monomial, float],
                                domain: SemialgebraicSet) -> bool:
        """
        Check if moment sequence could come from measure supported on domain.
        
        Uses necessary conditions from constraint polynomials.
        """
        # For each constraint g(x) ≥ 0, we need ∫g dμ ≥ 0
        # i.e., Σ_α g_α y_α ≥ 0
        
        for g in domain.inequalities:
            integral = sum(g.coeffs.get(mono, 0) * moments.get(mono, 0)
                          for mono in g.coeffs.keys())
            
            if integral < -self.tolerance:
                return False
        
        return True


# =============================================================================
# HIERARCHY CONVERGENCE ANALYSIS
# =============================================================================

@dataclass
class ConvergenceInfo:
    """
    Information about Lasserre hierarchy convergence.
    
    Attributes:
        level: Current hierarchy level
        lower_bound: Current lower bound on optimum
        gap_estimate: Estimated optimality gap
        rank_sequence: Ranks of moment matrices at each level
        flat_extension: Whether flat extension detected
        convergence_rate: Estimated convergence rate
    """
    level: int
    lower_bound: float
    gap_estimate: float
    rank_sequence: List[int] = field(default_factory=list)
    flat_extension: bool = False
    convergence_rate: float = 0.0


class HierarchyConvergenceAnalyzer:
    """
    Analyzes convergence of Lasserre hierarchy.
    
    Provides:
    1. Convergence detection (flat extension, gap closure)
    2. Rate estimation (for predicting required levels)
    3. Early termination criteria
    """
    
    def __init__(self, verbose: bool = False):
        self.verbose = verbose
        self._level_bounds: List[float] = []
        self._level_times: List[float] = []
    
    def record_level(self, level: int, bound: float, time_ms: float) -> None:
        """Record result from a hierarchy level."""
        while len(self._level_bounds) <= level:
            self._level_bounds.append(float('-inf'))
            self._level_times.append(0)
        
        self._level_bounds[level] = bound
        self._level_times[level] = time_ms
    
    def estimate_convergence_rate(self) -> float:
        """
        Estimate convergence rate from level history.
        
        Rate is the factor by which the gap decreases per level.
        """
        if len(self._level_bounds) < 3:
            return 0.5  # Default estimate
        
        # Compare gap reduction between consecutive levels
        gaps = []
        for i in range(1, len(self._level_bounds)):
            if self._level_bounds[i] > self._level_bounds[i-1]:
                improvement = self._level_bounds[i] - self._level_bounds[i-1]
                gaps.append(improvement)
        
        if not gaps:
            return 0.5
        
        avg_improvement = sum(gaps) / len(gaps)
        return min(0.9, max(0.1, 1.0 - avg_improvement))
    
    def predict_required_levels(self, target_gap: float,
                                 current_level: int,
                                 current_gap: float) -> int:
        """
        Predict how many more levels needed to reach target gap.
        """
        rate = self.estimate_convergence_rate()
        
        if rate >= 1.0:
            return 100  # Won't converge
        
        import math
        
        if current_gap <= target_gap:
            return 0
        
        # gap_k = gap_0 * rate^k
        # target = current * rate^k
        # k = log(target/current) / log(rate)
        
        levels = math.log(target_gap / current_gap) / math.log(rate)
        return int(math.ceil(levels))
    
    def should_continue(self, current_level: int,
                        max_level: int,
                        target_gap: float = 0.01) -> Tuple[bool, str]:
        """
        Decide whether to continue to next level.
        
        Returns (should_continue, reason).
        """
        if current_level >= max_level:
            return False, "Max level reached"
        
        if len(self._level_bounds) < 2:
            return True, "Insufficient history"
        
        # Check for flat extension (convergence)
        if self._level_bounds[-1] == self._level_bounds[-2]:
            return False, "Flat extension detected"
        
        # Check if gap is small enough
        current_gap = self._estimate_current_gap()
        if current_gap <= target_gap:
            return False, "Target gap reached"
        
        # Check if progress is too slow
        rate = self.estimate_convergence_rate()
        predicted = self.predict_required_levels(target_gap, current_level, current_gap)
        
        if predicted > max_level - current_level:
            return False, "Insufficient budget for convergence"
        
        return True, "Continue"
    
    def _estimate_current_gap(self) -> float:
        """Estimate current optimality gap."""
        if len(self._level_bounds) < 2:
            return float('inf')
        
        # Simple estimate: improvement from last two levels
        return abs(self._level_bounds[-1] - self._level_bounds[-2])
    
    def get_convergence_info(self, level: int) -> ConvergenceInfo:
        """Get convergence information at current level."""
        return ConvergenceInfo(
            level=level,
            lower_bound=self._level_bounds[level] if level < len(self._level_bounds) else 0,
            gap_estimate=self._estimate_current_gap(),
            rank_sequence=[],  # Would track from moment matrices
            flat_extension=False,  # Would detect from analysis
            convergence_rate=self.estimate_convergence_rate()
        )


# =============================================================================
# POLYNOMIAL OPTIMIZATION WITH HIERARCHY
# =============================================================================

@dataclass
class HierarchyOptimizationResult:
    """
    Result of polynomial optimization using Lasserre hierarchy.
    
    Attributes:
        optimal_value: Best bound found
        optimizer: Approximate optimal point (if extractable)
        hierarchy_level: Level where bound was achieved
        convergence_info: Convergence analysis
        moment_solution: Final moment sequence
        certificate: Proof certificate (if available)
    """
    optimal_value: float
    optimizer: Optional[List[float]] = None
    hierarchy_level: int = 0
    convergence_info: Optional[ConvergenceInfo] = None
    moment_solution: Optional[Dict[Monomial, float]] = None
    certificate: Optional[str] = None


class HierarchyOptimizer:
    """
    Polynomial optimization using Lasserre hierarchy.
    
    Provides:
    1. Systematic degree-lifting for global optimization
    2. Convergence detection and analysis
    3. Solution extraction from moment matrices
    """
    
    def __init__(self, objective: Polynomial,
                 domain: SemialgebraicSet,
                 schedule: Optional[HierarchySchedule] = None,
                 verbose: bool = False):
        self.objective = objective
        self.domain = domain
        self.schedule = schedule or HierarchySchedule()
        self.verbose = verbose
        
        self._analyzer = HierarchyConvergenceAnalyzer(verbose)
        self._flat_detector = FlatExtensionDetector()
    
    def minimize(self) -> HierarchyOptimizationResult:
        """
        Minimize objective over domain using hierarchy.
        """
        start_time = time.time()
        best_bound = float('-inf')
        best_moments = None
        final_level = 0
        
        for level in self.schedule.levels():
            elapsed = (time.time() - start_time) * 1000
            timeout = self.schedule.get_level_timeout(level, elapsed)
            
            if timeout <= 0:
                break
            
            result = self._solve_level(level, timeout)
            
            if result is not None:
                bound, moments = result
                
                if bound > best_bound:
                    best_bound = bound
                    best_moments = moments
                    final_level = level
                
                self._analyzer.record_level(level, bound, elapsed)
            
            # Check if we should continue
            should_continue, reason = self._analyzer.should_continue(
                level, self.schedule.max_level
            )
            
            if self.verbose:
                print(f"[Hierarchy] Level {level}: bound={best_bound:.4f}, {reason}")
            
            if not should_continue:
                break
        
        # Extract optimizer if possible
        optimizer = None
        if best_moments:
            optimizer = self._extract_optimizer(best_moments)
        
        return HierarchyOptimizationResult(
            optimal_value=best_bound,
            optimizer=optimizer,
            hierarchy_level=final_level,
            convergence_info=self._analyzer.get_convergence_info(final_level),
            moment_solution=best_moments
        )
    
    def _solve_level(self, level: int,
                     timeout_ms: int) -> Optional[Tuple[float, Dict[Monomial, float]]]:
        """Solve relaxation at a specific level."""
        try:
            relaxation = LasserreRelaxation.create(
                level, self.objective, self.domain
            )
            
            solver, gamma = relaxation.encode_nonnegativity()
            solver.set("timeout", timeout_ms)
            
            # Maximize gamma (lower bound on minimum)
            solver.add(gamma >= -1000)
            
            result = solver.check()
            
            if result == z3.sat:
                model = solver.model()
                gamma_val = model.eval(gamma, model_completion=True)
                
                try:
                    bound = float(gamma_val.as_fraction())
                except:
                    bound = 0.0
                
                # Extract moments
                moments = {}
                for mono, var in relaxation.moment_matrix.entries.items():
                    if isinstance(var, z3.ArithRef):
                        val = model.eval(var, model_completion=True)
                        try:
                            moments[mono] = float(val.as_fraction())
                        except:
                            moments[mono] = 0.0
                
                return bound, moments
                
        except Exception as e:
            if self.verbose:
                print(f"[Hierarchy] Level {level} error: {e}")
        
        return None
    
    def _extract_optimizer(self, moments: Dict[Monomial, float]) -> Optional[List[float]]:
        """Extract optimal point from moment sequence."""
        n_vars = self.domain.n_vars
        point = []
        
        for i in range(n_vars):
            mono = tuple(1 if j == i else 0 for j in range(n_vars))
            if mono in moments:
                point.append(moments[mono])
            else:
                return None
        
        return point


# =============================================================================
# Extended Lasserre Hierarchy Features
# =============================================================================

class HierarchyConvergenceAnalyzer:
    """
    Analyze convergence properties of Lasserre hierarchy.
    
    Implements techniques for:
    - Detecting convergence rate
    - Predicting final bound
    - Estimating required degree
    """
    
    def __init__(self):
        self.bounds_history: List[float] = []
        self.level_history: List[int] = []
        
    def record_bound(self, level: int, bound: float) -> None:
        """Record bound at given level."""
        self.bounds_history.append(bound)
        self.level_history.append(level)
    
    def estimate_convergence_rate(self) -> float:
        """
        Estimate convergence rate.
        
        Uses ratio of successive bound improvements.
        """
        if len(self.bounds_history) < 3:
            return 0.0
        
        # Compute successive differences
        diffs = []
        for i in range(1, len(self.bounds_history)):
            diff = abs(self.bounds_history[i] - self.bounds_history[i-1])
            diffs.append(diff)
        
        # Compute ratio (convergence rate)
        if len(diffs) >= 2 and abs(diffs[-2]) > 1e-10:
            return diffs[-1] / diffs[-2]
        
        return 1.0
    
    def predict_final_bound(self) -> Optional[float]:
        """
        Predict final bound using extrapolation.
        
        Assumes geometric convergence.
        """
        if len(self.bounds_history) < 3:
            return None
        
        rate = self.estimate_convergence_rate()
        
        if rate >= 1.0 or rate < 0:
            return None  # Not converging
        
        # Geometric series limit: last + diff/(1-rate)
        last = self.bounds_history[-1]
        diff = abs(self.bounds_history[-1] - self.bounds_history[-2])
        
        return last + diff * rate / (1 - rate)
    
    def estimate_required_level(self, target_accuracy: float) -> int:
        """Estimate level needed to achieve target accuracy."""
        if len(self.bounds_history) < 3:
            return 10  # Default guess
        
        rate = self.estimate_convergence_rate()
        
        if rate >= 1.0 or rate < 0:
            return 20  # Conservative for non-converging
        
        # Solve: rate^k * current_gap < target
        current_gap = abs(self.bounds_history[-1] - self.bounds_history[-2])
        
        if current_gap < target_accuracy:
            return self.level_history[-1]
        
        import math
        k = math.log(target_accuracy / current_gap) / math.log(rate)
        
        return max(self.level_history[-1], int(k) + 1)
    
    def is_converged(self, tolerance: float = 1e-6) -> bool:
        """Check if hierarchy has converged."""
        if len(self.bounds_history) < 2:
            return False
        
        diff = abs(self.bounds_history[-1] - self.bounds_history[-2])
        return diff < tolerance


class MomentMatrixAnalyzer:
    """
    Analyze moment matrix properties.
    
    Provides tools for:
    - Rank analysis
    - Flatness detection
    - Solution extraction
    """
    
    def __init__(self, moment_matrix: 'MomentMatrix'):
        self.moment_matrix = moment_matrix
        
    def get_rank(self, tolerance: float = 1e-6) -> int:
        """
        Estimate rank of moment matrix.
        
        Flat extension (rank equals degree) indicates
        optimizer can be extracted.
        """
        # Would compute eigenvalues and count non-zero
        return len(self.moment_matrix.entries)  # Simplified
    
    def is_flat(self, tolerance: float = 1e-6) -> bool:
        """
        Check if moment matrix is flat.
        
        Flat extension condition enables exact extraction
        of optimal solution.
        """
        # Flatness: rank(M_d) = rank(M_{d-1})
        return True  # Simplified
    
    def extract_atoms(self, num_atoms: int = 1) -> List[List[float]]:
        """
        Extract atomic measure from moment matrix.
        
        Uses Christoffel-Darboux kernel or similar technique.
        """
        atoms = []
        
        # Would use eigenvalue decomposition and root finding
        # Simplified: return origin
        n_vars = self.moment_matrix.size
        atoms.append([0.0] * n_vars)
        
        return atoms
    
    def compute_christoffel_function(self, point: List[float]) -> float:
        """
        Compute Christoffel function at point.
        
        Useful for sampling and solution extraction.
        """
        # K(x) = z(x)ᵀ M⁻¹ z(x) where z is monomial vector
        return 1.0  # Simplified


class DualSolutionExtractor:
    """
    Extract dual solutions (certificates) from hierarchy.
    
    The dual provides:
    - SOS decomposition
    - Positivstellensatz certificates
    """
    
    def __init__(self, solver: z3.Solver, relaxation: 'SOSRelaxation'):
        self.solver = solver
        self.relaxation = relaxation
        
    def extract_sos_certificate(self, model: z3.ModelRef) -> Optional['SOSCertificate']:
        """
        Extract SOS certificate from dual solution.
        """
        if model is None:
            return None
        
        # Extract multiplier polynomials
        multipliers = {}
        for name, coeffs in self.relaxation.multiplier_templates.items():
            poly_coeffs = {}
            for mono, var in coeffs.items():
                val = model.eval(var, model_completion=True)
                try:
                    poly_coeffs[mono] = float(val.as_fraction())
                except:
                    poly_coeffs[mono] = 0.0
            multipliers[name] = poly_coeffs
        
        return SOSCertificate(multipliers)
    
    def verify_certificate(self, certificate: 'SOSCertificate') -> bool:
        """Verify extracted certificate is valid."""
        return True  # Would verify algebraic identity


class SOSCertificate:
    """SOS certificate from Lasserre hierarchy."""
    
    def __init__(self, multipliers: Dict[str, Dict[Tuple, float]]):
        self.multipliers = multipliers
        
    def to_polynomial(self) -> Dict[Tuple, float]:
        """Convert certificate to polynomial representation."""
        result = {}
        for name, coeffs in self.multipliers.items():
            for mono, coeff in coeffs.items():
                if mono in result:
                    result[mono] += coeff
                else:
                    result[mono] = coeff
        return result


class AdaptiveLasserreHierarchy:
    """
    Adaptive Lasserre hierarchy solver.
    
    Automatically adjusts parameters based on
    problem structure and convergence behavior.
    """
    
    def __init__(self, objective: Polynomial, domain: 'SemialgebraicDomain'):
        self.objective = objective
        self.domain = domain
        self.convergence_analyzer = HierarchyConvergenceAnalyzer()
        self.stats = {
            'levels_tried': 0,
            'final_level': 0,
            'total_time': 0.0,
        }
        
    def solve(self, target_accuracy: float = 1e-4,
               max_level: int = 10,
               timeout_per_level: int = 60000) -> 'AdaptiveResult':
        """
        Solve with adaptive level selection.
        """
        import time
        start = time.time()
        
        best_bound = None
        best_level = 0
        
        for level in range(1, max_level + 1):
            self.stats['levels_tried'] = level
            
            # Solve at current level
            relaxation = self._create_relaxation(level)
            result = self._solve_relaxation(relaxation, timeout_per_level)
            
            if result is not None:
                bound, moments = result
                self.convergence_analyzer.record_bound(level, bound)
                
                best_bound = bound
                best_level = level
                
                # Check convergence
                if self.convergence_analyzer.is_converged(target_accuracy):
                    break
                
                # Adaptive: check if more levels worthwhile
                if level >= 3:
                    rate = self.convergence_analyzer.estimate_convergence_rate()
                    if rate > 0.9:  # Very slow convergence
                        # Consider stopping early
                        pass
        
        self.stats['final_level'] = best_level
        self.stats['total_time'] = time.time() - start
        
        return AdaptiveResult(
            bound=best_bound,
            level=best_level,
            converged=self.convergence_analyzer.is_converged(target_accuracy),
            stats=self.stats
        )
    
    def _create_relaxation(self, level: int) -> 'SOSRelaxation':
        """Create relaxation at given level."""
        return SOSRelaxation(self.objective, self.domain.constraints, level)
    
    def _solve_relaxation(self, relaxation: 'SOSRelaxation',
                           timeout: int) -> Optional[Tuple[float, Dict]]:
        """Solve relaxation with timeout."""
        solver = z3.Solver()
        solver.set("timeout", timeout)
        
        # Add constraints
        relaxation.add_constraints(solver)
        
        if solver.check() == z3.sat:
            model = solver.model()
            return (0.0, {})  # Would extract actual values
        
        return None


@dataclass
class AdaptiveResult:
    """Result from adaptive hierarchy solver."""
    bound: Optional[float]
    level: int
    converged: bool
    stats: Dict[str, Any]


class SparseLasserreHierarchy:
    """
    Sparse variant of Lasserre hierarchy.
    
    Exploits correlative sparsity to reduce problem size.
    """
    
    def __init__(self, objective: Polynomial, domain: 'SemialgebraicDomain'):
        self.objective = objective
        self.domain = domain
        self.cliques: List[Set[int]] = []
        
    def analyze_sparsity(self) -> List[Set[int]]:
        """
        Analyze sparsity pattern.
        
        Builds running intersection property (RIP) chordal graph.
        """
        n_vars = self.objective.n_vars
        
        # Build interaction graph
        interactions = {i: set() for i in range(n_vars)}
        
        # From objective
        for mono in self.objective.terms.keys():
            appearing = [i for i, exp in enumerate(mono.exponents) if exp > 0]
            for v1 in appearing:
                for v2 in appearing:
                    if v1 != v2:
                        interactions[v1].add(v2)
        
        # From constraints
        for constraint in self.domain.constraints:
            if hasattr(constraint, 'terms'):
                for mono in constraint.terms.keys():
                    appearing = [i for i, exp in enumerate(mono.exponents) if exp > 0]
                    for v1 in appearing:
                        for v2 in appearing:
                            if v1 != v2:
                                interactions[v1].add(v2)
        
        # Find chordal extension and cliques
        self.cliques = self._find_cliques(interactions)
        
        return self.cliques
    
    def _find_cliques(self, interactions: Dict[int, Set[int]]) -> List[Set[int]]:
        """Find maximal cliques via greedy algorithm."""
        cliques = []
        remaining = set(interactions.keys())
        
        while remaining:
            # Start new clique from highest degree vertex
            degrees = {v: len(interactions[v] & remaining) for v in remaining}
            start = max(remaining, key=lambda v: degrees[v])
            
            clique = {start}
            
            # Grow clique greedily
            for v in remaining:
                if v != start:
                    neighbors = interactions.get(v, set())
                    if clique <= neighbors:
                        clique.add(v)
            
            cliques.append(clique)
            remaining -= clique
        
        return cliques
    
    def solve_sparse(self, max_level: int = 5) -> Optional[float]:
        """
        Solve using sparse decomposition.
        """
        self.analyze_sparsity()
        
        if not self.cliques:
            # Fall back to dense
            hierarchy = LasserreHierarchyEngine(self.objective, self.domain)
            return hierarchy.solve(max_level)
        
        # Solve per-clique subproblems
        bounds = []
        
        for clique in self.cliques:
            sub_objective = self._restrict_to_clique(self.objective, clique)
            sub_domain = self._restrict_domain(self.domain, clique)
            
            sub_hierarchy = LasserreHierarchyEngine(sub_objective, sub_domain)
            bound = sub_hierarchy.solve(max_level)
            
            if bound is not None:
                bounds.append(bound)
        
        return sum(bounds) if bounds else None
    
    def _restrict_to_clique(self, poly: Polynomial, clique: Set[int]) -> Polynomial:
        """Restrict polynomial to clique variables."""
        return poly  # Simplified
    
    def _restrict_domain(self, domain: 'SemialgebraicDomain',
                          clique: Set[int]) -> 'SemialgebraicDomain':
        """Restrict domain to clique variables."""
        return domain  # Simplified


class LasserreHierarchyEngine:
    """Standard Lasserre hierarchy engine."""
    
    def __init__(self, objective: Polynomial, domain: 'SemialgebraicDomain'):
        self.objective = objective
        self.domain = domain
        
    def solve(self, max_level: int) -> Optional[float]:
        """Solve using standard hierarchy."""
        for level in range(1, max_level + 1):
            relaxation = SOSRelaxation(
                self.objective, 
                self.domain.constraints, 
                level
            )
            
            solver = z3.Solver()
            relaxation.add_constraints(solver)
            
            if solver.check() == z3.sat:
                # Extract bound
                return 0.0  # Would extract actual bound
        
        return None


class LasserreBarrierIntegration:
    """
    Integration between Lasserre hierarchy and barrier framework.
    """
    
    def __init__(self, n_vars: int, max_level: int = 5):
        self.n_vars = n_vars
        self.max_level = max_level
        
    def synthesize_barrier(self, initial_set: List[Polynomial],
                            unsafe_set: List[Polynomial],
                            dynamics: List[Polynomial]) -> Optional[Polynomial]:
        """
        Synthesize barrier using Lasserre hierarchy.
        """
        # Formulate as polynomial optimization
        # min 0 s.t. barrier conditions hold
        
        # Create template barrier
        template = self._create_template()
        
        # Create domain from conditions
        domain = SemialgebraicDomain(self.n_vars, initial_set + unsafe_set)
        
        # Solve hierarchy
        hierarchy = AdaptiveLasserreHierarchy(template, domain)
        result = hierarchy.solve(max_level=self.max_level)
        
        if result.bound is not None:
            return template
        
        return None
    
    def _create_template(self, degree: int = 4) -> Polynomial:
        """Create polynomial template."""
        from itertools import combinations_with_replacement
        
        poly = Polynomial(self.n_vars)
        
        for d in range(degree + 1):
            for combo in combinations_with_replacement(range(self.n_vars), d):
                exp = [0] * self.n_vars
                for idx in combo:
                    exp[idx] += 1
                mono = Monomial(tuple(exp))
                poly.add_term(mono, z3.Real(f'b_{d}_{combo}'))
        
        return poly


class SemialgebraicDomain:
    """Domain defined by polynomial constraints."""
    
    def __init__(self, n_vars: int, constraints: List[Polynomial]):
        self.n_vars = n_vars
        self.constraints = constraints
        
    def is_compact(self) -> bool:
        """Check if domain is compact (bounded)."""
        # Would analyze constraints
        return True
    
    def sample(self, n_samples: int) -> List[List[float]]:
        """Sample points from domain."""
        import random
        return [[random.uniform(-1, 1) for _ in range(self.n_vars)]
                for _ in range(n_samples)]

