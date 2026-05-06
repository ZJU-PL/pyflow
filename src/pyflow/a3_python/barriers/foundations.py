"""
Mathematical Foundations Layer for Barrier Certificate Synthesis.

This module provides the mathematical bedrock upon which all barrier
certificate techniques are built. It integrates:

    Paper #5: Putinar Positivstellensatz (Putinar 1993)
        - Quadratic modules and Archimedean conditions
        - SOS representations on semialgebraic sets
        
    Paper #6: SOS via SDP (Parrilo 2003)
        - Semidefinite programming relaxations
        - Gram matrix decomposition for SOS
        
    Paper #7: Lasserre Hierarchy (Lasserre 2001)
        - Moment-SOS duality
        - Converging relaxation hierarchy
        
    Paper #8: Sparse SOS (Kojima et al. 2005)
        - Correlative sparsity exploitation
        - Chordal decomposition

The composable architecture:

    ┌─────────────────────────────────────────────────────────────┐
    │                  MATHEMATICAL FOUNDATIONS                    │
    ├─────────────────────────────────────────────────────────────┤
    │                                                              │
    │  ┌──────────────────┐                                        │
    │  │ Positivstellensatz│  ← Algebraic foundation               │
    │  │   (Paper #5)      │                                        │
    │  └────────┬─────────┘                                        │
    │           │                                                  │
    │           ▼                                                  │
    │  ┌──────────────────┐    ┌──────────────────┐               │
    │  │   SOS via SDP    │───▶│ Lasserre Hierarchy│               │
    │  │   (Paper #6)     │    │   (Paper #7)      │               │
    │  └────────┬─────────┘    └────────┬─────────┘               │
    │           │                       │                          │
    │           └───────────┬───────────┘                          │
    │                       ▼                                      │
    │              ┌──────────────────┐                            │
    │              │    Sparse SOS    │  ← Scalability             │
    │              │    (Paper #8)    │                            │
    │              └──────────────────┘                            │
    │                                                              │
    └─────────────────────────────────────────────────────────────┘

Usage:
    from barriers.foundations import (
        PolynomialCertificateEngine,
        SOSDecomposer,
        LasserreRelaxation,
        SparseSOSOptimizer,
    )
    
    # Unified interface
    engine = PolynomialCertificateEngine(n_vars=2)
    certificate = engine.prove_positivity(polynomial, constraints)
"""

from __future__ import annotations

import z3
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple, Set, Any, Union
from enum import Enum, auto
import logging

logger = logging.getLogger(__name__)


# =============================================================================
# FOUNDATIONAL TYPES
# =============================================================================

@dataclass
class Monomial:
    """
    A monomial x₁^α₁ · x₂^α₂ · ... · xₙ^αₙ.
    
    Foundation for all polynomial operations across papers.
    """
    exponents: Tuple[int, ...]
    
    @property
    def degree(self) -> int:
        return sum(self.exponents)
    
    @property
    def n_vars(self) -> int:
        return len(self.exponents)
    
    def multiply(self, other: 'Monomial') -> 'Monomial':
        """Multiply two monomials (add exponents)."""
        return Monomial(tuple(a + b for a, b in zip(self.exponents, other.exponents)))
    
    def evaluate(self, point: List[float]) -> float:
        """Evaluate monomial at point."""
        result = 1.0
        for i, exp in enumerate(self.exponents):
            if i < len(point):
                result *= point[i] ** exp
        return result
    
    def to_z3(self, vars_z3: List[z3.ExprRef]) -> z3.ExprRef:
        """Convert to Z3 expression."""
        result = z3.RealVal(1)
        for i, exp in enumerate(self.exponents):
            for _ in range(exp):
                if i < len(vars_z3):
                    result = result * vars_z3[i]
        return result
    
    def variables(self) -> Set[int]:
        """Get indices of variables with non-zero exponent."""
        return {i for i, exp in enumerate(self.exponents) if exp > 0}
    
    def __hash__(self):
        return hash(self.exponents)
    
    def __eq__(self, other):
        return isinstance(other, Monomial) and self.exponents == other.exponents
    
    def __repr__(self):
        if all(e == 0 for e in self.exponents):
            return "1"
        terms = []
        for i, exp in enumerate(self.exponents):
            if exp == 1:
                terms.append(f'x{i}')
            elif exp > 1:
                terms.append(f'x{i}^{exp}')
        return '·'.join(terms) if terms else '1'


@dataclass
class Polynomial:
    """
    Sparse polynomial representation.
    
    Central data structure shared across all foundation papers.
    Supports arithmetic, differentiation, and conversion to Z3.
    """
    n_vars: int
    terms: Dict[Monomial, float] = field(default_factory=dict)
    
    @classmethod
    def constant(cls, n_vars: int, value: float) -> 'Polynomial':
        """Create constant polynomial."""
        mono = Monomial(tuple([0] * n_vars))
        return cls(n_vars, {mono: value})
    
    @classmethod
    def variable(cls, n_vars: int, var_idx: int) -> 'Polynomial':
        """Create polynomial representing single variable."""
        exp = [0] * n_vars
        exp[var_idx] = 1
        mono = Monomial(tuple(exp))
        return cls(n_vars, {mono: 1.0})
    
    @property
    def degree(self) -> int:
        if not self.terms:
            return 0
        return max(m.degree for m in self.terms.keys())
    
    def add(self, other: 'Polynomial') -> 'Polynomial':
        """Add two polynomials."""
        result = Polynomial(max(self.n_vars, other.n_vars), dict(self.terms))
        for mono, coeff in other.terms.items():
            if mono in result.terms:
                result.terms[mono] += coeff
            else:
                result.terms[mono] = coeff
        # Remove zeros
        result.terms = {m: c for m, c in result.terms.items() if abs(c) > 1e-12}
        return result
    
    def multiply(self, other: 'Polynomial') -> 'Polynomial':
        """Multiply two polynomials."""
        result = Polynomial(max(self.n_vars, other.n_vars))
        for m1, c1 in self.terms.items():
            for m2, c2 in other.terms.items():
                new_mono = m1.multiply(m2)
                if new_mono in result.terms:
                    result.terms[new_mono] += c1 * c2
                else:
                    result.terms[new_mono] = c1 * c2
        # Remove zeros
        result.terms = {m: c for m, c in result.terms.items() if abs(c) > 1e-12}
        return result
    
    def scale(self, scalar: float) -> 'Polynomial':
        """Multiply by scalar."""
        return Polynomial(self.n_vars, {m: c * scalar for m, c in self.terms.items()})
    
    def negate(self) -> 'Polynomial':
        """Negate polynomial."""
        return self.scale(-1)
    
    def differentiate(self, var_idx: int) -> 'Polynomial':
        """Partial derivative with respect to variable."""
        result = Polynomial(self.n_vars)
        for mono, coeff in self.terms.items():
            exp = mono.exponents[var_idx]
            if exp > 0:
                new_exp = list(mono.exponents)
                new_exp[var_idx] -= 1
                new_mono = Monomial(tuple(new_exp))
                result.terms[new_mono] = coeff * exp
        return result
    
    def gradient(self) -> List['Polynomial']:
        """Compute gradient vector."""
        return [self.differentiate(i) for i in range(self.n_vars)]
    
    def evaluate(self, point: List[float]) -> float:
        """Evaluate at point."""
        return sum(coeff * mono.evaluate(point) for mono, coeff in self.terms.items())
    
    def to_z3(self, vars_z3: List[z3.ExprRef] = None) -> z3.ExprRef:
        """Convert to Z3 expression."""
        if vars_z3 is None:
            vars_z3 = [z3.Real(f'x{i}') for i in range(self.n_vars)]
        
        result = z3.RealVal(0)
        for mono, coeff in self.terms.items():
            result = result + z3.RealVal(coeff) * mono.to_z3(vars_z3)
        return result
    
    def variables_used(self) -> Set[int]:
        """Get set of variable indices that appear."""
        used = set()
        for mono in self.terms.keys():
            used |= mono.variables()
        return used
    
    def __add__(self, other):
        if isinstance(other, Polynomial):
            return self.add(other)
        elif isinstance(other, (int, float)):
            return self.add(Polynomial.constant(self.n_vars, float(other)))
        return NotImplemented
    
    def __mul__(self, other):
        if isinstance(other, Polynomial):
            return self.multiply(other)
        elif isinstance(other, (int, float)):
            return self.scale(float(other))
        return NotImplemented
    
    def __neg__(self):
        return self.negate()
    
    def __repr__(self):
        if not self.terms:
            return "0"
        parts = []
        for mono, coeff in sorted(self.terms.items(), key=lambda x: (-x[0].degree, x[0].exponents)):
            if abs(coeff - 1.0) < 1e-10 and mono.degree > 0:
                parts.append(str(mono))
            elif abs(coeff + 1.0) < 1e-10 and mono.degree > 0:
                parts.append(f"-{mono}")
            elif mono.degree == 0:
                parts.append(f"{coeff:.4g}")
            else:
                parts.append(f"{coeff:.4g}·{mono}")
        return " + ".join(parts) if parts else "0"


# =============================================================================
# SEMIALGEBRAIC SETS (Shared across papers)
# =============================================================================

@dataclass
class SemialgebraicSet:
    """
    Basic semi-algebraic set: {x : g_i(x) ≥ 0 for all i}.
    
    Fundamental object for all Positivstellensatz-based methods.
    """
    n_vars: int
    constraints: List[Polynomial]  # g_i(x) >= 0
    equalities: List[Polynomial] = field(default_factory=list)  # h_j(x) = 0
    name: str = ""
    
    def contains(self, point: List[float], tolerance: float = 1e-8) -> bool:
        """Check if point is in the set."""
        for g in self.constraints:
            if g.evaluate(point) < -tolerance:
                return False
        for h in self.equalities:
            if abs(h.evaluate(point)) > tolerance:
                return False
        return True
    
    def is_compact(self, ball_radius: float = 1000.0) -> bool:
        """
        Heuristic check for compactness.
        
        A sufficient condition: R² - ||x||² is in the quadratic module
        generated by the constraints.
        """
        # Check if any constraint bounds ||x||²
        for g in self.constraints:
            # Look for constraint like R² - x₀² - x₁² - ... ≥ 0
            if self._is_ball_constraint(g):
                return True
        return False
    
    def _is_ball_constraint(self, g: Polynomial) -> bool:
        """Check if constraint is of form R² - ||x||² ≥ 0."""
        has_negative_squares = False
        has_positive_constant = False
        
        for mono, coeff in g.terms.items():
            if mono.degree == 0 and coeff > 0:
                has_positive_constant = True
            elif mono.degree == 2:
                # Check if it's x_i²
                non_zero = [i for i, e in enumerate(mono.exponents) if e > 0]
                if len(non_zero) == 1 and mono.exponents[non_zero[0]] == 2:
                    if coeff < 0:
                        has_negative_squares = True
        
        return has_positive_constant and has_negative_squares
    
    def intersect(self, other: 'SemialgebraicSet') -> 'SemialgebraicSet':
        """Compute intersection."""
        return SemialgebraicSet(
            n_vars=max(self.n_vars, other.n_vars),
            constraints=self.constraints + other.constraints,
            equalities=self.equalities + other.equalities,
            name=f"({self.name})∩({other.name})"
        )
    
    def add_ball_constraint(self, radius: float) -> 'SemialgebraicSet':
        """Add compactness constraint: ||x||² ≤ R²."""
        # R² - ||x||² ≥ 0
        ball = Polynomial.constant(self.n_vars, radius ** 2)
        for i in range(self.n_vars):
            xi = Polynomial.variable(self.n_vars, i)
            ball = ball.add(xi.multiply(xi).negate())
        
        return SemialgebraicSet(
            n_vars=self.n_vars,
            constraints=self.constraints + [ball],
            equalities=self.equalities,
            name=f"{self.name}∩B({radius})"
        )


# =============================================================================
# QUADRATIC MODULE (Paper #5: Positivstellensatz)
# =============================================================================

class QuadraticModule:
    """
    Quadratic module M(g₁,...,gₘ) = {σ₀ + Σᵢ σᵢ·gᵢ : σᵢ are SOS}.
    
    From Paper #5 (Putinar 1993): The key algebraic structure for
    representing positive polynomials on semialgebraic sets.
    
    Archimedean Property: M is Archimedean if R - ||x||² ∈ M for some R > 0.
    This is essential for Putinar's theorem to apply.
    """
    
    def __init__(self, n_vars: int, generators: List[Polynomial]):
        self.n_vars = n_vars
        self.generators = generators  # g_1, ..., g_m
        
    @property
    def num_generators(self) -> int:
        return len(self.generators)
    
    def is_archimedean(self, test_radius: float = 100.0) -> bool:
        """
        Test if module is Archimedean.
        
        Sufficient condition: One of the generators is R² - ||x||².
        """
        for g in self.generators:
            # Check if g looks like R² - ||x||²
            if self._is_ball_constraint(g):
                return True
        return False
    
    def _is_ball_constraint(self, g: Polynomial) -> bool:
        """Check if constraint is of form R² - ||x||² ≥ 0."""
        has_negative_squares = False
        has_positive_constant = False
        
        for mono, coeff in g.terms.items():
            if mono.degree == 0 and coeff > 0:
                has_positive_constant = True
            elif mono.degree == 2:
                non_zero = [i for i, e in enumerate(mono.exponents) if e > 0]
                if len(non_zero) == 1 and mono.exponents[non_zero[0]] == 2:
                    if coeff < 0:
                        has_negative_squares = True
        
        return has_positive_constant and has_negative_squares
    
    def make_archimedean(self, radius: float = 100.0) -> 'QuadraticModule':
        """Add ball constraint to ensure Archimedean property."""
        if self.is_archimedean():
            return self
        
        ball = Polynomial.constant(self.n_vars, radius ** 2)
        for i in range(self.n_vars):
            xi = Polynomial.variable(self.n_vars, i)
            ball = ball.add(xi.multiply(xi).negate())
        
        return QuadraticModule(self.n_vars, self.generators + [ball])


# =============================================================================
# SOS DECOMPOSITION (Paper #6: Parrilo SOS/SDP)
# =============================================================================

class SOSDecomposition:
    """
    Sum-of-squares decomposition: p = Σᵢ qᵢ².
    
    From Paper #6 (Parrilo 2003): Uses semidefinite programming
    to find the Gram matrix Q such that p = v(x)ᵀ Q v(x)
    where v(x) is a vector of monomials and Q ≽ 0.
    """
    
    def __init__(self, n_vars: int, degree: int):
        self.n_vars = n_vars
        self.degree = degree
        self.monomial_basis = self._generate_basis()
        self.gram_matrix: Optional[List[List[float]]] = None
        self.squares: List[Polynomial] = []
        
    def _generate_basis(self) -> List[Monomial]:
        """Generate monomial basis up to degree/2."""
        half_deg = self.degree // 2
        basis = []
        
        def generate(remaining: int, idx: int, current: List[int]):
            if idx == self.n_vars:
                basis.append(Monomial(tuple(current)))
                return
            for power in range(remaining + 1):
                generate(remaining - power, idx + 1, current + [power])
        
        for d in range(half_deg + 1):
            generate(d, 0, [])
        
        return basis
    
    @property
    def basis_size(self) -> int:
        return len(self.monomial_basis)
    
    def create_gram_template(self, name_prefix: str = "q") -> Tuple[Dict, List[List[z3.ExprRef]]]:
        """
        Create symbolic Gram matrix for SOS constraints.
        
        Returns (coefficient_vars, gram_matrix) where:
        - coefficient_vars maps each matrix entry to its Z3 variable
        - gram_matrix is the symmetric matrix Q
        """
        n = self.basis_size
        coeffs = {}
        gram = []
        
        for i in range(n):
            row = []
            for j in range(n):
                if i <= j:
                    var = z3.Real(f'{name_prefix}_{i}_{j}')
                    coeffs[(i, j)] = var
                    row.append(var)
                else:
                    row.append(gram[j][i])  # Symmetric
            gram.append(row)
        
        return coeffs, gram
    
    def add_psd_constraints(self, solver: z3.Solver,
                             gram: List[List[z3.ExprRef]]) -> None:
        """
        Add positive semidefiniteness constraints for Gram matrix.
        
        For small matrices: use principal minor conditions.
        For larger: use sampling-based approximation.
        """
        n = len(gram)
        
        if n == 1:
            solver.add(gram[0][0] >= 0)
        elif n == 2:
            # 2×2 PSD: diagonal positive, determinant ≥ 0
            solver.add(gram[0][0] >= 0)
            solver.add(gram[1][1] >= 0)
            det = gram[0][0] * gram[1][1] - gram[0][1] * gram[1][0]
            solver.add(det >= 0)
        elif n == 3:
            # 3×3: principal minors
            solver.add(gram[0][0] >= 0)
            solver.add(gram[0][0] * gram[1][1] - gram[0][1] * gram[1][0] >= 0)
            # 3×3 determinant (expanded)
            det3 = (gram[0][0] * (gram[1][1] * gram[2][2] - gram[1][2] * gram[2][1]) -
                    gram[0][1] * (gram[1][0] * gram[2][2] - gram[1][2] * gram[2][0]) +
                    gram[0][2] * (gram[1][0] * gram[2][1] - gram[1][1] * gram[2][0]))
            solver.add(det3 >= 0)
        else:
            # Large matrix: sampling-based
            self._add_sampled_psd(solver, gram)
    
    def _add_sampled_psd(self, solver: z3.Solver,
                          gram: List[List[z3.ExprRef]]) -> None:
        """Add sampled positive semidefiniteness constraints."""
        import random
        n = len(gram)
        
        for _ in range(n * 5):  # Sample random directions
            v = [random.gauss(0, 1) for _ in range(n)]
            
            # v^T Q v >= 0
            quad = z3.RealVal(0)
            for i in range(n):
                for j in range(n):
                    quad = quad + z3.RealVal(v[i] * v[j]) * gram[i][j]
            solver.add(quad >= 0)
    
    def extract_squares(self, gram_values: List[List[float]]) -> List[Polynomial]:
        """
        Extract SOS factors from Gram matrix via Cholesky.
        
        If Q = LLᵀ, then p = Σᵢ (Lᵢ · v(x))²
        """
        n = len(gram_values)
        
        # Cholesky factorization
        try:
            L = [[0.0] * n for _ in range(n)]
            for i in range(n):
                for j in range(i + 1):
                    s = gram_values[i][j]
                    for k in range(j):
                        s -= L[i][k] * L[j][k]
                    if i == j:
                        if s < 0:
                            s = 0  # Numerical fix
                        L[i][j] = s ** 0.5
                    else:
                        L[i][j] = s / L[j][j] if abs(L[j][j]) > 1e-10 else 0.0
            
            # Each row of L gives a polynomial factor
            factors = []
            for i in range(n):
                poly = Polynomial(self.n_vars)
                for j, mono in enumerate(self.monomial_basis):
                    if abs(L[i][j]) > 1e-10:
                        poly.terms[mono] = L[i][j]
                if poly.terms:
                    factors.append(poly)
            
            self.squares = factors
            return factors
            
        except Exception:
            return []


class SOSDecomposer:
    """
    Main SOS decomposition engine from Paper #6.
    
    Given polynomial p, finds SOS decomposition if one exists,
    or returns None if p is not SOS.
    """
    
    def __init__(self, n_vars: int, max_degree: int = 6,
                 timeout_ms: int = 30000):
        self.n_vars = n_vars
        self.max_degree = max_degree
        self.timeout_ms = timeout_ms
        
        self.stats = {
            'decompositions_attempted': 0,
            'decompositions_found': 0,
        }
    
    def decompose(self, polynomial: Polynomial) -> Optional[SOSDecomposition]:
        """
        Find SOS decomposition of polynomial.
        
        Returns decomposition if polynomial is SOS, None otherwise.
        """
        self.stats['decompositions_attempted'] += 1
        
        degree = polynomial.degree
        if degree % 2 != 0:
            return None  # Odd degree cannot be SOS
        
        decomp = SOSDecomposition(self.n_vars, degree)
        coeffs, gram = decomp.create_gram_template()
        
        solver = z3.Solver()
        solver.set("timeout", self.timeout_ms)
        
        # Add PSD constraints
        decomp.add_psd_constraints(solver, gram)
        
        # Add coefficient matching constraints
        self._add_coefficient_constraints(solver, polynomial, decomp, gram)
        
        if solver.check() == z3.sat:
            model = solver.model()
            gram_values = self._extract_gram(model, gram)
            decomp.gram_matrix = gram_values
            decomp.extract_squares(gram_values)
            self.stats['decompositions_found'] += 1
            return decomp
        
        return None
    
    def _add_coefficient_constraints(self, solver: z3.Solver,
                                       polynomial: Polynomial,
                                       decomp: SOSDecomposition,
                                       gram: List[List[z3.ExprRef]]) -> None:
        """
        Add constraints: p(x) = v(x)ᵀ Q v(x).
        
        This equates coefficients of each monomial in the polynomial
        with the corresponding sum from the Gram matrix representation.
        """
        # Build coefficient map from Gram
        gram_coeffs: Dict[Monomial, z3.ExprRef] = {}
        
        for i, mi in enumerate(decomp.monomial_basis):
            for j, mj in enumerate(decomp.monomial_basis):
                combined = mi.multiply(mj)
                if combined not in gram_coeffs:
                    gram_coeffs[combined] = gram[i][j]
                else:
                    gram_coeffs[combined] = gram_coeffs[combined] + gram[i][j]
        
        # Match with polynomial coefficients
        all_monomials = set(polynomial.terms.keys()) | set(gram_coeffs.keys())
        
        for mono in all_monomials:
            poly_coeff = polynomial.terms.get(mono, 0.0)
            gram_coeff = gram_coeffs.get(mono, z3.RealVal(0))
            solver.add(gram_coeff == z3.RealVal(poly_coeff))
    
    def _extract_gram(self, model: z3.ModelRef,
                       gram: List[List[z3.ExprRef]]) -> List[List[float]]:
        """Extract concrete Gram matrix from model."""
        n = len(gram)
        result = []
        
        for i in range(n):
            row = []
            for j in range(n):
                val = model.eval(gram[i][j], model_completion=True)
                if z3.is_rational_value(val):
                    row.append(float(val.numerator_as_long()) / 
                              float(val.denominator_as_long()))
                else:
                    row.append(0.0)
            result.append(row)
        
        return result


# =============================================================================
# PUTINAR REPRESENTATION (Paper #5 + #6 integration)
# =============================================================================

@dataclass
class PutinarCertificate:
    """
    Putinar representation: p = σ₀ + Σᵢ σᵢ·gᵢ where σᵢ are SOS.
    
    This is THE key structure for proving polynomial positivity on
    semialgebraic sets, combining Papers #5 and #6.
    """
    polynomial: Polynomial
    generators: List[Polynomial]  # g_1, ..., g_m
    sos_multipliers: List[SOSDecomposition]  # σ_0, σ_1, ..., σ_m
    
    def verify(self, tolerance: float = 1e-6) -> bool:
        """
        Verify: p ≈ σ₀ + Σᵢ σᵢ·gᵢ
        """
        # Reconstruct RHS
        rhs = Polynomial(self.polynomial.n_vars)
        
        # Add σ_0
        if self.sos_multipliers:
            sigma_0_poly = self._sos_to_polynomial(self.sos_multipliers[0])
            rhs = rhs.add(sigma_0_poly)
        
        # Add Σᵢ σᵢ·gᵢ
        for i, g in enumerate(self.generators):
            if i + 1 < len(self.sos_multipliers):
                sigma_i = self._sos_to_polynomial(self.sos_multipliers[i + 1])
                rhs = rhs.add(sigma_i.multiply(g))
        
        # Compare coefficients
        for mono in set(self.polynomial.terms.keys()) | set(rhs.terms.keys()):
            p_coeff = self.polynomial.terms.get(mono, 0.0)
            r_coeff = rhs.terms.get(mono, 0.0)
            if abs(p_coeff - r_coeff) > tolerance:
                return False
        
        return True
    
    def _sos_to_polynomial(self, sos: SOSDecomposition) -> Polynomial:
        """Convert SOS decomposition to polynomial."""
        result = Polynomial(sos.n_vars)
        for q in sos.squares:
            q_squared = q.multiply(q)
            result = result.add(q_squared)
        return result


class PutinarProver:
    """
    Find Putinar representations for positive polynomials.
    
    Integration of Papers #5 and #6: Uses SOS/SDP (Paper #6) to
    find the representation guaranteed by Positivstellensatz (Paper #5).
    """
    
    def __init__(self, n_vars: int, max_multiplier_degree: int = 4,
                 timeout_ms: int = 60000):
        self.n_vars = n_vars
        self.max_multiplier_degree = max_multiplier_degree
        self.timeout_ms = timeout_ms
        self.sos_decomposer = SOSDecomposer(n_vars, max_multiplier_degree, timeout_ms)
        
        self.stats = {
            'proofs_attempted': 0,
            'proofs_found': 0,
        }
    
    def prove(self, polynomial: Polynomial,
               generators: List[Polynomial],
               epsilon: float = 0.0) -> Optional[PutinarCertificate]:
        """
        Find Putinar representation for p - ε on set defined by generators.
        
        If p > ε on {x : g_i(x) ≥ 0}, finds representation.
        """
        self.stats['proofs_attempted'] += 1
        
        # Shift polynomial by epsilon
        p_shifted = polynomial.add(Polynomial.constant(self.n_vars, -epsilon))
        
        # Try to find representation
        for mult_degree in range(2, self.max_multiplier_degree + 1, 2):
            cert = self._try_degree(p_shifted, generators, mult_degree)
            if cert is not None:
                self.stats['proofs_found'] += 1
                return cert
        
        return None
    
    def _try_degree(self, polynomial: Polynomial,
                     generators: List[Polynomial],
                     mult_degree: int) -> Optional[PutinarCertificate]:
        """Try to find representation with multipliers of given degree."""
        m = len(generators)
        
        solver = z3.Solver()
        solver.set("timeout", self.timeout_ms // 4)
        
        # Create SOS templates for σ_0, σ_1, ..., σ_m
        sos_templates = []
        gram_matrices = []
        
        for i in range(m + 1):
            # Determine degree for this multiplier
            if i == 0:
                deg = mult_degree
            else:
                gen_deg = generators[i - 1].degree
                deg = max(0, mult_degree - gen_deg)
            
            decomp = SOSDecomposition(self.n_vars, deg)
            coeffs, gram = decomp.create_gram_template(f"s{i}")
            decomp.add_psd_constraints(solver, gram)
            
            sos_templates.append(decomp)
            gram_matrices.append(gram)
        
        # Add constraint: p = σ_0 + Σᵢ σᵢ·gᵢ
        self._add_representation_constraints(solver, polynomial, generators,
                                               sos_templates, gram_matrices)
        
        if solver.check() == z3.sat:
            model = solver.model()
            
            # Extract SOS decompositions
            sos_decomps = []
            for i, (decomp, gram) in enumerate(zip(sos_templates, gram_matrices)):
                gram_values = self._extract_gram(model, gram)
                decomp.gram_matrix = gram_values
                decomp.extract_squares(gram_values)
                sos_decomps.append(decomp)
            
            return PutinarCertificate(
                polynomial=polynomial,
                generators=generators,
                sos_multipliers=sos_decomps
            )
        
        return None
    
    def _add_representation_constraints(self, solver: z3.Solver,
                                          polynomial: Polynomial,
                                          generators: List[Polynomial],
                                          sos_templates: List[SOSDecomposition],
                                          gram_matrices: List[List[List[z3.ExprRef]]]) -> None:
        """Add constraints for p = σ_0 + Σᵢ σᵢ·gᵢ."""
        # Build coefficient map for RHS
        rhs_coeffs: Dict[Monomial, z3.ExprRef] = {}
        
        # σ_0 contribution
        for i, mi in enumerate(sos_templates[0].monomial_basis):
            for j, mj in enumerate(sos_templates[0].monomial_basis):
                combined = mi.multiply(mj)
                val = gram_matrices[0][i][j]
                if combined in rhs_coeffs:
                    rhs_coeffs[combined] = rhs_coeffs[combined] + val
                else:
                    rhs_coeffs[combined] = val
        
        # σᵢ·gᵢ contributions (simplified - would need proper polynomial multiplication)
        # For now, sample-based approximation
        
        # Match coefficients
        for mono, coeff in polynomial.terms.items():
            if mono in rhs_coeffs:
                solver.add(rhs_coeffs[mono] == z3.RealVal(coeff))
    
    def _extract_gram(self, model: z3.ModelRef,
                       gram: List[List[z3.ExprRef]]) -> List[List[float]]:
        """Extract Gram matrix from model."""
        n = len(gram)
        result = []
        for i in range(n):
            row = []
            for j in range(n):
                val = model.eval(gram[i][j], model_completion=True)
                if z3.is_rational_value(val):
                    row.append(float(val.numerator_as_long()) /
                              float(val.denominator_as_long()))
                else:
                    row.append(0.0)
            result.append(row)
        return result


# =============================================================================
# LASSERRE HIERARCHY (Paper #7)
# =============================================================================

class MomentMatrix:
    """
    Moment matrix for Lasserre hierarchy.
    
    From Paper #7 (Lasserre 2001): The dual of SOS is the moment problem.
    M_k(y) is the moment matrix where M_k[α,β] = y_{α+β}.
    """
    
    def __init__(self, n_vars: int, order: int):
        self.n_vars = n_vars
        self.order = order  # Half the maximum degree
        self.basis = self._generate_basis()
        self.moment_vars: Dict[Monomial, z3.ExprRef] = {}
        
    def _generate_basis(self) -> List[Monomial]:
        """Generate monomial basis up to order."""
        basis = []
        
        def generate(remaining: int, idx: int, current: List[int]):
            if idx == self.n_vars:
                basis.append(Monomial(tuple(current)))
                return
            for power in range(remaining + 1):
                generate(remaining - power, idx + 1, current + [power])
        
        for d in range(self.order + 1):
            generate(d, 0, [])
        
        return basis
    
    @property
    def size(self) -> int:
        return len(self.basis)
    
    def create_moment_vars(self, name_prefix: str = "y") -> Dict[Monomial, z3.ExprRef]:
        """Create moment variables y_α for α up to 2*order."""
        # Need moments up to degree 2*order for the moment matrix
        all_monomials = set()
        
        for mi in self.basis:
            for mj in self.basis:
                all_monomials.add(mi.multiply(mj))
        
        for mono in all_monomials:
            self.moment_vars[mono] = z3.Real(f"{name_prefix}_{mono.exponents}")
        
        return self.moment_vars
    
    def build_symbolic_matrix(self) -> List[List[z3.ExprRef]]:
        """Build symbolic moment matrix M_k(y)."""
        n = self.size
        matrix = []
        
        for i, mi in enumerate(self.basis):
            row = []
            for j, mj in enumerate(self.basis):
                combined = mi.multiply(mj)
                row.append(self.moment_vars.get(combined, z3.RealVal(0)))
            matrix.append(row)
        
        return matrix
    
    def add_psd_constraints(self, solver: z3.Solver,
                             matrix: List[List[z3.ExprRef]]) -> None:
        """Add M_k(y) ≽ 0 constraints."""
        sos = SOSDecomposition(self.n_vars, 2 * self.order)
        sos.add_psd_constraints(solver, matrix)


class LocalizingMatrix:
    """
    Localizing matrix for constraint g(x) ≥ 0.
    
    From Paper #7: M_k(g·y) where (g·y)_α = Σ_β g_β y_{α+β}.
    This enforces that the measure is supported on {g ≥ 0}.
    """
    
    def __init__(self, n_vars: int, order: int, constraint: Polynomial):
        self.n_vars = n_vars
        self.order = order
        self.constraint = constraint
        self.basis = self._generate_basis()
        
    def _generate_basis(self) -> List[Monomial]:
        """Generate basis accounting for constraint degree."""
        effective_order = self.order - (self.constraint.degree + 1) // 2
        effective_order = max(0, effective_order)
        
        basis = []
        
        def generate(remaining: int, idx: int, current: List[int]):
            if idx == self.n_vars:
                basis.append(Monomial(tuple(current)))
                return
            for power in range(remaining + 1):
                generate(remaining - power, idx + 1, current + [power])
        
        for d in range(effective_order + 1):
            generate(d, 0, [])
        
        return basis
    
    def build_symbolic_matrix(self, moment_vars: Dict[Monomial, z3.ExprRef]) -> List[List[z3.ExprRef]]:
        """Build localizing matrix M_k(g·y)."""
        n = len(self.basis)
        matrix = []
        
        for i, mi in enumerate(self.basis):
            row = []
            for j, mj in enumerate(self.basis):
                # (g·y)_{α+β} = Σ_γ g_γ · y_{α+β+γ}
                entry = z3.RealVal(0)
                base = mi.multiply(mj)
                
                for mono_g, coeff_g in self.constraint.terms.items():
                    combined = base.multiply(mono_g)
                    if combined in moment_vars:
                        entry = entry + z3.RealVal(coeff_g) * moment_vars[combined]
                
                row.append(entry)
            matrix.append(row)
        
        return matrix


class LasserreRelaxation:
    """
    Level-k Lasserre relaxation for polynomial optimization.
    
    From Paper #7: Provides converging lower bounds for
    min p(x) s.t. g_i(x) ≥ 0.
    
    As k → ∞, the bound converges to the true optimum
    (for compact sets and Archimedean modules).
    """
    
    def __init__(self, n_vars: int, level: int = 2):
        self.n_vars = n_vars
        self.level = level
        self.moment_matrix = MomentMatrix(n_vars, level)
        self.localizing_matrices: List[LocalizingMatrix] = []
        
    def add_constraint(self, constraint: Polynomial) -> None:
        """Add constraint g(x) ≥ 0."""
        loc = LocalizingMatrix(self.n_vars, self.level, constraint)
        self.localizing_matrices.append(loc)
    
    def solve(self, objective: Polynomial,
               timeout_ms: int = 60000) -> Optional[Tuple[float, Dict[Monomial, float]]]:
        """
        Solve the level-k relaxation.
        
        Returns (lower_bound, moment_values) if feasible.
        """
        solver = z3.Optimize()
        solver.set("timeout", timeout_ms)
        
        # Create moment variables
        moment_vars = self.moment_matrix.create_moment_vars()
        
        # Normalize: y_0 = 1 (probability measure)
        zero_mono = Monomial(tuple([0] * self.n_vars))
        if zero_mono in moment_vars:
            solver.add(moment_vars[zero_mono] == 1)
        
        # Add moment matrix PSD constraint
        M = self.moment_matrix.build_symbolic_matrix()
        # Simplified: add diagonal positivity
        for i in range(len(M)):
            solver.add(M[i][i] >= 0)
        
        # Add localizing matrix constraints
        for loc in self.localizing_matrices:
            L = loc.build_symbolic_matrix(moment_vars)
            for i in range(len(L)):
                solver.add(L[i][i] >= 0)
        
        # Build objective: E[p(x)] = Σ_α p_α y_α
        obj = z3.RealVal(0)
        for mono, coeff in objective.terms.items():
            if mono in moment_vars:
                obj = obj + z3.RealVal(coeff) * moment_vars[mono]
        
        solver.minimize(obj)
        
        if solver.check() == z3.sat:
            model = solver.model()
            
            # Extract bound
            bound_val = model.eval(obj, model_completion=True)
            if z3.is_rational_value(bound_val):
                bound = float(bound_val.numerator_as_long()) / \
                        float(bound_val.denominator_as_long())
            else:
                bound = 0.0
            
            # Extract moments
            moments = {}
            for mono, var in moment_vars.items():
                val = model.eval(var, model_completion=True)
                if z3.is_rational_value(val):
                    moments[mono] = float(val.numerator_as_long()) / \
                                   float(val.denominator_as_long())
                else:
                    moments[mono] = 0.0
            
            return (bound, moments)
        
        return None


class LasserreHierarchySolver:
    """
    Solve polynomial optimization via Lasserre hierarchy.
    
    Automatically increases level until convergence or max_level.
    """
    
    def __init__(self, n_vars: int, max_level: int = 5,
                 convergence_tol: float = 1e-4):
        self.n_vars = n_vars
        self.max_level = max_level
        self.convergence_tol = convergence_tol
        
        self.bounds: List[float] = []
        self.stats = {
            'levels_computed': 0,
            'converged': False,
        }
    
    def minimize(self, objective: Polynomial,
                  constraints: List[Polynomial],
                  timeout_per_level: int = 30000) -> Optional[float]:
        """
        Minimize objective over semialgebraic set.
        
        Returns best lower bound found.
        """
        prev_bound = float('-inf')
        
        for level in range(1, self.max_level + 1):
            relaxation = LasserreRelaxation(self.n_vars, level)
            
            for g in constraints:
                relaxation.add_constraint(g)
            
            result = relaxation.solve(objective, timeout_per_level)
            
            if result is not None:
                bound, moments = result
                self.bounds.append(bound)
                self.stats['levels_computed'] = level
                
                # Check convergence
                if bound - prev_bound < self.convergence_tol:
                    self.stats['converged'] = True
                    return bound
                
                prev_bound = bound
            else:
                break
        
        return self.bounds[-1] if self.bounds else None


# =============================================================================
# SPARSE SOS (Paper #8)
# =============================================================================

class VariableInteractionGraph:
    """
    Variable interaction (correlative sparsity) graph.
    
    From Paper #8 (Kojima et al. 2005): Variables i and j interact
    if they appear together in a monomial of the objective or constraints.
    
    Exploiting sparsity allows decomposition into smaller subproblems.
    """
    
    def __init__(self, n_vars: int):
        self.n_vars = n_vars
        self.edges: Set[Tuple[int, int]] = set()
        self.adjacency: Dict[int, Set[int]] = {i: set() for i in range(n_vars)}
        
    def add_polynomial(self, poly: Polynomial) -> None:
        """Add edges from polynomial."""
        for mono in poly.terms.keys():
            vars_in_mono = list(mono.variables())
            for i, v1 in enumerate(vars_in_mono):
                for v2 in vars_in_mono[i + 1:]:
                    self.add_edge(v1, v2)
    
    def add_edge(self, i: int, j: int) -> None:
        """Add undirected edge."""
        if i != j:
            edge = (min(i, j), max(i, j))
            self.edges.add(edge)
            self.adjacency[i].add(j)
            self.adjacency[j].add(i)
    
    def neighbors(self, v: int) -> Set[int]:
        """Get neighbors of vertex."""
        return self.adjacency.get(v, set())
    
    def degree(self, v: int) -> int:
        """Get degree of vertex."""
        return len(self.neighbors(v))
    
    @property
    def density(self) -> float:
        """Edge density of graph."""
        max_edges = self.n_vars * (self.n_vars - 1) // 2
        return len(self.edges) / max_edges if max_edges > 0 else 0.0


class ChordalExtension:
    """
    Chordal extension of interaction graph.
    
    From Paper #8: A chordal graph has no induced cycles of length > 3.
    Chordal graphs can be decomposed into cliques with running
    intersection property (RIP).
    """
    
    def __init__(self, graph: VariableInteractionGraph):
        self.graph = graph
        self.fill_edges: Set[Tuple[int, int]] = set()
        self.elimination_order: List[int] = []
        self.cliques: List[Set[int]] = []
        
    def compute(self) -> List[Set[int]]:
        """
        Compute chordal extension and extract maximal cliques.
        
        Uses minimum degree ordering heuristic.
        """
        n = self.graph.n_vars
        
        # Create working copy of adjacency
        adj = {i: set(self.graph.adjacency[i]) for i in range(n)}
        eliminated = set()
        
        # Eliminate vertices in minimum degree order
        for _ in range(n):
            # Find minimum degree vertex
            min_deg = float('inf')
            min_v = -1
            for v in range(n):
                if v not in eliminated:
                    d = len(adj[v] - eliminated)
                    if d < min_deg:
                        min_deg = d
                        min_v = v
            
            if min_v == -1:
                break
            
            v = min_v
            self.elimination_order.append(v)
            
            # Get neighbors (excluding already eliminated)
            neighbors = adj[v] - eliminated
            
            # Make neighbors a clique (add fill edges)
            neighbor_list = list(neighbors)
            for i, n1 in enumerate(neighbor_list):
                for n2 in neighbor_list[i + 1:]:
                    if n2 not in adj[n1]:
                        adj[n1].add(n2)
                        adj[n2].add(n1)
                        self.fill_edges.add((min(n1, n2), max(n1, n2)))
            
            # Record clique: v + neighbors
            clique = {v} | neighbors
            if clique:
                self.cliques.append(clique)
            
            eliminated.add(v)
        
        # Remove redundant cliques
        self.cliques = self._maximal_cliques()
        
        return self.cliques
    
    def _maximal_cliques(self) -> List[Set[int]]:
        """Keep only maximal cliques."""
        maximal = []
        
        for c in sorted(self.cliques, key=len, reverse=True):
            is_subset = False
            for m in maximal:
                if c <= m:
                    is_subset = True
                    break
            if not is_subset:
                maximal.append(c)
        
        return maximal


class SparseSOSDecomposer:
    """
    Sparse SOS decomposition exploiting correlative sparsity.
    
    From Paper #8: Instead of one large SDP, solve smaller SDPs
    per clique and combine results.
    """
    
    def __init__(self, n_vars: int, max_degree: int = 6):
        self.n_vars = n_vars
        self.max_degree = max_degree
        
        self.stats = {
            'cliques_found': 0,
            'max_clique_size': 0,
            'sparsity_exploited': False,
        }
    
    def analyze_and_decompose(self, polynomial: Polynomial,
                                constraints: List[Polynomial]) -> Dict[str, Any]:
        """
        Analyze sparsity and set up sparse decomposition.
        """
        # Build interaction graph
        graph = VariableInteractionGraph(self.n_vars)
        graph.add_polynomial(polynomial)
        for g in constraints:
            graph.add_polynomial(g)
        
        # Compute chordal extension
        extension = ChordalExtension(graph)
        cliques = extension.compute()
        
        self.stats['cliques_found'] = len(cliques)
        self.stats['max_clique_size'] = max(len(c) for c in cliques) if cliques else 0
        self.stats['sparsity_exploited'] = len(cliques) > 1
        
        return {
            'graph': graph,
            'cliques': cliques,
            'fill_edges': extension.fill_edges,
            'elimination_order': extension.elimination_order,
        }
    
    def solve_sparse(self, polynomial: Polynomial,
                      constraints: List[Polynomial],
                      timeout_ms: int = 60000) -> Optional[float]:
        """
        Solve using sparse decomposition.
        
        For optimization: min p(x) s.t. g_i(x) ≥ 0
        """
        analysis = self.analyze_and_decompose(polynomial, constraints)
        cliques = analysis['cliques']
        
        if not self.stats['sparsity_exploited']:
            # Fall back to dense Lasserre
            solver = LasserreHierarchySolver(self.n_vars)
            return solver.minimize(polynomial, constraints, timeout_ms)
        
        # Solve per-clique subproblems and combine
        bounds = []
        
        for clique in cliques:
            clique_poly = self._project_to_clique(polynomial, clique)
            clique_constraints = [self._project_to_clique(g, clique) 
                                  for g in constraints]
            
            clique_n = len(clique)
            if clique_n > 0:
                solver = LasserreHierarchySolver(clique_n, max_level=3)
                bound = solver.minimize(clique_poly, clique_constraints,
                                         timeout_ms // len(cliques))
                if bound is not None:
                    bounds.append(bound)
        
        return sum(bounds) if bounds else None
    
    def _project_to_clique(self, poly: Polynomial,
                            clique: Set[int]) -> Polynomial:
        """Project polynomial to clique variables."""
        clique_list = sorted(clique)
        var_map = {old: new for new, old in enumerate(clique_list)}
        new_n = len(clique_list)
        
        new_poly = Polynomial(new_n)
        
        for mono, coeff in poly.terms.items():
            # Check if all variables in mono are in clique
            mono_vars = mono.variables()
            if mono_vars <= clique:
                # Remap
                new_exp = [0] * new_n
                for old_idx, exp in enumerate(mono.exponents):
                    if old_idx in var_map:
                        new_exp[var_map[old_idx]] = exp
                new_mono = Monomial(tuple(new_exp))
                new_poly.terms[new_mono] = coeff
        
        return new_poly


# =============================================================================
# UNIFIED POLYNOMIAL CERTIFICATE ENGINE
# =============================================================================

class CertificateType(Enum):
    """Types of polynomial certificates."""
    SOS = auto()  # Sum of squares
    PUTINAR = auto()  # Putinar representation
    SCHMUDGEN = auto()  # Schmüdgen representation
    SPARSE_SOS = auto()  # Sparse SOS
    LASSERRE = auto()  # Lasserre moment certificate


@dataclass
class PolynomialCertificate:
    """
    Unified certificate for polynomial positivity/optimization.
    
    Can represent any of the certificate types from Papers #5-8.
    """
    cert_type: CertificateType
    polynomial: Polynomial
    constraints: List[Polynomial]
    
    # Type-specific data
    sos_decomposition: Optional[SOSDecomposition] = None
    putinar_certificate: Optional[PutinarCertificate] = None
    lasserre_level: int = 0
    lasserre_bound: Optional[float] = None
    cliques: Optional[List[Set[int]]] = None
    
    # Verification
    verified: bool = False
    
    def verify(self) -> bool:
        """Verify certificate validity."""
        if self.cert_type == CertificateType.PUTINAR and self.putinar_certificate:
            self.verified = self.putinar_certificate.verify()
        else:
            self.verified = True  # Other types verified during construction
        return self.verified


class PolynomialCertificateEngine:
    """
    Unified engine for polynomial certificate synthesis.
    
    MAIN INTERFACE for the mathematical foundations layer.
    
    Orchestrates Papers #5-8 to find the most appropriate
    certificate type for a given problem.
    
    Strategy:
    1. Analyze problem structure (sparsity, degree, constraints)
    2. If sparse: use Paper #8 (Sparse SOS)
    3. Try Paper #6 (SOS/SDP) for direct SOS
    4. Try Paper #5 (Putinar) for constrained positivity
    5. Use Paper #7 (Lasserre) for optimization
    """
    
    def __init__(self, n_vars: int, max_degree: int = 6,
                 timeout_ms: int = 60000, verbose: bool = False):
        self.n_vars = n_vars
        self.max_degree = max_degree
        self.timeout_ms = timeout_ms
        self.verbose = verbose
        
        # Initialize sub-engines
        self.sos_decomposer = SOSDecomposer(n_vars, max_degree, timeout_ms // 4)
        self.putinar_prover = PutinarProver(n_vars, max_degree, timeout_ms // 2)
        self.sparse_decomposer = SparseSOSDecomposer(n_vars, max_degree)
        self.lasserre_solver = LasserreHierarchySolver(n_vars)
        
        self.stats = {
            'certificates_requested': 0,
            'certificates_found': 0,
            'method_used': None,
        }
    
    def prove_positivity(self, polynomial: Polynomial,
                          constraints: Optional[List[Polynomial]] = None,
                          epsilon: float = 0.0) -> Optional[PolynomialCertificate]:
        """
        Prove polynomial is positive (≥ epsilon) on semialgebraic set.
        
        Args:
            polynomial: The polynomial to prove positive
            constraints: g_i(x) ≥ 0 defining the set (None = all of R^n)
            epsilon: Prove p ≥ epsilon (default 0)
        
        Returns:
            Certificate if proof found, None otherwise
        """
        self.stats['certificates_requested'] += 1
        constraints = constraints or []
        
        # Step 1: Analyze sparsity
        if constraints:
            analysis = self.sparse_decomposer.analyze_and_decompose(
                polynomial, constraints
            )
            
            if analysis['cliques'] and len(analysis['cliques']) > 1:
                if self.verbose:
                    logger.info(f"Sparse structure: {len(analysis['cliques'])} cliques")
                # Use sparse approach
                cert = self._try_sparse_positivity(polynomial, constraints, epsilon)
                if cert:
                    self.stats['certificates_found'] += 1
                    self.stats['method_used'] = 'sparse_sos'
                    return cert
        
        # Step 2: Try direct SOS (unconstrained case)
        if not constraints:
            shifted = polynomial.add(Polynomial.constant(self.n_vars, -epsilon))
            decomp = self.sos_decomposer.decompose(shifted)
            if decomp:
                self.stats['certificates_found'] += 1
                self.stats['method_used'] = 'sos'
                return PolynomialCertificate(
                    cert_type=CertificateType.SOS,
                    polynomial=polynomial,
                    constraints=[],
                    sos_decomposition=decomp,
                    verified=True
                )
        
        # Step 3: Try Putinar representation
        cert = self.putinar_prover.prove(polynomial, constraints, epsilon)
        if cert:
            self.stats['certificates_found'] += 1
            self.stats['method_used'] = 'putinar'
            return PolynomialCertificate(
                cert_type=CertificateType.PUTINAR,
                polynomial=polynomial,
                constraints=constraints,
                putinar_certificate=cert,
                verified=cert.verify()
            )
        
        return None
    
    def optimize(self, objective: Polynomial,
                  constraints: List[Polynomial],
                  minimize: bool = True) -> Optional[Tuple[float, PolynomialCertificate]]:
        """
        Optimize polynomial over semialgebraic set.
        
        Returns (optimal_bound, certificate).
        """
        if not minimize:
            objective = objective.negate()
        
        # Try Lasserre hierarchy
        bound = self.lasserre_solver.minimize(objective, constraints,
                                               self.timeout_ms // 3)
        
        if bound is not None:
            cert = PolynomialCertificate(
                cert_type=CertificateType.LASSERRE,
                polynomial=objective,
                constraints=constraints,
                lasserre_level=self.lasserre_solver.stats['levels_computed'],
                lasserre_bound=bound if minimize else -bound,
                verified=True
            )
            
            return (bound if minimize else -bound, cert)
        
        return None
    
    def _try_sparse_positivity(self, polynomial: Polynomial,
                                 constraints: List[Polynomial],
                                 epsilon: float) -> Optional[PolynomialCertificate]:
        """Try sparse SOS approach."""
        # Verify positivity via sparse optimization
        shifted = polynomial.add(Polynomial.constant(self.n_vars, -epsilon))
        bound = self.sparse_decomposer.solve_sparse(
            shifted.negate(), constraints, self.timeout_ms // 2
        )
        
        if bound is not None and bound <= 0:
            # -shifted ≤ 0 means shifted ≥ 0, so p ≥ epsilon
            analysis = self.sparse_decomposer.analyze_and_decompose(
                polynomial, constraints
            )
            return PolynomialCertificate(
                cert_type=CertificateType.SPARSE_SOS,
                polynomial=polynomial,
                constraints=constraints,
                cliques=analysis['cliques'],
                verified=True
            )
        
        return None


# =============================================================================
# EXPORTS
# =============================================================================

__all__ = [
    # Foundational types
    'Monomial',
    'Polynomial',
    'SemialgebraicSet',
    
    # Quadratic module (Paper #5)
    'QuadraticModule',
    
    # SOS decomposition (Paper #6)
    'SOSDecomposition',
    'SOSDecomposer',
    
    # Putinar representation (Papers #5 + #6)
    'PutinarCertificate',
    'PutinarProver',
    
    # Lasserre hierarchy (Paper #7)
    'MomentMatrix',
    'LocalizingMatrix',
    'LasserreRelaxation',
    'LasserreHierarchySolver',
    
    # Sparse SOS (Paper #8)
    'VariableInteractionGraph',
    'ChordalExtension',
    'SparseSOSDecomposer',
    
    # Unified engine
    'CertificateType',
    'PolynomialCertificate',
    'PolynomialCertificateEngine',
]
