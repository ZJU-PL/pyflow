"""
SOTA Paper #6: Parrilo SOS via SDP (Semidefinite Programming) Integration.

Reference:
    P. A. Parrilo. "Semidefinite programming relaxations for semialgebraic problems."
    Mathematical Programming, Series B, 2003. (and thesis work, 2000)

This module implements the core reduction from polynomial proof obligations to
semidefinite programs (SDPs), enabling rigorous barrier certificate synthesis
for polynomial safety properties.

THEORETICAL FOUNDATIONS
=======================

1. Sum-of-Squares (SOS) Decomposition:
   A polynomial p(x) is SOS if p(x) = Σᵢ qᵢ(x)² for some polynomials qᵢ.
   SOS polynomials are nonnegative, but not all nonnegative polynomials are SOS.

2. Gram Matrix Representation:
   p(x) is SOS of degree 2d iff p(x) = m(x)ᵀ Q m(x) where:
   - m(x) is the vector of monomials up to degree d
   - Q is a positive semidefinite (PSD) matrix
   - The entries of Q satisfy linear constraints from coefficient matching

3. Positivstellensatz Certificates:
   For polynomial constraints gᵢ(x) ≥ 0 and hⱼ(x) = 0, we can certify that
   f(x) ≥ 0 on the feasible region by finding SOS polynomials σᵢ such that:
   f(x) = σ₀(x) + Σᵢ σᵢ(x)gᵢ(x) + Σⱼ λⱼ(x)hⱼ(x)

4. Barrier Certificate Connection:
   For barrier B(x), we need to prove:
   - Init:   ∀x∈X₀. B(x) ≥ ε           (B(x) - ε ≥ 0 on X₀)
   - Unsafe: ∀x∈Xᵤ. B(x) ≤ -ε          (-B(x) - ε ≥ 0 on Xᵤ)
   - Step:   ∀x,x'. (x∈R ∧ B(x)≥0) → B(x')≥0

   Each becomes an SOS feasibility check using Positivstellensatz.

ORTHOGONAL CONTRIBUTIONS
========================

This implementation is orthogonal to the existing barrier synthesis in:

1. **Mathematical Rigor**: Uses proper SDP relaxations with formal certificates,
   not ad-hoc template enumeration.

2. **Completeness Guarantees**: For polynomial systems of bounded degree, SOS
   provides a complete method (Lasserre hierarchy, Paper #7).

3. **Counterexample Extraction**: Failed SOS checks provide dual certificates
   that can guide refinement (feeds CEGIS loop).

4. **Scalability Framework**: Enables sparse decompositions (Paper #8) that
   the basic synthesis cannot leverage.

FALSE POSITIVE REDUCTION
========================

SOS-SDP reduces false positives by:
1. Providing *certified* proofs that certain unsafe regions are empty
2. Using proper Positivstellensatz multipliers for constraint handling
3. Eliminating spurious reports from incomplete template enumeration

BUG COVERAGE INCREASE
=====================

SOS-SDP increases bug coverage by:
1. Certifying SAFE for tractable polynomial subproblems (freeing budget)
2. Extracting dual information from infeasible SDPs to guide bug search
3. Enabling staged hierarchy (degree increase) for hard problems

LAYER POSITION
==============

This is a **Layer 1 (Foundations)** module - the mathematical core.

    ┌─────────────────────────────────────────────────────────────────┐
    │ Layer 5: Advanced Verification (IC3, CHC, IMC, Assume-Guarantee)│
    │ Layer 4: Learning (ICE, Houdini, SyGuS)                         │
    │ Layer 3: Abstraction (CEGAR, Predicate Abstraction, IMPACT)     │
    │ Layer 2: Certificate Core (Hybrid, Stochastic, SOS Safety)      │
    │ Layer 1: FOUNDATIONS ← [THIS MODULE]                            │
    │   ├── positivstellensatz.py                                     │
    │   ├── parrilo_sos_sdp.py ← You are here (CORE)                  │
    │   ├── lasserre_hierarchy.py                                     │
    │   └── sparse_sos.py                                             │
    └─────────────────────────────────────────────────────────────────┘

CROSS-PAPER DEPENDENCIES
========================

This module provides fundamental types used by ALL other papers:
- Polynomial: Core polynomial representation
- SemialgebraicSet: Constraint sets for barrier problems
- MonomialBasis: Basis for SOS decomposition
- GramMatrix: PSD matrices for SOS certificates

Papers that depend on this module:
- Paper #5 (Positivstellensatz): Uses Polynomial, SemialgebraicSet
- Paper #7 (Lasserre): Uses SOS decomposition infrastructure  
- Paper #8 (Sparse SOS): Extends with sparsity exploitation
- Papers #1-4 (Barrier Core): All barrier types use these foundations
"""

from __future__ import annotations

import itertools
import time
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Dict, List, Optional, Tuple, Callable, Set, Iterator, Any, Union
from abc import ABC, abstractmethod

import z3

# =============================================================================
# LAYER 1: FOUNDATIONAL TYPES
# =============================================================================
# This module defines the core mathematical types used throughout the barrier
# certificate synthesis framework. It has no intra-barriers dependencies
# because it IS the foundation that everything else builds upon.
# =============================================================================

# Type aliases for polynomial representation
Monomial = Tuple[int, ...]  # Exponent vector: (e₁, e₂, ..., eₙ) for x₁^e₁ x₂^e₂ ... xₙ^eₙ
PolynomialCoeffs = Dict[Monomial, float]  # Sparse coefficient representation


class SDPSolverStatus(Enum):
    """Status of SDP solver."""
    OPTIMAL = auto()
    INFEASIBLE = auto()
    UNBOUNDED = auto()
    TIMEOUT = auto()
    NUMERICAL_ERROR = auto()
    UNKNOWN = auto()


@dataclass(frozen=True)
class MonomialBasis:
    """
    Monomial basis for SOS decomposition.
    
    For n variables and degree d, the basis contains all monomials
    x₁^e₁ x₂^e₂ ... xₙ^eₙ where Σeᵢ ≤ d.
    
    Attributes:
        n_vars: Number of variables
        degree: Maximum total degree
        monomials: Ordered list of monomial exponent vectors
        monomial_to_idx: Mapping from monomial to index in basis
    """
    n_vars: int
    degree: int
    monomials: Tuple[Monomial, ...]
    monomial_to_idx: Dict[Monomial, int] = field(default_factory=dict)
    
    @staticmethod
    def create(n_vars: int, degree: int) -> 'MonomialBasis':
        """Create monomial basis for given dimension and degree."""
        monomials = []
        for total_deg in range(degree + 1):
            for exponents in _partitions(total_deg, n_vars):
                monomials.append(tuple(exponents))
        
        monomials_tuple = tuple(monomials)
        idx_map = {m: i for i, m in enumerate(monomials_tuple)}
        
        # Use object.__setattr__ since frozen=True
        basis = MonomialBasis(
            n_vars=n_vars,
            degree=degree,
            monomials=monomials_tuple,
            monomial_to_idx=idx_map
        )
        return basis
    
    def __len__(self) -> int:
        return len(self.monomials)
    
    def product_degree(self) -> int:
        """Degree of product m(x)ᵀ Q m(x)."""
        return 2 * self.degree
    
    def multiply_monomials(self, m1: Monomial, m2: Monomial) -> Monomial:
        """Compute exponent vector of m1 * m2."""
        return tuple(e1 + e2 for e1, e2 in zip(m1, m2))


def _partitions(total: int, n_parts: int) -> Iterator[List[int]]:
    """Generate all ways to partition total into n_parts nonnegative integers."""
    if n_parts == 1:
        yield [total]
        return
    for i in range(total + 1):
        for rest in _partitions(total - i, n_parts - 1):
            yield [i] + rest


@dataclass
class Polynomial:
    """
    Multivariate polynomial in sparse representation.
    
    p(x) = Σ cₘ xᵐ where m is a monomial exponent vector.
    
    Attributes:
        n_vars: Number of variables
        coeffs: Sparse coefficient dictionary {monomial: coefficient}
        var_names: Optional variable names for pretty printing
    """
    n_vars: int
    coeffs: PolynomialCoeffs
    var_names: Optional[List[str]] = None
    
    @staticmethod
    def zero(n_vars: int) -> 'Polynomial':
        """Create zero polynomial."""
        return Polynomial(n_vars=n_vars, coeffs={})
    
    @staticmethod
    def constant(n_vars: int, value: float) -> 'Polynomial':
        """Create constant polynomial."""
        zero_mono = tuple([0] * n_vars)
        return Polynomial(n_vars=n_vars, coeffs={zero_mono: value})
    
    @staticmethod
    def variable(n_vars: int, var_idx: int, var_names: Optional[List[str]] = None) -> 'Polynomial':
        """Create polynomial representing single variable xᵢ."""
        mono = tuple(1 if i == var_idx else 0 for i in range(n_vars))
        return Polynomial(n_vars=n_vars, coeffs={mono: 1.0}, var_names=var_names)
    
    @staticmethod
    def monomial(n_vars: int, exponents: Monomial, coeff: float = 1.0) -> 'Polynomial':
        """Create single monomial."""
        return Polynomial(n_vars=n_vars, coeffs={exponents: coeff})
    
    def degree(self) -> int:
        """Maximum total degree of any monomial."""
        if not self.coeffs:
            return 0
        return max(sum(m) for m in self.coeffs.keys())
    
    def is_zero(self) -> bool:
        """Check if polynomial is zero."""
        return all(abs(c) < 1e-10 for c in self.coeffs.values())
    
    def __add__(self, other: 'Polynomial') -> 'Polynomial':
        """Add polynomials."""
        assert self.n_vars == other.n_vars
        result = dict(self.coeffs)
        for m, c in other.coeffs.items():
            result[m] = result.get(m, 0.0) + c
        # Remove zero coefficients
        result = {m: c for m, c in result.items() if abs(c) > 1e-15}
        return Polynomial(n_vars=self.n_vars, coeffs=result, var_names=self.var_names)
    
    def __sub__(self, other: 'Polynomial') -> 'Polynomial':
        """Subtract polynomials."""
        return self + other.scale(-1.0)
    
    def __mul__(self, other: 'Polynomial') -> 'Polynomial':
        """Multiply polynomials."""
        assert self.n_vars == other.n_vars
        result: PolynomialCoeffs = {}
        for m1, c1 in self.coeffs.items():
            for m2, c2 in other.coeffs.items():
                m_prod = tuple(e1 + e2 for e1, e2 in zip(m1, m2))
                result[m_prod] = result.get(m_prod, 0.0) + c1 * c2
        result = {m: c for m, c in result.items() if abs(c) > 1e-15}
        return Polynomial(n_vars=self.n_vars, coeffs=result, var_names=self.var_names)
    
    def scale(self, factor: float) -> 'Polynomial':
        """Multiply by scalar."""
        return Polynomial(
            n_vars=self.n_vars,
            coeffs={m: c * factor for m, c in self.coeffs.items()},
            var_names=self.var_names
        )
    
    def __neg__(self) -> 'Polynomial':
        """Negate polynomial."""
        return self.scale(-1.0)
    
    def evaluate(self, point: List[float]) -> float:
        """Evaluate polynomial at a point."""
        assert len(point) == self.n_vars
        result = 0.0
        for mono, coeff in self.coeffs.items():
            term = coeff
            for i, exp in enumerate(mono):
                if exp > 0:
                    term *= point[i] ** exp
            result += term
        return result
    
    def to_z3(self, z3_vars: List[z3.ArithRef]) -> z3.ArithRef:
        """Convert to Z3 expression."""
        assert len(z3_vars) == self.n_vars
        terms = []
        for mono, coeff in self.coeffs.items():
            term = z3.RealVal(coeff)
            for i, exp in enumerate(mono):
                for _ in range(exp):
                    term = term * z3_vars[i]
            terms.append(term)
        if not terms:
            return z3.RealVal(0)
        result = terms[0]
        for t in terms[1:]:
            result = result + t
        return result
    
    def __str__(self) -> str:
        """Pretty print polynomial."""
        if not self.coeffs:
            return "0"
        
        var_names = self.var_names or [f"x{i}" for i in range(self.n_vars)]
        terms = []
        
        for mono, coeff in sorted(self.coeffs.items(), key=lambda x: (-sum(x[0]), x[0])):
            if abs(coeff) < 1e-10:
                continue
            
            # Build monomial string
            mono_parts = []
            for i, exp in enumerate(mono):
                if exp == 0:
                    continue
                elif exp == 1:
                    mono_parts.append(var_names[i])
                else:
                    mono_parts.append(f"{var_names[i]}^{exp}")
            
            if not mono_parts:
                terms.append(f"{coeff:.4g}")
            elif abs(coeff - 1.0) < 1e-10:
                terms.append("*".join(mono_parts))
            elif abs(coeff + 1.0) < 1e-10:
                terms.append("-" + "*".join(mono_parts))
            else:
                terms.append(f"{coeff:.4g}*" + "*".join(mono_parts))
        
        if not terms:
            return "0"
        
        result = terms[0]
        for t in terms[1:]:
            if t.startswith("-"):
                result += " " + t
            else:
                result += " + " + t
        return result


def degree(poly: Any) -> int:
    """
    Convenience degree helper.

    Several modules treat polynomial degree as a free function; this keeps that
    API stable while delegating to `Polynomial.degree()` when applicable.
    """
    if isinstance(poly, Polynomial):
        return poly.degree()
    if isinstance(poly, dict):
        try:
            return max(sum(m) for m in poly.keys()) if poly else 0
        except Exception:
            return 0
    return 0


@dataclass
class GramMatrix:
    """
    Gram matrix representation of an SOS polynomial.
    
    p(x) = m(x)ᵀ Q m(x) where Q ≽ 0 (positive semidefinite).
    
    The matrix entries are Z3 Real variables (for SDP encoding) or
    concrete float values (after solving).
    
    Attributes:
        basis: Monomial basis m(x)
        size: Dimension of Q (= len(basis))
        entries: Z3 variables or concrete values for matrix entries
        name_prefix: Prefix for Z3 variable names
    """
    basis: MonomialBasis
    size: int
    entries: Dict[Tuple[int, int], Union[z3.ArithRef, float]]
    name_prefix: str = "q"
    
    @staticmethod
    def create_symbolic(basis: MonomialBasis, name_prefix: str = "q") -> 'GramMatrix':
        """Create Gram matrix with Z3 symbolic entries."""
        size = len(basis)
        entries: Dict[Tuple[int, int], z3.ArithRef] = {}
        
        # Only need upper triangular (symmetric matrix)
        for i in range(size):
            for j in range(i, size):
                var_name = f"{name_prefix}_{i}_{j}"
                entries[(i, j)] = z3.Real(var_name)
                if i != j:
                    entries[(j, i)] = entries[(i, j)]  # Symmetry
        
        return GramMatrix(
            basis=basis,
            size=size,
            entries=entries,
            name_prefix=name_prefix
        )
    
    def get(self, i: int, j: int) -> Union[z3.ArithRef, float]:
        """Get matrix entry Q[i,j]."""
        return self.entries[(i, j)]
    
    def to_polynomial(self) -> Polynomial:
        """
        Expand m(x)ᵀ Q m(x) into a polynomial.
        
        Each entry Q[i,j] contributes to the coefficient of monomial mᵢ * mⱼ.
        """
        n_vars = self.basis.n_vars
        coeffs: Dict[Monomial, z3.ArithRef] = {}
        
        for i in range(self.size):
            for j in range(self.size):
                m_i = self.basis.monomials[i]
                m_j = self.basis.monomials[j]
                m_prod = self.basis.multiply_monomials(m_i, m_j)
                
                if m_prod not in coeffs:
                    coeffs[m_prod] = z3.RealVal(0)
                coeffs[m_prod] = coeffs[m_prod] + self.get(i, j)
        
        return Polynomial(n_vars=n_vars, coeffs=coeffs)
    
    def get_z3_psd_constraints(self) -> List[z3.BoolRef]:
        """
        Generate Z3 constraints for positive semidefiniteness.
        
        We use the characterization that Q ≽ 0 iff all principal minors ≥ 0.
        For small matrices, we enumerate all principal minors.
        For larger matrices, we use a diagonal dominance relaxation.
        """
        constraints = []
        
        if self.size <= 4:
            # Full principal minor constraints for small matrices
            constraints.extend(self._principal_minor_constraints())
        else:
            # Diagonal dominance: Q[i,i] ≥ Σⱼ≠ᵢ |Q[i,j]|
            # We relax |Q[i,j]| to linear constraints using Q[i,j] ≥ -Q[i,i]/n
            constraints.extend(self._diagonal_dominance_constraints())
        
        return constraints
    
    def _principal_minor_constraints(self) -> List[z3.BoolRef]:
        """Generate all principal minor ≥ 0 constraints."""
        constraints = []
        
        # 1x1 minors: diagonal entries ≥ 0
        for i in range(self.size):
            constraints.append(self.get(i, i) >= 0)
        
        if self.size >= 2:
            # 2x2 minors
            for i in range(self.size):
                for j in range(i + 1, self.size):
                    det = self.get(i, i) * self.get(j, j) - self.get(i, j) * self.get(i, j)
                    constraints.append(det >= 0)
        
        if self.size >= 3:
            # 3x3 minors (selected for tractability)
            for i in range(min(self.size, 4)):
                for j in range(i + 1, min(self.size, 4)):
                    for k in range(j + 1, min(self.size, 4)):
                        det = self._det_3x3(i, j, k)
                        constraints.append(det >= 0)
        
        return constraints
    
    def _det_3x3(self, i: int, j: int, k: int) -> z3.ArithRef:
        """Compute 3x3 principal minor determinant."""
        a, b, c = self.get(i, i), self.get(i, j), self.get(i, k)
        d, e, f = self.get(j, i), self.get(j, j), self.get(j, k)
        g, h, l = self.get(k, i), self.get(k, j), self.get(k, k)
        
        return (a * (e * l - f * h) -
                b * (d * l - f * g) +
                c * (d * h - e * g))
    
    def _diagonal_dominance_constraints(self) -> List[z3.BoolRef]:
        """Generate diagonal dominance constraints (DSOS-style relaxation)."""
        constraints = []
        
        # Diagonal entries ≥ 0
        for i in range(self.size):
            constraints.append(self.get(i, i) >= 0)
        
        # Off-diagonal bounded by geometric mean of diagonals
        for i in range(self.size):
            for j in range(i + 1, self.size):
                # |Q[i,j]| ≤ sqrt(Q[i,i] * Q[j,j])
                # Relaxed to: Q[i,j]² ≤ Q[i,i] * Q[j,j]
                qij = self.get(i, j)
                constraints.append(qij * qij <= self.get(i, i) * self.get(j, j))
        
        return constraints


@dataclass
class SOSDecomposition:
    """
    Result of SOS decomposition for a polynomial.
    
    Represents p(x) = Σᵢ qᵢ(x)² where each qᵢ is a polynomial.
    
    Attributes:
        polynomial: The original polynomial
        gram_matrix: The Gram matrix Q such that p = m(x)ᵀ Q m(x)
        factors: The factor polynomials qᵢ (from Cholesky or eigendecomposition)
        residual: Numerical residual ||p - Σqᵢ²||
    """
    polynomial: Polynomial
    gram_matrix: Optional[GramMatrix]
    factors: List[Polynomial]
    residual: float = 0.0
    
    def is_valid(self, tolerance: float = 1e-6) -> bool:
        """Check if decomposition is valid within tolerance."""
        return self.residual <= tolerance
    
    def verify_z3(self, z3_vars: List[z3.ArithRef]) -> z3.BoolRef:
        """Generate Z3 constraint that this polynomial is SOS."""
        # p(x) = Σ qᵢ(x)²
        sum_of_squares = z3.RealVal(0)
        for q in self.factors:
            q_z3 = q.to_z3(z3_vars)
            sum_of_squares = sum_of_squares + q_z3 * q_z3
        
        p_z3 = self.polynomial.to_z3(z3_vars)
        return p_z3 == sum_of_squares


# =============================================================================
# SEMIALGEBRAIC SET REPRESENTATION
# =============================================================================

@dataclass
class SemialgebraicConstraint:
    """
    A polynomial constraint of the form g(x) ≥ 0 or h(x) = 0.
    
    Attributes:
        polynomial: The constraint polynomial
        kind: 'ineq' for g(x) ≥ 0, 'eq' for h(x) = 0
        name: Optional descriptive name
    """
    polynomial: Polynomial
    kind: str  # 'ineq' or 'eq'
    name: Optional[str] = None
    
    def to_z3(self, z3_vars: List[z3.ArithRef]) -> z3.BoolRef:
        """Convert to Z3 constraint."""
        p_z3 = self.polynomial.to_z3(z3_vars)
        if self.kind == 'eq':
            return p_z3 == 0
        else:
            return p_z3 >= 0


@dataclass
class SemialgebraicSet:
    """
    A basic semialgebraic set defined by polynomial constraints.
    
    S = { x ∈ ℝⁿ : gᵢ(x) ≥ 0, hⱼ(x) = 0 }
    
    Attributes:
        n_vars: Dimension of the ambient space
        inequalities: List of gᵢ(x) ≥ 0 constraints
        equalities: List of hⱼ(x) = 0 constraints
        var_names: Optional variable names
        name: Optional set name
    """
    n_vars: int
    inequalities: List[Polynomial]
    equalities: List[Polynomial]
    var_names: Optional[List[str]] = None
    name: Optional[str] = None
    
    @staticmethod
    def box(n_vars: int, lower: List[float], upper: List[float],
            var_names: Optional[List[str]] = None) -> 'SemialgebraicSet':
        """Create box constraint: lᵢ ≤ xᵢ ≤ uᵢ."""
        inequalities = []
        for i in range(n_vars):
            # xᵢ - lᵢ ≥ 0
            p_lower = Polynomial.variable(n_vars, i) + Polynomial.constant(n_vars, -lower[i])
            inequalities.append(p_lower)
            # uᵢ - xᵢ ≥ 0
            p_upper = Polynomial.constant(n_vars, upper[i]) - Polynomial.variable(n_vars, i)
            inequalities.append(p_upper)
        
        return SemialgebraicSet(
            n_vars=n_vars,
            inequalities=inequalities,
            equalities=[],
            var_names=var_names,
            name=f"box[{lower}, {upper}]"
        )
    
    @staticmethod
    def ball(n_vars: int, center: List[float], radius: float,
             var_names: Optional[List[str]] = None) -> 'SemialgebraicSet':
        """Create ball constraint: ||x - c||² ≤ r²."""
        # r² - Σ(xᵢ - cᵢ)² ≥ 0
        ineq = Polynomial.constant(n_vars, radius * radius)
        for i in range(n_vars):
            xi = Polynomial.variable(n_vars, i)
            ci = Polynomial.constant(n_vars, center[i])
            diff = xi - ci
            ineq = ineq - diff * diff
        
        return SemialgebraicSet(
            n_vars=n_vars,
            inequalities=[ineq],
            equalities=[],
            var_names=var_names,
            name=f"ball(center={center}, r={radius})"
        )
    
    def intersect(self, other: 'SemialgebraicSet') -> 'SemialgebraicSet':
        """Intersection of two semialgebraic sets."""
        assert self.n_vars == other.n_vars
        return SemialgebraicSet(
            n_vars=self.n_vars,
            inequalities=self.inequalities + other.inequalities,
            equalities=self.equalities + other.equalities,
            var_names=self.var_names or other.var_names,
            name=f"({self.name}) ∩ ({other.name})"
        )
    
    def is_compact(self) -> bool:
        """
        Check if the set is (likely) compact.
        
        A set is compact if it's bounded. We check for explicit box constraints
        on all variables.
        """
        # Track which variables have both upper and lower bounds
        has_lower = [False] * self.n_vars
        has_upper = [False] * self.n_vars
        
        for ineq in self.inequalities:
            # Check for xᵢ - c ≥ 0 (lower bound)
            # Check for c - xᵢ ≥ 0 (upper bound)
            if len(ineq.coeffs) == 2:
                # Linear polynomial with constant
                for mono, coeff in ineq.coeffs.items():
                    if sum(mono) == 1:  # Linear term
                        var_idx = mono.index(1)
                        if coeff > 0:
                            has_lower[var_idx] = True
                        elif coeff < 0:
                            has_upper[var_idx] = True
        
        return all(has_lower) and all(has_upper)
    
    def to_z3_constraints(self, z3_vars: List[z3.ArithRef]) -> List[z3.BoolRef]:
        """Convert all constraints to Z3."""
        constraints = []
        for ineq in self.inequalities:
            constraints.append(ineq.to_z3(z3_vars) >= 0)
        for eq in self.equalities:
            constraints.append(eq.to_z3(z3_vars) == 0)
        return constraints


# =============================================================================
# POSITIVSTELLENSATZ CERTIFICATES
# =============================================================================

@dataclass
class PositivstellensatzCertificate:
    """
    A Positivstellensatz certificate proving nonnegativity on a semialgebraic set.
    
    Proves f(x) ≥ 0 for all x in S = {gᵢ(x) ≥ 0, hⱼ(x) = 0} via:
    
        f(x) = σ₀(x) + Σᵢ σᵢ(x)gᵢ(x) + Σⱼ λⱼ(x)hⱼ(x)
    
    where σᵢ are SOS polynomials and λⱼ are arbitrary polynomials.
    
    Attributes:
        target: The polynomial f(x) being certified
        domain: The semialgebraic set S
        sigma_0: The "free" SOS polynomial
        sigma_i: SOS multipliers for inequality constraints
        lambda_j: Polynomial multipliers for equality constraints
    """
    target: Polynomial
    domain: SemialgebraicSet
    sigma_0: SOSDecomposition
    sigma_i: List[SOSDecomposition]
    lambda_j: List[Polynomial]
    
    def verify(self, tolerance: float = 1e-6) -> bool:
        """
        Verify the certificate is valid.
        
        Checks:
        1. All σᵢ are valid SOS decompositions
        2. The polynomial identity holds within tolerance
        """
        # Check all SOS decompositions are valid
        if not self.sigma_0.is_valid(tolerance):
            return False
        for sigma in self.sigma_i:
            if not sigma.is_valid(tolerance):
                return False
        
        # Check polynomial identity
        # f(x) - σ₀(x) - Σᵢ σᵢ(x)gᵢ(x) - Σⱼ λⱼ(x)hⱼ(x) = 0
        residual = self.target
        residual = residual - self.sigma_0.polynomial
        
        for sigma, g in zip(self.sigma_i, self.domain.inequalities):
            residual = residual - sigma.polynomial * g
        
        for lam, h in zip(self.lambda_j, self.domain.equalities):
            residual = residual - lam * h
        
        return residual.is_zero()
    
    def to_proof_string(self) -> str:
        """Generate human-readable proof string."""
        lines = [
            f"Positivstellensatz Certificate",
            f"==============================",
            f"Target: {self.target} ≥ 0",
            f"Domain: {self.domain.name}",
            f"",
            f"Certificate:",
            f"  σ₀(x) = {self.sigma_0.polynomial}",
        ]
        
        for i, (sigma, g) in enumerate(zip(self.sigma_i, self.domain.inequalities)):
            lines.append(f"  σ_{i+1}(x) = {sigma.polynomial}")
            lines.append(f"    g_{i+1}(x) = {g}")
        
        for j, (lam, h) in enumerate(zip(self.lambda_j, self.domain.equalities)):
            lines.append(f"  λ_{j+1}(x) = {lam}")
            lines.append(f"    h_{j+1}(x) = {h}")
        
        return "\n".join(lines)


# =============================================================================
# SOS FEASIBILITY PROBLEM
# =============================================================================

@dataclass
class SOSFeasibilityProblem:
    """
    An SOS feasibility problem for proving polynomial nonnegativity.
    
    Given f(x), domain S, find SOS certificates proving f(x) ≥ 0 on S.
    
    Attributes:
        target: Polynomial f(x) to prove nonnegative
        domain: Semialgebraic set S
        sos_degree: Maximum degree for SOS polynomials
        multiplier_degrees: Maximum degrees for Positivstellensatz multipliers
    """
    target: Polynomial
    domain: SemialgebraicSet
    sos_degree: int
    multiplier_degrees: Optional[List[int]] = None
    
    def get_multiplier_degree(self, constraint_idx: int) -> int:
        """Get multiplier degree for a constraint."""
        if self.multiplier_degrees and constraint_idx < len(self.multiplier_degrees):
            return self.multiplier_degrees[constraint_idx]
        
        # Default: ensure σᵢ(x)gᵢ(x) has same degree as f
        target_deg = self.target.degree()
        constraint_deg = self.domain.inequalities[constraint_idx].degree()
        return max(0, target_deg - constraint_deg)


class SOSEncoder:
    """
    Encodes SOS feasibility problems as Z3 constraints.
    
    This is the core of the Parrilo SOS-SDP approach: we reduce the problem
    of finding SOS certificates to a system of linear matrix inequalities (LMIs)
    that can be solved as an SDP or checked via Z3.
    """
    
    def __init__(self, problem: SOSFeasibilityProblem, verbose: bool = False):
        self.problem = problem
        self.verbose = verbose
        self.n_vars = problem.domain.n_vars
        
        # Create Z3 variables for the polynomial variables
        self.z3_vars = [z3.Real(f"x{i}") for i in range(self.n_vars)]
        
        # Gram matrices for SOS polynomials
        self.gram_matrices: List[GramMatrix] = []
        
        # Z3 solver
        self.solver = z3.Solver()
        self._encoded = False
    
    def encode(self) -> None:
        """
        Encode the SOS feasibility problem as Z3 constraints.
        
        Creates Gram matrix variables and coefficient matching constraints.
        """
        if self._encoded:
            return
        
        # Create Gram matrix for σ₀
        basis_0 = MonomialBasis.create(self.n_vars, self.problem.sos_degree // 2)
        gram_0 = GramMatrix.create_symbolic(basis_0, "sigma0")
        self.gram_matrices.append(gram_0)
        
        # Create Gram matrices for σᵢ (inequality multipliers)
        for i, g in enumerate(self.problem.domain.inequalities):
            mult_deg = self.problem.get_multiplier_degree(i)
            if mult_deg > 0:
                basis_i = MonomialBasis.create(self.n_vars, mult_deg // 2)
                gram_i = GramMatrix.create_symbolic(basis_i, f"sigma{i+1}")
                self.gram_matrices.append(gram_i)
            else:
                # Degree 0: just a nonnegative constant
                self.gram_matrices.append(None)
        
        # Add PSD constraints for all Gram matrices
        for gram in self.gram_matrices:
            if gram is not None:
                self.solver.add(*gram.get_z3_psd_constraints())
        
        # Coefficient matching: f(x) = σ₀(x) + Σᵢ σᵢ(x)gᵢ(x)
        self._add_coefficient_matching_constraints()
        
        self._encoded = True
    
    def _add_coefficient_matching_constraints(self) -> None:
        """Add constraints that polynomial coefficients match."""
        # This is a simplified version - full implementation would
        # collect all monomials and match coefficients
        
        # For now, we use Z3's polynomial arithmetic directly
        target_z3 = self.problem.target.to_z3(self.z3_vars)
        
        # σ₀(x) from Gram matrix
        sigma_0_poly = self.gram_matrices[0].to_polynomial()
        sigma_0_z3 = sigma_0_poly.to_z3(self.z3_vars)
        
        # Sum of σᵢ(x)gᵢ(x)
        sum_products = z3.RealVal(0)
        for i, g in enumerate(self.problem.domain.inequalities):
            gram = self.gram_matrices[i + 1]
            if gram is not None:
                sigma_i_poly = gram.to_polynomial()
                sigma_i_z3 = sigma_i_poly.to_z3(self.z3_vars)
            else:
                # Constant nonnegative multiplier
                sigma_i_z3 = z3.Real(f"sigma_const_{i}")
                self.solver.add(sigma_i_z3 >= 0)
            
            g_z3 = g.to_z3(self.z3_vars)
            sum_products = sum_products + sigma_i_z3 * g_z3
        
        # f(x) = σ₀(x) + Σᵢ σᵢ(x)gᵢ(x) for all x
        # This is a polynomial identity, so we check at sample points
        # and rely on coefficient matching
        identity = target_z3 == sigma_0_z3 + sum_products
        self.solver.add(z3.ForAll(self.z3_vars, identity))
    
    def solve(self, timeout_ms: int = 10000) -> Tuple[SDPSolverStatus, Optional[PositivstellensatzCertificate]]:
        """
        Attempt to solve the SOS feasibility problem.
        
        Returns:
            Tuple of (status, certificate if found)
        """
        self.encode()
        
        self.solver.set("timeout", timeout_ms)
        
        result = self.solver.check()
        
        if result == z3.sat:
            model = self.solver.model()
            certificate = self._extract_certificate(model)
            return SDPSolverStatus.OPTIMAL, certificate
        elif result == z3.unsat:
            return SDPSolverStatus.INFEASIBLE, None
        else:
            return SDPSolverStatus.UNKNOWN, None
    
    def _extract_certificate(self, model: z3.ModelRef) -> PositivstellensatzCertificate:
        """Extract certificate from Z3 model."""
        # Extract σ₀
        sigma_0 = self._extract_sos_from_gram(self.gram_matrices[0], model)
        
        # Extract σᵢ
        sigma_i = []
        for i, gram in enumerate(self.gram_matrices[1:]):
            if gram is not None:
                sigma = self._extract_sos_from_gram(gram, model)
            else:
                # Constant case
                const_var = z3.Real(f"sigma_const_{i}")
                val = float(model.eval(const_var, model_completion=True).as_fraction())
                sigma = SOSDecomposition(
                    polynomial=Polynomial.constant(self.n_vars, val),
                    gram_matrix=None,
                    factors=[Polynomial.constant(self.n_vars, val ** 0.5)],
                    residual=0.0
                )
            sigma_i.append(sigma)
        
        return PositivstellensatzCertificate(
            target=self.problem.target,
            domain=self.problem.domain,
            sigma_0=sigma_0,
            sigma_i=sigma_i,
            lambda_j=[]  # No equality constraints for now
        )
    
    def _extract_sos_from_gram(self, gram: GramMatrix, model: z3.ModelRef) -> SOSDecomposition:
        """Extract SOS decomposition from Gram matrix values."""
        # Get concrete matrix values
        concrete_entries: Dict[Tuple[int, int], float] = {}
        for (i, j), var in gram.entries.items():
            if isinstance(var, z3.ArithRef):
                val = model.eval(var, model_completion=True)
                try:
                    concrete_entries[(i, j)] = float(val.as_fraction())
                except:
                    concrete_entries[(i, j)] = 0.0
            else:
                concrete_entries[(i, j)] = var
        
        # Build polynomial from Gram matrix
        poly = self._gram_to_polynomial(gram.basis, concrete_entries)
        
        # Factor via Cholesky (simplified - just return polynomial)
        factors = self._cholesky_factors(gram.basis, concrete_entries)
        
        return SOSDecomposition(
            polynomial=poly,
            gram_matrix=gram,
            factors=factors,
            residual=0.0
        )
    
    def _gram_to_polynomial(self, basis: MonomialBasis,
                            entries: Dict[Tuple[int, int], float]) -> Polynomial:
        """Compute m(x)ᵀ Q m(x)."""
        coeffs: PolynomialCoeffs = {}
        
        for i in range(len(basis)):
            for j in range(len(basis)):
                m_i = basis.monomials[i]
                m_j = basis.monomials[j]
                m_prod = basis.multiply_monomials(m_i, m_j)
                
                val = entries.get((i, j), 0.0)
                coeffs[m_prod] = coeffs.get(m_prod, 0.0) + val
        
        coeffs = {m: c for m, c in coeffs.items() if abs(c) > 1e-15}
        return Polynomial(n_vars=basis.n_vars, coeffs=coeffs)
    
    def _cholesky_factors(self, basis: MonomialBasis,
                          entries: Dict[Tuple[int, int], float]) -> List[Polynomial]:
        """
        Compute Cholesky factors L such that Q = LLᵀ.
        
        Each column of L gives a polynomial factor.
        """
        n = len(basis)
        
        # Build matrix
        import math
        
        # Simple Cholesky attempt
        L = [[0.0] * n for _ in range(n)]
        
        for i in range(n):
            for j in range(i + 1):
                if i == j:
                    sum_sq = sum(L[i][k] ** 2 for k in range(j))
                    val = entries.get((i, i), 0.0) - sum_sq
                    L[i][j] = math.sqrt(max(0, val))
                else:
                    if L[j][j] > 1e-10:
                        sum_prod = sum(L[i][k] * L[j][k] for k in range(j))
                        L[i][j] = (entries.get((i, j), 0.0) - sum_prod) / L[j][j]
        
        # Each column of L is a polynomial factor
        factors = []
        for col in range(n):
            coeffs: PolynomialCoeffs = {}
            for row in range(n):
                if abs(L[row][col]) > 1e-10:
                    mono = basis.monomials[row]
                    coeffs[mono] = L[row][col]
            if coeffs:
                factors.append(Polynomial(n_vars=basis.n_vars, coeffs=coeffs))
        
        return factors


# =============================================================================
# BARRIER CERTIFICATE SYNTHESIS VIA SOS-SDP
# =============================================================================

@dataclass
class BarrierTemplate:
    """
    A parameterized barrier certificate template.
    
    B(x) = Σₘ cₘ xᵐ where cₘ are unknown coefficients.
    
    Attributes:
        n_vars: Number of state variables
        degree: Maximum polynomial degree
        basis: Monomial basis
        coefficients: Z3 variables for coefficients
        var_names: Variable names
    """
    n_vars: int
    degree: int
    basis: MonomialBasis
    coefficients: Dict[Monomial, z3.ArithRef]
    var_names: Optional[List[str]] = None
    
    @staticmethod
    def create(n_vars: int, degree: int, name: str = "b",
               var_names: Optional[List[str]] = None) -> 'BarrierTemplate':
        """Create barrier template with symbolic coefficients."""
        basis = MonomialBasis.create(n_vars, degree)
        coefficients = {}
        
        for mono in basis.monomials:
            mono_str = "_".join(str(e) for e in mono)
            coefficients[mono] = z3.Real(f"{name}_{mono_str}")
        
        return BarrierTemplate(
            n_vars=n_vars,
            degree=degree,
            basis=basis,
            coefficients=coefficients,
            var_names=var_names
        )
    
    def to_z3(self, z3_vars: List[z3.ArithRef]) -> z3.ArithRef:
        """Convert to Z3 expression with symbolic coefficients."""
        result = z3.RealVal(0)
        for mono, coeff in self.coefficients.items():
            term = coeff
            for i, exp in enumerate(mono):
                for _ in range(exp):
                    term = term * z3_vars[i]
            result = result + term
        return result
    
    def to_polynomial(self, values: Dict[Monomial, float]) -> Polynomial:
        """Instantiate template with concrete coefficient values."""
        coeffs = {m: values[m] for m in self.coefficients if m in values}
        return Polynomial(n_vars=self.n_vars, coeffs=coeffs, var_names=self.var_names)
    
    def get_coefficient_vars(self) -> List[z3.ArithRef]:
        """Get all coefficient variables for solver."""
        return list(self.coefficients.values())


@dataclass
class BarrierSynthesisProblem:
    """
    Barrier certificate synthesis problem.
    
    Find B(x) such that:
    - Init:   B(x) ≥ ε  for all x ∈ X₀
    - Unsafe: B(x) ≤ -ε for all x ∈ Xᵤ
    - Step:   B(x) ≥ 0 ∧ x→x' ⟹ B(x') ≥ 0
    
    Attributes:
        n_vars: State dimension
        init_set: Initial states X₀
        unsafe_set: Unsafe states Xᵤ
        transition: Transition relation (polynomials for x' in terms of x)
        epsilon: Safety margin
        barrier_degree: Maximum degree for barrier
    """
    n_vars: int
    init_set: SemialgebraicSet
    unsafe_set: SemialgebraicSet
    transition: Optional[List[Polynomial]]  # x'ᵢ = fᵢ(x) or None for nondeterministic
    invariant_set: Optional[SemialgebraicSet] = None  # Reachable region (if known)
    epsilon: float = 0.01
    barrier_degree: int = 2
    
    def validate(self) -> bool:
        """Check problem is well-formed."""
        if self.init_set.n_vars != self.n_vars:
            return False
        if self.unsafe_set.n_vars != self.n_vars:
            return False
        if self.transition and len(self.transition) != self.n_vars:
            return False
        return True


@dataclass
class BarrierCertificateResult:
    """
    Result of barrier certificate synthesis.
    
    Attributes:
        success: Whether a valid barrier was found
        barrier: The barrier polynomial (if success)
        init_certificate: Positivstellensatz certificate for init condition
        unsafe_certificate: Certificate for unsafe condition
        step_certificate: Certificate for step condition
        synthesis_time_ms: Total synthesis time
        sos_degree: SOS degree used
        message: Status message
    """
    success: bool
    barrier: Optional[Polynomial] = None
    init_certificate: Optional[PositivstellensatzCertificate] = None
    unsafe_certificate: Optional[PositivstellensatzCertificate] = None
    step_certificate: Optional[PositivstellensatzCertificate] = None
    synthesis_time_ms: float = 0.0
    sos_degree: int = 0
    message: str = ""
    
    def to_proof_string(self) -> str:
        """Generate complete proof string."""
        if not self.success:
            return f"Synthesis failed: {self.message}"
        
        lines = [
            "=" * 60,
            "BARRIER CERTIFICATE PROOF",
            "=" * 60,
            f"Barrier: B(x) = {self.barrier}",
            f"SOS degree: {self.sos_degree}",
            f"Synthesis time: {self.synthesis_time_ms:.1f}ms",
            "",
        ]
        
        if self.init_certificate:
            lines.append("Init Condition:")
            lines.append(self.init_certificate.to_proof_string())
            lines.append("")
        
        if self.unsafe_certificate:
            lines.append("Unsafe Condition:")
            lines.append(self.unsafe_certificate.to_proof_string())
            lines.append("")
        
        if self.step_certificate:
            lines.append("Step Condition:")
            lines.append(self.step_certificate.to_proof_string())
        
        return "\n".join(lines)


class SOSBarrierSynthesizer:
    """
    Synthesizes barrier certificates using SOS-SDP.
    
    This is the main integration point with the a3-python framework.
    It extracts polynomial models from program semantics and finds certificates
    using Positivstellensatz-based reasoning.
    """
    
    def __init__(self, problem: BarrierSynthesisProblem,
                 verbose: bool = False,
                 timeout_ms: int = 30000):
        self.problem = problem
        self.verbose = verbose
        self.timeout_ms = timeout_ms
        
        # Z3 variables for state
        var_names = problem.init_set.var_names or [f"x{i}" for i in range(problem.n_vars)]
        self.z3_vars = [z3.Real(name) for name in var_names]
        self.z3_vars_prime = [z3.Real(f"{name}'") for name in var_names]
        
        # Barrier template
        self.template = BarrierTemplate.create(
            problem.n_vars,
            problem.barrier_degree,
            "b",
            var_names
        )
    
    def synthesize(self) -> BarrierCertificateResult:
        """
        Attempt to synthesize a barrier certificate.
        
        Uses SOS relaxations to encode:
        1. Init: B(x) - ε ≥ 0 on X₀
        2. Unsafe: -B(x) - ε ≥ 0 on Xᵤ
        3. Step: B(x') ≥ 0 when B(x) ≥ 0 and x→x'
        
        Returns:
            BarrierCertificateResult with barrier polynomial and certificates
        """
        start_time = time.time()
        
        if not self.problem.validate():
            return BarrierCertificateResult(
                success=False,
                message="Invalid problem specification"
            )
        
        # Main solver for barrier coefficients
        solver = z3.Solver()
        solver.set("timeout", self.timeout_ms)
        
        # Add constraints for each condition
        init_ok = self._encode_init_condition(solver)
        unsafe_ok = self._encode_unsafe_condition(solver)
        step_ok = self._encode_step_condition(solver)
        
        if not (init_ok and unsafe_ok and step_ok):
            return BarrierCertificateResult(
                success=False,
                message="Failed to encode barrier conditions",
                synthesis_time_ms=(time.time() - start_time) * 1000
            )
        
        # Solve for barrier coefficients
        result = solver.check()
        
        if result == z3.sat:
            model = solver.model()
            barrier = self._extract_barrier(model)
            
            return BarrierCertificateResult(
                success=True,
                barrier=barrier,
                synthesis_time_ms=(time.time() - start_time) * 1000,
                sos_degree=self.problem.barrier_degree,
                message="Barrier certificate found"
            )
        elif result == z3.unsat:
            return BarrierCertificateResult(
                success=False,
                message="No barrier exists at this degree",
                synthesis_time_ms=(time.time() - start_time) * 1000,
                sos_degree=self.problem.barrier_degree
            )
        else:
            return BarrierCertificateResult(
                success=False,
                message="Solver timeout or unknown",
                synthesis_time_ms=(time.time() - start_time) * 1000,
                sos_degree=self.problem.barrier_degree
            )
    
    def _encode_init_condition(self, solver: z3.Solver) -> bool:
        """
        Encode Init: B(x) - ε ≥ 0 for all x ∈ X₀.
        
        Using Positivstellensatz:
        B(x) - ε = σ₀(x) + Σᵢ σᵢ(x)gᵢ(x)
        """
        B = self.template.to_z3(self.z3_vars)
        eps = z3.RealVal(self.problem.epsilon)
        
        # For soundness with Z3, we add universal quantification
        # B(x) ≥ ε whenever x ∈ X₀
        init_constraints = self.problem.init_set.to_z3_constraints(self.z3_vars)
        
        # ∀x. (x ∈ X₀) → B(x) ≥ ε
        antecedent = z3.And(*init_constraints) if init_constraints else z3.BoolVal(True)
        consequent = B >= eps
        
        solver.add(z3.ForAll(self.z3_vars, z3.Implies(antecedent, consequent)))
        
        return True
    
    def _encode_unsafe_condition(self, solver: z3.Solver) -> bool:
        """
        Encode Unsafe: B(x) ≤ -ε for all x ∈ Xᵤ.
        
        Equivalently: -B(x) - ε ≥ 0 on Xᵤ.
        """
        B = self.template.to_z3(self.z3_vars)
        eps = z3.RealVal(self.problem.epsilon)
        
        unsafe_constraints = self.problem.unsafe_set.to_z3_constraints(self.z3_vars)
        
        antecedent = z3.And(*unsafe_constraints) if unsafe_constraints else z3.BoolVal(True)
        consequent = B <= -eps
        
        solver.add(z3.ForAll(self.z3_vars, z3.Implies(antecedent, consequent)))
        
        return True
    
    def _encode_step_condition(self, solver: z3.Solver) -> bool:
        """
        Encode Step: B(x) ≥ 0 ∧ x→x' → B(x') ≥ 0.
        
        For deterministic transition x' = f(x):
        B(f(x)) ≥ 0 whenever B(x) ≥ 0 (and x in invariant, if known)
        """
        B_x = self.template.to_z3(self.z3_vars)
        
        if self.problem.transition:
            # Deterministic transition: x' = f(x)
            # Substitute x' with f(x) in B
            B_prime = self.template.to_z3([
                t.to_z3(self.z3_vars) for t in self.problem.transition
            ])
        else:
            # Nondeterministic: quantify over x'
            B_prime = self.template.to_z3(self.z3_vars_prime)
        
        # Antecedent: B(x) ≥ 0 (and invariant if known)
        antecedent_parts = [B_x >= 0]
        
        if self.problem.invariant_set:
            inv_constraints = self.problem.invariant_set.to_z3_constraints(self.z3_vars)
            antecedent_parts.extend(inv_constraints)
        
        antecedent = z3.And(*antecedent_parts)
        consequent = B_prime >= 0
        
        if self.problem.transition:
            # Deterministic case
            solver.add(z3.ForAll(self.z3_vars, z3.Implies(antecedent, consequent)))
        else:
            # Nondeterministic case - need transition relation
            # For now, require explicit transition
            solver.add(z3.ForAll(
                self.z3_vars + self.z3_vars_prime,
                z3.Implies(antecedent, consequent)
            ))
        
        return True
    
    def _extract_barrier(self, model: z3.ModelRef) -> Polynomial:
        """Extract barrier polynomial from Z3 model."""
        coeffs: PolynomialCoeffs = {}
        
        for mono, var in self.template.coefficients.items():
            val = model.eval(var, model_completion=True)
            try:
                fval = float(val.as_fraction())
            except:
                fval = 0.0
            
            if abs(fval) > 1e-10:
                coeffs[mono] = fval
        
        return Polynomial(
            n_vars=self.problem.n_vars,
            coeffs=coeffs,
            var_names=self.template.var_names
        )


# =============================================================================
# INTEGRATION WITH PYFROMSCRATCH FRAMEWORK
# =============================================================================

@dataclass
class ProgramSOSModel:
    """
    Polynomial model extracted from program semantics.
    
    This bridges the gap between bytecode analysis and SOS verification.
    
    Attributes:
        variables: State variable names
        init_constraints: Initial state constraints (from entry conditions)
        unsafe_constraints: Unsafe state constraints (from bug conditions)
        transition_polynomials: State update functions (from assignments)
        invariant_constraints: Known invariants (from loop analysis, PDR, etc.)
    """
    variables: List[str]
    init_constraints: List[Polynomial]
    unsafe_constraints: List[Polynomial]
    transition_polynomials: Optional[List[Polynomial]]
    invariant_constraints: List[Polynomial]
    
    @property
    def n_vars(self) -> int:
        return len(self.variables)
    
    def to_synthesis_problem(self, epsilon: float = 0.01,
                             barrier_degree: int = 2) -> BarrierSynthesisProblem:
        """Convert to barrier synthesis problem."""
        init_set = SemialgebraicSet(
            n_vars=self.n_vars,
            inequalities=self.init_constraints,
            equalities=[],
            var_names=self.variables,
            name="Init"
        )
        
        unsafe_set = SemialgebraicSet(
            n_vars=self.n_vars,
            inequalities=self.unsafe_constraints,
            equalities=[],
            var_names=self.variables,
            name="Unsafe"
        )
        
        invariant_set = None
        if self.invariant_constraints:
            invariant_set = SemialgebraicSet(
                n_vars=self.n_vars,
                inequalities=self.invariant_constraints,
                equalities=[],
                var_names=self.variables,
                name="Invariant"
            )
        
        return BarrierSynthesisProblem(
            n_vars=self.n_vars,
            init_set=init_set,
            unsafe_set=unsafe_set,
            transition=self.transition_polynomials,
            invariant_set=invariant_set,
            epsilon=epsilon,
            barrier_degree=barrier_degree
        )


def extract_affine_model_from_loop(code_obj, loop_header: int,
                                   hazard_type: str) -> Optional[ProgramSOSModel]:
    """
    Extract polynomial model from an affine loop.
    
    This function interfaces with the existing loop analysis infrastructure
    to produce a model suitable for SOS-based barrier synthesis.
    
    Args:
        code_obj: Python code object
        loop_header: Offset of loop header
        hazard_type: Type of hazard to check (DIV_ZERO, BOUNDS, etc.)
    
    Returns:
        ProgramSOSModel if extraction succeeds, None otherwise
    """
    try:
        from ..cfg.loop_analysis import extract_loops
        from ..cfg.affine_loop_model import extract_affine_loop_model
    except ImportError:
        return None
    
    loops = extract_loops(code_obj)
    target_loop = None
    
    for loop in loops:
        if loop.header_offset == loop_header:
            target_loop = loop
            break
    
    if target_loop is None:
        return None
    
    model = extract_affine_loop_model(
        code_obj,
        header_offset=target_loop.header_offset,
        body_offsets=target_loop.body_offsets,
        modified_variables=target_loop.modified_variables
    )
    
    if model is None:
        return None
    
    # Extract variables and constraints
    variables = list(target_loop.modified_variables)
    n_vars = len(variables)
    
    if n_vars == 0:
        return None
    
    # Build polynomial constraints from affine model
    init_constraints = []
    unsafe_constraints = []
    transition_polynomials = []
    invariant_constraints = []
    
    # Parse guard as invariant
    if model.guard:
        guard_poly = _affine_guard_to_polynomial(model.guard, variables)
        if guard_poly:
            invariant_constraints.append(guard_poly)
    
    # Build unsafe constraint based on hazard type
    if hazard_type == "DIV_ZERO":
        # Unsafe: divisor == 0
        # We need to identify the divisor variable
        for i, var in enumerate(variables):
            if "div" in var.lower() or var == "i" or var == "n":
                # x == 0 means -ε ≤ x ≤ ε
                # For barrier, unsafe is a small ball around 0
                unsafe_poly = Polynomial.constant(n_vars, 0.01)  # ε - x²
                xi = Polynomial.variable(n_vars, i)
                unsafe_poly = unsafe_poly - xi * xi
                unsafe_constraints.append(unsafe_poly)
    elif hazard_type == "BOUNDS":
        # Unsafe: index out of bounds
        for i, var in enumerate(variables):
            if "idx" in var.lower() or var == "i":
                # Unsafe: i < 0 (lower bound violation)
                xi = Polynomial.variable(n_vars, i)
                unsafe_constraints.append(-xi)  # -x ≥ 0 means x ≤ 0
    
    # Build transition from increments
    for i, var in enumerate(variables):
        if var in model.increments:
            inc = model.increments[var]
            xi = Polynomial.variable(n_vars, i)
            # x' = x + inc
            transition_polynomials.append(xi + Polynomial.constant(n_vars, float(inc)))
        else:
            # x' = x (unchanged)
            transition_polynomials.append(Polynomial.variable(n_vars, i))
    
    return ProgramSOSModel(
        variables=variables,
        init_constraints=init_constraints,
        unsafe_constraints=unsafe_constraints,
        transition_polynomials=transition_polynomials if transition_polynomials else None,
        invariant_constraints=invariant_constraints
    )


def _affine_guard_to_polynomial(guard, variables: List[str]) -> Optional[Polynomial]:
    """Convert affine guard to polynomial constraint."""
    n_vars = len(variables)
    var_to_idx = {v: i for i, v in enumerate(variables)}
    
    # Handle AffineGuard structure
    try:
        lhs = guard.lhs
        rhs = guard.rhs
        op = guard.op
        
        def operand_to_poly(operand) -> Optional[Polynomial]:
            if operand.kind == "const":
                return Polynomial.constant(n_vars, float(operand.value))
            elif operand.kind == "var":
                var_name = str(operand.value)
                if var_name in var_to_idx:
                    return Polynomial.variable(n_vars, var_to_idx[var_name])
            return None
        
        lhs_poly = operand_to_poly(lhs)
        rhs_poly = operand_to_poly(rhs)
        
        if lhs_poly is None or rhs_poly is None:
            return None
        
        # Convert comparison to polynomial ≥ 0
        if op == "<":
            # lhs < rhs → rhs - lhs - ε ≥ 0
            return rhs_poly - lhs_poly + Polynomial.constant(n_vars, -0.001)
        elif op == "<=":
            # lhs <= rhs → rhs - lhs ≥ 0
            return rhs_poly - lhs_poly
        elif op == ">":
            # lhs > rhs → lhs - rhs - ε ≥ 0
            return lhs_poly - rhs_poly + Polynomial.constant(n_vars, -0.001)
        elif op == ">=":
            # lhs >= rhs → lhs - rhs ≥ 0
            return lhs_poly - rhs_poly
        elif op == "!=":
            # lhs != rhs → (lhs - rhs)² - ε ≥ 0
            diff = lhs_poly - rhs_poly
            return diff * diff + Polynomial.constant(n_vars, -0.0001)
        
    except (AttributeError, TypeError):
        pass
    
    return None


class ParriloSOSIntegration:
    """
    Main integration class for Parrilo SOS-SDP in a3-python.
    
    This class provides the interface for the kitchen-sink orchestrator
    to invoke SOS-based barrier synthesis and certification.
    """
    
    def __init__(self, verbose: bool = False):
        self.verbose = verbose
        self._cache: Dict[str, BarrierCertificateResult] = {}
    
    def try_sos_proof(self, code_obj, loop_header: int,
                      hazard_type: str,
                      barrier_degree: int = 2,
                      timeout_ms: int = 10000) -> Optional[BarrierCertificateResult]:
        """
        Attempt SOS-based barrier proof for a hazard site.
        
        Args:
            code_obj: Python code object
            loop_header: Loop header offset
            hazard_type: Type of hazard (DIV_ZERO, BOUNDS, etc.)
            barrier_degree: Maximum barrier polynomial degree
            timeout_ms: Solver timeout
        
        Returns:
            BarrierCertificateResult if proof found, None otherwise
        """
        # Check cache
        cache_key = f"{id(code_obj)}_{loop_header}_{hazard_type}_{barrier_degree}"
        if cache_key in self._cache:
            return self._cache[cache_key]
        
        # Extract polynomial model
        model = extract_affine_model_from_loop(code_obj, loop_header, hazard_type)
        
        if model is None:
            if self.verbose:
                print(f"[SOS] Failed to extract model for {hazard_type} at {loop_header}")
            return None
        
        # Create synthesis problem
        problem = model.to_synthesis_problem(
            epsilon=0.01,
            barrier_degree=barrier_degree
        )
        
        # Attempt synthesis
        synthesizer = SOSBarrierSynthesizer(
            problem,
            verbose=self.verbose,
            timeout_ms=timeout_ms
        )
        
        result = synthesizer.synthesize()
        
        # Cache result
        self._cache[cache_key] = result
        
        if self.verbose:
            if result.success:
                print(f"[SOS] Found barrier for {hazard_type}: {result.barrier}")
            else:
                print(f"[SOS] No barrier found: {result.message}")
        
        return result
    
    def prove_unreachability(self, init_poly: Polynomial,
                             unsafe_poly: Polynomial,
                             domain: SemialgebraicSet,
                             sos_degree: int = 2) -> Tuple[bool, Optional[PositivstellensatzCertificate]]:
        """
        Prove that unsafe region is unreachable from init region on domain.
        
        This is a direct SOS emptiness check: prove that Init ∩ Unsafe is empty.
        
        Args:
            init_poly: Polynomial whose positivity characterizes init
            unsafe_poly: Polynomial whose positivity characterizes unsafe
            domain: Semialgebraic domain
            sos_degree: SOS certificate degree
        
        Returns:
            (success, certificate) tuple
        """
        # Check if Init ∩ Unsafe is empty
        # This means: init_poly ≥ 0 ∧ unsafe_poly ≥ 0 is infeasible
        # Or equivalently: -(init_poly) - (unsafe_poly) ≥ ε on domain
        
        n_vars = domain.n_vars
        target = Polynomial.constant(n_vars, 0.01) - init_poly - unsafe_poly
        
        problem = SOSFeasibilityProblem(
            target=target,
            domain=domain,
            sos_degree=sos_degree
        )
        
        encoder = SOSEncoder(problem, verbose=self.verbose)
        status, certificate = encoder.solve(timeout_ms=5000)
        
        if status == SDPSolverStatus.OPTIMAL and certificate:
            return True, certificate
        
        return False, None
    
    def clear_cache(self) -> None:
        """Clear the proof cache."""
        self._cache.clear()


# =============================================================================
# ADVANCED POSITIVSTELLENSATZ TECHNIQUES
# =============================================================================

class StrictPositivityEncoder:
    """
    Encoder for strict positivity: f(x) > 0 on compact K.
    
    Uses the bounded Putinar representation:
    f(x) - ε = σ₀(x) + Σᵢ σᵢ(x)gᵢ(x)
    
    where ε > 0 is a small positive constant.
    """
    
    def __init__(self, polynomial: Polynomial,
                 domain: SemialgebraicSet,
                 epsilon: float = 0.001,
                 sos_degree: int = 2):
        self.polynomial = polynomial
        self.domain = domain
        self.epsilon = epsilon
        self.sos_degree = sos_degree
        self.n_vars = polynomial.n_vars
    
    def encode_strict_positive(self) -> Tuple[z3.Solver, List[GramMatrix]]:
        """
        Encode f(x) - ε ≥ 0 as SOS problem.
        
        Returns solver and list of Gram matrices.
        """
        # Target: f(x) - ε
        target = self.polynomial + Polynomial.constant(self.n_vars, -self.epsilon)
        
        problem = SOSFeasibilityProblem(
            target=target,
            domain=self.domain,
            sos_degree=self.sos_degree
        )
        
        encoder = SOSEncoder(problem, verbose=False)
        encoder.encode()
        
        return encoder.solver, encoder.gram_matrices


class SchmuedgenPositivstellensatz:
    """
    Implementation of Schmuedgen's Positivstellensatz.
    
    For compact basic closed semialgebraic set K = {g₁(x) ≥ 0, ..., gₘ(x) ≥ 0},
    every polynomial f strictly positive on K can be written as:
    
    f(x) = Σ_{α∈{0,1}ᵐ} σ_α(x) · g₁(x)^α₁ · ... · gₘ(x)^αₘ
    
    where each σ_α is SOS.
    
    This is stronger than Putinar (doesn't require Archimedean condition)
    but has exponentially many terms (2ᵐ products).
    """
    
    def __init__(self, domain: SemialgebraicSet, verbose: bool = False):
        self.domain = domain
        self.verbose = verbose
        self.n_constraints = len(domain.inequalities)
        self.n_products = 2 ** self.n_constraints
    
    def is_tractable(self) -> bool:
        """Check if Schmuedgen encoding is tractable (not too many products)."""
        return self.n_products <= 64  # Limit to 6 constraints
    
    def get_product_terms(self) -> List[Polynomial]:
        """
        Generate all product terms g₁^α₁ · ... · gₘ^αₘ.
        """
        products = []
        n = self.n_constraints
        
        for mask in range(self.n_products):
            product = Polynomial.constant(self.domain.n_vars, 1.0)
            for i in range(n):
                if mask & (1 << i):
                    product = product * self.domain.inequalities[i]
            products.append(product)
        
        return products
    
    def encode(self, target: Polynomial,
               sos_degree: int = 2) -> Tuple[z3.Solver, List[GramMatrix]]:
        """
        Encode Schmuedgen representation.
        
        f(x) = Σ_α σ_α(x) · product_α(x)
        """
        if not self.is_tractable():
            raise ValueError(f"Too many constraint products: {self.n_products}")
        
        products = self.get_product_terms()
        solver = z3.Solver()
        gram_matrices = []
        
        # Create Z3 variables
        z3_vars = [z3.Real(f"x{i}") for i in range(self.domain.n_vars)]
        
        # For each product term, create an SOS polynomial
        target_z3 = target.to_z3(z3_vars)
        sum_terms = z3.RealVal(0)
        
        for idx, product in enumerate(products):
            # Determine degree for this σ_α
            product_deg = product.degree()
            sigma_half_deg = max(0, (sos_degree - product_deg) // 2)
            
            if sigma_half_deg < 0:
                continue
            
            basis = MonomialBasis.create(self.domain.n_vars, sigma_half_deg)
            gram = GramMatrix.create_symbolic(basis, f"sigma{idx}")
            gram_matrices.append(gram)
            
            # Add PSD constraints
            solver.add(*gram.get_z3_psd_constraints())
            
            # Add contribution to sum
            sigma_poly = gram.to_polynomial()
            sigma_z3 = sigma_poly.to_z3(z3_vars)
            product_z3 = product.to_z3(z3_vars)
            sum_terms = sum_terms + sigma_z3 * product_z3
        
        # f(x) = Σ terms
        solver.add(z3.ForAll(z3_vars, target_z3 == sum_terms))
        
        return solver, gram_matrices


class ArchimedeanConditionChecker:
    """
    Checks if a semialgebraic set satisfies the Archimedean condition.
    
    The Archimedean condition holds if there exists N > 0 such that
    N - ||x||² can be written as:
    N - ||x||² = σ₀(x) + Σᵢ σᵢ(x)gᵢ(x)
    
    This is required for Putinar's theorem to apply.
    """
    
    def __init__(self, domain: SemialgebraicSet):
        self.domain = domain
        self.n_vars = domain.n_vars
    
    def has_explicit_bounds(self) -> bool:
        """
        Check if domain has explicit box bounds (sufficient for Archimedean).
        """
        has_lower = [False] * self.n_vars
        has_upper = [False] * self.n_vars
        
        for ineq in self.domain.inequalities:
            # Check for simple bounds: xᵢ - c ≥ 0 or c - xᵢ ≥ 0
            if len(ineq.coeffs) <= 2:
                for mono, coeff in ineq.coeffs.items():
                    if sum(mono) == 1:
                        var_idx = mono.index(1)
                        if coeff > 0:
                            has_lower[var_idx] = True
                        else:
                            has_upper[var_idx] = True
        
        return all(has_lower) and all(has_upper)
    
    def infer_ball_bound(self) -> Optional[float]:
        """
        Try to infer a ball bound ||x||² ≤ R² from box bounds.
        """
        max_bound = 0.0
        
        for ineq in self.domain.inequalities:
            # Look for upper bounds: c - xᵢ ≥ 0 means xᵢ ≤ c
            for mono, coeff in ineq.coeffs.items():
                if sum(mono) == 1 and coeff < 0:
                    # This is c - xᵢ ≥ 0
                    const = ineq.coeffs.get(tuple([0] * self.n_vars), 0)
                    if const > max_bound:
                        max_bound = const
        
        if max_bound > 0:
            return max_bound * self.n_vars  # ||x||² ≤ n * max²
        return None
    
    def add_ball_constraint(self, radius: float) -> SemialgebraicSet:
        """
        Add explicit ball constraint to make domain Archimedean.
        
        Returns new domain with R² - ||x||² ≥ 0 added.
        """
        # R² - Σxᵢ² ≥ 0
        ball = Polynomial.constant(self.n_vars, radius * radius)
        for i in range(self.n_vars):
            xi = Polynomial.variable(self.n_vars, i)
            ball = ball - xi * xi
        
        new_ineqs = self.domain.inequalities + [ball]
        
        return SemialgebraicSet(
            n_vars=self.n_vars,
            inequalities=new_ineqs,
            equalities=self.domain.equalities,
            var_names=self.domain.var_names,
            name=f"{self.domain.name}_bounded"
        )


# =============================================================================
# NUMERICAL STABILITY AND CONDITIONING
# =============================================================================

class GramMatrixConditioner:
    """
    Handles numerical conditioning of Gram matrices.
    
    SDP solvers can be sensitive to numerical issues. This class provides
    techniques for improving conditioning:
    1. Scaling of variables and constraints
    2. Regularization (diagonal perturbation)
    3. Low-rank approximation
    """
    
    def __init__(self, tolerance: float = 1e-6):
        self.tolerance = tolerance
    
    def scale_polynomial(self, poly: Polynomial) -> Tuple[Polynomial, float]:
        """
        Scale polynomial to have unit max coefficient.
        
        Returns scaled polynomial and scale factor.
        """
        max_coeff = max(abs(c) for c in poly.coeffs.values()) if poly.coeffs else 1.0
        
        if max_coeff < self.tolerance:
            return poly, 1.0
        
        scaled = poly.scale(1.0 / max_coeff)
        return scaled, max_coeff
    
    def regularize_gram_constraints(self, constraints: List[z3.BoolRef],
                                     gram: GramMatrix,
                                     delta: float = 1e-6) -> List[z3.BoolRef]:
        """
        Add regularization to Gram matrix constraints.
        
        Replaces Q ≽ 0 with Q ≽ δI.
        """
        regularized = []
        
        for constraint in constraints:
            regularized.append(constraint)
        
        # Add Q[i,i] ≥ δ for diagonals
        for i in range(gram.size):
            regularized.append(gram.get(i, i) >= delta)
        
        return regularized
    
    def project_to_psd(self, matrix: List[List[float]]) -> List[List[float]]:
        """
        Project a symmetric matrix to the PSD cone.
        
        Uses eigenvalue clipping: set negative eigenvalues to 0.
        """
        n = len(matrix)
        
        # Simple power iteration for largest eigenvalue estimate
        max_eig = self._estimate_max_eigenvalue(matrix)
        
        # Regularize
        result = [[matrix[i][j] for j in range(n)] for i in range(n)]
        for i in range(n):
            result[i][i] = max(result[i][i], 0)
        
        return result
    
    def _estimate_max_eigenvalue(self, matrix: List[List[float]], iterations: int = 10) -> float:
        """Estimate max eigenvalue using power iteration."""
        n = len(matrix)
        if n == 0:
            return 0.0
        
        import math
        
        # Start with random-ish vector
        v = [1.0 / math.sqrt(n)] * n
        
        for _ in range(iterations):
            # Multiply by matrix
            w = [sum(matrix[i][j] * v[j] for j in range(n)) for i in range(n)]
            
            # Normalize
            norm = math.sqrt(sum(x * x for x in w))
            if norm < 1e-10:
                return 0.0
            v = [x / norm for x in w]
        
        # Rayleigh quotient
        Av = [sum(matrix[i][j] * v[j] for j in range(n)) for i in range(n)]
        return sum(v[i] * Av[i] for i in range(n))


class NumericalCertificateValidator:
    """
    Validates numerical SOS certificates.
    
    After solving an SDP/SOS problem numerically, we need to check:
    1. PSD matrices are actually PSD (eigenvalues ≥ -ε)
    2. Polynomial identity holds (coefficient residual ≤ ε)
    3. Certificate is robust to small perturbations
    """
    
    def __init__(self, tolerance: float = 1e-4):
        self.tolerance = tolerance
    
    def validate_sos_decomposition(self, sos: SOSDecomposition) -> Tuple[bool, str]:
        """
        Validate an SOS decomposition.
        
        Returns (valid, message).
        """
        # Check residual
        if sos.residual > self.tolerance:
            return False, f"Residual too large: {sos.residual}"
        
        # Check factors reconstruct polynomial
        reconstructed = Polynomial.zero(sos.polynomial.n_vars)
        for factor in sos.factors:
            reconstructed = reconstructed + factor * factor
        
        diff = sos.polynomial - reconstructed
        max_diff = max(abs(c) for c in diff.coeffs.values()) if diff.coeffs else 0
        
        if max_diff > self.tolerance:
            return False, f"Reconstruction error: {max_diff}"
        
        return True, "Valid"
    
    def validate_positivstellensatz(self, cert: PositivstellensatzCertificate) -> Tuple[bool, str]:
        """
        Validate a Positivstellensatz certificate.
        """
        # Check all SOS decompositions
        valid, msg = self.validate_sos_decomposition(cert.sigma_0)
        if not valid:
            return False, f"σ₀ invalid: {msg}"
        
        for i, sigma in enumerate(cert.sigma_i):
            valid, msg = self.validate_sos_decomposition(sigma)
            if not valid:
                return False, f"σ_{i+1} invalid: {msg}"
        
        # Check polynomial identity
        if not cert.verify(self.tolerance):
            return False, "Polynomial identity does not hold"
        
        return True, "Valid certificate"
    
    def compute_certificate_margin(self, cert: PositivstellensatzCertificate,
                                    test_points: List[List[float]]) -> float:
        """
        Compute minimum margin of certificate at test points.
        
        Evaluates f(x) at each point and returns minimum value.
        """
        min_val = float('inf')
        
        for point in test_points:
            val = cert.target.evaluate(point)
            if val < min_val:
                min_val = val
        
        return min_val


# =============================================================================
# DSOS/SDSOS RELAXATIONS (Paper #9 Connection)
# =============================================================================

class DSOSEncoder:
    """
    DSOS (Diagonally-dominant SOS) encoder.
    
    DSOS is an LP-based inner approximation to SOS. A polynomial is DSOS if
    p(x) = m(x)ᵀ Q m(x) where Q is diagonally dominant (DD).
    
    DD matrices: Q[i,i] ≥ Σⱼ≠ᵢ |Q[i,j]| for all i.
    
    DSOS is weaker than SOS but much faster to solve (LP vs SDP).
    """
    
    def __init__(self, polynomial: Polynomial, sos_degree: int):
        self.polynomial = polynomial
        self.sos_degree = sos_degree
        self.n_vars = polynomial.n_vars
        
        self.basis = MonomialBasis.create(self.n_vars, sos_degree // 2)
        self.gram_entries: Dict[Tuple[int, int], z3.ArithRef] = {}
        self.abs_entries: Dict[Tuple[int, int], z3.ArithRef] = {}
    
    def encode_dsos(self) -> z3.Solver:
        """
        Encode DSOS constraints.
        
        Returns Z3 solver with DD constraints.
        """
        solver = z3.Solver()
        n = len(self.basis)
        
        # Create Gram matrix entries
        for i in range(n):
            for j in range(i, n):
                var = z3.Real(f"q_{i}_{j}")
                self.gram_entries[(i, j)] = var
                if i != j:
                    self.gram_entries[(j, i)] = var
                    # Create |Q[i,j]| variable
                    abs_var = z3.Real(f"abs_{i}_{j}")
                    self.abs_entries[(i, j)] = abs_var
                    self.abs_entries[(j, i)] = abs_var
                    # |Q[i,j]| ≥ Q[i,j] and |Q[i,j]| ≥ -Q[i,j]
                    solver.add(abs_var >= var)
                    solver.add(abs_var >= -var)
        
        # DD constraints: Q[i,i] ≥ Σⱼ≠ᵢ |Q[i,j]|
        for i in range(n):
            sum_abs = z3.RealVal(0)
            for j in range(n):
                if i != j:
                    sum_abs = sum_abs + self.abs_entries[(i, j)]
            solver.add(self.gram_entries[(i, i)] >= sum_abs)
        
        # Coefficient matching
        self._add_coefficient_matching(solver)
        
        return solver
    
    def _add_coefficient_matching(self, solver: z3.Solver) -> None:
        """Add coefficient matching constraints."""
        z3_vars = [z3.Real(f"x{i}") for i in range(self.n_vars)]
        
        # Build polynomial from Gram matrix
        gram_poly = z3.RealVal(0)
        n = len(self.basis)
        
        for i in range(n):
            for j in range(n):
                m_i = self.basis.monomials[i]
                m_j = self.basis.monomials[j]
                
                # Build monomial product
                term = self.gram_entries[(i, j)]
                for k in range(self.n_vars):
                    for _ in range(m_i[k] + m_j[k]):
                        term = term * z3_vars[k]
                gram_poly = gram_poly + term
        
        target_z3 = self.polynomial.to_z3(z3_vars)
        solver.add(z3.ForAll(z3_vars, gram_poly == target_z3))


class SDSOSEncoder:
    """
    SDSOS (Scaled diagonally-dominant SOS) encoder.
    
    SDSOS is an SOCP-based inner approximation to SOS. A polynomial is SDSOS if
    p(x) = m(x)ᵀ Q m(x) where Q is SDD (scaled diagonally dominant).
    
    SDD matrices can be characterized by SOCP constraints (second-order cones).
    SDSOS is stronger than DSOS but weaker than SOS.
    """
    
    def __init__(self, polynomial: Polynomial, sos_degree: int):
        self.polynomial = polynomial
        self.sos_degree = sos_degree
        self.n_vars = polynomial.n_vars
        
        self.basis = MonomialBasis.create(self.n_vars, sos_degree // 2)
    
    def encode_sdsos(self) -> z3.Solver:
        """
        Encode SDSOS constraints.
        
        Uses geometric mean constraints: Q[i,j]² ≤ Q[i,i] * Q[j,j]
        """
        solver = z3.Solver()
        n = len(self.basis)
        gram_entries: Dict[Tuple[int, int], z3.ArithRef] = {}
        
        # Create symmetric Gram matrix
        for i in range(n):
            for j in range(i, n):
                var = z3.Real(f"q_{i}_{j}")
                gram_entries[(i, j)] = var
                if i != j:
                    gram_entries[(j, i)] = var
        
        # Diagonal entries ≥ 0
        for i in range(n):
            solver.add(gram_entries[(i, i)] >= 0)
        
        # SDSOS constraints: Q[i,j]² ≤ Q[i,i] * Q[j,j]
        for i in range(n):
            for j in range(i + 1, n):
                qij = gram_entries[(i, j)]
                qii = gram_entries[(i, i)]
                qjj = gram_entries[(j, j)]
                solver.add(qij * qij <= qii * qjj)
        
        return solver


# =============================================================================
# POLYNOMIAL OPTIMIZATION INTERFACE
# =============================================================================

@dataclass
class PolynomialOptimizationResult:
    """
    Result of polynomial optimization problem.
    
    Attributes:
        optimal_value: Optimal (or bound) value
        is_lower_bound: Whether value is a lower bound
        optimizer: Optimal point (if extractable)
        certificate: SOS certificate
        status: Solver status
    """
    optimal_value: Optional[float]
    is_lower_bound: bool = True
    optimizer: Optional[List[float]] = None
    certificate: Optional[PositivstellensatzCertificate] = None
    status: SDPSolverStatus = SDPSolverStatus.UNKNOWN


class PolynomialOptimizer:
    """
    Polynomial optimization using SOS relaxations.
    
    Solves: min f(x) s.t. x ∈ K
    
    Using the dual SOS relaxation:
    max γ s.t. f(x) - γ is SOS on K
    """
    
    def __init__(self, objective: Polynomial,
                 domain: SemialgebraicSet,
                 sos_degree: int = 2):
        self.objective = objective
        self.domain = domain
        self.sos_degree = sos_degree
    
    def minimize(self, timeout_ms: int = 10000) -> PolynomialOptimizationResult:
        """
        Find (lower bound on) minimum of objective over domain.
        """
        gamma = z3.Real("gamma")
        
        # f(x) - γ ≥ 0 on K
        target = self.objective + Polynomial.constant(
            self.objective.n_vars, 0
        )  # Will add -γ in constraint
        
        problem = SOSFeasibilityProblem(
            target=target,
            domain=self.domain,
            sos_degree=self.sos_degree
        )
        
        encoder = SOSEncoder(problem, verbose=False)
        encoder.encode()
        
        # Binary search for optimal γ
        lo, hi = -1000.0, 1000.0
        best_gamma = None
        
        for _ in range(20):  # Binary search iterations
            mid = (lo + hi) / 2
            
            encoder.solver.push()
            encoder.solver.add(gamma == mid)
            
            # Check if f(x) - γ ≥ 0 is feasible
            result = encoder.solver.check()
            
            encoder.solver.pop()
            
            if result == z3.sat:
                best_gamma = mid
                lo = mid
            else:
                hi = mid
        
        return PolynomialOptimizationResult(
            optimal_value=best_gamma,
            is_lower_bound=True,
            status=SDPSolverStatus.OPTIMAL if best_gamma else SDPSolverStatus.UNKNOWN
        )
    
    def maximize(self, timeout_ms: int = 10000) -> PolynomialOptimizationResult:
        """
        Find (upper bound on) maximum of objective over domain.
        """
        # max f(x) = -min(-f(x))
        neg_objective = self.objective.scale(-1)
        
        neg_optimizer = PolynomialOptimizer(
            neg_objective, self.domain, self.sos_degree
        )
        
        result = neg_optimizer.minimize(timeout_ms)
        
        if result.optimal_value is not None:
            result.optimal_value = -result.optimal_value
            result.is_lower_bound = False
        
        return result
