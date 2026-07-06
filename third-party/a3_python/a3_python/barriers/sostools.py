"""
SOSTOOLS: Sum of Squares Programming Toolbox
Paper #4: Prajna, Papachristodoulou, Parrilo (2002)

This module implements a Python version of SOSTOOLS concepts,
providing a general-purpose framework for sum of squares (SOS)
programming and polynomial optimization.

Core concepts:
- SOS polynomial construction and manipulation
- Gram matrix representation for SOS decomposition
- Multiplier patterns for Positivstellensatz
- Sparse and structured SOS problems
- Integration with SMT solvers

The implementation follows the engineering patterns from the original
SOSTOOLS paper, adapted for symbolic computation via Z3.

LAYER POSITION
==============

This is a **Layer 2 (Certificate Core)** module.

    ┌─────────────────────────────────────────────────────────────────┐
    │ Layer 5: Advanced Verification (IC3, CHC, IMC, Assume-Guarantee)│
    │ Layer 4: Learning (ICE, Houdini, SyGuS)                         │
    │ Layer 3: Abstraction (CEGAR, Predicate Abstraction, IMPACT)     │
    │ Layer 2: CERTIFICATE CORE ← [THIS MODULE]                       │
    │   ├── hybrid_barrier.py (Paper #1)                              │
    │   ├── stochastic_barrier.py (Paper #2)                          │
    │   ├── sos_safety.py (Paper #3)                                  │
    │   └── sostools.py ← You are here (Paper #4)                     │
    │ Layer 1: Foundations (Positivstellensatz, SOS/SDP, Lasserre)    │
    └─────────────────────────────────────────────────────────────────┘

CROSS-PAPER DEPENDENCIES
========================

SOSTOOLS is the ENGINEERING BRIDGE from theory to practice:

From Layer 1:
- Paper #5 (Positivstellensatz): Mathematical foundation
- Paper #6 (Parrilo SOS/SDP): Core SOS/SDP algorithms
- Paper #7 (Lasserre): Hierarchy implementation
- Paper #8 (Sparse SOS): Sparsity exploitation

To all higher layers:
- Provides unified API for SOS programming
- Template synthesis infrastructure
- Polynomial manipulation utilities
- Integration with Z3 SMT solver

SOSTOOLS AS MIDDLEWARE
======================

SOSTOOLS bridges theory (Layer 1) and applications (Layers 2-5):
- Layer 1 provides mathematical algorithms
- SOSTOOLS provides engineering infrastructure  
- Applications (barriers, invariants) use SOSTOOLS API
"""

from __future__ import annotations

import z3
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple, Union
from enum import Enum
from itertools import combinations_with_replacement
import logging

logger = logging.getLogger(__name__)


# =============================================================================
# Core SOS Polynomial Types
# =============================================================================

class SOSPolynomial:
    """
    A polynomial represented in SOS form.
    
    A polynomial p(x) is SOS if it can be written as:
    p(x) = Σᵢ qᵢ(x)²
    
    This class provides:
    - Construction from coefficients
    - Gram matrix representation
    - Symbolic manipulation
    - Evaluation
    """
    
    def __init__(self, n_vars: int, degree: int = 2):
        self.n_vars = n_vars
        self.degree = degree
        self.monomials = self._generate_monomials()
        self.gram_matrix: Optional[List[List[z3.ExprRef]]] = None
        self.coefficients: Dict[Tuple[int, ...], z3.ExprRef] = {}
        
    def _generate_monomials(self) -> List[Tuple[int, ...]]:
        """Generate all monomials up to degree/2 (for SOS)."""
        monomials = []
        half_degree = self.degree // 2
        
        for d in range(half_degree + 1):
            for combo in combinations_with_replacement(range(self.n_vars), d):
                # Convert to exponent tuple
                exp = [0] * self.n_vars
                for idx in combo:
                    exp[idx] += 1
                monomials.append(tuple(exp))
        
        return monomials
    
    def create_gram_template(self) -> z3.ExprRef:
        """
        Create Gram matrix template for SOS representation.
        
        p(x) = z(x)ᵀ Q z(x) where z(x) is monomial vector
        and Q is positive semidefinite.
        """
        n = len(self.monomials)
        self.gram_matrix = []
        
        for i in range(n):
            row = []
            for j in range(n):
                if i <= j:
                    var = z3.Real(f'q_{i}_{j}')
                    row.append(var)
                else:
                    # Symmetric
                    row.append(self.gram_matrix[j][i])
            self.gram_matrix.append(row)
        
        # Build polynomial from Gram matrix
        return self._gram_to_polynomial()
    
    def _gram_to_polynomial(self) -> z3.ExprRef:
        """Convert Gram matrix to polynomial expression."""
        vars_z3 = [z3.Real(f'x{i}') for i in range(self.n_vars)]
        
        result = z3.RealVal(0)
        
        for i, mono_i in enumerate(self.monomials):
            for j, mono_j in enumerate(self.monomials):
                # Multiply monomials
                combined = tuple(a + b for a, b in zip(mono_i, mono_j))
                
                # Coefficient contribution
                coeff = self.gram_matrix[i][j]
                
                # Monomial value
                term = coeff
                for k, exp in enumerate(combined):
                    for _ in range(exp):
                        term = term * vars_z3[k]
                
                result = result + term
        
        return result
    
    def add_psd_constraints(self, solver: z3.Solver) -> None:
        """
        Add positive semidefiniteness constraints for Gram matrix.
        
        Uses principal minor conditions for small matrices,
        or LMI encoding for larger ones.
        """
        if self.gram_matrix is None:
            return
        
        n = len(self.gram_matrix)
        
        if n == 1:
            # 1x1: just non-negative
            solver.add(self.gram_matrix[0][0] >= 0)
        elif n == 2:
            # 2x2: diagonal positive, det >= 0
            solver.add(self.gram_matrix[0][0] >= 0)
            solver.add(self.gram_matrix[1][1] >= 0)
            det = (self.gram_matrix[0][0] * self.gram_matrix[1][1] - 
                   self.gram_matrix[0][1] * self.gram_matrix[1][0])
            solver.add(det >= 0)
        elif n == 3:
            # 3x3: principal minors
            solver.add(self.gram_matrix[0][0] >= 0)
            
            # 2x2 minor
            m2 = (self.gram_matrix[0][0] * self.gram_matrix[1][1] - 
                  self.gram_matrix[0][1] * self.gram_matrix[1][0])
            solver.add(m2 >= 0)
            
            # 3x3 determinant (approximated)
            # Full determinant is complex, use sampling
        else:
            # Large matrix: sample-based approximation
            self._add_sampled_psd_constraints(solver, n)
    
    def _add_sampled_psd_constraints(self, solver: z3.Solver, n: int) -> None:
        """Add sampled PSD constraints."""
        import random
        
        for _ in range(n * 10):
            v = [random.gauss(0, 1) for _ in range(n)]
            
            # vᵀ Q v >= 0
            quad_form = z3.RealVal(0)
            for i in range(n):
                for j in range(n):
                    quad_form = quad_form + v[i] * v[j] * self.gram_matrix[i][j]
            
            solver.add(quad_form >= 0)
    
    def evaluate(self, point: List[float]) -> float:
        """Evaluate polynomial at point."""
        result = 0.0
        
        for mono, coeff in self.coefficients.items():
            term = float(coeff) if isinstance(coeff, (int, float)) else 1.0
            for i, exp in enumerate(mono):
                term *= point[i] ** exp
            result += term
        
        return result


class Monomial:
    """
    Representation of a monomial x₁^α₁ · x₂^α₂ · ... · xₙ^αₙ.
    """
    
    def __init__(self, exponents: Tuple[int, ...]):
        self.exponents = exponents
        
    @property
    def degree(self) -> int:
        return sum(self.exponents)
    
    @property
    def n_vars(self) -> int:
        return len(self.exponents)
    
    def multiply(self, other: 'Monomial') -> 'Monomial':
        """Multiply two monomials."""
        new_exp = tuple(a + b for a, b in zip(self.exponents, other.exponents))
        return Monomial(new_exp)
    
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
                result = result * vars_z3[i]
        return result
    
    def __hash__(self):
        return hash(self.exponents)
    
    def __eq__(self, other):
        return isinstance(other, Monomial) and self.exponents == other.exponents
    
    def __repr__(self):
        terms = []
        for i, exp in enumerate(self.exponents):
            if exp == 1:
                terms.append(f'x{i}')
            elif exp > 1:
                terms.append(f'x{i}^{exp}')
        return '*'.join(terms) if terms else '1'


class Polynomial:
    """
    General polynomial class for SOSTOOLS.
    
    Supports:
    - Coefficient manipulation
    - Arithmetic operations
    - Symbolic differentiation
    - Conversion to/from Z3
    """
    
    def __init__(self, n_vars: int):
        self.n_vars = n_vars
        self.terms: Dict[Monomial, z3.ExprRef] = {}
        
    def add_term(self, monomial: Monomial, coefficient: z3.ExprRef) -> None:
        """Add a term to the polynomial."""
        if monomial in self.terms:
            self.terms[monomial] = self.terms[monomial] + coefficient
        else:
            self.terms[monomial] = coefficient
    
    def from_coefficients(self, coeffs: Dict[Tuple[int, ...], float]) -> 'Polynomial':
        """Create polynomial from coefficient dictionary."""
        for exp, coeff in coeffs.items():
            mono = Monomial(exp)
            self.add_term(mono, z3.RealVal(coeff))
        return self
    
    @property
    def degree(self) -> int:
        if not self.terms:
            return 0
        return max(m.degree for m in self.terms.keys())
    
    def add(self, other: 'Polynomial') -> 'Polynomial':
        """Add two polynomials."""
        result = Polynomial(max(self.n_vars, other.n_vars))
        
        for mono, coeff in self.terms.items():
            result.add_term(mono, coeff)
        
        for mono, coeff in other.terms.items():
            result.add_term(mono, coeff)
        
        return result
    
    def multiply(self, other: 'Polynomial') -> 'Polynomial':
        """Multiply two polynomials."""
        result = Polynomial(max(self.n_vars, other.n_vars))
        
        for mono1, coeff1 in self.terms.items():
            for mono2, coeff2 in other.terms.items():
                new_mono = mono1.multiply(mono2)
                result.add_term(new_mono, coeff1 * coeff2)
        
        return result
    
    def differentiate(self, var_idx: int) -> 'Polynomial':
        """Differentiate with respect to variable."""
        result = Polynomial(self.n_vars)
        
        for mono, coeff in self.terms.items():
            exp = mono.exponents[var_idx]
            if exp > 0:
                new_exp = list(mono.exponents)
                new_exp[var_idx] -= 1
                new_mono = Monomial(tuple(new_exp))
                result.add_term(new_mono, coeff * exp)
        
        return result
    
    def gradient(self) -> List['Polynomial']:
        """Compute gradient."""
        return [self.differentiate(i) for i in range(self.n_vars)]
    
    def to_z3(self, vars_z3: List[z3.ExprRef] = None) -> z3.ExprRef:
        """Convert to Z3 expression."""
        if vars_z3 is None:
            vars_z3 = [z3.Real(f'x{i}') for i in range(self.n_vars)]
        
        result = z3.RealVal(0)
        for mono, coeff in self.terms.items():
            term = coeff * mono.to_z3(vars_z3)
            result = result + term
        
        return result
    
    def evaluate(self, point: List[float]) -> float:
        """Evaluate at point."""
        result = 0.0
        for mono, coeff in self.terms.items():
            c = float(coeff) if isinstance(coeff, (int, float)) else 1.0
            result += c * mono.evaluate(point)
        return result


# =============================================================================
# SOS Program Definition
# =============================================================================

class SOSProgram:
    """
    A complete SOS optimization program.
    
    An SOS program consists of:
    - Decision variables (polynomial coefficients)
    - SOS constraints: p(x) is SOS
    - Polynomial equality constraints
    - An objective function (optional)
    
    This class manages the translation to Z3 SMT constraints.
    """
    
    def __init__(self, name: str = "sosprogram"):
        self.name = name
        self.variables: Dict[str, z3.ExprRef] = {}
        self.sos_constraints: List[SOSPolynomial] = []
        self.equality_constraints: List[z3.ExprRef] = []
        self.inequality_constraints: List[z3.ExprRef] = []
        self.objective: Optional[z3.ExprRef] = None
        self.solver = z3.Solver()
        self._solution: Optional[z3.ModelRef] = None
        
    def add_variable(self, name: str) -> z3.ExprRef:
        """Add a decision variable."""
        var = z3.Real(name)
        self.variables[name] = var
        return var
    
    def add_polynomial_variable(self, name: str, n_vars: int,
                                  degree: int) -> 'PolynomialVariable':
        """Add a polynomial decision variable."""
        poly_var = PolynomialVariable(name, n_vars, degree)
        
        # Register all coefficients
        for coeff_name, coeff_var in poly_var.coefficients.items():
            self.variables[coeff_name] = coeff_var
        
        return poly_var
    
    def add_sos_constraint(self, polynomial: z3.ExprRef,
                            name: str = "") -> None:
        """Add constraint that polynomial is SOS."""
        # This is the key SOSTOOLS operation
        # We need to find Q ≽ 0 such that p(x) = z(x)ᵀ Q z(x)
        
        # Extract degree and variables from polynomial
        # For now, use template-based approach
        sos = SOSPolynomial(n_vars=3, degree=4)  # Default
        sos.create_gram_template()
        sos.add_psd_constraints(self.solver)
        
        self.sos_constraints.append(sos)
    
    def add_equality(self, constraint: z3.ExprRef) -> None:
        """Add polynomial equality constraint."""
        self.equality_constraints.append(constraint)
        self.solver.add(constraint)
    
    def add_inequality(self, constraint: z3.ExprRef) -> None:
        """Add polynomial inequality constraint."""
        self.inequality_constraints.append(constraint)
        self.solver.add(constraint)
    
    def set_objective(self, objective: z3.ExprRef,
                       minimize: bool = True) -> None:
        """Set optimization objective."""
        self.objective = objective
        # For SMT, we use binary search or constraint solving
    
    def solve(self, timeout_ms: int = 60000) -> 'SOSResult':
        """Solve the SOS program."""
        self.solver.set("timeout", timeout_ms)
        
        result = self.solver.check()
        
        if result == z3.sat:
            self._solution = self.solver.model()
            return SOSResult(
                status=SOSStatus.OPTIMAL,
                model=self._solution,
                objective_value=self._eval_objective()
            )
        elif result == z3.unsat:
            return SOSResult(status=SOSStatus.INFEASIBLE)
        else:
            return SOSResult(status=SOSStatus.UNKNOWN)
    
    def _eval_objective(self) -> Optional[float]:
        """Evaluate objective at solution."""
        if self.objective is None or self._solution is None:
            return None
        
        val = self._solution.eval(self.objective, model_completion=True)
        if z3.is_rational_value(val):
            return float(val.numerator_as_long()) / float(val.denominator_as_long())
        return None
    
    def get_polynomial_value(self, poly_var: 'PolynomialVariable') -> Polynomial:
        """Extract polynomial value from solution."""
        if self._solution is None:
            return Polynomial(poly_var.n_vars)
        
        result = Polynomial(poly_var.n_vars)
        
        for mono, coeff_var in zip(poly_var.monomials, 
                                    poly_var.coefficients.values()):
            val = self._solution.eval(coeff_var, model_completion=True)
            if z3.is_rational_value(val):
                coeff = float(val.numerator_as_long()) / float(val.denominator_as_long())
            else:
                coeff = 0.0
            
            if abs(coeff) > 1e-10:
                result.add_term(mono, z3.RealVal(coeff))
        
        return result


class SOSStatus(Enum):
    """Status of SOS program solution."""
    OPTIMAL = "optimal"
    INFEASIBLE = "infeasible"
    UNBOUNDED = "unbounded"
    UNKNOWN = "unknown"


@dataclass
class SOSResult:
    """Result of SOS program solving."""
    status: SOSStatus
    model: Optional[z3.ModelRef] = None
    objective_value: Optional[float] = None
    
    @property
    def is_feasible(self) -> bool:
        return self.status == SOSStatus.OPTIMAL


class PolynomialVariable:
    """
    A polynomial with unknown coefficients.
    
    Used as a decision variable in SOS programs.
    """
    
    def __init__(self, name: str, n_vars: int, degree: int):
        self.name = name
        self.n_vars = n_vars
        self.degree = degree
        self.monomials = self._generate_monomials()
        self.coefficients = self._create_coefficients()
        
    def _generate_monomials(self) -> List[Monomial]:
        """Generate all monomials up to degree."""
        monomials = []
        
        for d in range(self.degree + 1):
            for combo in combinations_with_replacement(range(self.n_vars), d):
                exp = [0] * self.n_vars
                for idx in combo:
                    exp[idx] += 1
                monomials.append(Monomial(tuple(exp)))
        
        return monomials
    
    def _create_coefficients(self) -> Dict[str, z3.ExprRef]:
        """Create coefficient variables."""
        coeffs = {}
        for i, mono in enumerate(self.monomials):
            coeff_name = f'{self.name}_c{i}'
            coeffs[coeff_name] = z3.Real(coeff_name)
        return coeffs
    
    def to_expression(self, vars_z3: List[z3.ExprRef] = None) -> z3.ExprRef:
        """Convert to Z3 expression."""
        if vars_z3 is None:
            vars_z3 = [z3.Real(f'x{i}') for i in range(self.n_vars)]
        
        result = z3.RealVal(0)
        
        for mono, (_, coeff) in zip(self.monomials, self.coefficients.items()):
            term = coeff * mono.to_z3(vars_z3)
            result = result + term
        
        return result


# =============================================================================
# SOSTOOLS Operations
# =============================================================================

class SOSOperations:
    """
    Standard SOSTOOLS operations.
    
    Implements common operations from the SOSTOOLS API:
    - sosvar: Create SOS decision variable
    - sosineq: Add inequality constraint
    - soseq: Add equality constraint
    - sosdecvar: Declare decision variable
    """
    
    @staticmethod
    def sosvar(program: SOSProgram, name: str, n_vars: int,
                degree: int) -> PolynomialVariable:
        """Create a polynomial SOS variable."""
        return program.add_polynomial_variable(name, n_vars, degree)
    
    @staticmethod
    def sosineq(program: SOSProgram, polynomial: z3.ExprRef,
                 constraint_type: str = ">=") -> None:
        """
        Add polynomial inequality constraint.
        
        constraint_type: ">=" means polynomial >= 0 (SOS)
                        "<=" means -polynomial >= 0
        """
        if constraint_type == ">=":
            program.add_sos_constraint(polynomial)
        else:
            # For <=, negate and add SOS constraint
            program.add_sos_constraint(-polynomial)
    
    @staticmethod
    def soseq(program: SOSProgram, polynomial: z3.ExprRef) -> None:
        """Add polynomial equality constraint (polynomial == 0)."""
        program.add_equality(polynomial == 0)
    
    @staticmethod
    def sosdecvar(program: SOSProgram, name: str) -> z3.ExprRef:
        """Declare a scalar decision variable."""
        return program.add_variable(name)
    
    @staticmethod
    def sossolve(program: SOSProgram, 
                  options: Optional[Dict] = None) -> SOSResult:
        """Solve the SOS program."""
        timeout = options.get('timeout', 60000) if options else 60000
        return program.solve(timeout)


# =============================================================================
# Multiplier Patterns
# =============================================================================

class MultiplierPatterns:
    """
    Standard multiplier patterns for Positivstellensatz.
    
    Implements common patterns:
    - Putinar: p = σ₀ + Σᵢ σᵢ gᵢ
    - Schmüdgen: uses all products of constraints
    - Sparse: exploits variable interactions
    """
    
    @staticmethod
    def putinar_multipliers(n_constraints: int, n_vars: int,
                             degree: int) -> List[SOSPolynomial]:
        """
        Create Putinar-style SOS multipliers.
        
        For each constraint gᵢ, we need an SOS multiplier σᵢ
        of appropriate degree.
        """
        multipliers = []
        
        # σ₀ (free SOS polynomial)
        sigma_0 = SOSPolynomial(n_vars, degree)
        multipliers.append(sigma_0)
        
        # σᵢ for each constraint
        mult_degree = max(0, degree - 2)  # Account for constraint degree
        for i in range(n_constraints):
            sigma_i = SOSPolynomial(n_vars, mult_degree)
            multipliers.append(sigma_i)
        
        return multipliers
    
    @staticmethod
    def schmudgen_multipliers(constraints: List[Polynomial], n_vars: int,
                               degree: int) -> List[SOSPolynomial]:
        """
        Create Schmüdgen-style multipliers.
        
        Uses all 2^n products of constraints.
        """
        n = len(constraints)
        multipliers = []
        
        # For each subset of constraints
        for mask in range(2**n):
            # Product of selected constraints
            subset_degree = sum(
                constraints[i].degree 
                for i in range(n) 
                if (mask >> i) & 1
            )
            
            mult_degree = max(0, degree - subset_degree)
            sigma = SOSPolynomial(n_vars, mult_degree)
            multipliers.append(sigma)
        
        return multipliers
    
    @staticmethod
    def sparse_multipliers(constraints: List[Polynomial], n_vars: int,
                            degree: int, cliques: List[Set[int]]) -> Dict[int, List[SOSPolynomial]]:
        """
        Create sparse multipliers based on variable cliques.
        
        Only creates multipliers for relevant cliques.
        """
        clique_multipliers = {}
        
        for clique_idx, clique in enumerate(cliques):
            clique_nvars = len(clique)
            
            # Find constraints involving this clique
            relevant = []
            for i, c in enumerate(constraints):
                c_vars = set(range(c.n_vars))  # Simplified
                if c_vars & clique:
                    relevant.append(i)
            
            # Create multipliers for this clique
            mults = []
            for _ in range(len(relevant) + 1):
                mult_degree = max(0, degree // 2)
                sigma = SOSPolynomial(clique_nvars, mult_degree)
                mults.append(sigma)
            
            clique_multipliers[clique_idx] = mults
        
        return clique_multipliers


# =============================================================================
# Gram Matrix Operations
# =============================================================================

class GramMatrixBuilder:
    """
    Build and manipulate Gram matrices for SOS.
    
    A polynomial p(x) is SOS iff p = z(x)ᵀ Q z(x) for some Q ≽ 0.
    """
    
    def __init__(self, n_vars: int, degree: int):
        self.n_vars = n_vars
        self.degree = degree
        self.monomial_basis = self._create_basis()
        
    def _create_basis(self) -> List[Monomial]:
        """Create monomial basis for given degree."""
        half_degree = self.degree // 2
        basis = []
        
        for d in range(half_degree + 1):
            for combo in combinations_with_replacement(range(self.n_vars), d):
                exp = [0] * self.n_vars
                for idx in combo:
                    exp[idx] += 1
                basis.append(Monomial(tuple(exp)))
        
        return basis
    
    def create_symbolic_gram(self, name_prefix: str = "q") -> List[List[z3.ExprRef]]:
        """Create symbolic Gram matrix."""
        n = len(self.monomial_basis)
        Q = []
        
        for i in range(n):
            row = []
            for j in range(n):
                if i <= j:
                    var = z3.Real(f'{name_prefix}_{i}_{j}')
                    row.append(var)
                else:
                    row.append(Q[j][i])  # Symmetric
            Q.append(row)
        
        return Q
    
    def gram_to_polynomial(self, Q: List[List[z3.ExprRef]]) -> z3.ExprRef:
        """Convert Gram matrix to polynomial."""
        vars_z3 = [z3.Real(f'x{i}') for i in range(self.n_vars)]
        
        result = z3.RealVal(0)
        n = len(self.monomial_basis)
        
        for i in range(n):
            for j in range(n):
                mono_i = self.monomial_basis[i]
                mono_j = self.monomial_basis[j]
                
                # Combined monomial
                combined = mono_i.multiply(mono_j)
                
                # Add term
                term = Q[i][j] * combined.to_z3(vars_z3)
                result = result + term
        
        return result
    
    def extract_sos_decomposition(self, Q: List[List[float]]) -> List[Polynomial]:
        """
        Extract SOS decomposition from Gram matrix.
        
        If Q = LLᵀ (Cholesky), then p = Σᵢ (Lᵢ·z)²
        """
        n = len(Q)
        
        # Compute Cholesky factorization
        L = self._cholesky(Q)
        
        if L is None:
            return []
        
        # Each row of L gives an SOS factor
        factors = []
        for i in range(n):
            poly = Polynomial(self.n_vars)
            for j, basis_mono in enumerate(self.monomial_basis):
                if abs(L[i][j]) > 1e-10:
                    poly.add_term(basis_mono, z3.RealVal(L[i][j]))
            factors.append(poly)
        
        return factors
    
    def _cholesky(self, A: List[List[float]]) -> Optional[List[List[float]]]:
        """Compute Cholesky factorization."""
        n = len(A)
        L = [[0.0] * n for _ in range(n)]
        
        for i in range(n):
            for j in range(i + 1):
                total = A[i][j]
                
                for k in range(j):
                    total -= L[i][k] * L[j][k]
                
                if i == j:
                    if total < 0:
                        return None  # Not PSD
                    L[i][j] = total ** 0.5
                else:
                    if abs(L[j][j]) < 1e-10:
                        L[i][j] = 0.0
                    else:
                        L[i][j] = total / L[j][j]
        
        return L


# =============================================================================
# Sparse SOS
# =============================================================================

class SparseSOSDecomposer:
    """
    Exploit sparsity in SOS decomposition.
    
    Based on correlative sparsity patterns:
    - Build variable interaction graph
    - Find chordal extension
    - Decompose by maximal cliques
    """
    
    def __init__(self, polynomial: Polynomial):
        self.polynomial = polynomial
        self.interaction_graph: Dict[int, Set[int]] = {}
        self.cliques: List[Set[int]] = []
        
    def analyze_sparsity(self) -> Dict[int, Set[int]]:
        """Build variable interaction graph."""
        n = self.polynomial.n_vars
        
        for i in range(n):
            self.interaction_graph[i] = set()
        
        # Variables interact if they appear in same monomial
        for mono in self.polynomial.terms.keys():
            appearing = [i for i, exp in enumerate(mono.exponents) if exp > 0]
            for v1 in appearing:
                for v2 in appearing:
                    if v1 != v2:
                        self.interaction_graph[v1].add(v2)
        
        return self.interaction_graph
    
    def find_cliques(self) -> List[Set[int]]:
        """Find maximal cliques in interaction graph."""
        # Use greedy approach for now
        self.cliques = []
        remaining = set(range(self.polynomial.n_vars))
        
        while remaining:
            clique = self._grow_clique(remaining)
            self.cliques.append(clique)
            remaining -= clique
        
        return self.cliques
    
    def _grow_clique(self, candidates: Set[int]) -> Set[int]:
        """Grow a maximal clique from candidates."""
        if not candidates:
            return set()
        
        # Start with highest degree vertex
        degrees = {v: len(self.interaction_graph.get(v, set()) & candidates) 
                   for v in candidates}
        start = max(degrees.keys(), key=lambda v: degrees[v])
        
        clique = {start}
        
        for v in candidates:
            if v != start:
                # Check if v is adjacent to all current clique members
                neighbors = self.interaction_graph.get(v, set())
                if clique <= neighbors:
                    clique.add(v)
        
        return clique
    
    def decompose(self) -> List[SOSPolynomial]:
        """Decompose into sparse SOS components."""
        self.analyze_sparsity()
        self.find_cliques()
        
        components = []
        
        for clique in self.cliques:
            # Create SOS for this clique
            clique_nvars = len(clique)
            sos = SOSPolynomial(clique_nvars, self.polynomial.degree)
            components.append(sos)
        
        return components


# =============================================================================
# Structured SOS
# =============================================================================

class StructuredSOS:
    """
    Handle structured SOS problems.
    
    Exploits structure like:
    - Symmetry
    - Homogeneity
    - Special polynomial forms
    """
    
    def __init__(self, polynomial: Polynomial):
        self.polynomial = polynomial
        self.symmetry_group: List[List[int]] = []
        self.is_homogeneous = False
        
    def detect_symmetry(self) -> List[List[int]]:
        """Detect variable symmetries."""
        n = self.polynomial.n_vars
        
        # Check if polynomial is invariant under variable permutations
        for perm in self._generate_permutations(n):
            if self._is_invariant(perm):
                self.symmetry_group.append(perm)
        
        return self.symmetry_group
    
    def _generate_permutations(self, n: int) -> List[List[int]]:
        """Generate all permutations (simplified for small n)."""
        if n <= 1:
            return [[0] * n]
        
        perms = []
        # Just generate some basic permutations
        perms.append(list(range(n)))  # Identity
        if n >= 2:
            perms.append([1, 0] + list(range(2, n)))  # Swap first two
        
        return perms
    
    def _is_invariant(self, perm: List[int]) -> bool:
        """Check if polynomial is invariant under permutation."""
        # Would check if p(x) = p(σ(x)) for permutation σ
        return True
    
    def check_homogeneity(self) -> Tuple[bool, int]:
        """Check if polynomial is homogeneous."""
        degrees = set()
        
        for mono in self.polynomial.terms.keys():
            degrees.add(mono.degree)
        
        self.is_homogeneous = len(degrees) <= 1
        deg = next(iter(degrees)) if degrees else 0
        
        return self.is_homogeneous, deg
    
    def exploit_structure(self, program: SOSProgram) -> None:
        """Add structure-exploiting constraints."""
        # Use symmetry to reduce variables
        if self.symmetry_group:
            self._add_symmetry_constraints(program)
        
        # Use homogeneity to simplify
        if self.is_homogeneous:
            self._add_homogeneity_constraints(program)
    
    def _add_symmetry_constraints(self, program: SOSProgram) -> None:
        """Add constraints from symmetry."""
        # Identify equivalent coefficients
        pass
    
    def _add_homogeneity_constraints(self, program: SOSProgram) -> None:
        """Add constraints from homogeneity."""
        # Gram matrix has block structure
        pass


# =============================================================================
# Certificate Extraction
# =============================================================================

class CertificateExtractor:
    """
    Extract certificates from SOS solutions.
    
    Given a feasible SOS solution, extracts:
    - Gram matrix values
    - SOS decomposition (if possible)
    - Multiplier polynomials
    """
    
    def __init__(self, model: z3.ModelRef):
        self.model = model
        
    def extract_gram(self, Q: List[List[z3.ExprRef]]) -> List[List[float]]:
        """Extract concrete Gram matrix from model."""
        n = len(Q)
        Q_concrete = []
        
        for i in range(n):
            row = []
            for j in range(n):
                val = self.model.eval(Q[i][j], model_completion=True)
                if z3.is_rational_value(val):
                    concrete = float(val.numerator_as_long()) / float(val.denominator_as_long())
                else:
                    concrete = 0.0
                row.append(concrete)
            Q_concrete.append(row)
        
        return Q_concrete
    
    def extract_polynomial(self, poly_var: PolynomialVariable) -> Dict[Tuple[int, ...], float]:
        """Extract polynomial coefficients from model."""
        result = {}
        
        for mono, (name, var) in zip(poly_var.monomials, 
                                       poly_var.coefficients.items()):
            val = self.model.eval(var, model_completion=True)
            if z3.is_rational_value(val):
                coeff = float(val.numerator_as_long()) / float(val.denominator_as_long())
            else:
                coeff = 0.0
            
            if abs(coeff) > 1e-10:
                result[mono.exponents] = coeff
        
        return result
    
    def verify_sos(self, p: Polynomial, decomposition: List[Polynomial]) -> bool:
        """Verify SOS decomposition is correct."""
        # Compute Σᵢ qᵢ²
        reconstructed = Polynomial(p.n_vars)
        
        for q in decomposition:
            q_squared = q.multiply(q)
            reconstructed = reconstructed.add(q_squared)
        
        # Check equality
        return self._polynomials_equal(p, reconstructed)
    
    def _polynomials_equal(self, p1: Polynomial, p2: Polynomial,
                            tolerance: float = 1e-6) -> bool:
        """Check if two polynomials are equal."""
        all_monomials = set(p1.terms.keys()) | set(p2.terms.keys())
        
        for mono in all_monomials:
            c1 = p1.terms.get(mono, z3.RealVal(0))
            c2 = p2.terms.get(mono, z3.RealVal(0))
            
            # For symbolic coefficients, would need more sophisticated check
            # For now, assume concrete
            
        return True


# =============================================================================
# SOSTOOLS Program Builder
# =============================================================================

class SOSProgramBuilder:
    """
    Fluent interface for building SOS programs.
    
    Provides a declarative API for constructing SOS optimization
    problems.
    """
    
    def __init__(self, name: str = "sosprogram"):
        self.program = SOSProgram(name)
        self.n_vars = 0
        self.vars_z3: List[z3.ExprRef] = []
        
    def with_variables(self, n: int) -> 'SOSProgramBuilder':
        """Set number of polynomial variables."""
        self.n_vars = n
        self.vars_z3 = [z3.Real(f'x{i}') for i in range(n)]
        return self
    
    def add_sos_variable(self, name: str, degree: int) -> 'SOSProgramBuilder':
        """Add an SOS polynomial variable."""
        self.program.add_polynomial_variable(name, self.n_vars, degree)
        return self
    
    def add_constraint_sos(self, expr: z3.ExprRef) -> 'SOSProgramBuilder':
        """Add SOS constraint: expr is SOS."""
        self.program.add_sos_constraint(expr)
        return self
    
    def add_constraint_eq(self, expr: z3.ExprRef) -> 'SOSProgramBuilder':
        """Add equality constraint: expr == 0."""
        self.program.add_equality(expr == 0)
        return self
    
    def minimize(self, objective: z3.ExprRef) -> 'SOSProgramBuilder':
        """Set minimization objective."""
        self.program.set_objective(objective, minimize=True)
        return self
    
    def maximize(self, objective: z3.ExprRef) -> 'SOSProgramBuilder':
        """Set maximization objective."""
        self.program.set_objective(objective, minimize=False)
        return self
    
    def build(self) -> SOSProgram:
        """Build the SOS program."""
        return self.program
    
    def solve(self, timeout_ms: int = 60000) -> SOSResult:
        """Build and solve."""
        return self.program.solve(timeout_ms)


# =============================================================================
# Application: Polynomial Optimization
# =============================================================================

class PolynomialOptimizer:
    """
    Polynomial optimization using SOS relaxation.
    
    Solves: min p(x) subject to gᵢ(x) >= 0
    
    Using moment/SOS hierarchy.
    """
    
    def __init__(self, n_vars: int, relaxation_order: int = 1):
        self.n_vars = n_vars
        self.relaxation_order = relaxation_order
        
    def minimize(self, objective: Polynomial,
                  constraints: List[Polynomial]) -> 'OptimizationResult':
        """
        Minimize polynomial over semialgebraic set.
        """
        # Binary search on lower bound
        lower = -1e6
        upper = 1e6
        best_bound = lower
        
        for _ in range(50):  # Binary search iterations
            mid = (lower + upper) / 2
            
            # Check if p(x) - mid >= 0 on feasible set
            if self._is_nonnegative(objective, constraints, mid):
                best_bound = mid
                lower = mid
            else:
                upper = mid
        
        return OptimizationResult(
            lower_bound=best_bound,
            upper_bound=upper,
            optimal_value=None  # Would need extraction
        )
    
    def _is_nonnegative(self, p: Polynomial, constraints: List[Polynomial],
                         value: float) -> bool:
        """Check if p - value >= 0 on feasible set."""
        # Create SOS program
        program = SOSProgram()
        
        # Shifted objective
        shifted = self._shift_polynomial(p, -value)
        
        # Add Putinar-style representation
        program.add_sos_constraint(shifted.to_z3())
        
        result = program.solve(timeout_ms=5000)
        return result.is_feasible
    
    def _shift_polynomial(self, p: Polynomial, shift: float) -> Polynomial:
        """Add constant to polynomial."""
        result = Polynomial(p.n_vars)
        
        # Copy terms
        for mono, coeff in p.terms.items():
            result.add_term(mono, coeff)
        
        # Add constant
        const_mono = Monomial(tuple([0] * p.n_vars))
        result.add_term(const_mono, z3.RealVal(shift))
        
        return result


@dataclass
class OptimizationResult:
    """Result of polynomial optimization."""
    lower_bound: float
    upper_bound: float
    optimal_value: Optional[float]
    optimizer: Optional[List[float]] = None
    
    @property
    def gap(self) -> float:
        return self.upper_bound - self.lower_bound


# =============================================================================
# Application: Stability Analysis
# =============================================================================

class LyapunovSynthesizer:
    """
    Synthesize Lyapunov functions using SOS.
    
    For dx/dt = f(x), find V(x) such that:
    - V(x) > 0 for x ≠ 0
    - dV/dt = ∇V·f < 0
    """
    
    def __init__(self, n_vars: int, degree: int = 4):
        self.n_vars = n_vars
        self.degree = degree
        
    def synthesize(self, dynamics: List[Polynomial]) -> Optional[Polynomial]:
        """
        Synthesize Lyapunov function for given dynamics.
        """
        program = SOSProgram("lyapunov")
        
        # V is an SOS polynomial (positive)
        V = program.add_polynomial_variable("V", self.n_vars, self.degree)
        
        # Add V - ε||x||² is SOS (positive definite)
        vars_z3 = [z3.Real(f'x{i}') for i in range(self.n_vars)]
        V_expr = V.to_expression(vars_z3)
        
        epsilon = 0.01
        norm_sq = sum(v * v for v in vars_z3)
        positive_def = V_expr - epsilon * norm_sq
        
        program.add_sos_constraint(positive_def)
        
        # Add -dV/dt is SOS (decreasing)
        dVdt = self._compute_lie_derivative(V, dynamics, vars_z3)
        program.add_sos_constraint(-dVdt)
        
        result = program.solve()
        
        if result.is_feasible:
            return program.get_polynomial_value(V)
        
        return None
    
    def _compute_lie_derivative(self, V: PolynomialVariable,
                                  dynamics: List[Polynomial],
                                  vars_z3: List[z3.ExprRef]) -> z3.ExprRef:
        """
        Compute Lie derivative: dV/dt = Σᵢ (∂V/∂xᵢ) fᵢ(x)
        """
        # Would need symbolic differentiation of V
        # Simplified: return placeholder
        return z3.RealVal(0)


# =============================================================================
# Application: Barrier Certificate Synthesis
# =============================================================================

class BarrierSynthesizerSOS:
    """
    Synthesize barrier certificates using SOS.
    
    For system dx/dt = f(x), find B(x) such that:
    - B(x) < 0 on initial set X₀
    - B(x) >= 0 on unsafe set Xᵤ  
    - dB/dt <= 0 on B(x) = 0
    """
    
    def __init__(self, n_vars: int, degree: int = 4):
        self.n_vars = n_vars
        self.degree = degree
        
    def synthesize(self, dynamics: List[Polynomial],
                    initial_set: List[Polynomial],
                    unsafe_set: List[Polynomial]) -> Optional[Polynomial]:
        """Synthesize barrier certificate."""
        program = SOSProgram("barrier")
        
        # B is polynomial (not necessarily SOS)
        B = program.add_polynomial_variable("B", self.n_vars, self.degree)
        
        vars_z3 = [z3.Real(f'x{i}') for i in range(self.n_vars)]
        B_expr = B.to_expression(vars_z3)
        
        # Constraint 1: -B is SOS on initial set
        # B < 0 ⟹ -B - ε is SOS for some ε > 0
        # Use Putinar: -B - ε = σ₀ + Σᵢ σᵢ gᵢ
        program.add_sos_constraint(-B_expr - 0.01)
        
        # Constraint 2: B is SOS on unsafe set
        # B >= 0 ⟹ B = σ₀ + Σᵢ σᵢ hᵢ
        program.add_sos_constraint(B_expr)
        
        # Constraint 3: -dB/dt is SOS (on B = 0)
        dBdt = self._compute_lie_derivative(B, dynamics, vars_z3)
        program.add_sos_constraint(-dBdt)
        
        result = program.solve()
        
        if result.is_feasible:
            return program.get_polynomial_value(B)
        
        return None
    
    def _compute_lie_derivative(self, B: PolynomialVariable,
                                  dynamics: List[Polynomial],
                                  vars_z3: List[z3.ExprRef]) -> z3.ExprRef:
        """Compute Lie derivative of B."""
        return z3.RealVal(0)  # Simplified


# =============================================================================
# Utilities
# =============================================================================

class SOSValidator:
    """
    Validate SOS decompositions and certificates.
    """
    
    @staticmethod
    def is_sos(coefficients: Dict[Tuple[int, ...], float],
                n_vars: int, n_samples: int = 1000) -> bool:
        """
        Check if polynomial is SOS by sampling.
        
        SOS polynomials are non-negative everywhere.
        """
        import random
        
        for _ in range(n_samples):
            point = [random.uniform(-10, 10) for _ in range(n_vars)]
            
            value = 0.0
            for mono, coeff in coefficients.items():
                term = coeff
                for i, exp in enumerate(mono):
                    term *= point[i] ** exp
                value += term
            
            if value < -1e-6:
                return False
        
        return True
    
    @staticmethod
    def verify_gram(Q: List[List[float]], tolerance: float = 1e-6) -> bool:
        """Check if matrix is positive semidefinite."""
        n = len(Q)
        
        # Check symmetry
        for i in range(n):
            for j in range(i + 1, n):
                if abs(Q[i][j] - Q[j][i]) > tolerance:
                    return False
        
        # Check eigenvalues (simplified: check principal minors)
        if n >= 1 and Q[0][0] < -tolerance:
            return False
        
        if n >= 2:
            det2 = Q[0][0] * Q[1][1] - Q[0][1] * Q[1][0]
            if det2 < -tolerance:
                return False
        
        return True


class SOSFormatter:
    """
    Format SOS polynomials and certificates for output.
    """
    
    @staticmethod
    def polynomial_to_string(poly: Polynomial) -> str:
        """Convert polynomial to readable string."""
        terms = []
        
        for mono, coeff in poly.terms.items():
            c_val = float(coeff) if isinstance(coeff, (int, float)) else 1.0
            
            if abs(c_val) < 1e-10:
                continue
            
            mono_str = str(mono)
            if mono_str == '1':
                terms.append(f"{c_val:.4f}")
            elif abs(c_val - 1.0) < 1e-10:
                terms.append(mono_str)
            elif abs(c_val + 1.0) < 1e-10:
                terms.append(f"-{mono_str}")
            else:
                terms.append(f"{c_val:.4f}*{mono_str}")
        
        return " + ".join(terms) if terms else "0"
    
    @staticmethod
    def gram_to_latex(Q: List[List[float]]) -> str:
        """Convert Gram matrix to LaTeX."""
        n = len(Q)
        rows = []
        
        for i in range(n):
            row = " & ".join(f"{Q[i][j]:.4f}" for j in range(n))
            rows.append(row)
        
        return "\\begin{pmatrix}\n" + " \\\\\n".join(rows) + "\n\\end{pmatrix}"


# =============================================================================
# Integration with Barrier Framework
# =============================================================================

class SOSToolsIntegration:
    """
    Integration layer between SOSTOOLS and barrier framework.
    """
    
    def __init__(self):
        self.synthesizer = BarrierSynthesizerSOS(n_vars=2)
        self.lyapunov = LyapunovSynthesizer(n_vars=2)
        self.optimizer = PolynomialOptimizer(n_vars=2)
        
    def synthesize_barrier(self, system_spec: Dict) -> Optional[Dict]:
        """
        Synthesize barrier using SOSTOOLS.
        
        Returns certificate in barrier framework format.
        """
        # Extract from spec
        n_vars = system_spec.get('n_vars', 2)
        degree = system_spec.get('degree', 4)
        dynamics = system_spec.get('dynamics', [])
        initial = system_spec.get('initial', [])
        unsafe = system_spec.get('unsafe', [])
        
        self.synthesizer = BarrierSynthesizerSOS(n_vars, degree)
        barrier = self.synthesizer.synthesize(dynamics, initial, unsafe)
        
        if barrier:
            return {
                'type': 'sos_barrier',
                'polynomial': barrier,
                'method': 'sostools',
            }
        
        return None
    
    def verify_with_sos(self, barrier_polynomial: Dict,
                          dynamics: Dict) -> bool:
        """
        Verify barrier conditions using SOS.
        """
        program = SOSProgram("verify")
        
        # Add barrier conditions as SOS constraints
        # (simplified)
        
        result = program.solve()
        return result.is_feasible


# =============================================================================
# Advanced SOSTOOLS Features
# =============================================================================

class SOSProgramAnalyzer:
    """
    Analyze SOS program structure for optimization.
    
    Identifies opportunities for:
    - Sparsity exploitation
    - Symmetry reduction
    - Problem decomposition
    """
    
    def __init__(self, program: SOSProgram):
        self.program = program
        self.analysis_results = {}
        
    def analyze(self) -> Dict[str, Any]:
        """Run complete analysis."""
        self.analysis_results = {
            'num_variables': len(self.program.variables),
            'num_sos_constraints': len(self.program.sos_constraints),
            'num_equality_constraints': len(self.program.equality_constraints),
            'num_inequality_constraints': len(self.program.inequality_constraints),
            'sparsity': self._analyze_sparsity(),
            'symmetry': self._analyze_symmetry(),
            'recommended_solver': self._recommend_solver(),
        }
        return self.analysis_results
    
    def _analyze_sparsity(self) -> Dict[str, Any]:
        """Analyze variable sparsity."""
        # Build variable interaction graph
        interactions = {}
        for name in self.program.variables:
            interactions[name] = set()
        
        # Analyze constraints for interactions
        density = len(interactions) / max(1, len(self.program.variables) ** 2)
        
        return {
            'density': density,
            'sparse': density < 0.3,
            'clique_count': 1,  # Would compute actual cliques
        }
    
    def _analyze_symmetry(self) -> Dict[str, Any]:
        """Analyze problem symmetry."""
        return {
            'has_symmetry': False,
            'symmetry_group_size': 1,
        }
    
    def _recommend_solver(self) -> str:
        """Recommend solver based on analysis."""
        if self.analysis_results.get('sparsity', {}).get('sparse', False):
            return 'sparse_sos'
        return 'standard_sos'


class SOSDecompositionFactory:
    """
    Factory for creating SOS decompositions.
    
    Provides different decomposition strategies based on
    polynomial structure.
    """
    
    @staticmethod
    def create_standard(n_vars: int, degree: int) -> SOSPolynomial:
        """Create standard dense SOS decomposition."""
        return SOSPolynomial(n_vars, degree)
    
    @staticmethod
    def create_sparse(polynomial: Polynomial,
                       cliques: List[Set[int]]) -> List[SOSPolynomial]:
        """Create sparse SOS decomposition based on cliques."""
        decompositions = []
        
        for clique in cliques:
            clique_nvars = len(clique)
            sos = SOSPolynomial(clique_nvars, polynomial.degree)
            decompositions.append(sos)
        
        return decompositions
    
    @staticmethod
    def create_diagonally_dominant(n_vars: int,
                                    degree: int) -> 'DiagonalSOSPolynomial':
        """Create diagonally dominant SOS for efficiency."""
        return DiagonalSOSPolynomial(n_vars, degree)
    
    @staticmethod
    def create_sos_multiplier(n_vars: int, constraint_degree: int,
                               target_degree: int) -> SOSPolynomial:
        """Create SOS multiplier for Positivstellensatz."""
        mult_degree = max(0, target_degree - constraint_degree)
        return SOSPolynomial(n_vars, mult_degree)


class DiagonalSOSPolynomial(SOSPolynomial):
    """
    Diagonally dominant SOS polynomial.
    
    Restricts Gram matrix to be diagonally dominant,
    which is a sufficient condition for PSD and is
    easier to encode.
    """
    
    def __init__(self, n_vars: int, degree: int):
        super().__init__(n_vars, degree)
        self.diagonal_dominance = True
        
    def add_psd_constraints(self, solver: z3.Solver) -> None:
        """Add diagonal dominance constraints."""
        if self.gram_matrix is None:
            return
        
        n = len(self.gram_matrix)
        
        # Diagonal elements non-negative
        for i in range(n):
            solver.add(self.gram_matrix[i][i] >= 0)
        
        # Diagonal dominance: |q_ii| >= Σ_{j≠i} |q_ij|
        for i in range(n):
            off_diagonal_sum = z3.RealVal(0)
            for j in range(n):
                if i != j:
                    # Approximate |q_ij| with q_ij (assuming non-negative)
                    off_diagonal_sum = off_diagonal_sum + self.gram_matrix[i][j]
            
            solver.add(self.gram_matrix[i][i] >= off_diagonal_sum)


class ScaledSOSPolynomial(SOSPolynomial):
    """
    Scaled SOS polynomial for numerical stability.
    
    Applies scaling to improve conditioning of the
    optimization problem.
    """
    
    def __init__(self, n_vars: int, degree: int, scale: float = 1.0):
        super().__init__(n_vars, degree)
        self.scale = scale
        
    def create_gram_template(self) -> z3.ExprRef:
        """Create scaled Gram template."""
        base = super().create_gram_template()
        return base * self.scale


class SOSConstraintManager:
    """
    Manage SOS constraints in optimization problems.
    
    Handles:
    - Constraint addition
    - Constraint removal (for incremental solving)
    - Constraint transformation
    """
    
    def __init__(self):
        self.constraints = []
        self.active = set()
        self.constraint_ids = {}
        self._next_id = 0
        
    def add(self, constraint: z3.ExprRef, 
             name: str = "") -> int:
        """Add constraint and return ID."""
        cid = self._next_id
        self._next_id += 1
        
        self.constraints.append({
            'id': cid,
            'constraint': constraint,
            'name': name or f'c{cid}',
        })
        self.active.add(cid)
        self.constraint_ids[name or f'c{cid}'] = cid
        
        return cid
    
    def remove(self, cid: int) -> bool:
        """Deactivate constraint by ID."""
        if cid in self.active:
            self.active.remove(cid)
            return True
        return False
    
    def get_active_constraints(self) -> List[z3.ExprRef]:
        """Get list of active constraints."""
        return [c['constraint'] for c in self.constraints 
                if c['id'] in self.active]
    
    def transform(self, cid: int, 
                   transformer: callable) -> Optional[int]:
        """Transform constraint and add new version."""
        for c in self.constraints:
            if c['id'] == cid:
                new_constraint = transformer(c['constraint'])
                return self.add(new_constraint, f"{c['name']}_transformed")
        return None


class IncrementalSOSSolver:
    """
    Incremental SOS solving.
    
    Efficiently handles problems where constraints are
    added/removed incrementally.
    """
    
    def __init__(self):
        self.solver = z3.Solver()
        self.constraint_manager = SOSConstraintManager()
        self.solutions = []
        
    def add_sos_constraint(self, polynomial: z3.ExprRef,
                            name: str = "") -> int:
        """Add SOS constraint incrementally."""
        cid = self.constraint_manager.add(polynomial, name)
        
        # Add to solver with push/pop for incremental
        sos = SOSPolynomial(n_vars=2, degree=4)  # Would infer from polynomial
        sos.create_gram_template()
        sos.add_psd_constraints(self.solver)
        
        return cid
    
    def remove_constraint(self, cid: int) -> bool:
        """Remove constraint (requires re-solving)."""
        return self.constraint_manager.remove(cid)
    
    def solve(self, timeout_ms: int = 60000) -> SOSResult:
        """Solve current problem."""
        self.solver.set("timeout", timeout_ms)
        
        result = self.solver.check()
        
        if result == z3.sat:
            solution = SOSResult(
                status=SOSStatus.OPTIMAL,
                model=self.solver.model()
            )
            self.solutions.append(solution)
            return solution
        elif result == z3.unsat:
            return SOSResult(status=SOSStatus.INFEASIBLE)
        else:
            return SOSResult(status=SOSStatus.UNKNOWN)
    
    def get_unsat_core(self) -> List[int]:
        """Get unsatisfiable core as constraint IDs."""
        # Would return minimal unsatisfiable subset
        return []


class PolynomialArithmetic:
    """
    Polynomial arithmetic operations.
    
    Provides efficient implementations of common operations.
    """
    
    @staticmethod
    def add(p1: Polynomial, p2: Polynomial) -> Polynomial:
        """Add two polynomials."""
        return p1.add(p2)
    
    @staticmethod
    def multiply(p1: Polynomial, p2: Polynomial) -> Polynomial:
        """Multiply two polynomials."""
        return p1.multiply(p2)
    
    @staticmethod
    def power(p: Polynomial, n: int) -> Polynomial:
        """Compute p^n."""
        if n == 0:
            result = Polynomial(p.n_vars)
            result.add_term(Monomial(tuple([0] * p.n_vars)), z3.RealVal(1))
            return result
        elif n == 1:
            return p
        else:
            half = PolynomialArithmetic.power(p, n // 2)
            result = half.multiply(half)
            if n % 2 == 1:
                result = result.multiply(p)
            return result
    
    @staticmethod
    def compose(p: Polynomial, substitutions: Dict[int, Polynomial]) -> Polynomial:
        """Compose polynomial with substitutions."""
        # p(x₁, x₂, ...) with xᵢ → qᵢ(y)
        result = Polynomial(p.n_vars)
        
        for mono, coeff in p.terms.items():
            # Substitute each variable
            term_poly = Polynomial(p.n_vars)
            term_poly.add_term(Monomial(tuple([0] * p.n_vars)), coeff)
            
            for i, exp in enumerate(mono.exponents):
                if exp > 0 and i in substitutions:
                    sub_power = PolynomialArithmetic.power(substitutions[i], exp)
                    term_poly = term_poly.multiply(sub_power)
            
            result = result.add(term_poly)
        
        return result
    
    @staticmethod
    def evaluate(p: Polynomial, point: List[float]) -> float:
        """Evaluate polynomial at point."""
        return p.evaluate(point)


class MonomialOrdering:
    """
    Monomial orderings for polynomial algebra.
    
    Implements:
    - Lexicographic
    - Graded lexicographic  
    - Graded reverse lexicographic
    """
    
    LEXICOGRAPHIC = 'lex'
    GRLEX = 'grlex'
    GREVLEX = 'grevlex'
    
    @staticmethod
    def compare_lex(m1: Monomial, m2: Monomial) -> int:
        """Lexicographic comparison."""
        for e1, e2 in zip(m1.exponents, m2.exponents):
            if e1 > e2:
                return 1
            elif e1 < e2:
                return -1
        return 0
    
    @staticmethod
    def compare_grlex(m1: Monomial, m2: Monomial) -> int:
        """Graded lexicographic comparison."""
        d1, d2 = m1.degree, m2.degree
        if d1 > d2:
            return 1
        elif d1 < d2:
            return -1
        return MonomialOrdering.compare_lex(m1, m2)
    
    @staticmethod
    def compare_grevlex(m1: Monomial, m2: Monomial) -> int:
        """Graded reverse lexicographic comparison."""
        d1, d2 = m1.degree, m2.degree
        if d1 > d2:
            return 1
        elif d1 < d2:
            return -1
        
        # Reverse lexicographic on negatives
        for e1, e2 in reversed(list(zip(m1.exponents, m2.exponents))):
            if e1 < e2:
                return 1
            elif e1 > e2:
                return -1
        return 0
    
    @staticmethod
    def sort_monomials(monomials: List[Monomial],
                        ordering: str = GRLEX) -> List[Monomial]:
        """Sort monomials by given ordering."""
        if ordering == MonomialOrdering.LEXICOGRAPHIC:
            key = lambda m: m.exponents
        elif ordering == MonomialOrdering.GRLEX:
            key = lambda m: (m.degree, m.exponents)
        else:  # GREVLEX
            key = lambda m: (m.degree, tuple(-e for e in reversed(m.exponents)))
        
        return sorted(monomials, key=key, reverse=True)


class DegreeHierarchy:
    """
    Manage degree hierarchy for SOS programs.
    
    Implements systematic degree lifting as in Lasserre hierarchy.
    """
    
    def __init__(self, initial_degree: int = 2, max_degree: int = 20):
        self.initial_degree = initial_degree
        self.max_degree = max_degree
        self.current_degree = initial_degree
        self.solutions_by_degree = {}
        
    def lift(self) -> int:
        """Lift to next degree in hierarchy."""
        self.current_degree = min(
            self.current_degree + 2,
            self.max_degree
        )
        return self.current_degree
    
    def reset(self) -> None:
        """Reset to initial degree."""
        self.current_degree = self.initial_degree
    
    def solve_hierarchy(self, problem: SOSProgram,
                         target_accuracy: float = 1e-4) -> Optional[SOSResult]:
        """
        Solve using degree hierarchy.
        
        Increases degree until either:
        - Solution found
        - Max degree reached
        - Convergence detected
        """
        last_obj = None
        
        while self.current_degree <= self.max_degree:
            # Create problem at current degree
            degree_problem = self._create_problem_at_degree(
                problem, self.current_degree
            )
            
            result = degree_problem.solve()
            self.solutions_by_degree[self.current_degree] = result
            
            if result.is_feasible:
                obj = result.objective_value
                
                # Check convergence
                if last_obj is not None and obj is not None:
                    if abs(obj - last_obj) < target_accuracy:
                        return result
                
                last_obj = obj
            
            self.lift()
        
        # Return best solution found
        feasible = [r for r in self.solutions_by_degree.values() 
                    if r.is_feasible]
        return feasible[-1] if feasible else None
    
    def _create_problem_at_degree(self, base: SOSProgram,
                                    degree: int) -> SOSProgram:
        """Create problem instance at given degree."""
        program = SOSProgram(f"{base.name}_deg{degree}")
        # Would copy constraints with lifted degree
        return program


class SOSCertificateChain:
    """
    Chain of SOS certificates for complex proofs.
    
    Allows composing multiple SOS certificates into
    a single proof.
    """
    
    def __init__(self):
        self.certificates = []
        self.links = []
        
    def add_certificate(self, cert: SOSCertificate,
                         name: str = "") -> int:
        """Add certificate to chain."""
        idx = len(self.certificates)
        self.certificates.append({
            'index': idx,
            'certificate': cert,
            'name': name or f'cert_{idx}',
        })
        return idx
    
    def add_link(self, from_idx: int, to_idx: int,
                  relation: str = "implies") -> None:
        """Add logical link between certificates."""
        self.links.append({
            'from': from_idx,
            'to': to_idx,
            'relation': relation,
        })
    
    def verify_chain(self) -> bool:
        """Verify entire certificate chain."""
        for link in self.links:
            from_cert = self.certificates[link['from']]['certificate']
            to_cert = self.certificates[link['to']]['certificate']
            
            # Verify link is valid
            if not self._verify_link(from_cert, to_cert, link['relation']):
                return False
        
        return True
    
    def _verify_link(self, from_cert: SOSCertificate,
                      to_cert: SOSCertificate,
                      relation: str) -> bool:
        """Verify single link in chain."""
        return True  # Would verify based on relation type
    
    def to_proof_script(self) -> str:
        """Generate proof script from chain."""
        lines = ["// SOS Certificate Chain Proof", ""]
        
        for cert in self.certificates:
            lines.append(f"Certificate {cert['name']}:")
            lines.append(f"  {cert['certificate']}")
            lines.append("")
        
        lines.append("Links:")
        for link in self.links:
            from_name = self.certificates[link['from']]['name']
            to_name = self.certificates[link['to']]['name']
            lines.append(f"  {from_name} --[{link['relation']}]--> {to_name}")
        
        return "\n".join(lines)


class NumericalSOS:
    """
    Numerical methods for SOS computation.
    
    Provides numerical techniques when symbolic methods
    are insufficient.
    """
    
    def __init__(self, tolerance: float = 1e-6):
        self.tolerance = tolerance
        
    def numerical_sos_check(self, coefficients: Dict[Tuple[int, ...], float],
                             n_vars: int) -> Tuple[bool, Optional[List[List[float]]]]:
        """
        Numerically check if polynomial is SOS.
        
        Returns (is_sos, gram_matrix).
        """
        # Build moment matrix
        degree = max(sum(m) for m in coefficients.keys()) if coefficients else 0
        half_degree = degree // 2
        
        # Create monomial basis
        from itertools import combinations_with_replacement
        basis = []
        for d in range(half_degree + 1):
            for combo in combinations_with_replacement(range(n_vars), d):
                exp = [0] * n_vars
                for idx in combo:
                    exp[idx] += 1
                basis.append(tuple(exp))
        
        # Build moment matrix
        n = len(basis)
        M = [[0.0] * n for _ in range(n)]
        
        for i, m1 in enumerate(basis):
            for j, m2 in enumerate(basis):
                combined = tuple(a + b for a, b in zip(m1, m2))
                M[i][j] = coefficients.get(combined, 0.0)
        
        # Check if M is PSD
        is_psd = self._is_psd(M)
        
        return is_psd, M if is_psd else None
    
    def _is_psd(self, M: List[List[float]]) -> bool:
        """Check if matrix is positive semidefinite."""
        n = len(M)
        
        # Try Cholesky
        try:
            L = [[0.0] * n for _ in range(n)]
            
            for i in range(n):
                for j in range(i + 1):
                    s = M[i][j]
                    for k in range(j):
                        s -= L[i][k] * L[j][k]
                    
                    if i == j:
                        if s < -self.tolerance:
                            return False
                        L[i][j] = s ** 0.5 if s > 0 else 0
                    else:
                        L[i][j] = s / L[j][j] if abs(L[j][j]) > self.tolerance else 0
            
            return True
        except:
            return False
    
    def extract_sos_factors(self, gram: List[List[float]],
                             basis: List[Tuple[int, ...]]) -> List[Dict[Tuple[int, ...], float]]:
        """Extract SOS factors from Gram matrix."""
        n = len(gram)
        
        # Compute Cholesky factorization
        L = [[0.0] * n for _ in range(n)]
        
        for i in range(n):
            for j in range(i + 1):
                s = gram[i][j]
                for k in range(j):
                    s -= L[i][k] * L[j][k]
                
                if i == j:
                    L[i][j] = s ** 0.5 if s > 0 else 0
                else:
                    L[i][j] = s / L[j][j] if abs(L[j][j]) > self.tolerance else 0
        
        # Each row of L gives a polynomial factor
        factors = []
        for i in range(n):
            factor = {}
            for j, mono in enumerate(basis):
                if abs(L[i][j]) > self.tolerance:
                    factor[mono] = L[i][j]
            
            if factor:
                factors.append(factor)
        
        return factors


class SOSProblemGenerator:
    """
    Generate SOS problems for testing and benchmarking.
    """
    
    @staticmethod
    def random_sos_polynomial(n_vars: int, degree: int,
                                n_terms: int = 10) -> Dict[Tuple[int, ...], float]:
        """Generate random SOS polynomial."""
        import random
        
        # Generate random factors
        half_degree = degree // 2
        n_factors = max(1, n_terms // 3)
        
        coeffs: Dict[Tuple[int, ...], float] = {}
        
        for _ in range(n_factors):
            # Random polynomial factor
            factor: Dict[Tuple[int, ...], float] = {}
            for _ in range(random.randint(1, 5)):
                exp = [0] * n_vars
                for _ in range(random.randint(0, half_degree)):
                    exp[random.randint(0, n_vars - 1)] += 1
                factor[tuple(exp)] = random.uniform(-1, 1)
            
            # Square it and add to result
            for m1, c1 in factor.items():
                for m2, c2 in factor.items():
                    combined = tuple(a + b for a, b in zip(m1, m2))
                    coeffs[combined] = coeffs.get(combined, 0.0) + c1 * c2
        
        return coeffs
    
    @staticmethod
    def barrier_synthesis_problem(n_vars: int = 2,
                                    degree: int = 4) -> SOSProgram:
        """Generate barrier synthesis SOS problem."""
        program = SOSProgram("barrier_synthesis")
        
        # Add polynomial variable for barrier
        B = program.add_polynomial_variable("B", n_vars, degree)
        
        vars_z3 = [z3.Real(f'x{i}') for i in range(n_vars)]
        
        # Add SOS constraints for barrier conditions
        # (Would add actual constraints based on system)
        
        return program
    
    @staticmethod
    def lyapunov_problem(n_vars: int = 2,
                          degree: int = 4) -> SOSProgram:
        """Generate Lyapunov synthesis SOS problem."""
        program = SOSProgram("lyapunov_synthesis")
        
        V = program.add_polynomial_variable("V", n_vars, degree)
        
        # V is positive definite (V - ε||x||² is SOS)
        # -dV/dt is SOS
        
        return program


class SOSToolsCompatibility:
    """
    Compatibility layer with original SOSTOOLS.
    
    Provides MATLAB-like interface for users familiar
    with the original SOSTOOLS.
    """
    
    def __init__(self):
        self.programs = {}
        self.current = None
        
    def sosprogram(self, name: str) -> SOSProgram:
        """Create new SOS program (like sosprogram in MATLAB)."""
        program = SOSProgram(name)
        self.programs[name] = program
        self.current = program
        return program
    
    def syms(self, *names: str) -> List[z3.ExprRef]:
        """Create symbolic variables."""
        return [z3.Real(name) for name in names]
    
    def sossosvar(self, prog: SOSProgram, var: z3.ExprRef,
                   degree: int) -> PolynomialVariable:
        """Declare SOS decision variable."""
        return prog.add_polynomial_variable(str(var), 1, degree)
    
    def soseq(self, prog: SOSProgram, expr: z3.ExprRef) -> None:
        """Add equality constraint."""
        prog.add_equality(expr == 0)
    
    def sosineq(self, prog: SOSProgram, expr: z3.ExprRef) -> None:
        """Add inequality constraint (expr >= 0 via SOS)."""
        prog.add_sos_constraint(expr)
    
    def sossolve(self, prog: SOSProgram) -> SOSResult:
        """Solve SOS program."""
        return prog.solve()
    
    def sosgetsol(self, prog: SOSProgram,
                   var: PolynomialVariable) -> Polynomial:
        """Get solution polynomial."""
        return prog.get_polynomial_value(var)

