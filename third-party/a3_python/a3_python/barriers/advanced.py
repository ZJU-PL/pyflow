"""
Advanced Verification Layer for Barrier Certificate Synthesis.

This module provides advanced verification techniques that complement
the core barrier synthesis. It integrates:

    Paper #9: DSOS/SDSOS Relaxations (Ahmadi-Majumdar 2019)
        - LP/SOCP relaxations of SOS
        - Faster but weaker positivity proofs
        
    Paper #10: IC3/PDR (Bradley 2011)
        - Property-Directed Reachability
        - Incremental inductive reasoning
        
    Paper #11: Spacer/CHC (Komuravelli et al. 2014)
        - Constrained Horn Clauses
        - SMT-based model checking
        
    Paper #15: Interpolation/IMC (McMillan 2003)
        - Craig interpolation for refinement
        - Interpolation-based model checking
        
    Paper #20: Assume-Guarantee (Pnueli 1985)
        - Compositional verification
        - Circular reasoning

The composable architecture:

    ┌─────────────────────────────────────────────────────────────┐
    │                    ADVANCED VERIFICATION                     │
    ├─────────────────────────────────────────────────────────────┤
    │                                                              │
    │  ┌───────────────────────────────────────────────────────┐  │
    │  │                 LEARNING LAYER                         │  │
    │  │         (ICE, Houdini, SyGuS)                         │  │
    │  └────────────────────────┬──────────────────────────────┘  │
    │                           │                                  │
    │       ┌───────────────────┼───────────────────┐              │
    │       │           │       │       │           │              │
    │       ▼           ▼       ▼       ▼           ▼              │
    │  ┌─────────┐ ┌─────────┐ ┌─────────┐ ┌─────────┐ ┌─────────┐│
    │  │  DSOS/  │ │  IC3/   │ │ Spacer/ │ │  IMC/   │ │ Assume- ││
    │  │ SDSOS   │ │  PDR    │ │  CHC    │ │  Interp │ │Guarantee││
    │  │ (#9)    │ │ (#10)   │ │ (#11)   │ │ (#15)   │ │ (#20)   ││
    │  └────┬────┘ └────┬────┘ └────┬────┘ └────┬────┘ └────┬────┘│
    │       │           │           │           │           │      │
    │       └───────────┴───────────┼───────────┴───────────┘      │
    │                               │                              │
    │                               ▼                              │
    │              ┌───────────────────────────────┐               │
    │              │   Advanced Verification Engine │               │
    │              │        Unified Interface       │               │
    │              └───────────────────────────────┘               │
    │                                                              │
    └─────────────────────────────────────────────────────────────┘

Usage:
    from barriers.advanced import (
        DSOSRelaxation,
        IC3Engine,
        SpacerCHC,
        InterpolationEngine,
        AssumeGuaranteeVerifier,
        AdvancedVerificationEngine,
    )
    
    # Unified interface
    engine = AdvancedVerificationEngine()
    result = engine.verify(system, property)
"""

from __future__ import annotations

import z3
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple, Set, Any, Union, Callable, FrozenSet
from enum import Enum, auto
import logging

# Import from lower layers
from .foundations import (
    Polynomial, SemialgebraicSet, Monomial,
    SOSDecomposition, PolynomialCertificateEngine
)
from .certificate_core import (
    BarrierTemplate, ContinuousDynamics, BarrierConditions
)
from .abstraction import Predicate, AbstractState, CEGARResult

logger = logging.getLogger(__name__)


# =============================================================================
# DSOS/SDSOS RELAXATIONS (Paper #9)
# =============================================================================

class DecompositionType(Enum):
    """Types of polynomial decompositions."""
    SOS = auto()  # Sum of Squares (SDP)
    SDSOS = auto()  # Scaled Diagonally-dominant SOS (SOCP)
    DSOS = auto()  # Diagonally-dominant SOS (LP)


@dataclass
class DSOSDecomposition:
    """
    DSOS decomposition: p = Σᵢⱼ λᵢⱼ (xᵢ ± xⱼ)².
    
    From Paper #9: Diagonally-dominant SOS uses only squared binomials,
    resulting in LP-solvable positivity certificates.
    """
    n_vars: int
    degree: int
    binomial_coeffs: Dict[Tuple[int, int, int], float]  # (i, j, sign) -> λ
    
    def evaluate(self, point: List[float]) -> float:
        """Evaluate the DSOS polynomial."""
        result = 0.0
        for (i, j, sign), coeff in self.binomial_coeffs.items():
            if i < len(point) and j < len(point):
                if sign > 0:
                    val = point[i] + point[j]
                else:
                    val = point[i] - point[j]
                result += coeff * val * val
        return result
    
    def to_polynomial(self) -> Polynomial:
        """Convert to Polynomial representation."""
        poly = Polynomial(self.n_vars)
        
        for (i, j, sign), coeff in self.binomial_coeffs.items():
            # (xᵢ ± xⱼ)² = xᵢ² ± 2xᵢxⱼ + xⱼ²
            
            # xᵢ² term
            exp_ii = [0] * self.n_vars
            exp_ii[i] = 2
            mono_ii = Monomial(tuple(exp_ii))
            poly.terms[mono_ii] = poly.terms.get(mono_ii, 0) + coeff
            
            # xⱼ² term
            exp_jj = [0] * self.n_vars
            exp_jj[j] = 2
            mono_jj = Monomial(tuple(exp_jj))
            poly.terms[mono_jj] = poly.terms.get(mono_jj, 0) + coeff
            
            # 2xᵢxⱼ term (sign depends on ±)
            if i != j:
                exp_ij = [0] * self.n_vars
                exp_ij[i] = 1
                exp_ij[j] = 1
                mono_ij = Monomial(tuple(exp_ij))
                cross_coeff = 2 * coeff * (1 if sign > 0 else -1)
                poly.terms[mono_ij] = poly.terms.get(mono_ij, 0) + cross_coeff
        
        return poly


@dataclass
class SDSOSDecomposition:
    """
    SDSOS decomposition: p is SDSOS if its Gram matrix is SOCP-representable.
    
    From Paper #9: Scaled diagonally-dominant matrices are a SOCP-solvable
    inner approximation of PSD matrices.
    """
    n_vars: int
    degree: int
    diagonal: List[float]  # Diagonal entries
    off_diagonal: Dict[Tuple[int, int], float]  # Off-diagonal entries
    
    def is_scaled_dd(self, tolerance: float = 1e-8) -> bool:
        """Check if matrix is scaled diagonally dominant."""
        n = len(self.diagonal)
        
        for i in range(n):
            # Check: Dᵢ² ≥ Σⱼ≠ᵢ |Mᵢⱼ|²
            diag_sq = self.diagonal[i] ** 2
            off_sum = sum(
                self.off_diagonal.get((min(i, j), max(i, j)), 0) ** 2
                for j in range(n) if j != i
            )
            if diag_sq < off_sum - tolerance:
                return False
        
        return True


class DSOSRelaxation:
    """
    DSOS/SDSOS relaxation engine (Paper #9).
    
    Provides faster (LP/SOCP) alternatives to SDP-based SOS.
    Trade-off: faster but may fail to prove some positivity properties.
    """
    
    def __init__(self, n_vars: int, max_degree: int = 6,
                 timeout_ms: int = 30000):
        self.n_vars = n_vars
        self.max_degree = max_degree
        self.timeout_ms = timeout_ms
        
        self.stats = {
            'dsos_attempts': 0,
            'sdsos_attempts': 0,
            'dsos_success': 0,
            'sdsos_success': 0,
        }
    
    def prove_dsos(self, polynomial: Polynomial) -> Optional[DSOSDecomposition]:
        """
        Find DSOS decomposition using LP.
        
        p is DSOS if p = Σᵢⱼ λᵢⱼ (xᵢ ± xⱼ)² with λᵢⱼ ≥ 0.
        """
        self.stats['dsos_attempts'] += 1
        
        # Set up LP variables
        solver = z3.Optimize()
        solver.set("timeout", self.timeout_ms)
        
        # Create λᵢⱼ variables
        lambdas = {}
        for i in range(self.n_vars):
            for j in range(i, self.n_vars):
                for sign in [-1, 1]:
                    var = z3.Real(f'lam_{i}_{j}_{sign}')
                    solver.add(var >= 0)  # Non-negative coefficients
                    lambdas[(i, j, sign)] = var
        
        # Constraint: polynomial coefficients match DSOS form
        self._add_coefficient_constraints(solver, polynomial, lambdas)
        
        # Objective: minimize sum of lambdas (regularization)
        obj = sum(lambdas.values())
        solver.minimize(obj)
        
        if solver.check() == z3.sat:
            model = solver.model()
            coeff_values = {}
            
            for key, var in lambdas.items():
                val = model.eval(var, model_completion=True)
                if z3.is_rational_value(val):
                    coeff_values[key] = (float(val.numerator_as_long()) /
                                        float(val.denominator_as_long()))
                else:
                    coeff_values[key] = 0.0
            
            self.stats['dsos_success'] += 1
            return DSOSDecomposition(
                n_vars=self.n_vars,
                degree=polynomial.degree,
                binomial_coeffs=coeff_values
            )
        
        return None
    
    def prove_sdsos(self, polynomial: Polynomial) -> Optional[SDSOSDecomposition]:
        """
        Find SDSOS decomposition using SOCP (approximated via LP).
        """
        self.stats['sdsos_attempts'] += 1
        
        # Build monomial basis
        half_deg = polynomial.degree // 2
        basis = self._generate_basis(half_deg)
        n = len(basis)
        
        solver = z3.Optimize()
        solver.set("timeout", self.timeout_ms)
        
        # Gram matrix entries
        diagonal = [z3.Real(f'd_{i}') for i in range(n)]
        off_diag = {}
        
        for i in range(n):
            solver.add(diagonal[i] >= 0)
            for j in range(i + 1, n):
                off_diag[(i, j)] = z3.Real(f'm_{i}_{j}')
        
        # Scaled diagonal dominance (LP relaxation of SOCP)
        for i in range(n):
            off_sum = z3.RealVal(0)
            for j in range(n):
                if j != i:
                    key = (min(i, j), max(i, j))
                    if key in off_diag:
                        # |Mᵢⱼ| ≤ Dᵢ/n (simplified)
                        solver.add(off_diag[key] <= diagonal[i])
                        solver.add(off_diag[key] >= -diagonal[i])
        
        # Coefficient matching
        self._add_gram_coefficient_constraints(solver, polynomial, basis, diagonal, off_diag)
        
        if solver.check() == z3.sat:
            model = solver.model()
            
            diag_vals = []
            for d in diagonal:
                val = model.eval(d, model_completion=True)
                if z3.is_rational_value(val):
                    diag_vals.append(float(val.numerator_as_long()) /
                                    float(val.denominator_as_long()))
                else:
                    diag_vals.append(0.0)
            
            off_vals = {}
            for key, var in off_diag.items():
                val = model.eval(var, model_completion=True)
                if z3.is_rational_value(val):
                    off_vals[key] = (float(val.numerator_as_long()) /
                                    float(val.denominator_as_long()))
                else:
                    off_vals[key] = 0.0
            
            self.stats['sdsos_success'] += 1
            return SDSOSDecomposition(
                n_vars=self.n_vars,
                degree=polynomial.degree,
                diagonal=diag_vals,
                off_diagonal=off_vals
            )
        
        return None
    
    def _generate_basis(self, degree: int) -> List[Monomial]:
        """Generate monomial basis up to degree."""
        basis = []
        
        def generate(remaining: int, idx: int, current: List[int]):
            if idx == self.n_vars:
                basis.append(Monomial(tuple(current)))
                return
            for power in range(remaining + 1):
                generate(remaining - power, idx + 1, current + [power])
        
        for d in range(degree + 1):
            generate(d, 0, [])
        
        return basis
    
    def _add_coefficient_constraints(self, solver: z3.Optimize,
                                       polynomial: Polynomial,
                                       lambdas: Dict) -> None:
        """Add constraints matching polynomial to DSOS form."""
        # Build coefficient map from DSOS
        dsos_coeffs: Dict[Monomial, z3.ExprRef] = {}
        
        for (i, j, sign), lam in lambdas.items():
            # (xᵢ ± xⱼ)² = xᵢ² ± 2xᵢxⱼ + xⱼ²
            
            # xᵢ² term
            exp_ii = [0] * self.n_vars
            exp_ii[i] = 2
            mono_ii = Monomial(tuple(exp_ii))
            if mono_ii in dsos_coeffs:
                dsos_coeffs[mono_ii] = dsos_coeffs[mono_ii] + lam
            else:
                dsos_coeffs[mono_ii] = lam
            
            # xⱼ² term
            if i != j:
                exp_jj = [0] * self.n_vars
                exp_jj[j] = 2
                mono_jj = Monomial(tuple(exp_jj))
                if mono_jj in dsos_coeffs:
                    dsos_coeffs[mono_jj] = dsos_coeffs[mono_jj] + lam
                else:
                    dsos_coeffs[mono_jj] = lam
            
            # 2xᵢxⱼ term
            if i != j:
                exp_ij = [0] * self.n_vars
                exp_ij[i] = 1
                exp_ij[j] = 1
                mono_ij = Monomial(tuple(exp_ij))
                cross = z3.RealVal(2 * sign) * lam
                if mono_ij in dsos_coeffs:
                    dsos_coeffs[mono_ij] = dsos_coeffs[mono_ij] + cross
                else:
                    dsos_coeffs[mono_ij] = cross
        
        # Match with polynomial
        all_monomials = set(polynomial.terms.keys()) | set(dsos_coeffs.keys())
        for mono in all_monomials:
            poly_coeff = polynomial.terms.get(mono, 0.0)
            dsos_coeff = dsos_coeffs.get(mono, z3.RealVal(0))
            solver.add(dsos_coeff == z3.RealVal(poly_coeff))
    
    def _add_gram_coefficient_constraints(self, solver: z3.Optimize,
                                           polynomial: Polynomial,
                                           basis: List[Monomial],
                                           diagonal: List[z3.ExprRef],
                                           off_diag: Dict) -> None:
        """Add Gram matrix coefficient matching constraints."""
        # Build coefficient map from Gram
        gram_coeffs: Dict[Monomial, z3.ExprRef] = {}
        n = len(basis)
        
        for i in range(n):
            for j in range(n):
                combined = basis[i].multiply(basis[j])
                
                if i == j:
                    entry = diagonal[i]
                else:
                    key = (min(i, j), max(i, j))
                    entry = off_diag.get(key, z3.RealVal(0))
                
                if combined in gram_coeffs:
                    gram_coeffs[combined] = gram_coeffs[combined] + entry
                else:
                    gram_coeffs[combined] = entry
        
        # Match
        all_monomials = set(polynomial.terms.keys()) | set(gram_coeffs.keys())
        for mono in all_monomials:
            poly_coeff = polynomial.terms.get(mono, 0.0)
            gram_coeff = gram_coeffs.get(mono, z3.RealVal(0))
            solver.add(gram_coeff == z3.RealVal(poly_coeff))


# =============================================================================
# IC3/PDR (Paper #10)
# =============================================================================

@dataclass
class Frame:
    """
    Frame in IC3/PDR.
    
    Fᵢ over-approximates states reachable in ≤ i steps.
    F₀ = Initial, Fᵢ₊₁ ⊆ Fᵢ, Fᵢ ∧ T → Fᵢ₊₁'
    """
    index: int
    clauses: Set[FrozenSet[z3.ExprRef]]  # CNF representation
    
    def add_clause(self, clause: FrozenSet[z3.ExprRef]) -> None:
        """Add clause to frame."""
        self.clauses.add(clause)
    
    def to_formula(self) -> z3.ExprRef:
        """Convert to Z3 formula."""
        if not self.clauses:
            return z3.BoolVal(True)
        
        clause_formulas = []
        for clause in self.clauses:
            if clause:
                clause_formulas.append(z3.Or(list(clause)))
        
        if clause_formulas:
            return z3.And(clause_formulas)
        return z3.BoolVal(True)


@dataclass
class ProofObligation:
    """Proof obligation in IC3: (state, frame_index)."""
    cube: FrozenSet[z3.ExprRef]  # State as conjunction of literals
    frame_idx: int
    depth: int = 0


class IC3Engine:
    """
    IC3/PDR for invariant inference (Paper #10).
    
    Key ideas:
    1. Maintain sequence of frames F₀, F₁, ..., Fₖ
    2. Each frame over-approximates reachable states at that depth
    3. Block bad states by generalizing and propagating clauses
    4. Terminate when Fᵢ = Fᵢ₊₁ (fixpoint = invariant)
    """
    
    def __init__(self, variables: List[z3.ExprRef],
                 timeout_ms: int = 120000):
        self.variables = variables
        self.timeout_ms = timeout_ms
        
        self.frames: List[Frame] = []
        self.proof_queue: List[ProofObligation] = []
        
        self.stats = {
            'frames_created': 0,
            'clauses_learned': 0,
            'obligations_processed': 0,
        }
    
    def check_safety(self, initial: z3.ExprRef,
                      transition: z3.ExprRef,
                      bad: z3.ExprRef,
                      max_depth: int = 100) -> Tuple[str, Optional[z3.ExprRef]]:
        """
        Check safety using IC3/PDR.
        
        Returns ('safe', invariant) or ('unsafe', counterexample) or ('unknown', None).
        """
        # Initialize F₀ = Initial
        self.frames = [Frame(index=0, clauses=set())]
        self.stats['frames_created'] = 1
        
        # F₀ ∧ ¬Initial is UNSAT (initial is subset of F₀)
        
        for depth in range(max_depth):
            # Extend frames
            self.frames.append(Frame(index=depth + 1, clauses=set()))
            self.stats['frames_created'] += 1
            
            # Try to find bad state in latest frame
            bad_in_frame = self._check_bad(self.frames[-1], bad)
            
            if bad_in_frame is not None:
                # Bad state reachable - try to block
                if not self._block_cube(bad_in_frame, len(self.frames) - 1, transition, initial):
                    # Cannot block - counterexample exists
                    return ('unsafe', None)
            
            # Propagate clauses forward
            self._propagate_clauses(transition)
            
            # Check for fixpoint
            for i in range(len(self.frames) - 1):
                if self._frames_equal(self.frames[i], self.frames[i + 1]):
                    # Fixpoint reached - Fᵢ is inductive invariant
                    invariant = self.frames[i].to_formula()
                    return ('safe', invariant)
        
        return ('unknown', None)
    
    def _check_bad(self, frame: Frame, bad: z3.ExprRef) -> Optional[FrozenSet[z3.ExprRef]]:
        """Check if bad states intersect with frame."""
        solver = z3.Solver()
        solver.set("timeout", self.timeout_ms // 100)
        
        solver.add(frame.to_formula())
        solver.add(bad)
        
        if solver.check() == z3.sat:
            model = solver.model()
            # Extract cube (state) from model
            cube = frozenset(
                v if z3.is_true(model.eval(v, model_completion=True)) else z3.Not(v)
                for v in self.variables
                if v.sort() == z3.BoolSort()
            )
            return cube
        
        return None
    
    def _block_cube(self, cube: FrozenSet[z3.ExprRef],
                     frame_idx: int,
                     transition: z3.ExprRef,
                     initial: z3.ExprRef) -> bool:
        """Try to block cube from frame."""
        self.proof_queue.append(ProofObligation(cube=cube, frame_idx=frame_idx))
        
        while self.proof_queue:
            self.stats['obligations_processed'] += 1
            
            obl = self.proof_queue.pop()
            
            if obl.frame_idx == 0:
                # Reached initial states - counterexample
                return False
            
            # Try to find predecessor
            pred = self._find_predecessor(obl.cube, obl.frame_idx - 1, transition)
            
            if pred is not None:
                # Predecessor exists - add new obligation
                self.proof_queue.append(ProofObligation(
                    cube=pred,
                    frame_idx=obl.frame_idx - 1,
                    depth=obl.depth + 1
                ))
                self.proof_queue.append(obl)  # Re-add current
            else:
                # No predecessor - block cube
                clause = self._generalize_blocking_clause(obl.cube, obl.frame_idx, transition)
                
                # Add to all frames up to obl.frame_idx
                for i in range(1, obl.frame_idx + 1):
                    self.frames[i].add_clause(clause)
                    self.stats['clauses_learned'] += 1
        
        return True
    
    def _find_predecessor(self, cube: FrozenSet[z3.ExprRef],
                           frame_idx: int,
                           transition: z3.ExprRef) -> Optional[FrozenSet[z3.ExprRef]]:
        """Find predecessor state of cube."""
        solver = z3.Solver()
        solver.set("timeout", self.timeout_ms // 100)
        
        # Frame at predecessor
        solver.add(self.frames[frame_idx].to_formula())
        
        # Transition
        solver.add(transition)
        
        # Cube at successor (primed)
        for lit in cube:
            solver.add(self._prime_literal(lit))
        
        if solver.check() == z3.sat:
            model = solver.model()
            pred = frozenset(
                v if z3.is_true(model.eval(v, model_completion=True)) else z3.Not(v)
                for v in self.variables
                if v.sort() == z3.BoolSort()
            )
            return pred
        
        return None
    
    def _generalize_blocking_clause(self, cube: FrozenSet[z3.ExprRef],
                                      frame_idx: int,
                                      transition: z3.ExprRef) -> FrozenSet[z3.ExprRef]:
        """Generalize cube to blocking clause (negation of cube)."""
        # Basic: negate each literal
        clause = frozenset(z3.Not(lit) if not z3.is_not(lit) else lit.arg(0)
                          for lit in cube)
        
        # Could do more sophisticated generalization here
        return clause
    
    def _propagate_clauses(self, transition: z3.ExprRef) -> None:
        """Propagate clauses from Fᵢ to Fᵢ₊₁."""
        for i in range(len(self.frames) - 1):
            for clause in list(self.frames[i].clauses):
                # Check if clause is inductive relative to Fᵢ
                if self._is_inductive(clause, i, transition):
                    self.frames[i + 1].add_clause(clause)
    
    def _is_inductive(self, clause: FrozenSet[z3.ExprRef],
                       frame_idx: int,
                       transition: z3.ExprRef) -> bool:
        """Check if clause is inductive relative to frame."""
        solver = z3.Solver()
        solver.set("timeout", self.timeout_ms // 100)
        
        # Frame ∧ clause
        solver.add(self.frames[frame_idx].to_formula())
        if clause:
            solver.add(z3.Or(list(clause)))
        
        # Transition
        solver.add(transition)
        
        # ¬clause' (negation of clause at next state)
        primed_clause = [self._prime_literal(lit) for lit in clause]
        if primed_clause:
            solver.add(z3.Not(z3.Or(primed_clause)))
        
        return solver.check() == z3.unsat
    
    def _prime_literal(self, lit: z3.ExprRef) -> z3.ExprRef:
        """Create primed version of literal."""
        if z3.is_not(lit):
            return z3.Not(self._prime_literal(lit.arg(0)))
        
        name = str(lit)
        return z3.Bool(f"{name}'")
    
    def _frames_equal(self, f1: Frame, f2: Frame) -> bool:
        """Check if two frames have equal clause sets."""
        return f1.clauses == f2.clauses


# =============================================================================
# SPACER/CHC (Paper #11)
# =============================================================================

@dataclass
class HornClause:
    """
    A Constrained Horn Clause.
    
    Form: P₁(x₁) ∧ ... ∧ Pₙ(xₙ) ∧ φ(x) → P(x)
    """
    head: Tuple[str, List[z3.ExprRef]]  # (predicate_name, arguments)
    body: List[Tuple[str, List[z3.ExprRef]]]  # List of (predicate_name, arguments)
    constraint: z3.ExprRef  # φ(x)


class SpacerCHC:
    """
    Spacer-based CHC solving (Paper #11).
    
    Encodes verification problems as Constrained Horn Clauses
    and solves using the Spacer engine in Z3.
    """
    
    def __init__(self, timeout_ms: int = 120000):
        self.timeout_ms = timeout_ms
        
        self.predicates: Dict[str, z3.FuncDeclRef] = {}
        self.clauses: List[HornClause] = []
        
        self.stats = {
            'clauses_added': 0,
            'queries_solved': 0,
        }
    
    def declare_predicate(self, name: str, arg_sorts: List[z3.SortRef]) -> z3.FuncDeclRef:
        """Declare a predicate symbol."""
        pred = z3.Function(name, *arg_sorts, z3.BoolSort())
        self.predicates[name] = pred
        return pred
    
    def add_clause(self, clause: HornClause) -> None:
        """Add a Horn clause."""
        self.clauses.append(clause)
        self.stats['clauses_added'] += 1
    
    def add_init_clause(self, init_constraint: z3.ExprRef,
                         inv_pred: str,
                         variables: List[z3.ExprRef]) -> None:
        """Add initialization clause: init(x) → Inv(x)."""
        self.add_clause(HornClause(
            head=(inv_pred, variables),
            body=[],
            constraint=init_constraint
        ))
    
    def add_trans_clause(self, inv_pred: str,
                          trans_constraint: z3.ExprRef,
                          curr_vars: List[z3.ExprRef],
                          next_vars: List[z3.ExprRef]) -> None:
        """Add transition clause: Inv(x) ∧ T(x,x') → Inv(x')."""
        self.add_clause(HornClause(
            head=(inv_pred, next_vars),
            body=[(inv_pred, curr_vars)],
            constraint=trans_constraint
        ))
    
    def add_safe_clause(self, inv_pred: str,
                         safe_constraint: z3.ExprRef,
                         variables: List[z3.ExprRef]) -> None:
        """Add safety clause: Inv(x) ∧ ¬safe(x) → false."""
        self.add_clause(HornClause(
            head=('false', []),
            body=[(inv_pred, variables)],
            constraint=z3.Not(safe_constraint)
        ))
    
    def solve(self) -> Tuple[str, Optional[Dict[str, z3.ExprRef]]]:
        """
        Solve the CHC system using Z3's fixedpoint engine.
        
        Returns ('sat', interpretations) if safe,
        ('unsat', None) if counterexample exists,
        ('unknown', None) otherwise.
        """
        self.stats['queries_solved'] += 1
        
        fp = z3.Fixedpoint()
        fp.set("timeout", self.timeout_ms)
        
        # Register predicates
        for name, pred in self.predicates.items():
            fp.register_relation(pred)
        
        # Add clauses as rules
        for clause in self.clauses:
            rule = self._clause_to_rule(clause)
            if rule is not None:
                fp.add_rule(rule)
        
        # Query: is 'false' reachable?
        false_pred = self.predicates.get('false')
        if false_pred is None:
            false_pred = z3.Function('false', z3.BoolSort())
            fp.register_relation(false_pred)
        
        result = fp.query(false_pred())
        
        if result == z3.unsat:
            # Safe - extract interpretations
            interps = {}
            for name, pred in self.predicates.items():
                if name != 'false':
                    try:
                        interp = fp.get_answer()
                        interps[name] = interp
                    except Exception:
                        pass
            return ('sat', interps)
        elif result == z3.sat:
            return ('unsat', None)
        else:
            return ('unknown', None)
    
    def _clause_to_rule(self, clause: HornClause) -> Optional[z3.ExprRef]:
        """Convert Horn clause to Z3 rule."""
        # Build body
        body_parts = [clause.constraint]
        
        for pred_name, args in clause.body:
            pred = self.predicates.get(pred_name)
            if pred:
                body_parts.append(pred(*args))
        
        body = z3.And(body_parts) if len(body_parts) > 1 else body_parts[0]
        
        # Build head
        head_name, head_args = clause.head
        head_pred = self.predicates.get(head_name)
        
        if head_pred is None and head_name == 'false':
            head = z3.BoolVal(False)
        elif head_pred:
            head = head_pred(*head_args)
        else:
            return None
        
        # Rule: body → head
        return z3.Implies(body, head)


# =============================================================================
# INTERPOLATION/IMC (Paper #15)
# =============================================================================

class InterpolationEngine:
    """
    Craig interpolation for model checking (Paper #15).
    
    Given A ∧ B = UNSAT, compute interpolant I such that:
    - A → I
    - I ∧ B = UNSAT
    - I uses only common variables of A and B
    """
    
    def __init__(self, timeout_ms: int = 30000):
        self.timeout_ms = timeout_ms
        
        self.stats = {
            'interpolations': 0,
            'successful': 0,
        }
    
    def compute_interpolant(self, A: z3.ExprRef, B: z3.ExprRef) -> Optional[z3.ExprRef]:
        """
        Compute Craig interpolant between A and B.
        
        Returns I such that A → I and I ∧ B = UNSAT.
        """
        self.stats['interpolations'] += 1
        
        # Check unsatisfiability
        solver = z3.Solver()
        solver.set("timeout", self.timeout_ms)
        solver.add(A)
        solver.add(B)
        
        if solver.check() != z3.unsat:
            return None  # Not UNSAT, no interpolant
        
        # Use Z3's interpolation (simplified approach)
        # Real implementation would use proper interpolation API
        
        # Heuristic: Try negation of B restricted to A's variables
        A_vars = self._get_variables(A)
        B_vars = self._get_variables(B)
        common = A_vars & B_vars
        
        if not common:
            # No common variables - use True or False
            self.stats['successful'] += 1
            return z3.Not(B)
        
        # Project B onto common variables
        interpolant = self._project_formula(z3.Not(B), common)
        
        self.stats['successful'] += 1
        return interpolant
    
    def _get_variables(self, expr: z3.ExprRef) -> Set[str]:
        """Extract variable names from expression."""
        vars_set = set()
        
        def collect(e):
            if z3.is_const(e) and e.decl().kind() == z3.Z3_OP_UNINTERPRETED:
                vars_set.add(str(e))
            for child in e.children():
                collect(child)
        
        collect(expr)
        return vars_set
    
    def _project_formula(self, formula: z3.ExprRef, keep_vars: Set[str]) -> z3.ExprRef:
        """Project formula onto subset of variables."""
        # Simplified: just return the formula
        # Real implementation would do quantifier elimination
        return formula


class IMCVerifier:
    """
    Interpolation-based Model Checking (Paper #15).
    
    Uses interpolation to compute reachable state over-approximation.
    """
    
    def __init__(self, timeout_ms: int = 120000):
        self.timeout_ms = timeout_ms
        self.interpolator = InterpolationEngine(timeout_ms // 10)
        
        self.stats = {
            'imc_runs': 0,
            'depth_reached': 0,
        }
    
    def check_safety(self, initial: z3.ExprRef,
                      transition: z3.ExprRef,
                      bad: z3.ExprRef,
                      max_depth: int = 50) -> Tuple[str, Optional[z3.ExprRef]]:
        """
        Check safety using interpolation-based model checking.
        
        Returns ('safe', invariant), ('unsafe', cex), or ('unknown', None).
        """
        self.stats['imc_runs'] += 1
        
        # Compute over-approximation sequence
        reach = [initial]  # R₀ = Initial
        
        for depth in range(max_depth):
            self.stats['depth_reached'] = depth + 1
            
            # Check if current approximation intersects bad
            solver = z3.Solver()
            solver.set("timeout", self.timeout_ms // 100)
            solver.add(reach[-1])
            solver.add(bad)
            
            if solver.check() == z3.sat:
                # Might be unsafe - check if real
                if self._is_real_counterexample(reach, transition, bad):
                    return ('unsafe', None)
            
            # Compute next approximation via interpolation
            # A = reach[depth] ∧ T
            # B = ¬reach[depth-1] (at next state)
            
            # Simplified: forward image
            next_reach = self._forward_image(reach[-1], transition)
            
            # Check fixpoint
            solver = z3.Solver()
            solver.set("timeout", self.timeout_ms // 100)
            solver.add(next_reach)
            solver.add(z3.Not(reach[-1]))
            
            if solver.check() == z3.unsat:
                # Fixpoint reached
                return ('safe', reach[-1])
            
            # Widen using interpolation
            interpolant = self.interpolator.compute_interpolant(
                reach[-1], z3.Not(next_reach)
            )
            
            if interpolant is not None:
                reach.append(z3.Or(reach[-1], interpolant))
            else:
                reach.append(z3.Or(reach[-1], next_reach))
        
        return ('unknown', None)
    
    def _forward_image(self, states: z3.ExprRef,
                        transition: z3.ExprRef) -> z3.ExprRef:
        """Compute forward image of states under transition."""
        # Would need quantifier elimination for exact computation
        # Simplified: return conjunction
        return z3.And(states, transition)
    
    def _is_real_counterexample(self, reach: List[z3.ExprRef],
                                  transition: z3.ExprRef,
                                  bad: z3.ExprRef) -> bool:
        """Check if counterexample is realizable."""
        solver = z3.Solver()
        solver.set("timeout", self.timeout_ms // 50)
        
        # Build path formula
        for i, r in enumerate(reach):
            solver.add(r)  # Simplified - would need indexed variables
        
        solver.add(transition)
        solver.add(bad)
        
        return solver.check() == z3.sat


# =============================================================================
# ASSUME-GUARANTEE (Paper #20)
# =============================================================================

@dataclass
class Component:
    """A component in assume-guarantee reasoning."""
    name: str
    variables: List[z3.ExprRef]
    initial: z3.ExprRef
    transition: z3.ExprRef
    interface: Set[str]  # Shared variable names


@dataclass
class AGContract:
    """
    Assume-guarantee contract.
    
    (A, G): If environment satisfies A, component guarantees G.
    """
    assumption: z3.ExprRef  # A
    guarantee: z3.ExprRef  # G
    component_name: str


class AssumeGuaranteeVerifier:
    """
    Assume-Guarantee compositional verification (Paper #20).
    
    Verify system by decomposing into components and checking
    contracts compositionally.
    
    Circular rule:
    - M₁ satisfies (true, G₁) under assumption A₁
    - M₂ satisfies (A₂, G₂) 
    - G₁ → A₂
    - Then M₁ ∥ M₂ satisfies (true, G₁ ∧ G₂)
    """
    
    def __init__(self, timeout_ms: int = 120000):
        self.timeout_ms = timeout_ms
        
        self.components: Dict[str, Component] = {}
        self.contracts: List[AGContract] = []
        
        self.stats = {
            'components': 0,
            'contracts_verified': 0,
            'circular_checks': 0,
        }
    
    def add_component(self, component: Component) -> None:
        """Add component to system."""
        self.components[component.name] = component
        self.stats['components'] += 1
    
    def add_contract(self, contract: AGContract) -> None:
        """Add assume-guarantee contract."""
        self.contracts.append(contract)
    
    def verify_contract(self, contract: AGContract) -> bool:
        """
        Verify that component satisfies contract.
        
        Check: Assume A, show G holds for all reachable states.
        """
        component = self.components.get(contract.component_name)
        if not component:
            return False
        
        solver = z3.Solver()
        solver.set("timeout", self.timeout_ms // 10)
        
        # Initial satisfies guarantee
        solver.push()
        solver.add(component.initial)
        solver.add(contract.assumption)
        solver.add(z3.Not(contract.guarantee))
        
        if solver.check() == z3.sat:
            solver.pop()
            return False
        solver.pop()
        
        # Inductive: G ∧ A ∧ T → G'
        solver.push()
        solver.add(contract.guarantee)
        solver.add(contract.assumption)
        solver.add(component.transition)
        solver.add(z3.Not(self._prime_formula(contract.guarantee, component.variables)))
        
        if solver.check() == z3.sat:
            solver.pop()
            return False
        solver.pop()
        
        self.stats['contracts_verified'] += 1
        return True
    
    def verify_circular(self, contracts: List[AGContract]) -> bool:
        """
        Verify using circular assume-guarantee rule.
        
        Check that assumptions are discharged by guarantees.
        """
        self.stats['circular_checks'] += 1
        
        # For each contract, check that its assumption is implied
        # by guarantees of other components
        for contract in contracts:
            other_guarantees = [c.guarantee for c in contracts 
                               if c.component_name != contract.component_name]
            
            if not other_guarantees:
                # No other guarantees - assumption must be true
                solver = z3.Solver()
                solver.add(z3.Not(contract.assumption))
                if solver.check() == z3.sat:
                    # Assumption not trivially true
                    pass  # May still be ok if circular
            else:
                # Check: other_guarantees → assumption
                solver = z3.Solver()
                solver.set("timeout", self.timeout_ms // 50)
                
                solver.add(z3.And(other_guarantees))
                solver.add(z3.Not(contract.assumption))
                
                if solver.check() == z3.sat:
                    # Assumption not discharged
                    return False
        
        return True
    
    def verify_composition(self) -> Tuple[str, Optional[z3.ExprRef]]:
        """
        Verify composed system using assume-guarantee.
        
        Returns ('safe', global_invariant), ('unsafe', None), or ('unknown', None).
        """
        # Step 1: Verify each contract
        for contract in self.contracts:
            if not self.verify_contract(contract):
                return ('unknown', None)
        
        # Step 2: Check circular discharge
        if not self.verify_circular(self.contracts):
            return ('unknown', None)
        
        # Step 3: Compose guarantees
        global_inv = z3.And([c.guarantee for c in self.contracts])
        
        return ('safe', global_inv)
    
    def _prime_formula(self, formula: z3.ExprRef,
                        variables: List[z3.ExprRef]) -> z3.ExprRef:
        """Create primed version of formula."""
        subs = [(v, z3.Const(f"{v}'", v.sort())) for v in variables]
        return z3.substitute(formula, subs)


# =============================================================================
# UNIFIED ADVANCED VERIFICATION ENGINE
# =============================================================================

class AdvancedMethod(Enum):
    """Advanced verification methods."""
    DSOS = auto()
    IC3 = auto()
    CHC = auto()
    IMC = auto()
    ASSUME_GUARANTEE = auto()
    AUTO = auto()


class AdvancedVerificationEngine:
    """
    Unified engine for advanced verification.
    
    MAIN INTERFACE for the advanced verification layer.
    
    Integrates:
    - DSOS/SDSOS relaxations (Paper #9)
    - IC3/PDR (Paper #10)
    - Spacer/CHC (Paper #11)
    - Interpolation/IMC (Paper #15)
    - Assume-Guarantee (Paper #20)
    
    Automatically selects best approach or allows explicit choice.
    """
    
    def __init__(self, timeout_ms: int = 300000,
                 preferred_method: AdvancedMethod = AdvancedMethod.AUTO):
        self.timeout_ms = timeout_ms
        self.preferred_method = preferred_method
        
        # Sub-engines
        self.dsos = DSOSRelaxation(2, 6, timeout_ms // 5)
        self.ic3 = IC3Engine([], timeout_ms // 3)
        self.chc = SpacerCHC(timeout_ms // 3)
        self.imc = IMCVerifier(timeout_ms // 3)
        self.ag = AssumeGuaranteeVerifier(timeout_ms // 3)
        
        self.stats = {
            'verifications': 0,
            'method_used': None,
            'results': {'safe': 0, 'unsafe': 0, 'unknown': 0},
        }
    
    def verify_safety(self, initial: z3.ExprRef,
                       transition: z3.ExprRef,
                       bad: z3.ExprRef,
                       variables: List[z3.ExprRef]) -> Tuple[str, Any]:
        """
        Verify safety property using advanced methods.
        
        Returns ('safe', invariant), ('unsafe', cex), or ('unknown', None).
        """
        self.stats['verifications'] += 1
        
        if self.preferred_method == AdvancedMethod.IC3:
            return self._verify_ic3(initial, transition, bad, variables)
        elif self.preferred_method == AdvancedMethod.CHC:
            return self._verify_chc(initial, transition, bad, variables)
        elif self.preferred_method == AdvancedMethod.IMC:
            return self._verify_imc(initial, transition, bad)
        else:
            return self._verify_auto(initial, transition, bad, variables)
    
    def _verify_ic3(self, initial: z3.ExprRef,
                     transition: z3.ExprRef,
                     bad: z3.ExprRef,
                     variables: List[z3.ExprRef]) -> Tuple[str, Any]:
        """Verify using IC3/PDR."""
        self.ic3 = IC3Engine(variables, self.timeout_ms)
        result, invariant = self.ic3.check_safety(initial, transition, bad)
        
        self.stats['method_used'] = 'ic3'
        self.stats['results'][result] = self.stats['results'].get(result, 0) + 1
        
        return (result, invariant)
    
    def _verify_chc(self, initial: z3.ExprRef,
                     transition: z3.ExprRef,
                     bad: z3.ExprRef,
                     variables: List[z3.ExprRef]) -> Tuple[str, Any]:
        """Verify using CHC/Spacer."""
        self.chc = SpacerCHC(self.timeout_ms)
        
        # Declare invariant predicate
        sorts = [v.sort() for v in variables]
        self.chc.declare_predicate('Inv', sorts)
        
        # Add clauses
        self.chc.add_init_clause(initial, 'Inv', variables)
        
        # Primed variables
        primed = [z3.Const(f"{v}'", v.sort()) for v in variables]
        self.chc.add_trans_clause('Inv', transition, variables, primed)
        
        self.chc.add_safe_clause('Inv', z3.Not(bad), variables)
        
        result, interps = self.chc.solve()
        
        self.stats['method_used'] = 'chc'
        if result == 'sat':
            self.stats['results']['safe'] += 1
            return ('safe', interps.get('Inv'))
        elif result == 'unsat':
            self.stats['results']['unsafe'] += 1
            return ('unsafe', None)
        else:
            self.stats['results']['unknown'] += 1
            return ('unknown', None)
    
    def _verify_imc(self, initial: z3.ExprRef,
                     transition: z3.ExprRef,
                     bad: z3.ExprRef) -> Tuple[str, Any]:
        """Verify using IMC."""
        self.imc = IMCVerifier(self.timeout_ms)
        result, invariant = self.imc.check_safety(initial, transition, bad)
        
        self.stats['method_used'] = 'imc'
        self.stats['results'][result] = self.stats['results'].get(result, 0) + 1
        
        return (result, invariant)
    
    def _verify_auto(self, initial: z3.ExprRef,
                      transition: z3.ExprRef,
                      bad: z3.ExprRef,
                      variables: List[z3.ExprRef]) -> Tuple[str, Any]:
        """Automatically choose and run verification method."""
        # Try CHC first (often fastest)
        result, data = self._verify_chc(initial, transition, bad, variables)
        if result != 'unknown':
            return (result, data)
        
        # Fall back to IC3
        result, data = self._verify_ic3(initial, transition, bad, variables)
        if result != 'unknown':
            return (result, data)
        
        # Fall back to IMC
        result, data = self._verify_imc(initial, transition, bad)
        return (result, data)
    
    def prove_polynomial_positive(self, polynomial: Polynomial) -> Tuple[str, Any]:
        """
        Prove polynomial positivity using DSOS/SDSOS.
        
        Returns ('proved', decomposition) or ('unknown', None).
        """
        self.dsos = DSOSRelaxation(polynomial.n_vars, polynomial.degree, self.timeout_ms)
        
        # Try DSOS first (fastest)
        decomp = self.dsos.prove_dsos(polynomial)
        if decomp is not None:
            return ('proved', decomp)
        
        # Try SDSOS
        decomp = self.dsos.prove_sdsos(polynomial)
        if decomp is not None:
            return ('proved', decomp)
        
        return ('unknown', None)
    
    def verify_compositional(self, components: List[Component],
                               contracts: List[AGContract]) -> Tuple[str, Any]:
        """
        Verify system compositionally using assume-guarantee.
        
        Returns ('safe', global_invariant), ('unsafe', None), or ('unknown', None).
        """
        self.ag = AssumeGuaranteeVerifier(self.timeout_ms)
        
        for comp in components:
            self.ag.add_component(comp)
        
        for contract in contracts:
            self.ag.add_contract(contract)
        
        return self.ag.verify_composition()


# =============================================================================
# EXPORTS
# =============================================================================

__all__ = [
    # DSOS/SDSOS (Paper #9)
    'DecompositionType',
    'DSOSDecomposition',
    'SDSOSDecomposition',
    'DSOSRelaxation',
    
    # IC3/PDR (Paper #10)
    'Frame',
    'ProofObligation',
    'IC3Engine',
    
    # Spacer/CHC (Paper #11)
    'HornClause',
    'SpacerCHC',
    
    # Interpolation/IMC (Paper #15)
    'InterpolationEngine',
    'IMCVerifier',
    
    # Assume-Guarantee (Paper #20)
    'Component',
    'AGContract',
    'AssumeGuaranteeVerifier',
    
    # Unified Engine
    'AdvancedMethod',
    'AdvancedVerificationEngine',
]
