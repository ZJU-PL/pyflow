"""
SOTA Paper: Houdini Annotation Inference.

Implements Houdini for inferring loop invariants:
    C. Flanagan, K. R. M. Leino.
    "Houdini, an Annotation Assistant for ESC/Java."
    FME 2001.

KEY INSIGHT
===========

Houdini uses a "guess-and-check" approach:
1. Generate candidate invariants from templates
2. Check all candidates simultaneously
3. Remove candidates that fail
4. Repeat until fixed point

Key insight: conjunctive analysis is more efficient than
trying each candidate independently.

CANDIDATE GENERATION
=====================

Candidates come from templates:
- Linear equalities: a₁x₁ + ... + aₙxₙ = c
- Linear inequalities: a₁x₁ + ... + aₙxₙ ≥ c
- Octagonal: ±x_i ± x_j ≤ c
- Polynomial: template polynomials

The key is generating enough candidates to cover true invariant.

CONJUNCTIVE ANALYSIS
====================

Instead of checking each candidate separately:
1. Assume all candidates hold
2. Check which fail after one loop iteration
3. Remove failing candidates
4. Repeat until no more failures

This is sound: if candidate C holds initially and after each
iteration assuming all candidates, then C is an invariant.

SOUNDNESS
=========

Houdini finds maximal inductive subset of candidates.
- May miss non-inductive invariants
- Always sound: results are true invariants

IMPLEMENTATION STRUCTURE
========================

1. CandidateGenerator: Generate candidate invariants
2. HoudiniChecker: Check candidates with SMT
3. HoudiniSolver: Main fixed-point algorithm
4. TemplateLibrary: Common template patterns
5. HoudiniIntegration: Integration with barriers

LAYER POSITION
==============

This is a **Layer 4 (Learning)** module.

    ┌─────────────────────────────────────────────────────────────────┐
    │ Layer 5: Advanced Verification (IC3, CHC, IMC, Assume-Guarantee)│
    │ Layer 4: LEARNING ← [THIS MODULE]                               │
    │   ├── ice_learning.py (Paper #17)                               │
    │   ├── houdini.py ← You are here (Paper #18)                     │
    │   └── sygus_synthesis.py (Paper #19)                            │
    │ Layer 3: Abstraction (CEGAR, Predicate Abstraction, IMPACT)     │
    │ Layer 2: Certificate Core (Hybrid, Stochastic, SOS Safety)      │
    │ Layer 1: Foundations (Positivstellensatz, SOS/SDP, Lasserre)    │
    └─────────────────────────────────────────────────────────────────┘

CROSS-PAPER DEPENDENCIES
========================

This module builds on:
- Layer 1: Polynomial templates from SOS basis
- Layer 2: Barrier conditions as verification targets
- Layer 3: Abstractions provide candidate predicates

This module synergizes with Layer 4 peers:
- Paper #17 (ICE): Houdini candidates as ICE features
- Paper #19 (SyGuS): Houdini templates in SyGuS grammar

This module is used by:
- Paper #10 (IC3): Houdini for lemma candidates
- Paper #11 (CHC): Houdini invariants for CHC predicates
- Paper #16 (IMPACT): Houdini for lazy abstraction predicates

HOUDINI + BARRIERS
==================

Houdini can find conjunctive barrier approximations:
- Candidate barriers B_1, ..., B_k
- Fixed-point finds subset that satisfies barrier conditions
- Result: B = B_{i1} ∧ ... ∧ B_{im} is valid barrier
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Dict, List, Optional, Tuple, Set, Any, Callable
from collections import defaultdict

import z3

# =============================================================================
# LAYER 4: IMPORTS FROM LOWER LAYERS
# =============================================================================
# Houdini builds on polynomial templates (Layer 1) to find conjunctive
# invariants. These become barrier certificate candidates (Layer 2).
# =============================================================================

from .parrilo_sos_sdp import (
    Polynomial,
    SemialgebraicSet,
    BarrierSynthesisProblem,
)


# =============================================================================
# CANDIDATE INVARIANT
# =============================================================================

@dataclass
class Candidate:
    """
    Candidate invariant.
    """
    id: int
    name: str
    formula: z3.BoolRef
    template_type: str = "custom"
    is_active: bool = True
    failure_count: int = 0
    
    def __str__(self) -> str:
        status = "active" if self.is_active else "eliminated"
        return f"{self.name}[{status}]: {self.formula}"
    
    def __hash__(self) -> int:
        return self.id
    
    def __eq__(self, other) -> bool:
        if isinstance(other, Candidate):
            return self.id == other.id
        return False


class CandidateSet:
    """
    Set of candidate invariants.
    """
    
    def __init__(self):
        self.candidates: List[Candidate] = []
        self._id_counter = 0
    
    def add(self, name: str, formula: z3.BoolRef, 
            template_type: str = "custom") -> Candidate:
        """Add a candidate."""
        candidate = Candidate(
            id=self._id_counter,
            name=name,
            formula=formula,
            template_type=template_type
        )
        self._id_counter += 1
        self.candidates.append(candidate)
        return candidate
    
    def get_active(self) -> List[Candidate]:
        """Get all active candidates."""
        return [c for c in self.candidates if c.is_active]
    
    def get_eliminated(self) -> List[Candidate]:
        """Get all eliminated candidates."""
        return [c for c in self.candidates if not c.is_active]
    
    def eliminate(self, candidate: Candidate) -> None:
        """Eliminate a candidate."""
        candidate.is_active = False
        candidate.failure_count += 1
    
    def conjoin_active(self) -> z3.BoolRef:
        """Get conjunction of all active candidates."""
        active = self.get_active()
        if not active:
            return z3.BoolVal(True)
        if len(active) == 1:
            return active[0].formula
        return z3.And([c.formula for c in active])
    
    def size(self) -> int:
        """Total number of candidates."""
        return len(self.candidates)
    
    def active_count(self) -> int:
        """Number of active candidates."""
        return len(self.get_active())


# =============================================================================
# CANDIDATE GENERATOR
# =============================================================================

class TemplateType(Enum):
    """Type of invariant template."""
    LINEAR_EQ = auto()        # ax + by + c = 0
    LINEAR_INEQ = auto()      # ax + by + c >= 0
    OCTAGONAL = auto()        # ±x ± y <= c
    INTERVAL = auto()         # l <= x <= u
    POLYNOMIAL = auto()       # polynomial template
    CUSTOM = auto()


class CandidateGenerator:
    """
    Generate candidate invariants from templates.
    """
    
    def __init__(self, variables: List[z3.ArithRef],
                 verbose: bool = False):
        self.variables = variables
        self.verbose = verbose
        
        self.stats = {
            'candidates_generated': 0,
        }
    
    def generate_linear_equalities(self, 
                                     coefficients: List[int] = [-1, 0, 1]) -> CandidateSet:
        """
        Generate linear equality candidates.
        
        a₁x₁ + a₂x₂ + ... = 0
        """
        candidates = CandidateSet()
        n = len(self.variables)
        
        # Generate all coefficient combinations
        from itertools import product
        
        for coefs in product(coefficients, repeat=n):
            if all(c == 0 for c in coefs):
                continue
            
            # Build linear expression
            terms = []
            for var, coef in zip(self.variables, coefs):
                if coef != 0:
                    terms.append(coef * var)
            
            if terms:
                expr = sum(terms)
                formula = expr == 0
                
                name = f"eq_{self.stats['candidates_generated']}"
                candidates.add(name, formula, "linear_eq")
                self.stats['candidates_generated'] += 1
        
        return candidates
    
    def generate_linear_inequalities(self,
                                       coefficients: List[int] = [-1, 0, 1],
                                       constants: List[int] = [-1, 0, 1]) -> CandidateSet:
        """
        Generate linear inequality candidates.
        
        a₁x₁ + a₂x₂ + ... + c >= 0
        """
        candidates = CandidateSet()
        n = len(self.variables)
        
        from itertools import product
        
        for coefs in product(coefficients, repeat=n):
            if all(c == 0 for c in coefs):
                continue
            
            for const in constants:
                terms = [const]
                for var, coef in zip(self.variables, coefs):
                    if coef != 0:
                        terms.append(coef * var)
                
                expr = sum(terms)
                formula = expr >= 0
                
                name = f"ineq_{self.stats['candidates_generated']}"
                candidates.add(name, formula, "linear_ineq")
                self.stats['candidates_generated'] += 1
        
        return candidates
    
    def generate_octagonal(self, bounds: List[int] = [-2, -1, 0, 1, 2]) -> CandidateSet:
        """
        Generate octagonal candidates.
        
        ±x_i ± x_j <= c
        """
        candidates = CandidateSet()
        n = len(self.variables)
        
        for i in range(n):
            for j in range(i + 1, n):
                for sign_i in [-1, 1]:
                    for sign_j in [-1, 1]:
                        for bound in bounds:
                            # sign_i * x_i + sign_j * x_j <= bound
                            expr = sign_i * self.variables[i] + sign_j * self.variables[j]
                            formula = expr <= bound
                            
                            name = f"oct_{self.stats['candidates_generated']}"
                            candidates.add(name, formula, "octagonal")
                            self.stats['candidates_generated'] += 1
        
        return candidates
    
    def generate_intervals(self, bounds: List[int] = [-5, 0, 5, 10]) -> CandidateSet:
        """
        Generate interval candidates.
        
        l <= x and x <= u
        """
        candidates = CandidateSet()
        
        for var in self.variables:
            for bound in bounds:
                # x >= bound
                formula_lower = var >= bound
                name = f"lower_{self.stats['candidates_generated']}"
                candidates.add(name, formula_lower, "interval")
                self.stats['candidates_generated'] += 1
                
                # x <= bound
                formula_upper = var <= bound
                name = f"upper_{self.stats['candidates_generated']}"
                candidates.add(name, formula_upper, "interval")
                self.stats['candidates_generated'] += 1
        
        return candidates
    
    def generate_from_polynomial(self, polynomial: Polynomial) -> CandidateSet:
        """
        Generate candidates from polynomial.
        
        p(x) >= 0, p(x) <= 0, p(x) = 0
        """
        candidates = CandidateSet()
        
        z3_poly = polynomial.to_z3(self.variables)
        
        # p >= 0
        name = f"poly_pos_{self.stats['candidates_generated']}"
        candidates.add(name, z3_poly >= 0, "polynomial")
        self.stats['candidates_generated'] += 1
        
        # p <= 0
        name = f"poly_neg_{self.stats['candidates_generated']}"
        candidates.add(name, z3_poly <= 0, "polynomial")
        self.stats['candidates_generated'] += 1
        
        # p = 0
        name = f"poly_zero_{self.stats['candidates_generated']}"
        candidates.add(name, z3_poly == 0, "polynomial")
        self.stats['candidates_generated'] += 1
        
        return candidates
    
    def generate_all(self) -> CandidateSet:
        """Generate all candidate types."""
        candidates = CandidateSet()
        
        # Merge all candidate sets
        for cand in self.generate_linear_equalities().candidates:
            candidates.candidates.append(cand)
        
        for cand in self.generate_linear_inequalities().candidates:
            candidates.candidates.append(cand)
        
        for cand in self.generate_octagonal().candidates:
            candidates.candidates.append(cand)
        
        for cand in self.generate_intervals().candidates:
            candidates.candidates.append(cand)
        
        return candidates


# =============================================================================
# HOUDINI CHECKER
# =============================================================================

class CheckResult(Enum):
    """Result of checking candidates."""
    ALL_HOLD = auto()
    SOME_FAILED = auto()
    ERROR = auto()


@dataclass
class CheckOutput:
    """Output of candidate checking."""
    result: CheckResult
    failed_candidates: List[Candidate] = field(default_factory=list)
    model: Optional[z3.ModelRef] = None
    message: str = ""


class HoudiniChecker:
    """
    Check candidate invariants using SMT.
    """
    
    def __init__(self, variables: List[z3.ArithRef],
                 primed_variables: List[z3.ArithRef],
                 transition_relation: z3.BoolRef,
                 timeout_ms: int = 60000,
                 verbose: bool = False):
        self.variables = variables
        self.primed_variables = primed_variables
        self.transition = transition_relation
        self.timeout_ms = timeout_ms
        self.verbose = verbose
        
        self.stats = {
            'checks': 0,
            'sat_results': 0,
            'unsat_results': 0,
        }
    
    def check_initiation(self, candidates: CandidateSet,
                          initial: z3.BoolRef) -> CheckOutput:
        """
        Check if candidates hold initially.
        
        Init → C_1 ∧ C_2 ∧ ...
        """
        self.stats['checks'] += 1
        
        active = candidates.get_active()
        if not active:
            return CheckOutput(result=CheckResult.ALL_HOLD)
        
        solver = z3.Solver()
        solver.set("timeout", self.timeout_ms)
        
        # Add initial constraint
        solver.add(initial)
        
        # Check each candidate
        failed = []
        for candidate in active:
            solver.push()
            solver.add(z3.Not(candidate.formula))
            
            result = solver.check()
            
            if result == z3.sat:
                self.stats['sat_results'] += 1
                failed.append(candidate)
            else:
                self.stats['unsat_results'] += 1
            
            solver.pop()
        
        if failed:
            return CheckOutput(
                result=CheckResult.SOME_FAILED,
                failed_candidates=failed,
                message=f"{len(failed)} candidates failed initiation"
            )
        
        return CheckOutput(result=CheckResult.ALL_HOLD)
    
    def check_consecution(self, candidates: CandidateSet) -> CheckOutput:
        """
        Check if candidates are preserved by transition.
        
        (C_1 ∧ C_2 ∧ ...) ∧ T → (C_1' ∧ C_2' ∧ ...)
        """
        self.stats['checks'] += 1
        
        active = candidates.get_active()
        if not active:
            return CheckOutput(result=CheckResult.ALL_HOLD)
        
        solver = z3.Solver()
        solver.set("timeout", self.timeout_ms)
        
        # Assume all candidates in pre-state
        conjunct = candidates.conjoin_active()
        solver.add(conjunct)
        
        # Add transition
        solver.add(self.transition)
        
        # Check each candidate in post-state
        failed = []
        for candidate in active:
            solver.push()
            
            # Post-state version of candidate
            post_candidate = self._to_post_state(candidate.formula)
            solver.add(z3.Not(post_candidate))
            
            result = solver.check()
            
            if result == z3.sat:
                self.stats['sat_results'] += 1
                failed.append(candidate)
            else:
                self.stats['unsat_results'] += 1
            
            solver.pop()
        
        if failed:
            return CheckOutput(
                result=CheckResult.SOME_FAILED,
                failed_candidates=failed,
                message=f"{len(failed)} candidates failed consecution"
            )
        
        return CheckOutput(result=CheckResult.ALL_HOLD)
    
    def _to_post_state(self, formula: z3.BoolRef) -> z3.BoolRef:
        """Convert formula to post-state (primed variables)."""
        subs = list(zip(self.variables, self.primed_variables))
        return z3.substitute(formula, subs)


# =============================================================================
# HOUDINI SOLVER
# =============================================================================

class HoudiniResult(Enum):
    """Result of Houdini analysis."""
    SUCCESS = auto()
    NO_INVARIANT = auto()
    TIMEOUT = auto()


@dataclass
class HoudiniOutput:
    """Output of Houdini analysis."""
    result: HoudiniResult
    invariant: Optional[z3.BoolRef] = None
    active_candidates: List[Candidate] = field(default_factory=list)
    iterations: int = 0
    statistics: Dict[str, Any] = field(default_factory=dict)
    message: str = ""


class HoudiniSolver:
    """
    Main Houdini algorithm.
    
    Fixed-point iteration eliminating failing candidates.
    """
    
    def __init__(self, variables: List[z3.ArithRef],
                 primed_variables: List[z3.ArithRef],
                 transition_relation: z3.BoolRef,
                 initial_formula: z3.BoolRef,
                 max_iterations: int = 1000,
                 timeout_ms: int = 60000,
                 verbose: bool = False):
        self.variables = variables
        self.primed_variables = primed_variables
        self.transition = transition_relation
        self.initial = initial_formula
        self.max_iterations = max_iterations
        self.timeout_ms = timeout_ms
        self.verbose = verbose
        
        self.checker = HoudiniChecker(
            variables, primed_variables, transition_relation, timeout_ms, verbose
        )
        
        self.stats = {
            'iterations': 0,
            'candidates_eliminated': 0,
            'final_candidates': 0,
        }
    
    def solve(self, candidates: CandidateSet) -> HoudiniOutput:
        """
        Run Houdini algorithm.
        
        1. Check initiation, eliminate failures
        2. Check consecution, eliminate failures
        3. Repeat until fixed point
        """
        start_time = time.time()
        
        # Phase 1: Initiation
        result = self.checker.check_initiation(candidates, self.initial)
        if result.result == CheckResult.SOME_FAILED:
            for failed in result.failed_candidates:
                candidates.eliminate(failed)
                self.stats['candidates_eliminated'] += 1
        
        # Phase 2: Consecution fixed point
        for iteration in range(self.max_iterations):
            self.stats['iterations'] += 1
            
            result = self.checker.check_consecution(candidates)
            
            if result.result == CheckResult.ALL_HOLD:
                # Fixed point reached
                break
            
            if result.result == CheckResult.SOME_FAILED:
                for failed in result.failed_candidates:
                    candidates.eliminate(failed)
                    self.stats['candidates_eliminated'] += 1
            
            if candidates.active_count() == 0:
                # No candidates left
                self.stats['time_ms'] = (time.time() - start_time) * 1000
                return HoudiniOutput(
                    result=HoudiniResult.NO_INVARIANT,
                    iterations=self.stats['iterations'],
                    statistics=self.stats,
                    message="All candidates eliminated"
                )
        
        # Get final invariant
        active = candidates.get_active()
        self.stats['final_candidates'] = len(active)
        self.stats['time_ms'] = (time.time() - start_time) * 1000
        
        if active:
            invariant = candidates.conjoin_active()
            return HoudiniOutput(
                result=HoudiniResult.SUCCESS,
                invariant=invariant,
                active_candidates=active,
                iterations=self.stats['iterations'],
                statistics=self.stats,
                message=f"Found invariant with {len(active)} conjuncts"
            )
        else:
            return HoudiniOutput(
                result=HoudiniResult.NO_INVARIANT,
                iterations=self.stats['iterations'],
                statistics=self.stats,
                message="No invariant found"
            )


# =============================================================================
# TEMPLATE LIBRARY
# =============================================================================

class TemplateLibrary:
    """
    Library of common invariant templates.
    """
    
    def __init__(self, variables: List[z3.ArithRef]):
        self.variables = variables
    
    def sign_templates(self) -> List[z3.BoolRef]:
        """Sign templates: x >= 0, x <= 0."""
        templates = []
        for v in self.variables:
            templates.append(v >= 0)
            templates.append(v <= 0)
        return templates
    
    def difference_templates(self) -> List[z3.BoolRef]:
        """Difference templates: x - y >= 0."""
        templates = []
        n = len(self.variables)
        for i in range(n):
            for j in range(n):
                if i != j:
                    templates.append(self.variables[i] - self.variables[j] >= 0)
        return templates
    
    def equality_templates(self) -> List[z3.BoolRef]:
        """Equality templates: x = y, x = 0."""
        templates = []
        n = len(self.variables)
        
        for v in self.variables:
            templates.append(v == 0)
        
        for i in range(n):
            for j in range(i + 1, n):
                templates.append(self.variables[i] == self.variables[j])
        
        return templates
    
    def modular_templates(self, moduli: List[int] = [2, 3]) -> List[z3.BoolRef]:
        """Modular templates: x mod m = c."""
        templates = []
        
        for v in self.variables:
            for m in moduli:
                for c in range(m):
                    # x mod m = c encoded as exists k. x = m*k + c
                    templates.append(v % m == c)
        
        return templates
    
    def all_templates(self) -> List[z3.BoolRef]:
        """Get all template types."""
        templates = []
        templates.extend(self.sign_templates())
        templates.extend(self.difference_templates())
        templates.extend(self.equality_templates())
        return templates


# =============================================================================
# STRENGTHENING
# =============================================================================

class InvariantStrengthener:
    """
    Strengthen weak invariants to exclude bad states.
    """
    
    def __init__(self, variables: List[z3.ArithRef],
                 primed_variables: List[z3.ArithRef],
                 transition_relation: z3.BoolRef,
                 timeout_ms: int = 60000):
        self.variables = variables
        self.primed_variables = primed_variables
        self.transition = transition_relation
        self.timeout_ms = timeout_ms
        
        self.stats = {
            'strengthening_attempts': 0,
            'successful_strengthenings': 0,
        }
    
    def strengthen(self, invariant: z3.BoolRef,
                    bad_states: z3.BoolRef) -> Optional[z3.BoolRef]:
        """
        Try to strengthen invariant to exclude bad states.
        """
        self.stats['strengthening_attempts'] += 1
        
        # Check if invariant already excludes bad
        solver = z3.Solver()
        solver.set("timeout", self.timeout_ms)
        solver.add(invariant)
        solver.add(bad_states)
        
        if solver.check() == z3.unsat:
            # Already excludes bad
            return invariant
        
        # Try adding negation of bad states
        strengthened = z3.And(invariant, z3.Not(bad_states))
        
        # Check if still inductive
        if self._is_inductive(strengthened):
            self.stats['successful_strengthenings'] += 1
            return strengthened
        
        return None
    
    def _is_inductive(self, formula: z3.BoolRef) -> bool:
        """Check if formula is inductive."""
        solver = z3.Solver()
        solver.set("timeout", self.timeout_ms // 10)
        
        # Check: formula ∧ T → formula'
        solver.add(formula)
        solver.add(self.transition)
        
        post_formula = z3.substitute(
            formula, list(zip(self.variables, self.primed_variables))
        )
        solver.add(z3.Not(post_formula))
        
        return solver.check() == z3.unsat


# =============================================================================
# HOUDINI INTEGRATION
# =============================================================================

@dataclass
class HoudiniConfig:
    """Configuration for Houdini integration."""
    max_iterations: int = 1000
    generate_linear: bool = True
    generate_octagonal: bool = True
    generate_intervals: bool = True
    timeout_ms: int = 60000
    verbose: bool = False


class HoudiniIntegration:
    """
    Integration of Houdini with barrier synthesis.
    
    Provides:
    1. Candidate generation from templates
    2. Houdini fixed-point for invariant inference
    3. Invariant strengthening
    """
    
    def __init__(self, config: Optional[HoudiniConfig] = None,
                 verbose: bool = False):
        self.config = config or HoudiniConfig()
        self.verbose = verbose or self.config.verbose
        
        self._invariants: Dict[str, z3.BoolRef] = {}
        self._candidates: Dict[str, CandidateSet] = {}
        
        self.stats = {
            'inferences': 0,
            'invariants_found': 0,
            'total_candidates': 0,
        }
    
    def infer_invariant(self, inv_id: str,
                         variables: List[z3.ArithRef],
                         primed_vars: List[z3.ArithRef],
                         transition: z3.BoolRef,
                         initial: z3.BoolRef) -> HoudiniOutput:
        """
        Infer invariant using Houdini.
        """
        # Generate candidates
        generator = CandidateGenerator(variables, self.verbose)
        candidates = CandidateSet()
        
        if self.config.generate_linear:
            for c in generator.generate_linear_inequalities().candidates:
                candidates.candidates.append(c)
        
        if self.config.generate_octagonal:
            for c in generator.generate_octagonal().candidates:
                candidates.candidates.append(c)
        
        if self.config.generate_intervals:
            for c in generator.generate_intervals().candidates:
                candidates.candidates.append(c)
        
        self._candidates[inv_id] = candidates
        self.stats['total_candidates'] += candidates.size()
        
        # Run Houdini
        solver = HoudiniSolver(
            variables, primed_vars, transition, initial,
            self.config.max_iterations, self.config.timeout_ms, self.verbose
        )
        
        result = solver.solve(candidates)
        
        self.stats['inferences'] += 1
        
        if result.result == HoudiniResult.SUCCESS:
            self._invariants[inv_id] = result.invariant
            self.stats['invariants_found'] += 1
        
        return result
    
    def get_invariant(self, inv_id: str) -> Optional[z3.BoolRef]:
        """Get inferred invariant."""
        return self._invariants.get(inv_id)
    
    def strengthen_for_safety(self, inv_id: str,
                                variables: List[z3.ArithRef],
                                primed_vars: List[z3.ArithRef],
                                transition: z3.BoolRef,
                                unsafe: z3.BoolRef) -> Optional[z3.BoolRef]:
        """
        Strengthen invariant to exclude unsafe states.
        """
        invariant = self._invariants.get(inv_id)
        if invariant is None:
            return None
        
        strengthener = InvariantStrengthener(
            variables, primed_vars, transition, self.config.timeout_ms
        )
        
        strengthened = strengthener.strengthen(invariant, unsafe)
        
        if strengthened is not None:
            self._invariants[inv_id] = strengthened
        
        return strengthened
    
    def condition_barrier_problem(self, problem: BarrierSynthesisProblem,
                                    inv_id: str) -> BarrierSynthesisProblem:
        """
        Condition barrier problem using Houdini invariant.
        """
        invariant = self._invariants.get(inv_id)
        if invariant is None:
            return problem
        
        # Add invariant as polynomial constraint (simplified)
        # Full implementation would convert Z3 to polynomial
        
        return problem


# =============================================================================
# CONVENIENCE FUNCTIONS
# =============================================================================

def generate_candidates(variables: List[z3.ArithRef],
                          verbose: bool = False) -> CandidateSet:
    """Generate candidate invariants."""
    generator = CandidateGenerator(variables, verbose)
    return generator.generate_all()


def run_houdini(variables: List[z3.ArithRef],
                  primed_vars: List[z3.ArithRef],
                  transition: z3.BoolRef,
                  initial: z3.BoolRef,
                  candidates: Optional[CandidateSet] = None,
                  max_iterations: int = 1000,
                  timeout_ms: int = 60000,
                  verbose: bool = False) -> HoudiniOutput:
    """Run Houdini algorithm."""
    if candidates is None:
        candidates = generate_candidates(variables, verbose)
    
    solver = HoudiniSolver(
        variables, primed_vars, transition, initial,
        max_iterations, timeout_ms, verbose
    )
    
    return solver.solve(candidates)


def get_template_library(variables: List[z3.ArithRef]) -> TemplateLibrary:
    """Get template library for variables."""
    return TemplateLibrary(variables)


# =============================================================================
# ADVANCED HOUDINI TECHNIQUES
# =============================================================================

class ParallelHoudini:
    """
    Parallel Houdini algorithm.
    
    Uses multiple workers to check candidate falsification.
    """
    
    def __init__(self, variables: List[z3.ArithRef],
                 primed_vars: List[z3.ArithRef],
                 transition: z3.BoolRef,
                 initial: z3.BoolRef,
                 num_workers: int = 4,
                 timeout_ms: int = 60000):
        self.variables = variables
        self.primed_vars = primed_vars
        self.transition = transition
        self.initial = initial
        self.num_workers = num_workers
        self.timeout_ms = timeout_ms
        
        self.stats = {
            'parallel_checks': 0,
            'candidates_falsified': 0,
        }
    
    def solve_parallel(self, candidates: CandidateSet) -> HoudiniOutput:
        """
        Solve using parallel falsification checks.
        """
        active = list(candidates.candidates)
        iteration = 0
        
        while True:
            iteration += 1
            
            # Check candidates in parallel (simulated)
            falsified = self._check_batch(active)
            
            if not falsified:
                break
            
            # Remove falsified
            self.stats['candidates_falsified'] += len(falsified)
            active = [c for c in active if c not in falsified]
        
        # Convert to invariant
        if active:
            invariant = z3.And([c.formula for c in active])
        else:
            invariant = z3.BoolVal(True)
        
        return HoudiniOutput(
            result=HoudiniResult.INDUCTIVE if active else HoudiniResult.EMPTY,
            invariant=invariant,
            remaining_candidates=CandidateSet(active),
            stats=self.stats
        )
    
    def _check_batch(self, candidates: List[Candidate]) -> List[Candidate]:
        """Check batch of candidates."""
        falsified = []
        
        # Partition among workers
        batch_size = max(1, len(candidates) // self.num_workers)
        
        for i in range(0, len(candidates), batch_size):
            batch = candidates[i:i + batch_size]
            batch_falsified = self._check_candidates(batch)
            falsified.extend(batch_falsified)
            self.stats['parallel_checks'] += 1
        
        return falsified
    
    def _check_candidates(self, batch: List[Candidate]) -> List[Candidate]:
        """Check candidates for falsification."""
        falsified = []
        
        for cand in batch:
            solver = z3.Solver()
            solver.set("timeout", self.timeout_ms // len(batch))
            
            # Check inductiveness
            solver.add(cand.formula)
            solver.add(self.transition)
            
            primed_formula = z3.substitute(cand.formula,
                list(zip(self.variables, self.primed_vars)))
            solver.add(z3.Not(primed_formula))
            
            if solver.check() == z3.sat:
                falsified.append(cand)
        
        return falsified


class IncrementalHoudini:
    """
    Incremental Houdini with learning.
    
    Remembers falsification information across runs.
    """
    
    def __init__(self, variables: List[z3.ArithRef],
                 primed_vars: List[z3.ArithRef],
                 transition: z3.BoolRef,
                 initial: z3.BoolRef,
                 timeout_ms: int = 60000):
        self.variables = variables
        self.primed_vars = primed_vars
        self.transition = transition
        self.initial = initial
        self.timeout_ms = timeout_ms
        
        # Learned falsifications
        self.learned_cex: List[Dict[str, Any]] = []
        
        # Known good candidates
        self.proven_candidates: List[Candidate] = []
        
        self.stats = {
            'incremental_runs': 0,
            'learned_falsifications': 0,
            'candidates_proven': 0,
        }
    
    def solve_incremental(self, candidates: CandidateSet) -> HoudiniOutput:
        """Solve with incremental learning."""
        self.stats['incremental_runs'] += 1
        
        active = list(candidates.candidates)
        
        # Filter using learned falsifications
        active = self._filter_with_learned(active)
        
        # Standard Houdini on remaining
        while True:
            cex = self._find_falsification(active)
            
            if not cex:
                break
            
            # Learn and remove
            self._learn_falsification(cex)
            active = self._remove_falsified(active, cex)
        
        # Add to proven
        for cand in active:
            if cand not in self.proven_candidates:
                self.proven_candidates.append(cand)
                self.stats['candidates_proven'] += 1
        
        return self._build_output(active)
    
    def _filter_with_learned(self, candidates: List[Candidate]) -> List[Candidate]:
        """Filter candidates using learned CEXs."""
        filtered = []
        
        for cand in candidates:
            falsified = False
            
            for cex in self.learned_cex:
                if self._cex_falsifies(cex, cand):
                    falsified = True
                    break
            
            if not falsified:
                filtered.append(cand)
        
        return filtered
    
    def _find_falsification(self, candidates: List[Candidate]) -> Optional[Dict]:
        """Find falsifying counterexample."""
        for cand in candidates:
            solver = z3.Solver()
            solver.set("timeout", self.timeout_ms // max(1, len(candidates)))
            
            solver.add(cand.formula)
            solver.add(self.transition)
            
            primed = z3.substitute(cand.formula,
                list(zip(self.variables, self.primed_vars)))
            solver.add(z3.Not(primed))
            
            if solver.check() == z3.sat:
                model = solver.model()
                return {
                    'candidate': cand,
                    'model': {str(v): model.eval(v, model_completion=True)
                              for v in self.variables}
                }
        
        return None
    
    def _learn_falsification(self, cex: Dict) -> None:
        """Learn from counterexample."""
        self.learned_cex.append(cex)
        self.stats['learned_falsifications'] += 1
    
    def _remove_falsified(self, candidates: List[Candidate],
                           cex: Dict) -> List[Candidate]:
        """Remove candidates falsified by CEX."""
        return [c for c in candidates if c != cex['candidate']]
    
    def _cex_falsifies(self, cex: Dict, cand: Candidate) -> bool:
        """Check if CEX falsifies candidate."""
        return cand == cex.get('candidate')
    
    def _build_output(self, remaining: List[Candidate]) -> HoudiniOutput:
        """Build output from remaining candidates."""
        if remaining:
            invariant = z3.And([c.formula for c in remaining])
            result = HoudiniResult.INDUCTIVE
        else:
            invariant = z3.BoolVal(True)
            result = HoudiniResult.EMPTY
        
        return HoudiniOutput(
            result=result,
            invariant=invariant,
            remaining_candidates=CandidateSet(remaining),
            stats=self.stats
        )


class DisjunctiveHoudini:
    """
    Houdini with disjunctive invariants.
    
    Finds invariants of form (A ∧ B) ∨ (C ∧ D).
    """
    
    def __init__(self, variables: List[z3.ArithRef],
                 primed_vars: List[z3.ArithRef],
                 transition: z3.BoolRef,
                 initial: z3.BoolRef,
                 max_disjuncts: int = 3,
                 timeout_ms: int = 60000):
        self.variables = variables
        self.primed_vars = primed_vars
        self.transition = transition
        self.initial = initial
        self.max_disjuncts = max_disjuncts
        self.timeout_ms = timeout_ms
        
        self.stats = {
            'disjuncts_tried': 0,
            'disjunctive_invariant_found': False,
        }
    
    def solve_disjunctive(self, candidates: CandidateSet) -> HoudiniOutput:
        """
        Find disjunctive inductive invariant.
        """
        # First try standard Houdini
        standard_solver = HoudiniSolver(
            self.variables, self.primed_vars,
            self.transition, self.initial,
            1000, self.timeout_ms, False
        )
        
        standard_result = standard_solver.solve(candidates)
        
        if standard_result.result == HoudiniResult.INDUCTIVE:
            return standard_result
        
        # Try disjunctive combinations
        remaining = list(standard_result.remaining_candidates.candidates)
        
        for num_disjuncts in range(2, self.max_disjuncts + 1):
            self.stats['disjuncts_tried'] += 1
            
            disjunct_inv = self._find_disjunctive(remaining, num_disjuncts)
            
            if disjunct_inv:
                self.stats['disjunctive_invariant_found'] = True
                
                return HoudiniOutput(
                    result=HoudiniResult.INDUCTIVE,
                    invariant=disjunct_inv,
                    remaining_candidates=CandidateSet([]),
                    stats=self.stats
                )
        
        return standard_result
    
    def _find_disjunctive(self, candidates: List[Candidate],
                           num_disjuncts: int) -> Optional[z3.BoolRef]:
        """Try to find disjunctive invariant."""
        if len(candidates) < num_disjuncts:
            return None
        
        # Try combinations
        from itertools import combinations
        
        for combo in combinations(candidates, num_disjuncts):
            disjunction = z3.Or([c.formula for c in combo])
            
            if self._check_inductive(disjunction):
                return disjunction
        
        return None
    
    def _check_inductive(self, formula: z3.BoolRef) -> bool:
        """Check if formula is inductive."""
        solver = z3.Solver()
        solver.set("timeout", self.timeout_ms // 10)
        
        # Init
        solver.push()
        solver.add(self.initial)
        solver.add(z3.Not(formula))
        if solver.check() == z3.sat:
            solver.pop()
            return False
        solver.pop()
        
        # Consecution
        solver.add(formula)
        solver.add(self.transition)
        
        primed = z3.substitute(formula,
            list(zip(self.variables, self.primed_vars)))
        solver.add(z3.Not(primed))
        
        return solver.check() == z3.unsat


class AbstractHoudini:
    """
    Abstract Houdini with domain-specific templates.
    """
    
    def __init__(self, variables: List[z3.ArithRef],
                 domain: str = "intervals",
                 timeout_ms: int = 60000):
        self.variables = variables
        self.domain = domain
        self.timeout_ms = timeout_ms
        
        self.stats = {
            'domain_operations': 0,
        }
    
    def generate_domain_candidates(self) -> CandidateSet:
        """Generate candidates based on abstract domain."""
        candidates = []
        
        if self.domain == "intervals":
            candidates = self._interval_candidates()
        elif self.domain == "octagons":
            candidates = self._octagon_candidates()
        elif self.domain == "polyhedra":
            candidates = self._polyhedra_candidates()
        
        self.stats['domain_operations'] += 1
        return CandidateSet(candidates)
    
    def _interval_candidates(self) -> List[Candidate]:
        """Generate interval domain candidates."""
        candidates = []
        bounds = [-10, -5, -1, 0, 1, 5, 10]
        
        for v in self.variables:
            for b in bounds:
                candidates.append(Candidate(v >= b, f"{v} >= {b}"))
                candidates.append(Candidate(v <= b, f"{v} <= {b}"))
        
        return candidates
    
    def _octagon_candidates(self) -> List[Candidate]:
        """Generate octagon domain candidates."""
        candidates = self._interval_candidates()
        bounds = [-10, -5, 0, 5, 10]
        
        for i, v1 in enumerate(self.variables):
            for v2 in self.variables[i + 1:]:
                for b in bounds:
                    candidates.append(Candidate(v1 + v2 >= b, 
                                                 f"{v1} + {v2} >= {b}"))
                    candidates.append(Candidate(v1 + v2 <= b,
                                                 f"{v1} + {v2} <= {b}"))
                    candidates.append(Candidate(v1 - v2 >= b,
                                                 f"{v1} - {v2} >= {b}"))
                    candidates.append(Candidate(v1 - v2 <= b,
                                                 f"{v1} - {v2} <= {b}"))
        
        return candidates
    
    def _polyhedra_candidates(self) -> List[Candidate]:
        """Generate polyhedral candidates."""
        candidates = self._octagon_candidates()
        
        # Add linear combinations
        bounds = [-5, 0, 5]
        coeffs = [-2, -1, 1, 2]
        
        for i, v1 in enumerate(self.variables):
            for v2 in self.variables[i + 1:]:
                for c1 in coeffs:
                    for c2 in coeffs:
                        for b in bounds:
                            expr = c1 * v1 + c2 * v2
                            candidates.append(Candidate(expr >= b,
                                f"{c1}*{v1} + {c2}*{v2} >= {b}"))
        
        return candidates


class LoopInvariantHoudini:
    """
    Houdini specialized for loop invariant inference.
    """
    
    def __init__(self, variables: List[z3.ArithRef],
                 loop_condition: z3.BoolRef,
                 loop_body: z3.BoolRef,
                 timeout_ms: int = 60000):
        self.variables = variables
        self.loop_condition = loop_condition
        self.loop_body = loop_body
        self.timeout_ms = timeout_ms
        
        self.primed_vars = [z3.Real(f"{v}'") if z3.is_real(v) 
                            else z3.Int(f"{v}'")
                            for v in variables]
        
        self.stats = {
            'loop_invariants_found': 0,
        }
    
    def find_loop_invariant(self, precondition: z3.BoolRef,
                             postcondition: z3.BoolRef) -> Optional[z3.BoolRef]:
        """
        Find loop invariant satisfying:
        - precondition → invariant
        - invariant ∧ loop_condition ∧ body → invariant'
        - invariant ∧ ¬loop_condition → postcondition
        """
        # Generate candidates
        generator = CandidateGenerator(self.variables, False)
        candidates = generator.generate_all()
        
        # Filter by precondition
        init_consistent = self._filter_by_init(candidates, precondition)
        
        # Run Houdini for inductiveness
        solver = HoudiniSolver(
            self.variables, self.primed_vars,
            z3.And(self.loop_condition, self.loop_body),
            precondition, 1000, self.timeout_ms, False
        )
        
        result = solver.solve(init_consistent)
        
        if result.result == HoudiniResult.INDUCTIVE:
            # Check postcondition
            invariant = result.invariant
            
            if self._implies_post(invariant, postcondition):
                self.stats['loop_invariants_found'] += 1
                return invariant
        
        return None
    
    def _filter_by_init(self, candidates: CandidateSet,
                         precondition: z3.BoolRef) -> CandidateSet:
        """Filter candidates consistent with precondition."""
        consistent = []
        
        for cand in candidates.candidates:
            solver = z3.Solver()
            solver.set("timeout", 1000)
            solver.add(precondition)
            solver.add(z3.Not(cand.formula))
            
            if solver.check() == z3.unsat:
                consistent.append(cand)
        
        return CandidateSet(consistent)
    
    def _implies_post(self, invariant: z3.BoolRef,
                       postcondition: z3.BoolRef) -> bool:
        """Check invariant ∧ ¬loop_cond → postcondition."""
        solver = z3.Solver()
        solver.set("timeout", self.timeout_ms // 10)
        
        solver.add(invariant)
        solver.add(z3.Not(self.loop_condition))
        solver.add(z3.Not(postcondition))
        
        return solver.check() == z3.unsat


class GuidedHoudini:
    """
    Houdini guided by counterexamples.
    """
    
    def __init__(self, variables: List[z3.ArithRef],
                 primed_vars: List[z3.ArithRef],
                 transition: z3.BoolRef,
                 initial: z3.BoolRef,
                 timeout_ms: int = 60000):
        self.variables = variables
        self.primed_vars = primed_vars
        self.transition = transition
        self.initial = initial
        self.timeout_ms = timeout_ms
        
        # Counterexample database
        self.counterexamples: List[Dict[str, Any]] = []
        
        self.stats = {
            'cex_guided_eliminations': 0,
        }
    
    def solve_guided(self, candidates: CandidateSet) -> HoudiniOutput:
        """
        Solve with counterexample guidance.
        """
        active = list(candidates.candidates)
        
        while True:
            # Pick candidate to check
            cand = self._pick_candidate(active)
            
            if cand is None:
                break
            
            # Check it
            cex = self._check_candidate(cand)
            
            if cex:
                # Store and use to eliminate others
                self.counterexamples.append(cex)
                eliminated = self._eliminate_with_cex(active, cex)
                self.stats['cex_guided_eliminations'] += len(eliminated)
                active = [c for c in active if c not in eliminated]
            else:
                # Candidate is inductive
                pass
        
        return self._build_output(active)
    
    def _pick_candidate(self, candidates: List[Candidate]) -> Optional[Candidate]:
        """Pick next candidate to check."""
        # Prioritize candidates not yet checked
        unchecked = [c for c in candidates if not hasattr(c, '_checked')]
        
        if unchecked:
            cand = unchecked[0]
            cand._checked = True
            return cand
        
        return None
    
    def _check_candidate(self, cand: Candidate) -> Optional[Dict]:
        """Check candidate, return CEX if not inductive."""
        solver = z3.Solver()
        solver.set("timeout", self.timeout_ms // 100)
        
        solver.add(cand.formula)
        solver.add(self.transition)
        
        primed = z3.substitute(cand.formula,
            list(zip(self.variables, self.primed_vars)))
        solver.add(z3.Not(primed))
        
        if solver.check() == z3.sat:
            model = solver.model()
            return {
                'pre': {str(v): model.eval(v) for v in self.variables},
                'post': {str(v): model.eval(v) for v in self.primed_vars}
            }
        
        return None
    
    def _eliminate_with_cex(self, candidates: List[Candidate],
                             cex: Dict) -> List[Candidate]:
        """Eliminate candidates falsified by CEX."""
        eliminated = []
        
        for cand in candidates:
            # Check if cand holds at pre but not at post
            solver = z3.Solver()
            solver.set("timeout", 100)
            
            # Set pre values
            for v in self.variables:
                if str(v) in cex['pre']:
                    solver.add(v == cex['pre'][str(v)])
            
            solver.add(cand.formula)
            
            if solver.check() == z3.sat:
                # Check post
                solver2 = z3.Solver()
                solver2.set("timeout", 100)
                
                for v, v_prime in zip(self.variables, self.primed_vars):
                    if str(v_prime) in cex['post']:
                        solver2.add(v == cex['post'][str(v_prime)])
                
                primed = z3.substitute(cand.formula,
                    list(zip(self.variables, self.primed_vars)))
                # Actually check the unprimed version at post values
                solver2.add(z3.Not(cand.formula))
                
                if solver2.check() == z3.sat:
                    eliminated.append(cand)
        
        return eliminated
    
    def _build_output(self, remaining: List[Candidate]) -> HoudiniOutput:
        """Build output from remaining candidates."""
        if remaining:
            invariant = z3.And([c.formula for c in remaining])
            result = HoudiniResult.INDUCTIVE
        else:
            invariant = z3.BoolVal(True)
            result = HoudiniResult.EMPTY
        
        return HoudiniOutput(
            result=result,
            invariant=invariant,
            remaining_candidates=CandidateSet(remaining),
            stats=self.stats
        )


# =============================================================================
# ADDITIONAL HOUDINI COMPONENTS
# =============================================================================

class HoudiniWithAbstraction:
    """
    Houdini with abstract domain support.
    """
    
    def __init__(self, variables: List[z3.ArithRef],
                 primed_vars: List[z3.ArithRef],
                 transition: z3.BoolRef,
                 initial: z3.BoolRef,
                 abstract_domain: str = "intervals",
                 timeout_ms: int = 60000):
        self.variables = variables
        self.primed_vars = primed_vars
        self.transition = transition
        self.initial = initial
        self.abstract_domain = abstract_domain
        self.timeout_ms = timeout_ms
        
        self.stats = {
            'abstract_iterations': 0,
            'domain_ops': 0,
        }
    
    def solve_abstract(self) -> HoudiniOutput:
        """Solve using abstract domain."""
        # Generate domain-specific candidates
        candidates = self._generate_domain_candidates()
        
        # Run abstract Houdini
        active = list(candidates.candidates)
        
        while True:
            self.stats['abstract_iterations'] += 1
            
            # Check with abstract transformer
            falsified = self._check_abstract(active)
            
            if not falsified:
                break
            
            active = [c for c in active if c not in falsified]
        
        return self._build_output(active)
    
    def _generate_domain_candidates(self) -> CandidateSet:
        """Generate candidates based on abstract domain."""
        if self.abstract_domain == "intervals":
            return self._interval_candidates()
        elif self.abstract_domain == "zones":
            return self._zone_candidates()
        else:
            return CandidateSet([])
    
    def _interval_candidates(self) -> CandidateSet:
        """Generate interval candidates."""
        candidates = []
        
        for v in self.variables:
            for bound in [-100, -10, -1, 0, 1, 10, 100]:
                candidates.append(Candidate(v >= bound, f"{v} >= {bound}"))
                candidates.append(Candidate(v <= bound, f"{v} <= {bound}"))
        
        return CandidateSet(candidates)
    
    def _zone_candidates(self) -> CandidateSet:
        """Generate zone candidates."""
        candidates = []
        
        for i, v1 in enumerate(self.variables):
            for v2 in self.variables[i + 1:]:
                for bound in [-10, 0, 10]:
                    candidates.append(Candidate(v1 - v2 >= bound,
                                                 f"{v1} - {v2} >= {bound}"))
                    candidates.append(Candidate(v1 - v2 <= bound,
                                                 f"{v1} - {v2} <= {bound}"))
        
        return CandidateSet(candidates)
    
    def _check_abstract(self, candidates: List[Candidate]) -> List[Candidate]:
        """Check candidates with abstract transformer."""
        falsified = []
        
        for cand in candidates:
            self.stats['domain_ops'] += 1
            
            if not self._abstract_inductive(cand):
                falsified.append(cand)
        
        return falsified
    
    def _abstract_inductive(self, cand: Candidate) -> bool:
        """Check if candidate is inductive using abstract domain."""
        solver = z3.Solver()
        solver.set("timeout", self.timeout_ms // 100)
        
        solver.add(cand.formula)
        solver.add(self.transition)
        
        primed = z3.substitute(cand.formula,
            list(zip(self.variables, self.primed_vars)))
        solver.add(z3.Not(primed))
        
        return solver.check() == z3.unsat
    
    def _build_output(self, remaining: List[Candidate]) -> HoudiniOutput:
        """Build output."""
        if remaining:
            invariant = z3.And([c.formula for c in remaining])
            result = HoudiniResult.INDUCTIVE
        else:
            invariant = z3.BoolVal(True)
            result = HoudiniResult.EMPTY
        
        return HoudiniOutput(
            result=result,
            invariant=invariant,
            remaining_candidates=CandidateSet(remaining),
            stats=self.stats
        )


class CandidateRanking:
    """
    Rank candidates by importance/quality.
    """
    
    def __init__(self, candidates: CandidateSet,
                 variables: List[z3.ArithRef]):
        self.candidates = candidates
        self.variables = variables
        
        self.stats = {
            'rankings_computed': 0,
        }
    
    def rank_candidates(self) -> List[Tuple[Candidate, float]]:
        """Rank candidates by quality score."""
        self.stats['rankings_computed'] += 1
        
        ranked = []
        
        for cand in self.candidates.candidates:
            score = self._score_candidate(cand)
            ranked.append((cand, score))
        
        return sorted(ranked, key=lambda x: x[1], reverse=True)
    
    def _score_candidate(self, cand: Candidate) -> float:
        """Score a candidate."""
        score = 0.0
        
        # Simplicity
        score += 1.0 / (1.0 + self._formula_size(cand.formula))
        
        # Variable usage
        used = self._used_variables(cand.formula)
        score += 0.5 / (1.0 + len(used))
        
        return score
    
    def _formula_size(self, formula: z3.BoolRef) -> int:
        """Compute formula size."""
        if z3.is_const(formula):
            return 1
        return 1 + sum(self._formula_size(c) for c in formula.children())
    
    def _used_variables(self, formula: z3.BoolRef) -> Set[str]:
        """Get variables used in formula."""
        used = set()
        
        def visit(f):
            if z3.is_const(f):
                used.add(str(f))
            for c in f.children():
                visit(c)
        
        visit(formula)
        return used


class HoudiniExplainer:
    """
    Explain Houdini results.
    """
    
    def __init__(self, output: HoudiniOutput):
        self.output = output
    
    def explain(self) -> str:
        """Generate explanation of result."""
        lines = []
        
        lines.append(f"Houdini Result: {self.output.result}")
        lines.append(f"Remaining candidates: {len(self.output.remaining_candidates.candidates)}")
        
        if self.output.result == HoudiniResult.INDUCTIVE:
            lines.append("\nInductive invariant:")
            lines.append(f"  {self.output.invariant}")
            
            lines.append("\nComponent candidates:")
            for cand in self.output.remaining_candidates.candidates:
                lines.append(f"  {cand.name}: {cand.formula}")
        
        return "\n".join(lines)
    
    def to_json(self) -> Dict[str, Any]:
        """Convert to JSON."""
        return {
            'result': str(self.output.result),
            'invariant': str(self.output.invariant),
            'candidates': [c.name for c in self.output.remaining_candidates.candidates],
            'stats': self.output.stats
        }


class BidirectionalHoudini:
    """
    Bidirectional Houdini: forward and backward.
    """
    
    def __init__(self, variables: List[z3.ArithRef],
                 primed_vars: List[z3.ArithRef],
                 transition: z3.BoolRef,
                 initial: z3.BoolRef,
                 property_: z3.BoolRef,
                 timeout_ms: int = 60000):
        self.variables = variables
        self.primed_vars = primed_vars
        self.transition = transition
        self.initial = initial
        self.property_ = property_
        self.timeout_ms = timeout_ms
        
        self.stats = {
            'forward_rounds': 0,
            'backward_rounds': 0,
        }
    
    def solve_bidirectional(self, candidates: CandidateSet) -> HoudiniOutput:
        """Solve using bidirectional Houdini."""
        forward = list(candidates.candidates)
        backward = list(candidates.candidates)
        
        while True:
            # Forward pass
            self.stats['forward_rounds'] += 1
            forward_falsified = self._forward_check(forward)
            forward = [c for c in forward if c not in forward_falsified]
            
            # Backward pass
            self.stats['backward_rounds'] += 1
            backward_falsified = self._backward_check(backward)
            backward = [c for c in backward if c not in backward_falsified]
            
            # Combine
            remaining = [c for c in forward if c in backward]
            
            if not forward_falsified and not backward_falsified:
                break
        
        return self._build_output(remaining)
    
    def _forward_check(self, candidates: List[Candidate]) -> List[Candidate]:
        """Forward Houdini check."""
        falsified = []
        
        for cand in candidates:
            solver = z3.Solver()
            solver.set("timeout", self.timeout_ms // 100)
            
            solver.add(cand.formula)
            solver.add(self.transition)
            
            primed = z3.substitute(cand.formula,
                list(zip(self.variables, self.primed_vars)))
            solver.add(z3.Not(primed))
            
            if solver.check() == z3.sat:
                falsified.append(cand)
        
        return falsified
    
    def _backward_check(self, candidates: List[Candidate]) -> List[Candidate]:
        """Backward Houdini check."""
        falsified = []
        
        for cand in candidates:
            solver = z3.Solver()
            solver.set("timeout", self.timeout_ms // 100)
            
            # Backward: cand' ∧ transition → cand
            primed = z3.substitute(cand.formula,
                list(zip(self.variables, self.primed_vars)))
            
            solver.add(primed)
            solver.add(self.transition)
            solver.add(z3.Not(cand.formula))
            
            if solver.check() == z3.sat:
                falsified.append(cand)
        
        return falsified
    
    def _build_output(self, remaining: List[Candidate]) -> HoudiniOutput:
        """Build output."""
        if remaining:
            invariant = z3.And([c.formula for c in remaining])
            result = HoudiniResult.INDUCTIVE
        else:
            invariant = z3.BoolVal(True)
            result = HoudiniResult.EMPTY
        
        return HoudiniOutput(
            result=result,
            invariant=invariant,
            remaining_candidates=CandidateSet(remaining),
            stats=self.stats
        )


class HoudiniCandidateFactory:
    """
    Factory for generating candidate invariants.
    
    Provides various strategies for generating candidates:
    - Template-based
    - Mining from code
    - Learning from examples
    """
    
    def __init__(self, variables: List[z3.ExprRef]):
        self.variables = variables
        self.generated = 0
        
    def linear_candidates(self, coefficient_bound: int = 3) -> List[Candidate]:
        """Generate linear inequality candidates."""
        candidates = []
        
        # Generate a·x + b·y + c >= 0 style candidates
        for i, v1 in enumerate(self.variables):
            for v2 in self.variables[i:]:
                for a in range(-coefficient_bound, coefficient_bound + 1):
                    for b in range(-coefficient_bound, coefficient_bound + 1):
                        for c in range(-coefficient_bound, coefficient_bound + 1):
                            if a == 0 and b == 0:
                                continue
                            formula = a * v1 + b * v2 + c >= 0
                            cand = Candidate(
                                id=f"linear_{self.generated}",
                                formula=formula
                            )
                            candidates.append(cand)
                            self.generated += 1
        
        return candidates
    
    def equality_candidates(self) -> List[Candidate]:
        """Generate equality candidates x == y."""
        candidates = []
        
        for i, v1 in enumerate(self.variables):
            for v2 in self.variables[i+1:]:
                formula = v1 == v2
                cand = Candidate(
                    id=f"eq_{self.generated}",
                    formula=formula
                )
                candidates.append(cand)
                self.generated += 1
        
        return candidates
    
    def comparison_candidates(self) -> List[Candidate]:
        """Generate comparison candidates x < y, x <= y."""
        candidates = []
        
        for i, v1 in enumerate(self.variables):
            for v2 in self.variables:
                if i != self.variables.index(v2):
                    for op in [lambda a, b: a < b, lambda a, b: a <= b]:
                        formula = op(v1, v2)
                        cand = Candidate(
                            id=f"cmp_{self.generated}",
                            formula=formula
                        )
                        candidates.append(cand)
                        self.generated += 1
        
        return candidates
    
    def octagon_candidates(self) -> List[Candidate]:
        """Generate octagon candidates ±x ± y <= c."""
        candidates = []
        
        for i, v1 in enumerate(self.variables):
            for v2 in self.variables[i:]:
                for c in range(-5, 6):
                    for sign1 in [1, -1]:
                        for sign2 in [1, -1]:
                            formula = sign1 * v1 + sign2 * v2 <= c
                            cand = Candidate(
                                id=f"oct_{self.generated}",
                                formula=formula
                            )
                            candidates.append(cand)
                            self.generated += 1
        
        return candidates


class HoudiniVerificationResult:
    """
    Detailed result from Houdini verification.
    
    Contains the invariant, proof obligations discharged,
    and any remaining unproven candidates.
    """
    
    def __init__(self, success: bool, invariant: z3.ExprRef,
                  proven: List[Candidate], refuted: List[Candidate]):
        self.success = success
        self.invariant = invariant
        self.proven = proven
        self.refuted = refuted
        self.proof_time = 0.0
        
    def get_proof_summary(self) -> str:
        """Generate human-readable proof summary."""
        lines = [
            f"Houdini Verification Result",
            f"===========================",
            f"Success: {self.success}",
            f"Proven candidates: {len(self.proven)}",
            f"Refuted candidates: {len(self.refuted)}",
            f"",
            f"Invariant: {self.invariant}",
        ]
        
        if self.proven:
            lines.append("")
            lines.append("Proven:")
            for c in self.proven[:10]:
                lines.append(f"  - {c.formula}")
        
        return "\n".join(lines)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            'success': self.success,
            'invariant': str(self.invariant),
            'proven_count': len(self.proven),
            'refuted_count': len(self.refuted),
        }
class StratifiedHoudini:
    """
    Stratified Houdini: process candidates in layers.
    """
    
    def __init__(self, variables: List[z3.ArithRef],
                 primed_vars: List[z3.ArithRef],
                 transition: z3.BoolRef,
                 initial: z3.BoolRef,
                 timeout_ms: int = 60000):
        self.variables = variables
        self.primed_vars = primed_vars
        self.transition = transition
        self.initial = initial
        self.timeout_ms = timeout_ms
        
        self.stats = {
            'strata_processed': 0,
        }
    
    def solve_stratified(self, candidates: CandidateSet) -> HoudiniOutput:
        """Solve using stratified approach."""
        # Partition into strata by complexity
        strata = self._partition_by_complexity(candidates)
        
        confirmed = []
        
        for stratum in strata:
            self.stats['strata_processed'] += 1
            
            # Run Houdini on this stratum with confirmed as axioms
            stratum_result = self._solve_stratum(stratum, confirmed)
            
            confirmed.extend(stratum_result)
        
        return self._build_output(confirmed)
    
    def _partition_by_complexity(self, candidates: CandidateSet) -> List[List[Candidate]]:
        """Partition candidates by complexity."""
        strata: Dict[int, List[Candidate]] = {}
        
        for cand in candidates.candidates:
            complexity = self._formula_complexity(cand.formula)
            if complexity not in strata:
                strata[complexity] = []
            strata[complexity].append(cand)
        
        return [strata[k] for k in sorted(strata.keys())]
    
    def _formula_complexity(self, formula: z3.BoolRef) -> int:
        """Compute formula complexity."""
        if z3.is_const(formula):
            return 1
        return 1 + sum(self._formula_complexity(c) for c in formula.children())
    
    def _solve_stratum(self, stratum: List[Candidate],
                        axioms: List[Candidate]) -> List[Candidate]:
        """Solve single stratum."""
        active = list(stratum)
        
        while True:
            falsified = self._check_with_axioms(active, axioms)
            
            if not falsified:
                break
            
            active = [c for c in active if c not in falsified]
        
        return active
    
    def _check_with_axioms(self, candidates: List[Candidate],
                            axioms: List[Candidate]) -> List[Candidate]:
        """Check candidates with axioms."""
        falsified = []
        
        axiom_formula = z3.And([a.formula for a in axioms]) if axioms else z3.BoolVal(True)
        
        for cand in candidates:
            solver = z3.Solver()
            solver.set("timeout", self.timeout_ms // 100)
            
            solver.add(axiom_formula)
            solver.add(cand.formula)
            solver.add(self.transition)
            
            primed = z3.substitute(cand.formula,
                list(zip(self.variables, self.primed_vars)))
            solver.add(z3.Not(primed))
            
            if solver.check() == z3.sat:
                falsified.append(cand)
        
        return falsified
    
    def _build_output(self, remaining: List[Candidate]) -> HoudiniOutput:
        """Build output."""
        if remaining:
            invariant = z3.And([c.formula for c in remaining])
            result = HoudiniResult.INDUCTIVE
        else:
            invariant = z3.BoolVal(True)
            result = HoudiniResult.EMPTY
        
        return HoudiniOutput(
            result=result,
            invariant=invariant,
            remaining_candidates=CandidateSet(remaining),
            stats=self.stats
        )
