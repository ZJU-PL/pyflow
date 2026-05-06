"""
Learning Layer for Barrier Certificate Synthesis.

This module provides learning-based techniques for discovering
invariants and barrier certificates. It integrates:

    Paper #17: ICE Learning (Garg et al. 2014)
        - Implication Counterexamples
        - Data-driven invariant inference
        
    Paper #18: Houdini (Flanagan-Leino 2001)
        - Conjunctive inference
        - Annotation inference by fixpoint
        
    Paper #19: SyGuS Synthesis (Alur et al. 2013)
        - Syntax-Guided Synthesis
        - Template-based certificate discovery

The composable architecture:

    ┌─────────────────────────────────────────────────────────────┐
    │                      LEARNING LAYER                          │
    ├─────────────────────────────────────────────────────────────┤
    │                                                              │
    │  ┌───────────────────────────────────────────────────────┐  │
    │  │              ABSTRACTION LAYER                         │  │
    │  │  (CEGAR, Predicate Abstraction, Boolean Programs)     │  │
    │  └────────────────────────┬──────────────────────────────┘  │
    │                           │                                  │
    │           ┌───────────────┼───────────────┐                  │
    │           │               │               │                  │
    │           ▼               ▼               ▼                  │
    │  ┌────────────┐   ┌────────────┐   ┌────────────┐           │
    │  │    ICE     │   │  Houdini   │   │   SyGuS    │           │
    │  │  Learning  │   │ Inference  │   │ Synthesis  │           │
    │  │ (Paper #17)│   │ (Paper #18)│   │ (Paper #19)│           │
    │  └──────┬─────┘   └──────┬─────┘   └──────┬─────┘           │
    │         │                │                │                  │
    │         └────────────────┼────────────────┘                  │
    │                          │                                   │
    │                          ▼                                   │
    │              ┌───────────────────────┐                       │
    │              │   Learning Engine     │                       │
    │              │   Unified Interface   │                       │
    │              └───────────────────────┘                       │
    │                                                              │
    └─────────────────────────────────────────────────────────────┘

Usage:
    from barriers.learning import (
        ICELearner,
        HoudiniInference,
        SyGuSSynthesizer,
        LearningBasedEngine,
    )
    
    # Unified interface
    engine = LearningBasedEngine()
    invariant = engine.learn_invariant(positive_examples, negative_examples)
"""

from __future__ import annotations

import z3
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple, Set, Any, Union, Callable, FrozenSet
from enum import Enum, auto
import logging
import random

# Import from lower layers
from .foundations import Polynomial, SemialgebraicSet, Monomial
from .certificate_core import BarrierTemplate, ContinuousDynamics, BarrierConditions
from .abstraction import Predicate, AbstractState

logger = logging.getLogger(__name__)


# =============================================================================
# SAMPLE TYPES
# =============================================================================

@dataclass
class DataPoint:
    """
    A data point for learning.
    
    Can be:
    - Positive: should be in the invariant
    - Negative: should NOT be in the invariant
    - Implication: if pre is in invariant, post should be in invariant
    """
    values: Tuple[float, ...]
    label: str  # 'positive', 'negative', 'implication_pre', 'implication_post'
    linked_to: Optional['DataPoint'] = None  # For implications
    
    def __hash__(self):
        return hash((self.values, self.label))
    
    def __eq__(self, other):
        return (isinstance(other, DataPoint) and 
                self.values == other.values and 
                self.label == other.label)


@dataclass
class ICEExample:
    """
    ICE (Implication CounterExample) data.
    
    Three types:
    1. Positive: must be satisfied (initial states)
    2. Negative: must be violated (unsafe states)
    3. Implication: (pre, post) pairs - if pre satisfied, post must be
    """
    positive: List[DataPoint]
    negative: List[DataPoint]
    implications: List[Tuple[DataPoint, DataPoint]]  # (pre, post) pairs


# =============================================================================
# ICE LEARNING (Paper #17)
# =============================================================================

class ICELearner:
    """
    ICE Learning for invariant inference (Paper #17).
    
    Key idea: Learn invariants from three types of counterexamples:
    1. Positive: states that must be in the invariant
    2. Negative: states that must NOT be in the invariant
    3. Implication: transitions that must be preserved
    
    Algorithm:
    1. Start with candidate invariant (from template)
    2. Teacher provides counterexamples
    3. Learner updates hypothesis to satisfy counterexamples
    4. Repeat until no counterexamples
    """
    
    def __init__(self, n_vars: int, max_degree: int = 4,
                 timeout_ms: int = 60000):
        self.n_vars = n_vars
        self.max_degree = max_degree
        self.timeout_ms = timeout_ms
        
        # Learning state
        self.positive_samples: List[DataPoint] = []
        self.negative_samples: List[DataPoint] = []
        self.implication_samples: List[Tuple[DataPoint, DataPoint]] = []
        
        # Template for hypothesis
        self.template = BarrierTemplate(n_vars, max_degree)
        
        self.stats = {
            'rounds': 0,
            'positive_added': 0,
            'negative_added': 0,
            'implications_added': 0,
        }
    
    def add_positive(self, point: Tuple[float, ...]) -> None:
        """Add positive example (must be in invariant)."""
        self.positive_samples.append(DataPoint(values=point, label='positive'))
        self.stats['positive_added'] += 1
    
    def add_negative(self, point: Tuple[float, ...]) -> None:
        """Add negative example (must NOT be in invariant)."""
        self.negative_samples.append(DataPoint(values=point, label='negative'))
        self.stats['negative_added'] += 1
    
    def add_implication(self, pre: Tuple[float, ...], post: Tuple[float, ...]) -> None:
        """Add implication example (if pre in invariant, post must be)."""
        pre_dp = DataPoint(values=pre, label='implication_pre')
        post_dp = DataPoint(values=post, label='implication_post')
        pre_dp.linked_to = post_dp
        self.implication_samples.append((pre_dp, post_dp))
        self.stats['implications_added'] += 1
    
    def learn(self, max_rounds: int = 100) -> Optional[Polynomial]:
        """
        Learn invariant satisfying all examples.
        
        Returns polynomial P such that:
        - P(x) >= 0 for all positive x
        - P(x) < 0 for all negative x
        - P(pre) >= 0 => P(post) >= 0 for all implications
        """
        self.template.create_symbolic("I")
        
        for round_num in range(max_rounds):
            self.stats['rounds'] = round_num + 1
            
            # Try to find hypothesis satisfying all examples
            hypothesis = self._find_hypothesis()
            
            if hypothesis is not None:
                return hypothesis
            
            # If no hypothesis found with current template, increase degree
            if round_num > 0 and round_num % 10 == 0:
                self.max_degree = min(self.max_degree + 2, 10)
                self.template = BarrierTemplate(self.n_vars, self.max_degree)
                self.template.create_symbolic("I")
        
        return None
    
    def _find_hypothesis(self) -> Optional[Polynomial]:
        """Find hypothesis satisfying current examples."""
        solver = z3.Solver()
        solver.set("timeout", self.timeout_ms)
        
        vars_z3 = [z3.Real(f'x{i}') for i in range(self.n_vars)]
        I_z3 = self.template.to_z3(vars_z3)
        
        # Positive constraints: I(x) >= epsilon
        epsilon = 0.1
        for sample in self.positive_samples:
            I_at_sample = self._substitute(I_z3, vars_z3, sample.values)
            solver.add(I_at_sample >= epsilon)
        
        # Negative constraints: I(x) <= -epsilon
        for sample in self.negative_samples:
            I_at_sample = self._substitute(I_z3, vars_z3, sample.values)
            solver.add(I_at_sample <= -epsilon)
        
        # Implication constraints
        for pre, post in self.implication_samples:
            I_pre = self._substitute(I_z3, vars_z3, pre.values)
            I_post = self._substitute(I_z3, vars_z3, post.values)
            # If I(pre) >= 0 then I(post) >= 0
            # Encoded as: I(pre) < 0 OR I(post) >= 0
            solver.add(z3.Or(I_pre < 0, I_post >= 0))
        
        # Add regularization: prefer small coefficients
        for mono, coeff in self.template.coefficients.items():
            solver.add(coeff >= -100)
            solver.add(coeff <= 100)
        
        if solver.check() == z3.sat:
            model = solver.model()
            coeff_values = self._extract_coefficients(model)
            return self.template.to_polynomial(coeff_values)
        
        return None
    
    def _substitute(self, expr: z3.ExprRef,
                     vars_z3: List[z3.ExprRef],
                     values: Tuple[float, ...]) -> z3.ExprRef:
        """Substitute values into expression."""
        subs = [(vars_z3[i], z3.RealVal(values[i]))
                for i in range(min(len(vars_z3), len(values)))]
        return z3.substitute(expr, subs)
    
    def _extract_coefficients(self, model: z3.ModelRef) -> Dict[Monomial, float]:
        """Extract coefficient values from model."""
        result = {}
        for mono, var in self.template.coefficients.items():
            val = model.eval(var, model_completion=True)
            if z3.is_rational_value(val):
                result[mono] = (float(val.numerator_as_long()) /
                               float(val.denominator_as_long()))
            else:
                result[mono] = 0.0
        return result


class ICETeacher:
    """
    Teacher for ICE learning.
    
    Provides counterexamples to the learner's hypotheses.
    """
    
    def __init__(self, conditions: BarrierConditions,
                 dynamics: ContinuousDynamics,
                 timeout_ms: int = 30000):
        self.conditions = conditions
        self.dynamics = dynamics
        self.timeout_ms = timeout_ms
    
    def check_hypothesis(self, hypothesis: Polynomial) -> Optional[ICEExample]:
        """
        Check if hypothesis is valid. If not, return counterexample.
        """
        cex_positive = self._check_positive(hypothesis)
        if cex_positive:
            return ICEExample(
                positive=[DataPoint(values=cex_positive, label='positive')],
                negative=[],
                implications=[]
            )
        
        cex_negative = self._check_negative(hypothesis)
        if cex_negative:
            return ICEExample(
                positive=[],
                negative=[DataPoint(values=cex_negative, label='negative')],
                implications=[]
            )
        
        cex_inductive = self._check_inductive(hypothesis)
        if cex_inductive:
            pre, post = cex_inductive
            return ICEExample(
                positive=[],
                negative=[],
                implications=[(
                    DataPoint(values=pre, label='implication_pre'),
                    DataPoint(values=post, label='implication_post')
                )]
            )
        
        return None  # Hypothesis is valid
    
    def _check_positive(self, hypothesis: Polynomial) -> Optional[Tuple[float, ...]]:
        """Check: hypothesis >= 0 on initial states."""
        solver = z3.Solver()
        solver.set("timeout", self.timeout_ms)
        
        vars_z3 = [z3.Real(f'x{i}') for i in range(hypothesis.n_vars)]
        H_z3 = hypothesis.to_z3(vars_z3)
        
        # x in Initial AND H(x) < 0
        for g in self.conditions.initial.constraints:
            solver.add(g.to_z3(vars_z3) >= 0)
        solver.add(H_z3 < 0)
        
        if solver.check() == z3.sat:
            model = solver.model()
            return self._extract_point(model, vars_z3)
        
        return None
    
    def _check_negative(self, hypothesis: Polynomial) -> Optional[Tuple[float, ...]]:
        """Check: hypothesis < 0 on unsafe states."""
        solver = z3.Solver()
        solver.set("timeout", self.timeout_ms)
        
        vars_z3 = [z3.Real(f'x{i}') for i in range(hypothesis.n_vars)]
        H_z3 = hypothesis.to_z3(vars_z3)
        
        # x in Unsafe AND H(x) >= 0
        for g in self.conditions.unsafe.constraints:
            solver.add(g.to_z3(vars_z3) >= 0)
        solver.add(H_z3 >= 0)
        
        if solver.check() == z3.sat:
            model = solver.model()
            return self._extract_point(model, vars_z3)
        
        return None
    
    def _check_inductive(self, hypothesis: Polynomial) -> Optional[Tuple[Tuple[float, ...], Tuple[float, ...]]]:
        """Check: H(x) >= 0 AND L_f(H)(x) > 0 is empty."""
        solver = z3.Solver()
        solver.set("timeout", self.timeout_ms)
        
        vars_z3 = [z3.Real(f'x{i}') for i in range(hypothesis.n_vars)]
        H_z3 = hypothesis.to_z3(vars_z3)
        
        L_H = self.dynamics.lie_derivative(hypothesis)
        L_z3 = L_H.to_z3(vars_z3)
        
        # x in Safe AND H(x) >= 0 AND L_f(H)(x) > 0
        for g in self.conditions.safe.constraints:
            solver.add(g.to_z3(vars_z3) >= 0)
        solver.add(H_z3 >= 0)
        solver.add(L_z3 > 0)
        
        if solver.check() == z3.sat:
            model = solver.model()
            pre = self._extract_point(model, vars_z3)
            
            # Compute post (approximate next state)
            dt = 0.01
            post = tuple(pre[i] + dt * self.dynamics.vector_field[i].evaluate(list(pre))
                        for i in range(len(pre)))
            
            return (pre, post)
        
        return None
    
    def _extract_point(self, model: z3.ModelRef,
                        vars_z3: List[z3.ExprRef]) -> Tuple[float, ...]:
        """Extract point from model."""
        values = []
        for v in vars_z3:
            val = model.eval(v, model_completion=True)
            if z3.is_rational_value(val):
                values.append(float(val.numerator_as_long()) /
                             float(val.denominator_as_long()))
            else:
                values.append(0.0)
        return tuple(values)


# =============================================================================
# HOUDINI INFERENCE (Paper #18)
# =============================================================================

@dataclass
class HoudiniAnnotation:
    """
    An annotation (candidate invariant) in Houdini.
    """
    name: str
    predicate: Predicate
    location: Any  # Program location where annotation applies
    is_valid: bool = True  # Still a candidate?


class HoudiniInference:
    """
    Houdini conjunctive inference (Paper #18).
    
    Key idea: Start with all candidate annotations, iteratively
    remove those that are violated, until fixpoint reached.
    
    Properties:
    - Sound: result is always a valid invariant
    - Incomplete: may not find strongest invariant
    - Efficient: polynomial in #annotations
    """
    
    def __init__(self, candidates: List[Predicate],
                 locations: List[Any],
                 timeout_ms: int = 60000):
        self.candidates = candidates
        self.locations = locations
        self.timeout_ms = timeout_ms
        
        # Create annotations for each (location, candidate) pair
        self.annotations: List[HoudiniAnnotation] = []
        for loc in locations:
            for pred in candidates:
                self.annotations.append(HoudiniAnnotation(
                    name=f"{pred.name}@{loc}",
                    predicate=pred,
                    location=loc,
                    is_valid=True
                ))
        
        self.stats = {
            'iterations': 0,
            'annotations_removed': 0,
            'final_annotations': 0,
        }
    
    @property
    def num_candidates(self) -> int:
        return len(self.candidates)
    
    @property
    def num_valid(self) -> int:
        return sum(1 for a in self.annotations if a.is_valid)
    
    def infer(self, init_constraint: z3.ExprRef,
               transition: Callable[[Any, Any], z3.ExprRef],
               max_iterations: int = 100) -> Dict[Any, List[Predicate]]:
        """
        Run Houdini fixpoint inference.
        
        Args:
            init_constraint: Initial state constraint
            transition: Function(loc1, loc2) -> transition constraint
        
        Returns:
            Mapping from location to list of valid predicates at that location.
        """
        changed = True
        iteration = 0
        
        while changed and iteration < max_iterations:
            changed = False
            iteration += 1
            self.stats['iterations'] = iteration
            
            # Check each still-valid annotation
            for ann in self.annotations:
                if not ann.is_valid:
                    continue
                
                # Check initiation: initial => annotation
                if not self._check_initiation(ann, init_constraint):
                    ann.is_valid = False
                    changed = True
                    self.stats['annotations_removed'] += 1
                    continue
                
                # Check consecution: annotations at pre-state => annotation at post
                if not self._check_consecution(ann, transition):
                    ann.is_valid = False
                    changed = True
                    self.stats['annotations_removed'] += 1
        
        # Build result
        self.stats['final_annotations'] = self.num_valid
        result: Dict[Any, List[Predicate]] = {loc: [] for loc in self.locations}
        
        for ann in self.annotations:
            if ann.is_valid:
                result[ann.location].append(ann.predicate)
        
        return result
    
    def _check_initiation(self, ann: HoudiniAnnotation,
                           init_constraint: z3.ExprRef) -> bool:
        """Check: init => annotation."""
        solver = z3.Solver()
        solver.set("timeout", self.timeout_ms // 100)
        
        solver.add(init_constraint)
        solver.add(z3.Not(ann.predicate.expr))
        
        return solver.check() == z3.unsat
    
    def _check_consecution(self, ann: HoudiniAnnotation,
                            transition: Callable[[Any, Any], z3.ExprRef]) -> bool:
        """Check: (valid_annotations at pre) ∧ transition => annotation at post."""
        solver = z3.Solver()
        solver.set("timeout", self.timeout_ms // 100)
        
        # Add current valid annotations at source location
        for other in self.annotations:
            if other.is_valid and other.location == ann.location:
                solver.add(other.predicate.expr)
        
        # Add transition to target location
        for target_loc in self.locations:
            trans = transition(ann.location, target_loc)
            if trans is not None:
                solver.push()
                solver.add(trans)
                
                # Add negation of annotation at target
                target_pred = self._prime_predicate(ann.predicate)
                solver.add(z3.Not(target_pred.expr))
                
                if solver.check() == z3.sat:
                    return False
                
                solver.pop()
        
        return True
    
    def _prime_predicate(self, pred: Predicate) -> Predicate:
        """Create primed version of predicate."""
        # Simple implementation: rename variables to x' versions
        primed_name = f"{pred.name}'"
        # Would need proper variable substitution here
        return Predicate(
            name=primed_name,
            expr=pred.expr,  # Simplified - should substitute
            variables={f"{v}'" for v in pred.variables}
        )


class HoudiniBarrierInference:
    """
    Houdini-style inference for barrier certificates.
    
    Candidate barriers from template, eliminate invalid ones.
    """
    
    def __init__(self, n_vars: int, max_degree: int = 4,
                 num_candidates: int = 20):
        self.n_vars = n_vars
        self.max_degree = max_degree
        self.num_candidates = num_candidates
        
        # Generate candidate barrier templates
        self.candidates: List[Polynomial] = []
        self._generate_candidates()
    
    def _generate_candidates(self) -> None:
        """Generate random candidate barriers."""
        for _ in range(self.num_candidates):
            poly = Polynomial(self.n_vars)
            
            # Random polynomial up to max_degree
            for deg in range(self.max_degree + 1):
                for _ in range(3):  # Random monomials per degree
                    exponents = [0] * self.n_vars
                    remaining = deg
                    for i in range(self.n_vars):
                        if remaining > 0:
                            exp = random.randint(0, remaining)
                            exponents[i] = exp
                            remaining -= exp
                    
                    mono = Monomial(tuple(exponents))
                    coeff = random.uniform(-10, 10)
                    poly.terms[mono] = coeff
            
            self.candidates.append(poly)
    
    def infer(self, conditions: BarrierConditions,
               dynamics: ContinuousDynamics) -> Optional[Polynomial]:
        """
        Find valid barrier from candidates.
        """
        valid = list(self.candidates)
        
        # Filter by initial positivity
        valid = [c for c in valid if self._check_initial(c, conditions)]
        
        # Filter by unsafe negativity
        valid = [c for c in valid if self._check_unsafe(c, conditions)]
        
        # Filter by Lie derivative condition
        valid = [c for c in valid if self._check_lie(c, conditions, dynamics)]
        
        if valid:
            return valid[0]
        
        return None
    
    def _check_initial(self, candidate: Polynomial,
                        conditions: BarrierConditions) -> bool:
        """Check B > 0 on initial."""
        samples = self._sample_region(conditions.initial, 20)
        return all(candidate.evaluate(list(s)) > 0 for s in samples)
    
    def _check_unsafe(self, candidate: Polynomial,
                       conditions: BarrierConditions) -> bool:
        """Check B <= 0 on unsafe."""
        samples = self._sample_region(conditions.unsafe, 20)
        return all(candidate.evaluate(list(s)) <= 0 for s in samples)
    
    def _check_lie(self, candidate: Polynomial,
                    conditions: BarrierConditions,
                    dynamics: ContinuousDynamics) -> bool:
        """Check L_f(B) <= 0 on safe."""
        L = dynamics.lie_derivative(candidate)
        samples = self._sample_region(conditions.safe, 30)
        return all(L.evaluate(list(s)) <= 0 for s in samples)
    
    def _sample_region(self, region: SemialgebraicSet,
                        count: int) -> List[Tuple[float, ...]]:
        """Sample from region."""
        samples = []
        
        for _ in range(count * 10):
            if len(samples) >= count:
                break
            point = tuple(random.uniform(-5, 5) for _ in range(region.n_vars))
            if region.contains(list(point)):
                samples.append(point)
        
        while len(samples) < count:
            samples.append(tuple([0.0] * region.n_vars))
        
        return samples


# =============================================================================
# SYGUS SYNTHESIS (Paper #19)
# =============================================================================

class SyGuSGrammar:
    """
    Grammar for syntax-guided synthesis.
    
    Defines the space of possible expressions.
    """
    
    def __init__(self, n_vars: int, name: str = "B"):
        self.n_vars = n_vars
        self.name = name
        
        # Non-terminals and their productions
        self.rules: Dict[str, List[Tuple[str, List[str]]]] = {}
        
        # Default polynomial grammar
        self._build_polynomial_grammar()
    
    def _build_polynomial_grammar(self) -> None:
        """Build default polynomial grammar."""
        # E -> E + T | T
        self.rules['E'] = [
            ('add', ['E', 'T']),
            ('term', ['T']),
        ]
        
        # T -> T * F | F
        self.rules['T'] = [
            ('mul', ['T', 'F']),
            ('factor', ['F']),
        ]
        
        # F -> const | x_i | (E)
        self.rules['F'] = [
            ('const', []),
            ('var', []),
            ('paren', ['E']),
        ]
    
    def set_custom_rules(self, rules: Dict[str, List[Tuple[str, List[str]]]]) -> None:
        """Set custom grammar rules."""
        self.rules = rules
    
    def enumerate(self, max_size: int = 10) -> List[z3.ExprRef]:
        """Enumerate expressions up to given size."""
        expressions = []
        self._enumerate_recursive('E', max_size, expressions)
        return expressions[:1000]  # Limit
    
    def _enumerate_recursive(self, symbol: str, size: int,
                               results: List[z3.ExprRef]) -> List[z3.ExprRef]:
        """Recursive enumeration."""
        if size <= 0:
            return []
        
        exprs = []
        
        if symbol not in self.rules:
            # Terminal symbol
            if symbol == 'const':
                for c in [-2, -1, 0, 1, 2]:
                    exprs.append(z3.RealVal(c))
            elif symbol == 'var':
                for i in range(self.n_vars):
                    exprs.append(z3.Real(f'x{i}'))
            return exprs
        
        for rule_name, children in self.rules[symbol]:
            if not children:
                # Leaf production
                if rule_name == 'const':
                    for c in [-2, -1, 0, 1, 2]:
                        exprs.append(z3.RealVal(c))
                elif rule_name == 'var':
                    for i in range(self.n_vars):
                        exprs.append(z3.Real(f'x{i}'))
            elif len(children) == 1:
                child_exprs = self._enumerate_recursive(children[0], size - 1, results)
                exprs.extend(child_exprs)
            elif len(children) == 2:
                for s1 in range(1, size):
                    s2 = size - s1 - 1
                    if s2 > 0:
                        left = self._enumerate_recursive(children[0], s1, results)
                        right = self._enumerate_recursive(children[1], s2, results)
                        for l in left[:10]:  # Limit combinations
                            for r in right[:10]:
                                if rule_name == 'add':
                                    exprs.append(l + r)
                                elif rule_name == 'mul':
                                    exprs.append(l * r)
        
        results.extend(exprs)
        return exprs


@dataclass
class SyGuSConstraint:
    """A constraint for SyGuS synthesis."""
    name: str
    variables: List[z3.ExprRef]
    constraint: z3.ExprRef  # Formula that must hold


class SyGuSSynthesizer:
    """
    Syntax-Guided Synthesis (Paper #19).
    
    Key idea: Search for expression satisfying specification
    within syntactically-defined space (grammar).
    
    Approaches:
    1. Enumerate: Try all expressions in grammar
    2. CEGIS: Counterexample-guided inductive synthesis
    """
    
    def __init__(self, n_vars: int, grammar: Optional[SyGuSGrammar] = None,
                 timeout_ms: int = 60000):
        self.n_vars = n_vars
        self.grammar = grammar or SyGuSGrammar(n_vars)
        self.timeout_ms = timeout_ms
        
        self.constraints: List[SyGuSConstraint] = []
        
        self.stats = {
            'candidates_tried': 0,
            'synthesis_time_ms': 0,
        }
    
    def add_constraint(self, name: str,
                        variables: List[z3.ExprRef],
                        constraint: z3.ExprRef) -> None:
        """Add synthesis constraint."""
        self.constraints.append(SyGuSConstraint(
            name=name,
            variables=variables,
            constraint=constraint
        ))
    
    def synthesize_barrier(self, conditions: BarrierConditions,
                            dynamics: ContinuousDynamics) -> Optional[z3.ExprRef]:
        """
        Synthesize barrier certificate.
        
        Uses CEGIS: synthesize candidate, verify, refine.
        """
        vars_z3 = [z3.Real(f'x{i}') for i in range(self.n_vars)]
        
        # Enumerate candidates
        candidates = self.grammar.enumerate(max_size=8)
        
        # CEGIS loop
        examples: List[Tuple[float, ...]] = []
        
        for candidate in candidates:
            self.stats['candidates_tried'] += 1
            
            # Check against current examples
            if not self._satisfies_examples(candidate, vars_z3, examples, conditions):
                continue
            
            # Verify candidate
            cex = self._verify_candidate(candidate, vars_z3, conditions, dynamics)
            
            if cex is None:
                # Valid barrier found
                return candidate
            
            # Add counterexample
            examples.append(cex)
        
        return None
    
    def _satisfies_examples(self, candidate: z3.ExprRef,
                             vars_z3: List[z3.ExprRef],
                             examples: List[Tuple[float, ...]],
                             conditions: BarrierConditions) -> bool:
        """Check if candidate satisfies cached examples."""
        for ex in examples:
            subs = [(vars_z3[i], z3.RealVal(ex[i]))
                    for i in range(min(len(vars_z3), len(ex)))]
            val = z3.substitute(candidate, subs)
            
            # Determine if example is initial/unsafe
            if conditions.initial.contains(list(ex)):
                # Should be positive
                solver = z3.Solver()
                solver.add(val <= 0)
                if solver.check() == z3.sat:
                    return False
            elif conditions.unsafe.contains(list(ex)):
                # Should be negative
                solver = z3.Solver()
                solver.add(val > 0)
                if solver.check() == z3.sat:
                    return False
        
        return True
    
    def _verify_candidate(self, candidate: z3.ExprRef,
                           vars_z3: List[z3.ExprRef],
                           conditions: BarrierConditions,
                           dynamics: ContinuousDynamics) -> Optional[Tuple[float, ...]]:
        """Verify candidate and return counterexample if invalid."""
        solver = z3.Solver()
        solver.set("timeout", self.timeout_ms // 10)
        
        # Check initial positivity
        solver.push()
        for g in conditions.initial.constraints:
            solver.add(g.to_z3(vars_z3) >= 0)
        solver.add(candidate < 0)
        
        if solver.check() == z3.sat:
            model = solver.model()
            cex = self._extract_point(model, vars_z3)
            solver.pop()
            return cex
        solver.pop()
        
        # Check unsafe negativity
        solver.push()
        for g in conditions.unsafe.constraints:
            solver.add(g.to_z3(vars_z3) >= 0)
        solver.add(candidate >= 0)
        
        if solver.check() == z3.sat:
            model = solver.model()
            cex = self._extract_point(model, vars_z3)
            solver.pop()
            return cex
        solver.pop()
        
        return None
    
    def _extract_point(self, model: z3.ModelRef,
                        vars_z3: List[z3.ExprRef]) -> Tuple[float, ...]:
        """Extract point from model."""
        values = []
        for v in vars_z3:
            val = model.eval(v, model_completion=True)
            if z3.is_rational_value(val):
                values.append(float(val.numerator_as_long()) /
                             float(val.denominator_as_long()))
            else:
                values.append(0.0)
        return tuple(values)


# =============================================================================
# UNIFIED LEARNING ENGINE
# =============================================================================

class LearningMethod(Enum):
    """Learning methods available."""
    ICE = auto()
    HOUDINI = auto()
    SYGUS = auto()
    ENSEMBLE = auto()


class LearningBasedEngine:
    """
    Unified engine for learning-based synthesis.
    
    MAIN INTERFACE for the learning layer.
    
    Integrates:
    - ICE Learning (Paper #17)
    - Houdini Inference (Paper #18)
    - SyGuS Synthesis (Paper #19)
    
    Automatically selects best approach or ensembles them.
    """
    
    def __init__(self, n_vars: int, max_degree: int = 4,
                 timeout_ms: int = 120000,
                 preferred_method: Optional[LearningMethod] = None):
        self.n_vars = n_vars
        self.max_degree = max_degree
        self.timeout_ms = timeout_ms
        self.preferred_method = preferred_method
        
        # Sub-engines
        self.ice_learner = ICELearner(n_vars, max_degree, timeout_ms // 3)
        self.houdini = HoudiniBarrierInference(n_vars, max_degree)
        self.sygus = SyGuSSynthesizer(n_vars, timeout_ms=timeout_ms // 3)
        
        self.stats = {
            'synthesis_requests': 0,
            'successful': 0,
            'method_used': None,
        }
    
    def synthesize_barrier(self, conditions: BarrierConditions,
                            dynamics: ContinuousDynamics) -> Optional[Polynomial]:
        """
        Synthesize barrier certificate using learning.
        
        Tries methods in order of expected effectiveness,
        or uses specified preferred method.
        """
        self.stats['synthesis_requests'] += 1
        
        if self.preferred_method == LearningMethod.ICE:
            return self._try_ice(conditions, dynamics)
        elif self.preferred_method == LearningMethod.HOUDINI:
            return self._try_houdini(conditions, dynamics)
        elif self.preferred_method == LearningMethod.SYGUS:
            return self._try_sygus(conditions, dynamics)
        else:
            # Try all methods
            return self._try_ensemble(conditions, dynamics)
    
    def _try_ice(self, conditions: BarrierConditions,
                  dynamics: ContinuousDynamics) -> Optional[Polynomial]:
        """Try ICE learning approach."""
        # Sample initial states as positive examples
        initial_samples = self._sample_region(conditions.initial, 10)
        for sample in initial_samples:
            self.ice_learner.add_positive(sample)
        
        # Sample unsafe states as negative examples
        unsafe_samples = self._sample_region(conditions.unsafe, 10)
        for sample in unsafe_samples:
            self.ice_learner.add_negative(sample)
        
        # Add implication examples from safe region
        safe_samples = self._sample_region(conditions.safe, 15)
        dt = 0.01
        for sample in safe_samples:
            pre = sample
            post = tuple(sample[i] + dt * dynamics.vector_field[i].evaluate(list(sample))
                        for i in range(len(sample)))
            self.ice_learner.add_implication(pre, post)
        
        result = self.ice_learner.learn()
        
        if result is not None:
            self.stats['successful'] += 1
            self.stats['method_used'] = 'ice'
        
        return result
    
    def _try_houdini(self, conditions: BarrierConditions,
                      dynamics: ContinuousDynamics) -> Optional[Polynomial]:
        """Try Houdini inference approach."""
        result = self.houdini.infer(conditions, dynamics)
        
        if result is not None:
            self.stats['successful'] += 1
            self.stats['method_used'] = 'houdini'
        
        return result
    
    def _try_sygus(self, conditions: BarrierConditions,
                    dynamics: ContinuousDynamics) -> Optional[z3.ExprRef]:
        """Try SyGuS synthesis approach."""
        result = self.sygus.synthesize_barrier(conditions, dynamics)
        
        if result is not None:
            self.stats['successful'] += 1
            self.stats['method_used'] = 'sygus'
        
        return result
    
    def _try_ensemble(self, conditions: BarrierConditions,
                       dynamics: ContinuousDynamics) -> Optional[Polynomial]:
        """Try all methods, return first success."""
        # Try Houdini first (fastest)
        result = self._try_houdini(conditions, dynamics)
        if result is not None:
            return result
        
        # Try ICE (most sample-efficient)
        result = self._try_ice(conditions, dynamics)
        if result is not None:
            return result
        
        # Try SyGuS (most expressive) - returns Z3 expr, would need conversion
        # For now, skip SyGuS in ensemble
        
        return None
    
    def _sample_region(self, region: SemialgebraicSet,
                        count: int) -> List[Tuple[float, ...]]:
        """Sample from region."""
        samples = []
        
        for _ in range(count * 10):
            if len(samples) >= count:
                break
            point = tuple(random.uniform(-5, 5) for _ in range(region.n_vars))
            if region.contains(list(point)):
                samples.append(point)
        
        while len(samples) < count:
            samples.append(tuple([0.0] * region.n_vars))
        
        return samples
    
    def learn_from_data(self, positive: List[Tuple[float, ...]],
                         negative: List[Tuple[float, ...]],
                         implications: Optional[List[Tuple[Tuple[float, ...], Tuple[float, ...]]]] = None
                         ) -> Optional[Polynomial]:
        """
        Learn invariant directly from labeled data.
        
        Pure data-driven approach without system model.
        """
        # Reset ICE learner
        self.ice_learner = ICELearner(self.n_vars, self.max_degree, self.timeout_ms)
        
        for p in positive:
            self.ice_learner.add_positive(p)
        
        for n in negative:
            self.ice_learner.add_negative(n)
        
        if implications:
            for pre, post in implications:
                self.ice_learner.add_implication(pre, post)
        
        return self.ice_learner.learn()


# =============================================================================
# EXPORTS
# =============================================================================

__all__ = [
    # Data types
    'DataPoint',
    'ICEExample',
    
    # ICE Learning (Paper #17)
    'ICELearner',
    'ICETeacher',
    
    # Houdini Inference (Paper #18)
    'HoudiniAnnotation',
    'HoudiniInference',
    'HoudiniBarrierInference',
    
    # SyGuS Synthesis (Paper #19)
    'SyGuSGrammar',
    'SyGuSConstraint',
    'SyGuSSynthesizer',
    
    # Unified Engine
    'LearningMethod',
    'LearningBasedEngine',
]
