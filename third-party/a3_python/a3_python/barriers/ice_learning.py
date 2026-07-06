"""
SOTA Paper: ICE Learning (Implication CounterExamples).

Implements ICE-based invariant learning:
    P. Garg, C. Löding, P. Madhusudan, D. Neider.
    "ICE: A Robust Framework for Learning Invariants." CAV 2014.

KEY INSIGHT
===========

ICE learning uses three types of examples to learn invariants:
1. **Positive examples**: States that MUST be in the invariant (reachable)
2. **Negative examples**: States that MUST NOT be in the invariant (bad)
3. **Implication examples**: (s, s') pairs where if s is in invariant, s' must be too

The implication examples are KEY - they capture inductiveness constraints
without requiring the learner to understand the transition relation.

LEARNING FRAMEWORK
==================

Given:
- P⁺: positive examples (reachable states)
- P⁻: negative examples (bad states)
- P→: implication pairs (s, s') from transition

Find invariant I such that:
- ∀s ∈ P⁺: I(s)           (includes positive)
- ∀s ∈ P⁻: ¬I(s)          (excludes negative)
- ∀(s,s') ∈ P→: I(s) → I(s')  (respects implications)

INTEGRATION WITH BARRIERS
=========================

ICE provides:
1. **Invariant templates**: Learned invariants become barrier constraints
2. **Feature discovery**: Predicates used by learner guide barrier templates
3. **Inductiveness constraints**: Implication examples directly constrain barriers
4. **Data-driven refinement**: Failed proofs add more examples

IMPLEMENTATION STRUCTURE
========================

1. ICELearner: Main learning algorithm
2. PredicateFeatures: Feature/predicate basis for learning
3. DecisionTreeLearner: DT-based invariant learner
4. ImplicationOracle: Generates implication examples from transitions
5. ICEBarrierBridge: Connect ICE to barrier synthesis

LAYER POSITION
==============

This is a **Layer 4 (Learning)** module.

    ┌─────────────────────────────────────────────────────────────────┐
    │ Layer 5: Advanced Verification (IC3, CHC, IMC, Assume-Guarantee)│
    │ Layer 4: LEARNING ← [THIS MODULE]                               │
    │   ├── ice_learning.py ← You are here (Paper #17)                │
    │   ├── houdini.py (Paper #18)                                    │
    │   └── sygus_synthesis.py (Paper #19)                            │
    │ Layer 3: Abstraction (CEGAR, Predicate Abstraction, IMPACT)     │
    │ Layer 2: Certificate Core (Hybrid, Stochastic, SOS Safety)      │
    │ Layer 1: Foundations (Positivstellensatz, SOS/SDP, Lasserre)    │
    └─────────────────────────────────────────────────────────────────┘

CROSS-PAPER DEPENDENCIES
========================

This module builds on:
- Layer 1: Uses Polynomial, SemialgebraicSet for constraint representation
- Layer 2: Learning targets are barrier certificate templates
- Layer 3: Can use predicate abstraction for feature discovery

This module is used by:
- Paper #12 (CEGAR): ICE provides samples for CEGAR refinement
- Paper #16 (IMPACT): ICE interpolants guide lazy abstraction
- Paper #11 (CHC/Spacer): CHC solving uses ICE for candidate invariants
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Dict, List, Optional, Tuple, Set, Any, Callable, FrozenSet
from collections import defaultdict
import random

import z3

# =============================================================================
# LAYER 4: IMPORTS FROM LOWER LAYERS
# =============================================================================
# ICE learning builds on polynomial representations (Layer 1) to learn
# invariants that become barrier certificates (Layer 2). The learned
# invariants can feed into abstraction refinement (Layer 3).
# =============================================================================

from .parrilo_sos_sdp import (
    Polynomial,
    SemialgebraicSet,
    BarrierSynthesisProblem,
)


# =============================================================================
# EXAMPLE TYPES
# =============================================================================

@dataclass(frozen=True)
class ICEExample:
    """
    An ICE example (state valuation).
    
    Represents a concrete state as a mapping from variables to values.
    """
    values: Tuple[Tuple[str, int], ...]  # Frozen dict representation
    
    @staticmethod
    def from_dict(d: Dict[str, int]) -> "ICEExample":
        return ICEExample(tuple(sorted(d.items())))
    
    def to_dict(self) -> Dict[str, int]:
        return dict(self.values)
    
    def get(self, var: str, default: int = 0) -> int:
        for k, v in self.values:
            if k == var:
                return v
        return default
    
    def __str__(self) -> str:
        return str(self.to_dict())


@dataclass
class ImplicationExample:
    """
    An implication example (s, s') pair.
    
    If s is in the invariant, then s' must also be in the invariant.
    Captures one step of the transition relation.
    """
    antecedent: ICEExample
    consequent: ICEExample
    
    def __str__(self) -> str:
        return f"{self.antecedent} → {self.consequent}"


class ExampleType(Enum):
    """Type of ICE example."""
    POSITIVE = auto()    # Must be in invariant
    NEGATIVE = auto()    # Must not be in invariant
    IMPLICATION = auto() # Implication constraint


@dataclass
class ICEDataset:
    """
    Collection of ICE examples.
    
    Maintains positive, negative, and implication examples.
    """
    positive: Set[ICEExample] = field(default_factory=set)
    negative: Set[ICEExample] = field(default_factory=set)
    implications: Set[ImplicationExample] = field(default_factory=set)
    
    def add_positive(self, example: ICEExample) -> None:
        """Add positive example."""
        self.positive.add(example)
    
    def add_negative(self, example: ICEExample) -> None:
        """Add negative example."""
        self.negative.add(example)
    
    def add_implication(self, ante: ICEExample, cons: ICEExample) -> None:
        """Add implication example."""
        self.implications.add(ImplicationExample(ante, cons))
    
    def is_consistent(self) -> bool:
        """Check if dataset is consistent (no positive in negative)."""
        return self.positive.isdisjoint(self.negative)
    
    def size(self) -> int:
        """Total number of examples."""
        return len(self.positive) + len(self.negative) + len(self.implications)
    
    def clear(self) -> None:
        """Clear all examples."""
        self.positive.clear()
        self.negative.clear()
        self.implications.clear()
    
    def to_string(self) -> str:
        """String representation."""
        return (f"ICEDataset(+{len(self.positive)}, "
                f"-{len(self.negative)}, →{len(self.implications)})")


# =============================================================================
# PREDICATE/FEATURE BASIS
# =============================================================================

@dataclass
class Predicate:
    """
    A predicate for ICE learning.
    
    Predicates are atomic formulas over program variables.
    """
    name: str
    formula: z3.BoolRef
    variables: List[str]
    
    def evaluate(self, example: ICEExample) -> bool:
        """Evaluate predicate on an example."""
        # Substitute values into formula
        substitutions = []
        for var in self.variables:
            val = example.get(var, 0)
            z3_var = z3.Int(var)
            substitutions.append((z3_var, z3.IntVal(val)))
        
        result = z3.substitute(self.formula, substitutions)
        result = z3.simplify(result)
        
        return z3.is_true(result)
    
    def __str__(self) -> str:
        return f"{self.name}: {self.formula}"


class PredicateFeatures:
    """
    Feature basis for ICE learning.
    
    Manages a set of predicates used as features for learning.
    Supports:
    - Linear predicates (x >= c, x <= c, x + y >= c)
    - Interval predicates
    - Polynomial predicates
    """
    
    def __init__(self, variables: List[str], verbose: bool = False):
        self.variables = variables
        self.verbose = verbose
        
        self._predicates: List[Predicate] = []
        self._z3_vars = {v: z3.Int(v) for v in variables}
    
    def add_predicate(self, name: str, formula: z3.BoolRef) -> None:
        """Add a predicate to the basis."""
        # Extract variables from formula
        vars_used = [v for v in self.variables if v in str(formula)]
        pred = Predicate(name, formula, vars_used)
        self._predicates.append(pred)
    
    def add_interval_predicates(self, bounds: Dict[str, Tuple[int, int]]) -> None:
        """Add interval predicates for variables."""
        for var, (lo, hi) in bounds.items():
            if var not in self._z3_vars:
                continue
            
            z3_var = self._z3_vars[var]
            
            # x >= lo
            self.add_predicate(f"{var}>={lo}", z3_var >= lo)
            # x <= hi
            self.add_predicate(f"{var}<={hi}", z3_var <= hi)
    
    def add_comparison_predicates(self) -> None:
        """Add comparison predicates between variables."""
        for i, v1 in enumerate(self.variables):
            z3_v1 = self._z3_vars[v1]
            
            for v2 in self.variables[i + 1:]:
                z3_v2 = self._z3_vars[v2]
                
                # v1 <= v2
                self.add_predicate(f"{v1}<={v2}", z3_v1 <= z3_v2)
                # v1 < v2
                self.add_predicate(f"{v1}<{v2}", z3_v1 < z3_v2)
                # v1 == v2
                self.add_predicate(f"{v1}=={v2}", z3_v1 == z3_v2)
    
    def add_linear_predicates(self, max_coef: int = 2) -> None:
        """Add linear combination predicates."""
        for v in self.variables:
            z3_v = self._z3_vars[v]
            
            # x >= 0, x > 0, x <= 0, x < 0
            self.add_predicate(f"{v}>=0", z3_v >= 0)
            self.add_predicate(f"{v}>0", z3_v > 0)
            self.add_predicate(f"{v}<=0", z3_v <= 0)
            self.add_predicate(f"{v}<0", z3_v < 0)
    
    def add_polynomial_predicates(self, max_degree: int = 2) -> None:
        """Add polynomial predicates (squares, products)."""
        for v in self.variables:
            z3_v = self._z3_vars[v]
            
            # x^2 >= 0 (always true, but useful as feature)
            self.add_predicate(f"{v}^2>=0", z3_v * z3_v >= 0)
            
            # x^2 >= 1 (|x| >= 1)
            self.add_predicate(f"{v}^2>=1", z3_v * z3_v >= 1)
    
    def evaluate(self, example: ICEExample) -> Tuple[bool, ...]:
        """Evaluate all predicates on an example."""
        return tuple(p.evaluate(example) for p in self._predicates)
    
    def get_feature_vector(self, example: ICEExample) -> List[int]:
        """Get feature vector (0/1) for an example."""
        return [1 if p.evaluate(example) else 0 for p in self._predicates]
    
    def get_predicate_names(self) -> List[str]:
        """Get list of predicate names."""
        return [p.name for p in self._predicates]
    
    def get_predicates(self) -> List[Predicate]:
        """Get all predicates."""
        return list(self._predicates)
    
    def __len__(self) -> int:
        return len(self._predicates)


# =============================================================================
# ICE LEARNER
# =============================================================================

class ICEResult(Enum):
    """Result of ICE learning."""
    SUCCESS = auto()    # Invariant found
    FAILURE = auto()    # Could not find invariant
    INCONSISTENT = auto()  # Dataset is inconsistent
    TIMEOUT = auto()    # Timeout


@dataclass
class LearnedInvariant:
    """
    An invariant learned by ICE.
    
    Represented as a Boolean combination of predicates.
    """
    formula: z3.BoolRef
    predicates_used: List[str]
    is_dnf: bool = False  # True if in DNF form
    
    def evaluate(self, example: ICEExample, var_map: Dict[str, z3.ArithRef]) -> bool:
        """Evaluate invariant on an example."""
        substitutions = []
        for var, z3_var in var_map.items():
            val = example.get(var, 0)
            substitutions.append((z3_var, z3.IntVal(val)))
        
        result = z3.substitute(self.formula, substitutions)
        result = z3.simplify(result)
        
        return z3.is_true(result)
    
    def to_string(self) -> str:
        return str(self.formula)


@dataclass
class ICELearningResult:
    """
    Result of ICE learning.
    
    Contains the learned invariant and statistics.
    """
    result: ICEResult
    invariant: Optional[LearnedInvariant] = None
    iterations: int = 0
    examples_processed: int = 0
    statistics: Dict[str, Any] = field(default_factory=dict)
    message: str = ""


class ICELearner:
    """
    ICE (Implication CounterExamples) learner.
    
    Learns invariants from positive, negative, and implication examples.
    Uses decision tree or Boolean formula learning.
    """
    
    def __init__(self, features: PredicateFeatures,
                 max_iterations: int = 100,
                 timeout_ms: int = 60000,
                 verbose: bool = False):
        self.features = features
        self.max_iterations = max_iterations
        self.timeout_ms = timeout_ms
        self.verbose = verbose
        
        self._var_map = {v: z3.Int(v) for v in features.variables}
        
        self.stats = {
            'iterations': 0,
            'candidates_rejected': 0,
            'examples_added': 0,
            'total_time_ms': 0,
        }
    
    def learn(self, dataset: ICEDataset) -> ICELearningResult:
        """
        Learn invariant from ICE dataset.
        
        Main learning algorithm:
        1. Start with TRUE (accept all)
        2. Refine to exclude negative examples
        3. Check implication constraints
        4. Add more examples if constraints violated
        """
        start_time = time.time()
        
        if not dataset.is_consistent():
            return ICELearningResult(
                result=ICEResult.INCONSISTENT,
                message="Dataset has positive example in negative set"
            )
        
        # Convert examples to feature vectors
        pos_features = [self.features.evaluate(ex) for ex in dataset.positive]
        neg_features = [self.features.evaluate(ex) for ex in dataset.negative]
        
        # Learn separating formula
        for iteration in range(self.max_iterations):
            # Check timeout
            elapsed = (time.time() - start_time) * 1000
            if elapsed > self.timeout_ms:
                self.stats['total_time_ms'] = elapsed
                return ICELearningResult(
                    result=ICEResult.TIMEOUT,
                    iterations=iteration,
                    statistics=self.stats,
                    message="Timeout"
                )
            
            self.stats['iterations'] = iteration + 1
            
            # Try to learn a candidate
            candidate = self._learn_candidate(pos_features, neg_features, dataset)
            
            if candidate is None:
                self.stats['candidates_rejected'] += 1
                continue
            
            # Check implication constraints
            violated = self._check_implications(candidate, dataset.implications)
            
            if not violated:
                # Found valid invariant
                self.stats['total_time_ms'] = (time.time() - start_time) * 1000
                
                return ICELearningResult(
                    result=ICEResult.SUCCESS,
                    invariant=candidate,
                    iterations=iteration + 1,
                    examples_processed=dataset.size(),
                    statistics=self.stats,
                    message="Invariant found"
                )
            
            # Add violated implication as new constraint
            self._handle_violated_implication(violated, dataset)
            self.stats['examples_added'] += 1
            
            # Update feature vectors
            pos_features = [self.features.evaluate(ex) for ex in dataset.positive]
            neg_features = [self.features.evaluate(ex) for ex in dataset.negative]
        
        self.stats['total_time_ms'] = (time.time() - start_time) * 1000
        
        return ICELearningResult(
            result=ICEResult.FAILURE,
            iterations=self.max_iterations,
            statistics=self.stats,
            message="Max iterations reached"
        )
    
    def _learn_candidate(self, pos_features: List[Tuple[bool, ...]],
                          neg_features: List[Tuple[bool, ...]],
                          dataset: ICEDataset) -> Optional[LearnedInvariant]:
        """Learn a candidate invariant from features."""
        # Use a simple decision tree or conjunction learner
        
        # Try conjunction of predicates that separate pos from neg
        n_preds = len(self.features)
        
        if n_preds == 0:
            return LearnedInvariant(z3.BoolVal(True), [])
        
        # Find predicates that are TRUE for all positive examples
        # and FALSE for at least some negative examples
        
        separating_preds = []
        
        for i, pred in enumerate(self.features.get_predicates()):
            # Check if predicate is true for all positive
            all_pos_true = all(features[i] for features in pos_features) if pos_features else True
            
            # Check if predicate is false for some negative
            some_neg_false = any(not features[i] for features in neg_features) if neg_features else True
            
            if all_pos_true:
                separating_preds.append(pred)
        
        if not separating_preds:
            # No single predicate works, try disjunction
            return self._learn_disjunction(pos_features, neg_features)
        
        # Build conjunction of separating predicates
        formula = z3.And([p.formula for p in separating_preds])
        pred_names = [p.name for p in separating_preds]
        
        return LearnedInvariant(formula, pred_names)
    
    def _learn_disjunction(self, pos_features: List[Tuple[bool, ...]],
                            neg_features: List[Tuple[bool, ...]]) -> Optional[LearnedInvariant]:
        """Learn a DNF formula if conjunction doesn't work."""
        predicates = self.features.get_predicates()
        
        if not predicates:
            return None
        
        # Try OR of predicates that cover positive without covering negative
        covering_preds = []
        
        for i, pred in enumerate(predicates):
            # Check if predicate covers some positive
            covers_pos = any(features[i] for features in pos_features) if pos_features else False
            
            # Check if predicate covers no negative
            covers_neg = any(features[i] for features in neg_features) if neg_features else False
            
            if covers_pos and not covers_neg:
                covering_preds.append(pred)
        
        if covering_preds:
            formula = z3.Or([p.formula for p in covering_preds])
            pred_names = [p.name for p in covering_preds]
            return LearnedInvariant(formula, pred_names, is_dnf=True)
        
        # Fallback: just use all predicates that don't exclude positive
        safe_preds = []
        for i, pred in enumerate(predicates):
            excludes_pos = any(not features[i] for features in pos_features) if pos_features else False
            if not excludes_pos:
                safe_preds.append(pred)
        
        if safe_preds:
            formula = z3.And([p.formula for p in safe_preds])
            return LearnedInvariant(formula, [p.name for p in safe_preds])
        
        return None
    
    def _check_implications(self, candidate: LearnedInvariant,
                             implications: Set[ImplicationExample]) -> Optional[ImplicationExample]:
        """Check if candidate satisfies all implication constraints."""
        for impl in implications:
            ante_in = candidate.evaluate(impl.antecedent, self._var_map)
            cons_in = candidate.evaluate(impl.consequent, self._var_map)
            
            # If antecedent is in invariant, consequent must be too
            if ante_in and not cons_in:
                return impl
        
        return None
    
    def _handle_violated_implication(self, impl: ImplicationExample,
                                       dataset: ICEDataset) -> None:
        """Handle a violated implication by updating dataset."""
        # Two options:
        # 1. Add antecedent to negative (exclude it)
        # 2. Add consequent to positive (include it)
        
        # Heuristic: if consequent is "close" to existing positive, include it
        # Otherwise, exclude antecedent
        
        # Simple heuristic: randomly choose
        if random.random() < 0.5:
            dataset.add_negative(impl.antecedent)
        else:
            dataset.add_positive(impl.consequent)
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get learning statistics."""
        return dict(self.stats)


# =============================================================================
# IMPLICATION ORACLE
# =============================================================================

class ImplicationOracle:
    """
    Oracle for generating implication examples.
    
    Given a transition relation, generates (s, s') pairs
    where s transitions to s'.
    """
    
    def __init__(self, variables: List[str],
                 transition: z3.BoolRef,
                 verbose: bool = False):
        self.variables = variables
        self.transition = transition
        self.verbose = verbose
        
        self._z3_vars = [z3.Int(v) for v in variables]
        self._z3_vars_prime = [z3.Int(f"{v}_prime") for v in variables]
        
        self._solver = z3.Solver()
    
    def get_implication(self, state: ICEExample) -> Optional[ICEExample]:
        """
        Get a successor state for the given state.
        
        Returns None if state has no successors.
        """
        self._solver.push()
        
        # Fix current state
        for var, z3_var in zip(self.variables, self._z3_vars):
            val = state.get(var, 0)
            self._solver.add(z3_var == val)
        
        # Add transition
        self._solver.add(self.transition)
        
        if self._solver.check() == z3.sat:
            model = self._solver.model()
            
            # Extract successor state
            succ_dict = {}
            for var, z3_var_prime in zip(self.variables, self._z3_vars_prime):
                val = model.eval(z3_var_prime, model_completion=True)
                if z3.is_int_value(val):
                    succ_dict[var] = val.as_long()
                else:
                    succ_dict[var] = 0
            
            self._solver.pop()
            return ICEExample.from_dict(succ_dict)
        
        self._solver.pop()
        return None
    
    def generate_implications(self, states: Set[ICEExample],
                               max_per_state: int = 5) -> Set[ImplicationExample]:
        """
        Generate implication examples from a set of states.
        """
        implications = set()
        
        for state in states:
            for _ in range(max_per_state):
                succ = self.get_implication(state)
                if succ:
                    implications.add(ImplicationExample(state, succ))
                    # Use successor as new source
                    state = succ
                else:
                    break
        
        return implications
    
    def sample_reachable_states(self, init_state: ICEExample,
                                  num_samples: int = 100,
                                  max_depth: int = 20) -> Set[ICEExample]:
        """
        Sample reachable states from initial state.
        
        Uses random simulation to explore reachable states.
        """
        states = {init_state}
        frontier = [init_state]
        
        for _ in range(num_samples):
            if not frontier:
                break
            
            # Pick random state from frontier
            current = random.choice(frontier)
            
            # Get successor
            for _ in range(max_depth):
                succ = self.get_implication(current)
                if succ and succ not in states:
                    states.add(succ)
                    frontier.append(succ)
                    current = succ
                else:
                    break
        
        return states


# =============================================================================
# DECISION TREE LEARNER
# =============================================================================

@dataclass
class DTNode:
    """
    Decision tree node.
    
    Either a leaf (label) or internal (predicate + children).
    """
    is_leaf: bool
    label: Optional[bool] = None           # For leaf nodes
    predicate: Optional[Predicate] = None  # For internal nodes
    true_child: Optional["DTNode"] = None
    false_child: Optional["DTNode"] = None
    
    def evaluate(self, example: ICEExample) -> bool:
        """Evaluate decision tree on example."""
        if self.is_leaf:
            return self.label or False
        
        if self.predicate and self.predicate.evaluate(example):
            return self.true_child.evaluate(example) if self.true_child else False
        else:
            return self.false_child.evaluate(example) if self.false_child else False
    
    def to_formula(self, var_map: Dict[str, z3.ArithRef]) -> z3.BoolRef:
        """Convert decision tree to Z3 formula."""
        if self.is_leaf:
            return z3.BoolVal(self.label or False)
        
        if not self.predicate:
            return z3.BoolVal(False)
        
        pred_formula = self.predicate.formula
        true_formula = self.true_child.to_formula(var_map) if self.true_child else z3.BoolVal(False)
        false_formula = self.false_child.to_formula(var_map) if self.false_child else z3.BoolVal(False)
        
        return z3.If(pred_formula, true_formula, false_formula)


class DecisionTreeLearner:
    """
    Learn invariants using decision trees.
    
    Builds a decision tree that classifies examples as
    positive (in invariant) or negative (not in invariant).
    """
    
    def __init__(self, features: PredicateFeatures,
                 max_depth: int = 10,
                 verbose: bool = False):
        self.features = features
        self.max_depth = max_depth
        self.verbose = verbose
    
    def learn(self, positive: Set[ICEExample],
               negative: Set[ICEExample]) -> Optional[DTNode]:
        """
        Learn decision tree from positive/negative examples.
        """
        if not positive and not negative:
            return DTNode(is_leaf=True, label=True)
        
        return self._build_tree(list(positive), list(negative), 0)
    
    def _build_tree(self, positive: List[ICEExample],
                     negative: List[ICEExample],
                     depth: int) -> DTNode:
        """Recursively build decision tree."""
        # Base cases
        if not negative:
            return DTNode(is_leaf=True, label=True)
        
        if not positive:
            return DTNode(is_leaf=True, label=False)
        
        if depth >= self.max_depth:
            # Majority vote
            label = len(positive) >= len(negative)
            return DTNode(is_leaf=True, label=label)
        
        # Find best splitting predicate
        best_pred = None
        best_score = -1
        best_split = None
        
        for pred in self.features.get_predicates():
            pos_true = [ex for ex in positive if pred.evaluate(ex)]
            pos_false = [ex for ex in positive if not pred.evaluate(ex)]
            neg_true = [ex for ex in negative if pred.evaluate(ex)]
            neg_false = [ex for ex in negative if not pred.evaluate(ex)]
            
            # Score: information gain (simplified)
            score = self._compute_score(pos_true, pos_false, neg_true, neg_false)
            
            if score > best_score:
                best_score = score
                best_pred = pred
                best_split = (pos_true, pos_false, neg_true, neg_false)
        
        if best_pred is None or best_score <= 0:
            # No good split found
            label = len(positive) >= len(negative)
            return DTNode(is_leaf=True, label=label)
        
        pos_true, pos_false, neg_true, neg_false = best_split
        
        # Recurse
        true_child = self._build_tree(pos_true, neg_true, depth + 1)
        false_child = self._build_tree(pos_false, neg_false, depth + 1)
        
        return DTNode(
            is_leaf=False,
            predicate=best_pred,
            true_child=true_child,
            false_child=false_child
        )
    
    def _compute_score(self, pos_true: List, pos_false: List,
                        neg_true: List, neg_false: List) -> float:
        """Compute split score (simplified information gain)."""
        # Prefer splits that separate positive from negative
        n_pos = len(pos_true) + len(pos_false)
        n_neg = len(neg_true) + len(neg_false)
        
        if n_pos == 0 or n_neg == 0:
            return 0
        
        # Score: separation quality
        # High if pos_true is large and neg_true is small (or vice versa)
        if len(pos_true) + len(neg_true) == 0:
            return 0
        if len(pos_false) + len(neg_false) == 0:
            return 0
        
        purity_true = len(pos_true) / (len(pos_true) + len(neg_true) + 0.001)
        purity_false = len(neg_false) / (len(pos_false) + len(neg_false) + 0.001)
        
        return purity_true + purity_false


# =============================================================================
# ICE-BARRIER BRIDGE
# =============================================================================

@dataclass
class ICEConstraint:
    """
    Constraint derived from ICE for barrier synthesis.
    """
    formula: z3.BoolRef
    as_polynomial: Optional[Polynomial] = None
    source: str = ""  # "positive", "negative", or "implication"


class ICEBarrierBridge:
    """
    Bridge between ICE learning and barrier synthesis.
    
    Uses ICE invariants to:
    1. Condition barrier search space
    2. Provide polynomial template features
    3. Extract inductiveness constraints
    """
    
    def __init__(self, n_vars: int, var_names: Optional[List[str]] = None,
                 verbose: bool = False):
        self.n_vars = n_vars
        self.var_names = var_names or [f"x_{i}" for i in range(n_vars)]
        self.verbose = verbose
        
        self._constraints: List[ICEConstraint] = []
        self._invariant: Optional[LearnedInvariant] = None
    
    def set_learned_invariant(self, invariant: LearnedInvariant) -> None:
        """Set the learned invariant."""
        self._invariant = invariant
        self._extract_constraints()
    
    def _extract_constraints(self) -> None:
        """Extract constraints from learned invariant."""
        if self._invariant is None:
            return
        
        # Convert invariant formula to constraints
        formula = self._invariant.formula
        
        # Add as constraint
        constraint = ICEConstraint(
            formula=formula,
            as_polynomial=self._formula_to_polynomial(formula),
            source="invariant"
        )
        self._constraints.append(constraint)
    
    def _formula_to_polynomial(self, formula: z3.BoolRef) -> Optional[Polynomial]:
        """Convert formula to polynomial constraint."""
        # Handle comparison operators
        if z3.is_le(formula) or z3.is_lt(formula):
            lhs, rhs = formula.children()
            return self._expr_to_polynomial(rhs - lhs)
        
        if z3.is_ge(formula) or z3.is_gt(formula):
            lhs, rhs = formula.children()
            return self._expr_to_polynomial(lhs - rhs)
        
        return None
    
    def _expr_to_polynomial(self, expr: z3.ArithRef) -> Optional[Polynomial]:
        """Convert Z3 expression to polynomial."""
        coeffs = {}
        
        def process(e, sign=1):
            if z3.is_int_value(e):
                zero_mono = tuple([0] * self.n_vars)
                coeffs[zero_mono] = coeffs.get(zero_mono, 0) + sign * e.as_long()
            elif z3.is_const(e):
                var_name = str(e)
                if var_name in self.var_names:
                    idx = self.var_names.index(var_name)
                    mono = tuple(1 if i == idx else 0 for i in range(self.n_vars))
                    coeffs[mono] = coeffs.get(mono, 0) + sign
            elif z3.is_add(e):
                for child in e.children():
                    process(child, sign)
            elif z3.is_sub(e):
                children = e.children()
                process(children[0], sign)
                for child in children[1:]:
                    process(child, -sign)
            elif z3.is_mul(e):
                children = e.children()
                if len(children) == 2 and z3.is_int_value(children[0]):
                    coef = children[0].as_long()
                    process(children[1], sign * coef)
        
        try:
            process(expr)
            if coeffs:
                return Polynomial(self.n_vars, coeffs)
        except Exception:
            pass
        
        return None
    
    def condition_barrier_problem(self, problem: BarrierSynthesisProblem) -> BarrierSynthesisProblem:
        """Condition barrier problem using ICE constraints."""
        if not self._invariant:
            return problem
        
        # Add invariant as constraint to init set
        poly_constraints = []
        for constraint in self._constraints:
            if constraint.as_polynomial:
                poly_constraints.append(constraint.as_polynomial)
        
        if not poly_constraints:
            return problem
        
        new_init = SemialgebraicSet(
            n_vars=problem.init_set.n_vars,
            inequalities=problem.init_set.inequalities + poly_constraints,
            equalities=problem.init_set.equalities,
            var_names=problem.init_set.var_names,
            name=f"{problem.init_set.name}_ice"
        )
        
        return BarrierSynthesisProblem(
            n_vars=problem.n_vars,
            init_set=new_init,
            unsafe_set=problem.unsafe_set,
            transition=problem.transition,
            epsilon=problem.epsilon,
            barrier_degree=problem.barrier_degree
        )
    
    def get_template_features(self) -> List[Polynomial]:
        """Get polynomial features for template construction."""
        return [c.as_polynomial for c in self._constraints if c.as_polynomial]


# =============================================================================
# ICE INTEGRATION
# =============================================================================

@dataclass
class ICEIntegrationConfig:
    """Configuration for ICE integration."""
    max_learning_iterations: int = 100
    sample_states: int = 50
    use_decision_tree: bool = True
    add_interval_predicates: bool = True
    add_comparison_predicates: bool = True
    timeout_ms: int = 60000
    verbose: bool = False


class ICEIntegration:
    """
    Integration of ICE learning with barrier synthesis.
    
    Provides:
    1. ICE-based invariant learning
    2. Invariant-based barrier conditioning
    3. Feature extraction for templates
    """
    
    def __init__(self, config: Optional[ICEIntegrationConfig] = None,
                 verbose: bool = False):
        self.config = config or ICEIntegrationConfig()
        self.verbose = verbose or self.config.verbose
        
        self._invariants: Dict[str, LearnedInvariant] = {}
        self._bridges: Dict[str, ICEBarrierBridge] = {}
        
        self.stats = {
            'learning_runs': 0,
            'invariants_found': 0,
            'conditioning_applications': 0,
        }
    
    def learn_invariant(self, variables: List[str],
                         init_states: Set[ICEExample],
                         bad_states: Set[ICEExample],
                         transition: z3.BoolRef,
                         problem_id: str = "default") -> ICELearningResult:
        """
        Learn invariant using ICE.
        """
        self.stats['learning_runs'] += 1
        
        # Build features
        features = PredicateFeatures(variables, self.verbose)
        
        if self.config.add_interval_predicates:
            # Infer bounds from examples
            bounds = self._infer_bounds(variables, init_states | bad_states)
            features.add_interval_predicates(bounds)
        
        if self.config.add_comparison_predicates:
            features.add_comparison_predicates()
        
        features.add_linear_predicates()
        
        # Build dataset
        dataset = ICEDataset()
        for state in init_states:
            dataset.add_positive(state)
        for state in bad_states:
            dataset.add_negative(state)
        
        # Generate implications
        oracle = ImplicationOracle(variables, transition, self.verbose)
        implications = oracle.generate_implications(init_states)
        for impl in implications:
            dataset.add_implication(impl.antecedent, impl.consequent)
        
        # Learn
        learner = ICELearner(
            features,
            self.config.max_learning_iterations,
            self.config.timeout_ms,
            self.verbose
        )
        
        result = learner.learn(dataset)
        
        if result.result == ICEResult.SUCCESS and result.invariant:
            self.stats['invariants_found'] += 1
            self._invariants[problem_id] = result.invariant
            
            # Build bridge
            bridge = ICEBarrierBridge(len(variables), variables, self.verbose)
            bridge.set_learned_invariant(result.invariant)
            self._bridges[problem_id] = bridge
        
        return result
    
    def _infer_bounds(self, variables: List[str],
                       examples: Set[ICEExample]) -> Dict[str, Tuple[int, int]]:
        """Infer variable bounds from examples."""
        bounds = {}
        
        for var in variables:
            values = [ex.get(var, 0) for ex in examples]
            if values:
                lo = min(values)
                hi = max(values)
                bounds[var] = (lo - 10, hi + 10)  # Add slack
            else:
                bounds[var] = (-100, 100)  # Default
        
        return bounds
    
    def condition_barrier_problem(self, problem: BarrierSynthesisProblem,
                                    problem_id: str = "default") -> BarrierSynthesisProblem:
        """Condition barrier problem using ICE invariant."""
        bridge = self._bridges.get(problem_id)
        if bridge:
            self.stats['conditioning_applications'] += 1
            return bridge.condition_barrier_problem(problem)
        return problem
    
    def get_invariant(self, problem_id: str) -> Optional[LearnedInvariant]:
        """Get learned invariant."""
        return self._invariants.get(problem_id)
    
    def clear_cache(self) -> None:
        """Clear all caches."""
        self._invariants.clear()
        self._bridges.clear()


# =============================================================================
# CONVENIENCE FUNCTIONS
# =============================================================================

def learn_ice_invariant(variables: List[str],
                         positive: Set[Dict[str, int]],
                         negative: Set[Dict[str, int]],
                         implications: List[Tuple[Dict[str, int], Dict[str, int]]],
                         timeout_ms: int = 60000,
                         verbose: bool = False) -> ICELearningResult:
    """
    Learn invariant from ICE examples.
    
    Main entry point for ICE learning.
    """
    # Convert to ICEExample
    pos_examples = {ICEExample.from_dict(d) for d in positive}
    neg_examples = {ICEExample.from_dict(d) for d in negative}
    
    impl_examples = {
        ImplicationExample(ICEExample.from_dict(a), ICEExample.from_dict(c))
        for a, c in implications
    }
    
    # Build features
    features = PredicateFeatures(variables, verbose)
    features.add_linear_predicates()
    features.add_comparison_predicates()
    
    # Build dataset
    dataset = ICEDataset()
    dataset.positive = pos_examples
    dataset.negative = neg_examples
    dataset.implications = impl_examples
    
    # Learn
    learner = ICELearner(features, timeout_ms=timeout_ms, verbose=verbose)
    return learner.learn(dataset)


def condition_barrier_with_ice(problem: BarrierSynthesisProblem,
                                init_states: Set[Dict[str, int]],
                                bad_states: Set[Dict[str, int]],
                                transition: z3.BoolRef,
                                timeout_ms: int = 30000,
                                verbose: bool = False) -> BarrierSynthesisProblem:
    """
    Condition barrier problem using ICE-learned invariant.
    """
    variables = problem.init_set.var_names or [f"x_{i}" for i in range(problem.n_vars)]
    
    pos = {ICEExample.from_dict(d) for d in init_states}
    neg = {ICEExample.from_dict(d) for d in bad_states}
    
    config = ICEIntegrationConfig(timeout_ms=timeout_ms, verbose=verbose)
    integration = ICEIntegration(config, verbose)
    
    result = integration.learn_invariant(variables, pos, neg, transition)
    
    if result.result == ICEResult.SUCCESS:
        return integration.condition_barrier_problem(problem)
    
    return problem


# =============================================================================
# ADVANCED ICE FEATURES
# =============================================================================

class HoudiniLearner:
    """
    Houdini-style annotation inference.
    
    From: C. Flanagan, K. R. M. Leino. "Houdini, an Annotation Assistant for ESC/Java."
    
    Algorithm:
    1. Start with all candidate predicates
    2. Check each against examples
    3. Refute predicates that fail
    4. Keep predicates that survive
    """
    
    def __init__(self, features: PredicateFeatures,
                 verbose: bool = False):
        self.features = features
        self.verbose = verbose
        
        self.stats = {
            'predicates_checked': 0,
            'predicates_refuted': 0,
            'iterations': 0,
        }
    
    def infer(self, dataset: ICEDataset) -> List[Predicate]:
        """
        Infer valid predicates using Houdini refutation.
        """
        # Start with all predicates
        candidates = list(self.features.get_predicates())
        
        changed = True
        iteration = 0
        
        while changed:
            changed = False
            iteration += 1
            self.stats['iterations'] = iteration
            
            new_candidates = []
            
            for pred in candidates:
                self.stats['predicates_checked'] += 1
                
                # Check against positive examples
                valid = True
                for pos in dataset.positive:
                    if not pred.evaluate(pos):
                        valid = False
                        break
                
                if valid:
                    new_candidates.append(pred)
                else:
                    self.stats['predicates_refuted'] += 1
                    changed = True
            
            candidates = new_candidates
        
        return candidates
    
    def to_invariant(self, predicates: List[Predicate]) -> Optional[LearnedInvariant]:
        """Convert surviving predicates to invariant."""
        if not predicates:
            return None
        
        formula = z3.And([p.formula for p in predicates])
        names = [p.name for p in predicates]
        
        return LearnedInvariant(formula, names)


class SamplingOracle:
    """
    Sampling-based oracle for generating examples.
    
    Uses random or systematic sampling to generate
    positive, negative, and implication examples.
    """
    
    def __init__(self, variables: List[str],
                 init: z3.BoolRef,
                 trans: z3.BoolRef,
                 property: z3.BoolRef,
                 verbose: bool = False):
        self.variables = variables
        self.init = init
        self.trans = trans
        self.property = property
        self.verbose = verbose
        
        self._z3_vars = [z3.Int(v) for v in variables]
    
    def sample_initial_states(self, num_samples: int = 10) -> Set[ICEExample]:
        """Sample states satisfying init."""
        states = set()
        solver = z3.Solver()
        solver.add(self.init)
        
        for _ in range(num_samples):
            if solver.check() == z3.sat:
                model = solver.model()
                state_dict = {}
                
                for v, z3_v in zip(self.variables, self._z3_vars):
                    val = model.eval(z3_v, model_completion=True)
                    state_dict[v] = val.as_long() if z3.is_int_value(val) else 0
                
                state = ICEExample.from_dict(state_dict)
                states.add(state)
                
                # Block this state for diversity
                block = z3.Or([z3_v != state_dict[v] for v, z3_v in zip(self.variables, self._z3_vars)])
                solver.add(block)
            else:
                break
        
        return states
    
    def sample_bad_states(self, num_samples: int = 10) -> Set[ICEExample]:
        """Sample states violating property."""
        states = set()
        solver = z3.Solver()
        solver.add(z3.Not(self.property))
        
        for _ in range(num_samples):
            if solver.check() == z3.sat:
                model = solver.model()
                state_dict = {}
                
                for v, z3_v in zip(self.variables, self._z3_vars):
                    val = model.eval(z3_v, model_completion=True)
                    state_dict[v] = val.as_long() if z3.is_int_value(val) else 0
                
                state = ICEExample.from_dict(state_dict)
                states.add(state)
                
                # Block for diversity
                block = z3.Or([z3_v != state_dict[v] for v, z3_v in zip(self.variables, self._z3_vars)])
                solver.add(block)
            else:
                break
        
        return states
    
    def generate_dataset(self, num_positive: int = 10,
                          num_negative: int = 10,
                          num_implications: int = 20) -> ICEDataset:
        """Generate a complete ICE dataset."""
        dataset = ICEDataset()
        
        # Sample positive (initial states)
        for state in self.sample_initial_states(num_positive):
            dataset.add_positive(state)
        
        # Sample negative (bad states)
        for state in self.sample_bad_states(num_negative):
            dataset.add_negative(state)
        
        # Generate implications
        oracle = ImplicationOracle(self.variables, self.trans, self.verbose)
        implications = oracle.generate_implications(dataset.positive, max_per_state=3)
        
        for impl in list(implications)[:num_implications]:
            dataset.add_implication(impl.antecedent, impl.consequent)
        
        return dataset


class IterativeICE:
    """
    Iterative ICE learning with refinement.
    
    Combines ICE learning with verification to
    iteratively refine the invariant.
    """
    
    def __init__(self, variables: List[str],
                 init: z3.BoolRef,
                 trans: z3.BoolRef,
                 property: z3.BoolRef,
                 verbose: bool = False):
        self.variables = variables
        self.init = init
        self.trans = trans
        self.property = property
        self.verbose = verbose
        
        self.sampling_oracle = SamplingOracle(variables, init, trans, property, verbose)
        self.features = PredicateFeatures(variables, verbose)
        
        self._setup_features()
        
        self.stats = {
            'iterations': 0,
            'refinements': 0,
            'final_examples': 0,
        }
    
    def _setup_features(self) -> None:
        """Set up predicate features."""
        self.features.add_linear_predicates()
        self.features.add_comparison_predicates()
    
    def learn_with_refinement(self, max_iterations: int = 10,
                                timeout_ms: int = 60000) -> ICELearningResult:
        """
        Learn invariant with iterative refinement.
        """
        start_time = time.time()
        
        # Generate initial dataset
        dataset = self.sampling_oracle.generate_dataset()
        
        for iteration in range(max_iterations):
            # Check timeout
            elapsed = (time.time() - start_time) * 1000
            if elapsed > timeout_ms:
                return ICELearningResult(
                    result=ICEResult.TIMEOUT,
                    iterations=iteration,
                    message="Timeout"
                )
            
            self.stats['iterations'] = iteration + 1
            
            # Learn candidate
            learner = ICELearner(
                self.features,
                max_iterations=50,
                timeout_ms=int((timeout_ms - elapsed) / 2),
                verbose=self.verbose
            )
            
            result = learner.learn(dataset)
            
            if result.result != ICEResult.SUCCESS:
                continue
            
            # Verify candidate
            is_valid, counterexample = self._verify_candidate(result.invariant)
            
            if is_valid:
                self.stats['final_examples'] = dataset.size()
                return result
            
            # Refine with counterexample
            if counterexample:
                self._refine_dataset(dataset, counterexample)
                self.stats['refinements'] += 1
        
        return ICELearningResult(
            result=ICEResult.FAILURE,
            iterations=max_iterations,
            statistics=self.stats,
            message="Max iterations reached"
        )
    
    def _verify_candidate(self, invariant: LearnedInvariant) -> Tuple[bool, Optional[Dict[str, Any]]]:
        """Verify candidate invariant."""
        z3_vars = [z3.Int(v) for v in self.variables]
        z3_vars_prime = [z3.Int(f"{v}_prime") for v in self.variables]
        
        solver = z3.Solver()
        
        # Check initiation: Init → Inv
        solver.push()
        solver.add(self.init)
        solver.add(z3.Not(invariant.formula))
        if solver.check() == z3.sat:
            model = solver.model()
            cex = {"type": "initiation", "state": self._model_to_dict(model, z3_vars)}
            solver.pop()
            return False, cex
        solver.pop()
        
        # Check consecution: Inv ∧ Trans → Inv'
        inv_prime = z3.substitute(
            invariant.formula,
            list(zip(z3_vars, z3_vars_prime))
        )
        
        solver.push()
        solver.add(invariant.formula)
        solver.add(self.trans)
        solver.add(z3.Not(inv_prime))
        if solver.check() == z3.sat:
            model = solver.model()
            cex = {
                "type": "consecution",
                "state": self._model_to_dict(model, z3_vars),
                "next_state": self._model_to_dict(model, z3_vars_prime)
            }
            solver.pop()
            return False, cex
        solver.pop()
        
        # Check safety: Inv → Property
        solver.push()
        solver.add(invariant.formula)
        solver.add(z3.Not(self.property))
        if solver.check() == z3.sat:
            model = solver.model()
            cex = {"type": "safety", "state": self._model_to_dict(model, z3_vars)}
            solver.pop()
            return False, cex
        solver.pop()
        
        return True, None
    
    def _model_to_dict(self, model: z3.ModelRef, vars: List[z3.ArithRef]) -> Dict[str, int]:
        """Convert Z3 model to dictionary."""
        result = {}
        for var, z3_var in zip(self.variables, vars):
            val = model.eval(z3_var, model_completion=True)
            result[var] = val.as_long() if z3.is_int_value(val) else 0
        return result
    
    def _refine_dataset(self, dataset: ICEDataset, cex: Dict[str, Any]) -> None:
        """Refine dataset with counterexample."""
        cex_type = cex.get("type")
        
        if cex_type == "initiation":
            # State satisfies Init but not Inv → positive example
            state = ICEExample.from_dict(cex["state"])
            dataset.add_positive(state)
        
        elif cex_type == "consecution":
            # State in Inv transitions to state not in Inv → implication
            state = ICEExample.from_dict(cex["state"])
            next_state = ICEExample.from_dict(cex["next_state"])
            dataset.add_implication(state, next_state)
        
        elif cex_type == "safety":
            # State in Inv but violates property → negative example
            state = ICEExample.from_dict(cex["state"])
            dataset.add_negative(state)


# =============================================================================
# BOOLEAN FORMULA LEARNER
# =============================================================================

class BooleanFormulaLearner:
    """
    Learn Boolean formulas over predicates.
    
    Learns invariants in CNF or DNF form using
    constraint solving.
    """
    
    def __init__(self, features: PredicateFeatures,
                 max_clauses: int = 5,
                 max_literals_per_clause: int = 3,
                 use_dnf: bool = False,
                 verbose: bool = False):
        self.features = features
        self.max_clauses = max_clauses
        self.max_literals = max_literals_per_clause
        self.use_dnf = use_dnf
        self.verbose = verbose
        
        self.stats = {
            'formulas_tried': 0,
            'solutions_found': 0,
        }
    
    def learn(self, dataset: ICEDataset) -> Optional[LearnedInvariant]:
        """
        Learn Boolean formula from ICE dataset.
        
        Uses SAT encoding to find a formula that:
        1. Includes all positive examples
        2. Excludes all negative examples
        3. Respects all implication constraints
        """
        predicates = self.features.get_predicates()
        n_preds = len(predicates)
        
        if n_preds == 0:
            return None
        
        solver = z3.Solver()
        
        # Variables for formula structure
        # active[c][p] = predicate p is active in clause c
        # sign[c][p] = predicate p is positive in clause c
        active = [[z3.Bool(f"active_{c}_{p}") for p in range(n_preds)] 
                  for c in range(self.max_clauses)]
        sign = [[z3.Bool(f"sign_{c}_{p}") for p in range(n_preds)]
                for c in range(self.max_clauses)]
        
        # Constraint: at most max_literals per clause
        for c in range(self.max_clauses):
            solver.add(z3.PbLe([(active[c][p], 1) for p in range(n_preds)], self.max_literals))
        
        # Helper: evaluate clause on example
        def clause_sat(c: int, example: ICEExample) -> z3.BoolRef:
            """Clause c is satisfied by example (DNF: at least one literal true)."""
            literals = []
            for p, pred in enumerate(predicates):
                pred_val = pred.evaluate(example)
                # literal is true if:
                # - predicate is active AND
                # - (sign is positive AND pred is true) OR (sign is negative AND pred is false)
                lit_true = z3.And(active[c][p],
                                   z3.If(sign[c][p],
                                         z3.BoolVal(pred_val),
                                         z3.BoolVal(not pred_val)))
                literals.append(lit_true)
            return z3.Or(literals) if literals else z3.BoolVal(False)
        
        def formula_sat(example: ICEExample) -> z3.BoolRef:
            """Formula is satisfied by example."""
            if self.use_dnf:
                # DNF: at least one clause satisfied
                return z3.Or([clause_sat(c, example) for c in range(self.max_clauses)])
            else:
                # CNF: all clauses satisfied
                return z3.And([z3.Or([z3.Not(active[c][0])] +  # Inactive clause = true
                                      [clause_sat(c, example)])
                               for c in range(self.max_clauses)])
        
        # Constraint: positive examples must satisfy formula
        for pos in dataset.positive:
            solver.add(formula_sat(pos))
        
        # Constraint: negative examples must not satisfy formula
        for neg in dataset.negative:
            solver.add(z3.Not(formula_sat(neg)))
        
        # Constraint: implications
        for impl in dataset.implications:
            # ante_sat → cons_sat
            ante_sat = formula_sat(impl.antecedent)
            cons_sat = formula_sat(impl.consequent)
            solver.add(z3.Implies(ante_sat, cons_sat))
        
        self.stats['formulas_tried'] += 1
        
        if solver.check() == z3.sat:
            model = solver.model()
            formula = self._extract_formula(model, active, sign, predicates)
            self.stats['solutions_found'] += 1
            return formula
        
        return None
    
    def _extract_formula(self, model: z3.ModelRef,
                          active: List[List[z3.BoolRef]],
                          sign: List[List[z3.BoolRef]],
                          predicates: List[Predicate]) -> LearnedInvariant:
        """Extract learned formula from SAT model."""
        clauses = []
        used_preds = set()
        
        for c in range(self.max_clauses):
            literals = []
            
            for p, pred in enumerate(predicates):
                is_active = z3.is_true(model.eval(active[c][p], model_completion=True))
                is_positive = z3.is_true(model.eval(sign[c][p], model_completion=True))
                
                if is_active:
                    used_preds.add(pred.name)
                    if is_positive:
                        literals.append(pred.formula)
                    else:
                        literals.append(z3.Not(pred.formula))
            
            if literals:
                if self.use_dnf:
                    clauses.append(z3.And(literals))  # Conjunction for DNF clause
                else:
                    clauses.append(z3.Or(literals))   # Disjunction for CNF clause
        
        if not clauses:
            formula = z3.BoolVal(True)
        elif self.use_dnf:
            formula = z3.Or(clauses)
        else:
            formula = z3.And(clauses)
        
        return LearnedInvariant(
            formula=z3.simplify(formula),
            predicates_used=list(used_preds),
            is_dnf=self.use_dnf
        )


class LinearClassifierLearner:
    """
    Learn linear classifiers as invariants.
    
    Finds a hyperplane that separates positive from negative examples.
    """
    
    def __init__(self, variables: List[str],
                 verbose: bool = False):
        self.variables = variables
        self.verbose = verbose
        
        self._z3_vars = {v: z3.Int(v) for v in variables}
    
    def learn(self, positive: Set[ICEExample],
               negative: Set[ICEExample]) -> Optional[LearnedInvariant]:
        """
        Learn linear classifier.
        
        Finds coefficients a_i such that:
        - Σ a_i * x_i >= 0 for positive examples
        - Σ a_i * x_i < 0 for negative examples
        """
        n = len(self.variables)
        
        solver = z3.Solver()
        
        # Coefficients (including constant term)
        coeffs = [z3.Int(f"a_{i}") for i in range(n)]
        const = z3.Int("a_const")
        
        # Bound coefficients to prevent trivial solutions
        for c in coeffs:
            solver.add(c >= -100, c <= 100)
        solver.add(const >= -1000, const <= 1000)
        
        # At least one non-zero coefficient
        solver.add(z3.Or([c != 0 for c in coeffs] + [const != 0]))
        
        def linear_expr(example: ICEExample) -> z3.ArithRef:
            """Compute linear expression for example."""
            terms = [coeffs[i] * example.get(self.variables[i], 0) for i in range(n)]
            return sum(terms) + const
        
        # Positive examples: linear >= 0
        for pos in positive:
            solver.add(linear_expr(pos) >= 0)
        
        # Negative examples: linear < 0
        for neg in negative:
            solver.add(linear_expr(neg) < 0)
        
        if solver.check() == z3.sat:
            model = solver.model()
            
            # Extract coefficients
            coef_vals = [model.eval(c, model_completion=True).as_long() for c in coeffs]
            const_val = model.eval(const, model_completion=True).as_long()
            
            # Build formula
            z3_vars = list(self._z3_vars.values())
            linear = sum(coef_vals[i] * z3_vars[i] for i in range(n)) + const_val
            formula = linear >= 0
            
            return LearnedInvariant(
                formula=formula,
                predicates_used=[f"{coef_vals[i]}*{self.variables[i]}" 
                                  for i in range(n) if coef_vals[i] != 0]
            )
        
        return None


class PolynomialClassifierLearner:
    """
    Learn polynomial classifiers as invariants.
    
    Finds a polynomial that separates positive from negative examples.
    """
    
    def __init__(self, variables: List[str],
                 max_degree: int = 2,
                 verbose: bool = False):
        self.variables = variables
        self.max_degree = max_degree
        self.verbose = verbose
        
        self._z3_vars = {v: z3.Int(v) for v in variables}
        self._monomials = self._generate_monomials()
    
    def _generate_monomials(self) -> List[Tuple[Tuple[int, ...], str]]:
        """Generate all monomials up to max_degree."""
        monomials = []
        n = len(self.variables)
        
        def gen_powers(remaining_deg: int, var_idx: int, current: List[int]):
            if var_idx == n:
                mono = tuple(current)
                name = self._mono_name(mono)
                monomials.append((mono, name))
                return
            
            for power in range(remaining_deg + 1):
                gen_powers(remaining_deg - power, var_idx + 1, current + [power])
        
        gen_powers(self.max_degree, 0, [])
        return monomials
    
    def _mono_name(self, powers: Tuple[int, ...]) -> str:
        """Get human-readable monomial name."""
        parts = []
        for i, p in enumerate(powers):
            if p == 1:
                parts.append(self.variables[i])
            elif p > 1:
                parts.append(f"{self.variables[i]}^{p}")
        return "*".join(parts) if parts else "1"
    
    def _mono_value(self, powers: Tuple[int, ...], example: ICEExample) -> int:
        """Evaluate monomial on example."""
        result = 1
        for i, p in enumerate(powers):
            val = example.get(self.variables[i], 0)
            result *= val ** p
        return result
    
    def learn(self, positive: Set[ICEExample],
               negative: Set[ICEExample]) -> Optional[LearnedInvariant]:
        """
        Learn polynomial classifier.
        """
        solver = z3.Solver()
        
        # Coefficients for each monomial
        coeffs = {mono: z3.Int(f"c_{name}") for mono, name in self._monomials}
        
        # Bound coefficients
        for c in coeffs.values():
            solver.add(c >= -100, c <= 100)
        
        # At least one non-zero
        solver.add(z3.Or([c != 0 for c in coeffs.values()]))
        
        def poly_expr(example: ICEExample) -> z3.ArithRef:
            """Evaluate polynomial on example."""
            terms = [coeffs[mono] * self._mono_value(mono, example) 
                     for mono, _ in self._monomials]
            return sum(terms)
        
        # Positive: poly >= 0
        for pos in positive:
            solver.add(poly_expr(pos) >= 0)
        
        # Negative: poly < 0
        for neg in negative:
            solver.add(poly_expr(neg) < 0)
        
        if solver.check() == z3.sat:
            model = solver.model()
            
            # Extract polynomial
            z3_vars = list(self._z3_vars.values())
            terms = []
            used = []
            
            for mono, name in self._monomials:
                coef = model.eval(coeffs[mono], model_completion=True).as_long()
                if coef != 0:
                    mono_z3 = 1
                    for i, p in enumerate(mono):
                        for _ in range(p):
                            mono_z3 = mono_z3 * z3_vars[i]
                    terms.append(coef * mono_z3)
                    used.append(f"{coef}*{name}")
            
            if terms:
                poly = sum(terms)
                formula = poly >= 0
                
                return LearnedInvariant(
                    formula=formula,
                    predicates_used=used
                )
        
        return None


# =============================================================================
# PARALLEL ICE
# =============================================================================

class ParallelICE:
    """
    Parallel ICE learning with multiple learners.
    
    Runs multiple learners in parallel and combines results.
    """
    
    def __init__(self, variables: List[str],
                 verbose: bool = False):
        self.variables = variables
        self.verbose = verbose
        
        self._learners: List[Any] = []
        self._setup_learners()
    
    def _setup_learners(self) -> None:
        """Set up different learners."""
        features = PredicateFeatures(self.variables, self.verbose)
        features.add_linear_predicates()
        features.add_comparison_predicates()
        
        self._learners = [
            ("ice", ICELearner(features, max_iterations=50, verbose=self.verbose)),
            ("dt", DecisionTreeLearner(features, max_depth=5, verbose=self.verbose)),
            ("linear", LinearClassifierLearner(self.variables, self.verbose)),
            ("poly", PolynomialClassifierLearner(self.variables, max_degree=2, verbose=self.verbose)),
        ]
    
    def learn(self, dataset: ICEDataset) -> List[Tuple[str, Optional[LearnedInvariant]]]:
        """
        Run all learners and collect results.
        """
        results = []
        
        for name, learner in self._learners:
            try:
                if name == "ice":
                    result = learner.learn(dataset)
                    inv = result.invariant if result.result == ICEResult.SUCCESS else None
                elif name == "dt":
                    dt = learner.learn(dataset.positive, dataset.negative)
                    if dt:
                        var_map = {v: z3.Int(v) for v in self.variables}
                        formula = dt.to_formula(var_map)
                        inv = LearnedInvariant(formula, [])
                    else:
                        inv = None
                elif name == "linear":
                    inv = learner.learn(dataset.positive, dataset.negative)
                elif name == "poly":
                    inv = learner.learn(dataset.positive, dataset.negative)
                else:
                    inv = None
                
                results.append((name, inv))
            except Exception as e:
                if self.verbose:
                    print(f"  Learner {name} failed: {e}")
                results.append((name, None))
        
        return results
    
    def select_best(self, results: List[Tuple[str, Optional[LearnedInvariant]]],
                     dataset: ICEDataset) -> Optional[LearnedInvariant]:
        """Select best invariant from results."""
        valid = [(name, inv) for name, inv in results if inv is not None]
        
        if not valid:
            return None
        
        # Score by simplicity (fewer predicates = better)
        best = min(valid, key=lambda x: len(x[1].predicates_used))
        return best[1]


# =============================================================================
# INCREMENTAL ICE
# =============================================================================

class IncrementalICE:
    """
    Incremental ICE learning.
    
    Supports adding examples incrementally and re-learning.
    """
    
    def __init__(self, variables: List[str],
                 verbose: bool = False):
        self.variables = variables
        self.verbose = verbose
        
        self.dataset = ICEDataset()
        self.features = PredicateFeatures(variables, verbose)
        self.features.add_linear_predicates()
        self.features.add_comparison_predicates()
        
        self._current_invariant: Optional[LearnedInvariant] = None
        self._learner = ICELearner(self.features, max_iterations=100, verbose=verbose)
        
        self.stats = {
            'total_examples': 0,
            'relearning_count': 0,
        }
    
    def add_positive(self, example: Dict[str, int]) -> bool:
        """
        Add positive example.
        
        Returns True if invariant needs relearning.
        """
        ice_ex = ICEExample.from_dict(example)
        self.dataset.add_positive(ice_ex)
        self.stats['total_examples'] += 1
        
        # Check if current invariant includes this example
        if self._current_invariant:
            var_map = {v: z3.Int(v) for v in self.variables}
            if not self._current_invariant.evaluate(ice_ex, var_map):
                return True
        
        return False
    
    def add_negative(self, example: Dict[str, int]) -> bool:
        """
        Add negative example.
        
        Returns True if invariant needs relearning.
        """
        ice_ex = ICEExample.from_dict(example)
        self.dataset.add_negative(ice_ex)
        self.stats['total_examples'] += 1
        
        # Check if current invariant excludes this example
        if self._current_invariant:
            var_map = {v: z3.Int(v) for v in self.variables}
            if self._current_invariant.evaluate(ice_ex, var_map):
                return True
        
        return False
    
    def add_implication(self, ante: Dict[str, int], cons: Dict[str, int]) -> bool:
        """
        Add implication example.
        
        Returns True if invariant needs relearning.
        """
        ante_ex = ICEExample.from_dict(ante)
        cons_ex = ICEExample.from_dict(cons)
        self.dataset.add_implication(ante_ex, cons_ex)
        self.stats['total_examples'] += 1
        
        # Check implication
        if self._current_invariant:
            var_map = {v: z3.Int(v) for v in self.variables}
            ante_in = self._current_invariant.evaluate(ante_ex, var_map)
            cons_in = self._current_invariant.evaluate(cons_ex, var_map)
            if ante_in and not cons_in:
                return True
        
        return False
    
    def relearn(self) -> ICELearningResult:
        """Relearn invariant from current dataset."""
        self.stats['relearning_count'] += 1
        
        result = self._learner.learn(self.dataset)
        
        if result.result == ICEResult.SUCCESS:
            self._current_invariant = result.invariant
        
        return result
    
    def get_invariant(self) -> Optional[LearnedInvariant]:
        """Get current invariant."""
        return self._current_invariant


# =============================================================================
# ICE WITH TEMPLATE SYNTHESIS
# =============================================================================

class TemplateGuidedICE:
    """
    ICE learning guided by templates.
    
    Uses polynomial templates to structure the invariant search.
    """
    
    def __init__(self, variables: List[str],
                 template_degree: int = 2,
                 verbose: bool = False):
        self.variables = variables
        self.template_degree = template_degree
        self.verbose = verbose
        
        self._z3_vars = {v: z3.Real(v) for v in variables}
        self._templates = self._generate_templates()
    
    def _generate_templates(self) -> List[z3.ArithRef]:
        """Generate polynomial templates."""
        templates = []
        n = len(self.variables)
        z3_vars = list(self._z3_vars.values())
        
        # Linear templates
        for v in z3_vars:
            templates.append(v)
            templates.append(-v)
        
        # Quadratic templates
        if self.template_degree >= 2:
            for i, v1 in enumerate(z3_vars):
                templates.append(v1 * v1)  # x^2
                for v2 in z3_vars[i + 1:]:
                    templates.append(v1 * v2)  # x*y
        
        return templates
    
    def synthesize(self, positive: Set[ICEExample],
                    negative: Set[ICEExample],
                    implications: Set[ImplicationExample]) -> Optional[LearnedInvariant]:
        """
        Synthesize invariant using templates.
        """
        solver = z3.Solver()
        
        # Template coefficients
        coeffs = [z3.Real(f"c_{i}") for i in range(len(self._templates))]
        const = z3.Real("c_const")
        
        # Bound coefficients
        for c in coeffs:
            solver.add(c >= -10, c <= 10)
        solver.add(const >= -100, const <= 100)
        
        def template_expr(example: ICEExample) -> z3.ArithRef:
            """Evaluate template at example."""
            subs = [(self._z3_vars[v], z3.RealVal(example.get(v, 0)))
                    for v in self.variables]
            
            terms = []
            for i, tmpl in enumerate(self._templates):
                val = z3.substitute(tmpl, subs)
                terms.append(coeffs[i] * val)
            
            return sum(terms) + const
        
        # Positive: template >= 0
        for pos in positive:
            solver.add(template_expr(pos) >= 0)
        
        # Negative: template < 0
        for neg in negative:
            solver.add(template_expr(neg) < -0.001)  # Small epsilon for strictness
        
        # Implications: ante >= 0 → cons >= 0
        for impl in implications:
            ante_val = template_expr(impl.antecedent)
            cons_val = template_expr(impl.consequent)
            solver.add(z3.Implies(ante_val >= 0, cons_val >= 0))
        
        if solver.check() == z3.sat:
            model = solver.model()
            
            # Build formula
            terms = []
            for i, tmpl in enumerate(self._templates):
                coef = model.eval(coeffs[i], model_completion=True)
                if not z3.is_true(coef == 0):
                    terms.append(coef * tmpl)
            
            const_val = model.eval(const, model_completion=True)
            if terms:
                poly = sum(terms) + const_val
            else:
                poly = const_val
            
            formula = poly >= 0
            
            return LearnedInvariant(
                formula=z3.simplify(formula),
                predicates_used=["polynomial_template"]
            )
        
        return None


# =============================================================================
# PROPERTY-DIRECTED ICE
# =============================================================================

class PropertyDirectedICE:
    """
    ICE learning directed by property/safety specification.
    
    Uses the safety property to guide example generation
    and invariant refinement.
    """
    
    def __init__(self, variables: List[str],
                 property: z3.BoolRef,
                 verbose: bool = False):
        self.variables = variables
        self.property = property
        self.verbose = verbose
        
        self._z3_vars = {v: z3.Int(v) for v in variables}
    
    def generate_property_examples(self, num_samples: int = 20) -> Tuple[Set[ICEExample], Set[ICEExample]]:
        """
        Generate examples from property boundary.
        
        Samples states near the property boundary:
        - Safe states (satisfy property) → positive candidates
        - Unsafe states (violate property) → negative examples
        """
        z3_vars = list(self._z3_vars.values())
        
        safe_states = set()
        unsafe_states = set()
        
        solver = z3.Solver()
        
        # Sample safe states
        solver.push()
        solver.add(self.property)
        
        for _ in range(num_samples):
            if solver.check() == z3.sat:
                model = solver.model()
                state = {}
                for v, z3_v in self._z3_vars.items():
                    val = model.eval(z3_v, model_completion=True)
                    state[v] = val.as_long() if z3.is_int_value(val) else 0
                safe_states.add(ICEExample.from_dict(state))
                
                # Block for diversity
                block = z3.Or([z3_v != state[v] for v, z3_v in self._z3_vars.items()])
                solver.add(block)
            else:
                break
        
        solver.pop()
        
        # Sample unsafe states
        solver.push()
        solver.add(z3.Not(self.property))
        
        for _ in range(num_samples):
            if solver.check() == z3.sat:
                model = solver.model()
                state = {}
                for v, z3_v in self._z3_vars.items():
                    val = model.eval(z3_v, model_completion=True)
                    state[v] = val.as_long() if z3.is_int_value(val) else 0
                unsafe_states.add(ICEExample.from_dict(state))
                
                block = z3.Or([z3_v != state[v] for v, z3_v in self._z3_vars.items()])
                solver.add(block)
            else:
                break
        
        solver.pop()
        
        return safe_states, unsafe_states
    
    def strengthen_with_property(self, invariant: LearnedInvariant) -> LearnedInvariant:
        """
        Strengthen invariant to imply property.
        """
        # Conjoin invariant with property
        strengthened = z3.And(invariant.formula, self.property)
        
        return LearnedInvariant(
            formula=z3.simplify(strengthened),
            predicates_used=invariant.predicates_used + ["property"]
        )


# =============================================================================
# ABSTRACTION-GUIDED ICE
# =============================================================================

class AbstractionGuidedICE:
    """
    ICE learning with abstraction.
    
    Uses predicate abstraction to define the invariant domain.
    """
    
    def __init__(self, variables: List[str],
                 abstraction_predicates: List[z3.BoolRef],
                 verbose: bool = False):
        self.variables = variables
        self.predicates = abstraction_predicates
        self.verbose = verbose
        
        self._z3_vars = {v: z3.Int(v) for v in variables}
    
    def abstract(self, example: ICEExample) -> Tuple[bool, ...]:
        """Abstract example to predicate valuation."""
        subs = [(self._z3_vars[v], z3.IntVal(example.get(v, 0)))
                for v in self.variables]
        
        valuation = []
        for pred in self.predicates:
            subst = z3.substitute(pred, subs)
            valuation.append(z3.is_true(z3.simplify(subst)))
        
        return tuple(valuation)
    
    def learn_over_abstraction(self, positive: Set[ICEExample],
                                 negative: Set[ICEExample]) -> Optional[LearnedInvariant]:
        """
        Learn over abstract domain.
        """
        # Abstract all examples
        pos_abstract = {self.abstract(ex) for ex in positive}
        neg_abstract = {self.abstract(ex) for ex in negative}
        
        # Find consistent formula over abstract domain
        # (cube over predicates that separates pos from neg)
        
        n_preds = len(self.predicates)
        
        # For each predicate, check if it consistently separates
        separating = []
        
        for i in range(n_preds):
            pos_true = all(abst[i] for abst in pos_abstract)
            neg_false = all(not abst[i] for abst in neg_abstract)
            
            if pos_true and neg_false:
                # This predicate separates: pos has it, neg doesn't
                separating.append((i, True))
            elif all(not abst[i] for abst in pos_abstract) and all(abst[i] for abst in neg_abstract):
                # Negation separates
                separating.append((i, False))
        
        if separating:
            # Build conjunction of separating predicates
            formula_parts = []
            for idx, positive_sign in separating:
                if positive_sign:
                    formula_parts.append(self.predicates[idx])
                else:
                    formula_parts.append(z3.Not(self.predicates[idx]))
            
            formula = z3.And(formula_parts) if len(formula_parts) > 1 else formula_parts[0]
            
            return LearnedInvariant(
                formula=z3.simplify(formula),
                predicates_used=[f"pred_{i}" for i, _ in separating]
            )
        
        return None


# =============================================================================
# AUXILIARY UTILITIES
# =============================================================================

class ICEVisualization:
    """
    Visualization utilities for ICE learning.
    """
    
    @staticmethod
    def dataset_to_string(dataset: ICEDataset) -> str:
        """Convert dataset to readable string."""
        lines = []
        lines.append(f"ICE Dataset ({dataset.size()} examples)")
        lines.append(f"  Positive ({len(dataset.positive)}):")
        for ex in list(dataset.positive)[:5]:
            lines.append(f"    {ex}")
        if len(dataset.positive) > 5:
            lines.append(f"    ... and {len(dataset.positive) - 5} more")
        
        lines.append(f"  Negative ({len(dataset.negative)}):")
        for ex in list(dataset.negative)[:5]:
            lines.append(f"    {ex}")
        if len(dataset.negative) > 5:
            lines.append(f"    ... and {len(dataset.negative) - 5} more")
        
        lines.append(f"  Implications ({len(dataset.implications)}):")
        for impl in list(dataset.implications)[:3]:
            lines.append(f"    {impl}")
        if len(dataset.implications) > 3:
            lines.append(f"    ... and {len(dataset.implications) - 3} more")
        
        return "\n".join(lines)
    
    @staticmethod
    def invariant_to_string(inv: LearnedInvariant) -> str:
        """Convert invariant to readable string."""
        return f"Learned Invariant:\n  Formula: {inv.formula}\n  Predicates: {inv.predicates_used}"


class ICEMetrics:
    """
    Metrics and evaluation for ICE learning.
    """
    
    @staticmethod
    def precision(invariant: LearnedInvariant,
                   true_positives: Set[ICEExample],
                   true_negatives: Set[ICEExample],
                   var_map: Dict[str, z3.ArithRef]) -> float:
        """Compute precision of learned invariant."""
        predicted_positive = [ex for ex in true_positives | true_negatives
                               if invariant.evaluate(ex, var_map)]
        if not predicted_positive:
            return 1.0
        
        correct = sum(1 for ex in predicted_positive if ex in true_positives)
        return correct / len(predicted_positive)
    
    @staticmethod
    def recall(invariant: LearnedInvariant,
                true_positives: Set[ICEExample],
                var_map: Dict[str, z3.ArithRef]) -> float:
        """Compute recall of learned invariant."""
        if not true_positives:
            return 1.0
        
        included = sum(1 for ex in true_positives if invariant.evaluate(ex, var_map))
        return included / len(true_positives)


# =============================================================================
# ENTRY POINTS
# =============================================================================

def create_ice_from_barrier_problem(problem: BarrierSynthesisProblem,
                                      num_samples: int = 20,
                                      verbose: bool = False) -> Tuple[ICEDataset, PredicateFeatures]:
    """
    Create ICE dataset from barrier synthesis problem.
    
    Samples initial and unsafe states to create examples.
    """
    n_vars = problem.n_vars
    var_names = problem.init_set.var_names or [f"x_{i}" for i in range(n_vars)]
    
    # Create Z3 variables
    z3_vars = [z3.Real(v) for v in var_names]
    
    dataset = ICEDataset()
    
    # Sample from init set (positive examples)
    init_constraints = [p.to_z3(z3_vars) >= 0 for p in problem.init_set.inequalities]
    init_constraints += [p.to_z3(z3_vars) == 0 for p in problem.init_set.equalities]
    
    solver = z3.Solver()
    solver.add(z3.And(init_constraints))
    
    for _ in range(num_samples):
        if solver.check() == z3.sat:
            model = solver.model()
            state = {}
            for v, z3_v in zip(var_names, z3_vars):
                val = model.eval(z3_v, model_completion=True)
                if z3.is_int_value(val):
                    state[v] = val.as_long()
                elif z3.is_rational_value(val):
                    state[v] = int(val.numerator_as_long() / val.denominator_as_long())
                else:
                    state[v] = 0
            dataset.add_positive(ICEExample.from_dict(state))
            
            # Block for diversity
            block = z3.Or([z3_v != model.eval(z3_v, model_completion=True) 
                           for z3_v in z3_vars])
            solver.add(block)
        else:
            break
    
    # Sample from unsafe set (negative examples)
    unsafe_constraints = [p.to_z3(z3_vars) >= 0 for p in problem.unsafe_set.inequalities]
    
    solver = z3.Solver()
    solver.add(z3.And(unsafe_constraints))
    
    for _ in range(num_samples):
        if solver.check() == z3.sat:
            model = solver.model()
            state = {}
            for v, z3_v in zip(var_names, z3_vars):
                val = model.eval(z3_v, model_completion=True)
                if z3.is_int_value(val):
                    state[v] = val.as_long()
                elif z3.is_rational_value(val):
                    state[v] = int(val.numerator_as_long() / val.denominator_as_long())
                else:
                    state[v] = 0
            dataset.add_negative(ICEExample.from_dict(state))
            
            block = z3.Or([z3_v != model.eval(z3_v, model_completion=True) 
                           for z3_v in z3_vars])
            solver.add(block)
        else:
            break
    
    # Create features
    features = PredicateFeatures(var_names, verbose)
    features.add_linear_predicates()
    features.add_comparison_predicates()
    
    return dataset, features
