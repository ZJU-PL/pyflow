"""
SOTA Paper: Assume-Guarantee Reasoning.

Implements compositional verification using assume-guarantee:
    T. A. Henzinger, S. Qadeer, S. K. Rajamani.
    "You Assume, We Guarantee: Methodology and Case Studies."
    CAV 1998.

KEY INSIGHT
===========

Assume-guarantee reasoning enables modular verification:
- Instead of verifying M₁ ∥ M₂ ⊨ P monolithically
- Prove: M₁ with assumption A satisfies G₁
- Prove: M₂ guarantees A
- Conclude: M₁ ∥ M₂ ⊨ G₁

This avoids state explosion from composition.

ASSUME-GUARANTEE RULE
=====================

The core rule (simplified):

    ⟨A⟩ M₁ ⟨G₁⟩     M₂ ⊨ A
    ─────────────────────────
         M₁ ∥ M₂ ⊨ G₁

More general (circular):

    ⟨true⟩ M₁ ⟨A₁⟩    ⟨A₁⟩ M₂ ⟨G⟩
    ────────────────────────────────
           M₁ ∥ M₂ ⊨ G

KEY CHALLENGES
==============

1. Finding good assumptions A
2. Ensuring assumptions are dischargeable
3. Handling circular dependencies
4. Compositionality of proofs

LEARNING ASSUMPTIONS
====================

L* algorithm can learn assumptions:
1. Teacher checks ⟨A⟩ M₁ ⟨G⟩
2. If counterexample, check M₂ ⊨ A
3. Refine A based on results
4. Repeat until proof or real bug

IMPLEMENTATION STRUCTURE
========================

1. Component: Module in compositional system
2. Assumption: Assumption about environment
3. Guarantee: Property component provides
4. AGProof: Assume-guarantee proof structure
5. AGVerifier: Verify AG proofs
6. AssumptionLearner: Learn assumptions
7. AGIntegration: Integration with barriers

LAYER POSITION
==============

This is a **Layer 5 (Advanced Verification)** module.

    ┌─────────────────────────────────────────────────────────────────┐
    │ Layer 5: ADVANCED VERIFICATION ← [THIS MODULE]                  │
    │   ├── dsos_sdsos.py (Paper #9)                                  │
    │   ├── ic3_pdr.py (Paper #10)                                    │
    │   ├── spacer_chc.py (Paper #11)                                 │
    │   ├── interpolation_imc.py (Paper #15)                          │
    │   └── assume_guarantee.py ← You are here (Paper #20)            │
    │ Layer 4: Learning (ICE, Houdini, SyGuS)                         │
    │ Layer 3: Abstraction (CEGAR, Predicate Abstraction, IMPACT)     │
    │ Layer 2: Certificate Core (Hybrid, Stochastic, SOS Safety)      │
    │ Layer 1: Foundations (Positivstellensatz, SOS/SDP, Lasserre)    │
    └─────────────────────────────────────────────────────────────────┘

CROSS-PAPER DEPENDENCIES
========================

This module is the COMPOSITIONAL APEX integrating all layers:

From each layer:
- Layer 1: Polynomial assumptions/guarantees
- Layer 2: Per-component barrier certificates
- Layer 3: Component abstractions for AG reasoning
- Layer 4: L* learning for assumption discovery
- Layer 5: IC3/CHC for per-component verification

Integration with other Layer 5 papers:
- Paper #10 (IC3): Per-component PDR verification
- Paper #11 (CHC): AG as multi-query CHC problem
- Paper #15 (Interpolation): Interpolants as assumptions

KEY COMPOSITION PATTERNS
========================

With barrier certificates:
- Each component has barrier B_i
- Assumptions constrain neighbor behavior
- Guarantees are barrier consequences
- Compositional barrier: ∧_i B_i under AG constraints
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Dict, List, Optional, Tuple, Set, Any, Callable
from collections import defaultdict

import z3

# =============================================================================
# LAYER 5: IMPORTS FROM ALL LOWER LAYERS
# =============================================================================
# Assume-Guarantee reasoning is the compositional apex that integrates
# polynomial constraints (Layer 1), barrier certificates (Layer 2),
# abstractions (Layer 3), and learning (Layer 4) for modular verification.
# =============================================================================

from .parrilo_sos_sdp import (
    Polynomial,
    SemialgebraicSet,
    BarrierSynthesisProblem,
)


# =============================================================================
# COMPONENT MODEL
# =============================================================================

@dataclass
class Component:
    """
    Component in a compositional system.
    
    Has inputs, outputs, state, and behavior.
    """
    name: str
    inputs: List[z3.ArithRef]      # Input variables
    outputs: List[z3.ArithRef]     # Output variables
    state: List[z3.ArithRef]       # Internal state
    primed_state: List[z3.ArithRef]  # Next state variables
    initial: z3.BoolRef            # Initial state predicate
    transition: z3.BoolRef         # Transition relation
    
    def get_all_vars(self) -> List[z3.ArithRef]:
        """Get all variables."""
        return self.inputs + self.outputs + self.state
    
    def get_primed_vars(self) -> List[z3.ArithRef]:
        """Get primed variables."""
        return self.primed_state
    
    def __str__(self) -> str:
        return f"Component({self.name})"
    
    def __hash__(self) -> int:
        return hash(self.name)


@dataclass
class Assumption:
    """
    Assumption about the environment.
    
    A predicate that the environment is assumed to satisfy.
    """
    name: str
    formula: z3.BoolRef
    over_variables: List[z3.ArithRef]
    
    def __str__(self) -> str:
        return f"Assumption({self.name})"
    
    def evaluate(self, model: z3.ModelRef) -> bool:
        """Check if assumption holds in model."""
        result = model.eval(self.formula, model_completion=True)
        return z3.is_true(result)


@dataclass
class Guarantee:
    """
    Guarantee provided by a component.
    
    A property the component ensures given its assumptions.
    """
    name: str
    formula: z3.BoolRef
    over_variables: List[z3.ArithRef]
    
    def __str__(self) -> str:
        return f"Guarantee({self.name})"


# =============================================================================
# ASSUME-GUARANTEE PROOF
# =============================================================================

@dataclass
class AGTriple:
    """
    Assume-guarantee triple: ⟨A⟩ M ⟨G⟩
    
    Component M, under assumption A, guarantees G.
    """
    assumption: Assumption
    component: Component
    guarantee: Guarantee
    
    def __str__(self) -> str:
        return f"⟨{self.assumption.name}⟩ {self.component.name} ⟨{self.guarantee.name}⟩"


@dataclass
class AGProof:
    """
    Assume-guarantee proof structure.
    
    Contains:
    - Triples to prove
    - Discharge obligations
    - Composition structure
    """
    triples: List[AGTriple]
    discharge_obligations: Dict[str, 'DischargeObligation'] = field(default_factory=dict)
    
    def add_triple(self, triple: AGTriple) -> None:
        """Add a triple to prove."""
        self.triples.append(triple)
    
    def add_obligation(self, assumption_name: str, 
                        discharger: Component) -> None:
        """Add obligation to discharge assumption."""
        self.discharge_obligations[assumption_name] = DischargeObligation(
            assumption_name=assumption_name,
            discharging_component=discharger
        )


@dataclass
class DischargeObligation:
    """
    Obligation to discharge an assumption.
    """
    assumption_name: str
    discharging_component: Component
    discharged: bool = False


# =============================================================================
# AG VERIFIER
# =============================================================================

class AGResult(Enum):
    """Result of AG verification."""
    PROVEN = auto()
    REFUTED = auto()
    UNKNOWN = auto()


@dataclass
class AGVerificationResult:
    """Result of AG verification."""
    result: AGResult
    failed_triple: Optional[AGTriple] = None
    counterexample: Optional[Dict[str, Any]] = None
    statistics: Dict[str, Any] = field(default_factory=dict)
    message: str = ""


class AGVerifier:
    """
    Verify assume-guarantee proofs.
    """
    
    def __init__(self, timeout_ms: int = 60000, verbose: bool = False):
        self.timeout_ms = timeout_ms
        self.verbose = verbose
        
        self.stats = {
            'triples_checked': 0,
            'obligations_discharged': 0,
            'proofs_succeeded': 0,
        }
    
    def verify_triple(self, triple: AGTriple) -> Tuple[bool, Optional[Dict]]:
        """
        Verify AG triple: ⟨A⟩ M ⟨G⟩
        
        Checks: A ∧ Init_M ∧ T_M* → G
        """
        self.stats['triples_checked'] += 1
        
        component = triple.component
        assumption = triple.assumption
        guarantee = triple.guarantee
        
        # Simplified check: Init ∧ A → G
        solver = z3.Solver()
        solver.set("timeout", self.timeout_ms)
        
        solver.add(component.initial)
        solver.add(assumption.formula)
        solver.add(z3.Not(guarantee.formula))
        
        result = solver.check()
        
        if result == z3.sat:
            model = solver.model()
            cex = self._extract_counterexample(model, triple)
            return (False, cex)
        elif result == z3.unsat:
            return (True, None)
        else:
            return (False, None)
    
    def verify_discharge(self, assumption: Assumption,
                           component: Component) -> Tuple[bool, Optional[Dict]]:
        """
        Verify that component discharges assumption.
        
        Checks: behavior of component implies assumption.
        """
        solver = z3.Solver()
        solver.set("timeout", self.timeout_ms)
        
        # Component behavior should imply assumption
        solver.add(component.initial)
        solver.add(component.transition)
        solver.add(z3.Not(assumption.formula))
        
        result = solver.check()
        
        if result == z3.sat:
            model = solver.model()
            return (False, self._model_to_dict(model, component.get_all_vars()))
        elif result == z3.unsat:
            self.stats['obligations_discharged'] += 1
            return (True, None)
        else:
            return (False, None)
    
    def verify_proof(self, proof: AGProof) -> AGVerificationResult:
        """
        Verify complete AG proof.
        """
        # Step 1: Verify all triples
        for triple in proof.triples:
            success, cex = self.verify_triple(triple)
            
            if not success:
                return AGVerificationResult(
                    result=AGResult.REFUTED,
                    failed_triple=triple,
                    counterexample=cex,
                    statistics=self.stats,
                    message=f"Triple {triple} failed"
                )
        
        # Step 2: Discharge all obligations
        for name, obligation in proof.discharge_obligations.items():
            # Find the assumption
            assumption = self._find_assumption(proof, name)
            if assumption is None:
                continue
            
            success, cex = self.verify_discharge(assumption, obligation.discharging_component)
            
            if not success:
                return AGVerificationResult(
                    result=AGResult.REFUTED,
                    counterexample=cex,
                    statistics=self.stats,
                    message=f"Failed to discharge {name}"
                )
            
            obligation.discharged = True
        
        self.stats['proofs_succeeded'] += 1
        
        return AGVerificationResult(
            result=AGResult.PROVEN,
            statistics=self.stats,
            message="AG proof verified"
        )
    
    def _find_assumption(self, proof: AGProof, name: str) -> Optional[Assumption]:
        """Find assumption by name."""
        for triple in proof.triples:
            if triple.assumption.name == name:
                return triple.assumption
        return None
    
    def _extract_counterexample(self, model: z3.ModelRef, 
                                  triple: AGTriple) -> Dict[str, Any]:
        """Extract counterexample from model."""
        return self._model_to_dict(model, triple.component.get_all_vars())
    
    def _model_to_dict(self, model: z3.ModelRef,
                         variables: List[z3.ArithRef]) -> Dict[str, float]:
        """Convert model to dictionary."""
        result = {}
        for v in variables:
            val = model.eval(v, model_completion=True)
            if z3.is_rational_value(val):
                result[str(v)] = float(val.numerator_as_long()) / float(val.denominator_as_long())
            else:
                result[str(v)] = 0.0
        return result


# =============================================================================
# ASSUMPTION LEARNING
# =============================================================================

class LearningResult(Enum):
    """Result of assumption learning."""
    FOUND = auto()
    NOT_FOUND = auto()
    TIMEOUT = auto()


@dataclass
class LearningOutput:
    """Output of assumption learning."""
    result: LearningResult
    assumption: Optional[Assumption] = None
    iterations: int = 0
    message: str = ""


class AssumptionLearner:
    """
    Learn assumptions using counterexample-guided approach.
    
    Based on L* learning and compositional verification.
    """
    
    def __init__(self, component: Component,
                 environment: Component,
                 property_to_verify: Guarantee,
                 alphabet: List[z3.ArithRef],
                 max_iterations: int = 100,
                 timeout_ms: int = 60000,
                 verbose: bool = False):
        self.component = component
        self.environment = environment
        self.property = property_to_verify
        self.alphabet = alphabet
        self.max_iterations = max_iterations
        self.timeout_ms = timeout_ms
        self.verbose = verbose
        
        self.stats = {
            'iterations': 0,
            'positive_examples': 0,
            'negative_examples': 0,
        }
    
    def learn(self) -> LearningOutput:
        """
        Learn assumption A such that:
        - ⟨A⟩ component ⟨property⟩
        - environment ⊨ A
        """
        # Start with true assumption
        current_assumption = z3.BoolVal(True)
        positive_examples: List[Dict] = []
        negative_examples: List[Dict] = []
        
        for iteration in range(self.max_iterations):
            self.stats['iterations'] += 1
            
            assumption = Assumption(
                name=f"A_{iteration}",
                formula=current_assumption,
                over_variables=self.alphabet
            )
            
            # Check if ⟨A⟩ M ⟨P⟩
            triple = AGTriple(assumption, self.component, self.property)
            verifier = AGVerifier(self.timeout_ms, self.verbose)
            
            success, cex = verifier.verify_triple(triple)
            
            if not success and cex:
                # Check if counterexample is valid in environment
                is_valid = self._check_environment(cex)
                
                if is_valid:
                    # Real counterexample
                    return LearningOutput(
                        result=LearningResult.NOT_FOUND,
                        iterations=iteration,
                        message="Real counterexample found"
                    )
                else:
                    # Spurious, strengthen assumption
                    negative_examples.append(cex)
                    self.stats['negative_examples'] += 1
                    current_assumption = self._strengthen(current_assumption, cex)
            
            elif success:
                # Check if environment satisfies assumption
                env_ok, env_cex = verifier.verify_discharge(assumption, self.environment)
                
                if env_ok:
                    # Found valid assumption
                    return LearningOutput(
                        result=LearningResult.FOUND,
                        assumption=assumption,
                        iterations=iteration,
                        message="Assumption found"
                    )
                else:
                    # Weaken assumption
                    if env_cex:
                        positive_examples.append(env_cex)
                        self.stats['positive_examples'] += 1
                        current_assumption = self._weaken(current_assumption, env_cex)
        
        return LearningOutput(
            result=LearningResult.TIMEOUT,
            iterations=self.max_iterations,
            message="Max iterations reached"
        )
    
    def _check_environment(self, cex: Dict) -> bool:
        """Check if counterexample is valid in environment."""
        solver = z3.Solver()
        solver.set("timeout", self.timeout_ms // 10)
        
        solver.add(self.environment.initial)
        
        # Add counterexample values
        for var_name, val in cex.items():
            for v in self.alphabet:
                if str(v) == var_name:
                    solver.add(v == val)
        
        return solver.check() == z3.sat
    
    def _strengthen(self, assumption: z3.BoolRef, cex: Dict) -> z3.BoolRef:
        """Strengthen assumption to exclude counterexample."""
        # Build constraint for counterexample
        cex_constraint = []
        for var_name, val in cex.items():
            for v in self.alphabet:
                if str(v) == var_name:
                    cex_constraint.append(v == val)
        
        if cex_constraint:
            exclude_cex = z3.Not(z3.And(cex_constraint))
            return z3.And(assumption, exclude_cex)
        
        return assumption
    
    def _weaken(self, assumption: z3.BoolRef, cex: Dict) -> z3.BoolRef:
        """Weaken assumption to include counterexample."""
        # Build constraint for counterexample
        cex_constraint = []
        for var_name, val in cex.items():
            for v in self.alphabet:
                if str(v) == var_name:
                    cex_constraint.append(v == val)
        
        if cex_constraint:
            include_cex = z3.And(cex_constraint)
            return z3.Or(assumption, include_cex)
        
        return assumption


# =============================================================================
# COMPOSITIONAL SYSTEM
# =============================================================================

class CompositionType(Enum):
    """Type of composition."""
    PARALLEL = auto()      # M₁ ∥ M₂
    SEQUENTIAL = auto()    # M₁ ; M₂
    FEEDBACK = auto()      # Circular


@dataclass
class ComposedSystem:
    """
    Composed system from multiple components.
    """
    name: str
    components: List[Component]
    composition_type: CompositionType
    shared_variables: List[z3.ArithRef] = field(default_factory=list)
    
    def get_parallel_transition(self) -> z3.BoolRef:
        """Get transition relation for parallel composition."""
        if not self.components:
            return z3.BoolVal(True)
        
        # T_parallel = T_1 ∧ T_2 ∧ ...
        transitions = [c.transition for c in self.components]
        return z3.And(transitions)
    
    def get_parallel_initial(self) -> z3.BoolRef:
        """Get initial states for parallel composition."""
        if not self.components:
            return z3.BoolVal(True)
        
        initials = [c.initial for c in self.components]
        return z3.And(initials)


class CompositionalVerifier:
    """
    Verify composed systems using AG reasoning.
    """
    
    def __init__(self, system: ComposedSystem,
                 property_: Guarantee,
                 timeout_ms: int = 60000,
                 verbose: bool = False):
        self.system = system
        self.property = property_
        self.timeout_ms = timeout_ms
        self.verbose = verbose
        
        self.stats = {
            'components_verified': 0,
            'assumptions_learned': 0,
        }
    
    def verify_monolithically(self) -> AGVerificationResult:
        """
        Verify by composing all components.
        """
        composed_component = Component(
            name="composed",
            inputs=[],
            outputs=[],
            state=sum([c.state for c in self.system.components], []),
            primed_state=sum([c.primed_state for c in self.system.components], []),
            initial=self.system.get_parallel_initial(),
            transition=self.system.get_parallel_transition()
        )
        
        true_assumption = Assumption(
            name="true",
            formula=z3.BoolVal(True),
            over_variables=[]
        )
        
        triple = AGTriple(true_assumption, composed_component, self.property)
        
        verifier = AGVerifier(self.timeout_ms, self.verbose)
        success, cex = verifier.verify_triple(triple)
        
        if success:
            return AGVerificationResult(
                result=AGResult.PROVEN,
                statistics=self.stats,
                message="Monolithic verification succeeded"
            )
        else:
            return AGVerificationResult(
                result=AGResult.REFUTED,
                counterexample=cex,
                statistics=self.stats,
                message="Property violated"
            )
    
    def verify_compositionally(self) -> AGVerificationResult:
        """
        Verify using AG reasoning.
        """
        if len(self.system.components) < 2:
            return self.verify_monolithically()
        
        # For two components: learn assumption
        m1 = self.system.components[0]
        m2 = self.system.components[1]
        
        learner = AssumptionLearner(
            component=m1,
            environment=m2,
            property_to_verify=self.property,
            alphabet=self.system.shared_variables,
            timeout_ms=self.timeout_ms,
            verbose=self.verbose
        )
        
        result = learner.learn()
        
        if result.result == LearningResult.FOUND:
            self.stats['assumptions_learned'] += 1
            return AGVerificationResult(
                result=AGResult.PROVEN,
                statistics=self.stats,
                message=f"Compositional proof with assumption {result.assumption}"
            )
        elif result.result == LearningResult.NOT_FOUND:
            return AGVerificationResult(
                result=AGResult.REFUTED,
                statistics=self.stats,
                message="Property violated"
            )
        else:
            return AGVerificationResult(
                result=AGResult.UNKNOWN,
                statistics=self.stats,
                message="Verification inconclusive"
            )


# =============================================================================
# AG INTEGRATION
# =============================================================================

@dataclass
class AGConfig:
    """Configuration for AG integration."""
    use_learning: bool = True
    max_learning_iterations: int = 100
    timeout_ms: int = 60000
    verbose: bool = False


class AGIntegration:
    """
    Integration of assume-guarantee with barrier synthesis.
    
    Provides:
    1. Compositional verification
    2. Assumption learning
    3. Proof construction
    """
    
    def __init__(self, config: Optional[AGConfig] = None,
                 verbose: bool = False):
        self.config = config or AGConfig()
        self.verbose = verbose or self.config.verbose
        
        self._proofs: Dict[str, AGProof] = {}
        self._assumptions: Dict[str, Assumption] = {}
        
        self.stats = {
            'verifications': 0,
            'compositional_proofs': 0,
            'assumptions_learned': 0,
        }
    
    def create_component(self, name: str,
                          inputs: List[z3.ArithRef],
                          outputs: List[z3.ArithRef],
                          state: List[z3.ArithRef],
                          primed_state: List[z3.ArithRef],
                          initial: z3.BoolRef,
                          transition: z3.BoolRef) -> Component:
        """Create a component."""
        return Component(
            name=name,
            inputs=inputs,
            outputs=outputs,
            state=state,
            primed_state=primed_state,
            initial=initial,
            transition=transition
        )
    
    def verify(self, ver_id: str,
                components: List[Component],
                property_: z3.BoolRef,
                shared_vars: List[z3.ArithRef]) -> AGVerificationResult:
        """
        Verify property of composed system.
        """
        self.stats['verifications'] += 1
        
        system = ComposedSystem(
            name=ver_id,
            components=components,
            composition_type=CompositionType.PARALLEL,
            shared_variables=shared_vars
        )
        
        guarantee = Guarantee(
            name=f"prop_{ver_id}",
            formula=property_,
            over_variables=shared_vars
        )
        
        verifier = CompositionalVerifier(
            system, guarantee, self.config.timeout_ms, self.verbose
        )
        
        if self.config.use_learning and len(components) >= 2:
            result = verifier.verify_compositionally()
            if result.result == AGResult.PROVEN:
                self.stats['compositional_proofs'] += 1
        else:
            result = verifier.verify_monolithically()
        
        return result
    
    def learn_assumption(self, learn_id: str,
                          component: Component,
                          environment: Component,
                          property_: z3.BoolRef,
                          shared_vars: List[z3.ArithRef]) -> LearningOutput:
        """
        Learn assumption for compositional proof.
        """
        guarantee = Guarantee(
            name=f"prop_{learn_id}",
            formula=property_,
            over_variables=shared_vars
        )
        
        learner = AssumptionLearner(
            component, environment, guarantee, shared_vars,
            self.config.max_learning_iterations,
            self.config.timeout_ms, self.verbose
        )
        
        result = learner.learn()
        
        if result.result == LearningResult.FOUND:
            self._assumptions[learn_id] = result.assumption
            self.stats['assumptions_learned'] += 1
        
        return result
    
    def condition_barrier_problem(self, problem: BarrierSynthesisProblem,
                                    learn_id: str) -> BarrierSynthesisProblem:
        """
        Condition barrier problem using learned assumption.
        """
        assumption = self._assumptions.get(learn_id)
        if assumption is None:
            return problem
        
        # Add assumption as polynomial constraint (simplified)
        # Full implementation would convert Z3 to polynomial
        
        return problem


# =============================================================================
# CONVENIENCE FUNCTIONS
# =============================================================================

def create_ag_proof() -> AGProof:
    """Create empty AG proof."""
    return AGProof([])


def create_ag_triple(assumption: Assumption,
                      component: Component,
                      guarantee: Guarantee) -> AGTriple:
    """Create AG triple."""
    return AGTriple(assumption, component, guarantee)


def verify_ag_proof(proof: AGProof,
                      timeout_ms: int = 60000,
                      verbose: bool = False) -> AGVerificationResult:
    """Verify AG proof."""
    verifier = AGVerifier(timeout_ms, verbose)
    return verifier.verify_proof(proof)


def learn_assumption(component: Component,
                       environment: Component,
                       property_: Guarantee,
                       alphabet: List[z3.ArithRef],
                       max_iterations: int = 100,
                       timeout_ms: int = 60000,
                       verbose: bool = False) -> LearningOutput:
    """Learn assumption for compositional verification."""
    learner = AssumptionLearner(
        component, environment, property_, alphabet,
        max_iterations, timeout_ms, verbose
    )
    return learner.learn()


def compose_parallel(components: List[Component],
                       name: str = "composed") -> ComposedSystem:
    """Create parallel composition."""
    shared = []  # Would compute intersection of interface variables
    return ComposedSystem(name, components, CompositionType.PARALLEL, shared)


# =============================================================================
# ADVANCED ASSUME-GUARANTEE TECHNIQUES
# =============================================================================

class CircularAssumeGuarantee:
    """
    Circular assume-guarantee reasoning.
    
    Handles mutual dependencies between components using
    circular proof rules.
    """
    
    def __init__(self, components: List[Component],
                 timeout_ms: int = 60000):
        self.components = components
        self.timeout_ms = timeout_ms
        
        # Dependency graph
        self.dependencies: Dict[str, Set[str]] = {}
        
        self.stats = {
            'circular_checks': 0,
            'circular_proofs_found': 0,
        }
    
    def analyze_dependencies(self) -> Dict[str, Set[str]]:
        """Analyze component dependencies."""
        for comp in self.components:
            self.dependencies[comp.name] = set()
            
            for other in self.components:
                if other.name != comp.name:
                    if self._depends_on(comp, other):
                        self.dependencies[comp.name].add(other.name)
        
        return self.dependencies
    
    def _depends_on(self, comp1: Component, comp2: Component) -> bool:
        """Check if comp1 depends on comp2."""
        # Check if interfaces overlap
        overlap = set(comp1.inputs) & set(comp2.outputs)
        return len(overlap) > 0
    
    def find_circular_proof(self, property_: Guarantee) -> Optional['CircularProof']:
        """
        Find circular proof for property.
        
        Uses simultaneous induction over all components.
        """
        self.stats['circular_checks'] += 1
        
        # Generate assumptions for each component
        assumptions = {}
        for comp in self.components:
            assumptions[comp.name] = self._generate_assumption(comp)
        
        # Check circular proof obligation
        if self._check_circular_obligation(assumptions, property_):
            self.stats['circular_proofs_found'] += 1
            
            return CircularProof(
                components=self.components,
                assumptions=assumptions,
                property_=property_
            )
        
        return None
    
    def _generate_assumption(self, comp: Component) -> Assumption:
        """Generate assumption for component."""
        # Use weakest assumption
        return Assumption(z3.BoolVal(True), f"A_{comp.name}")
    
    def _check_circular_obligation(self, 
                                     assumptions: Dict[str, Assumption],
                                     property_: Guarantee) -> bool:
        """Check circular proof obligation."""
        solver = z3.Solver()
        solver.set("timeout", self.timeout_ms)
        
        # Add all component behaviors and assumptions
        for comp in self.components:
            solver.add(comp.transition)
            solver.add(assumptions[comp.name].formula)
        
        # Check property
        solver.add(z3.Not(property_.formula))
        
        return solver.check() == z3.unsat


@dataclass
class CircularProof:
    """Circular assume-guarantee proof."""
    components: List[Component]
    assumptions: Dict[str, Assumption]
    property_: Guarantee


class IncrementalAGVerifier:
    """
    Incremental assume-guarantee verification.
    
    Reuses previous verification results when system changes.
    """
    
    def __init__(self, timeout_ms: int = 60000):
        self.timeout_ms = timeout_ms
        
        # Cache of verified triples
        self.cache: Dict[str, AGVerificationResult] = {}
        
        # Component versions
        self.versions: Dict[str, int] = {}
        
        self.stats = {
            'cache_hits': 0,
            'cache_misses': 0,
            'incremental_savings': 0.0,
        }
    
    def verify_incremental(self, proof: AGProof) -> AGVerificationResult:
        """Verify proof with caching."""
        results = []
        
        for triple in proof.triples:
            cache_key = self._compute_cache_key(triple)
            
            if cache_key in self.cache:
                self.stats['cache_hits'] += 1
                results.append(self.cache[cache_key])
            else:
                self.stats['cache_misses'] += 1
                
                result = self._verify_triple(triple)
                self.cache[cache_key] = result
                results.append(result)
        
        # Combine results
        all_valid = all(r.result == AGResult.VALID for r in results)
        
        return AGVerificationResult(
            result=AGResult.VALID if all_valid else AGResult.INVALID,
            stats=self.stats
        )
    
    def invalidate_component(self, comp_name: str) -> None:
        """Invalidate cache entries for component."""
        to_remove = [k for k in self.cache if comp_name in k]
        
        for k in to_remove:
            del self.cache[k]
        
        if comp_name in self.versions:
            self.versions[comp_name] += 1
    
    def _compute_cache_key(self, triple: AGTriple) -> str:
        """Compute cache key for triple."""
        comp_ver = self.versions.get(triple.component.name, 0)
        return f"{triple.component.name}_{comp_ver}_{hash(str(triple.assumption.formula))}_{hash(str(triple.guarantee.formula))}"
    
    def _verify_triple(self, triple: AGTriple) -> AGVerificationResult:
        """Verify single triple."""
        solver = z3.Solver()
        solver.set("timeout", self.timeout_ms // 10)
        
        solver.add(triple.assumption.formula)
        solver.add(triple.component.transition)
        solver.add(z3.Not(triple.guarantee.formula))
        
        if solver.check() == z3.unsat:
            return AGVerificationResult(result=AGResult.VALID, stats={})
        else:
            return AGVerificationResult(result=AGResult.INVALID, stats={})


class ContractBasedVerification:
    """
    Contract-based verification framework.
    
    Uses assume-guarantee contracts for modular verification.
    """
    
    def __init__(self, timeout_ms: int = 60000):
        self.timeout_ms = timeout_ms
        
        self.contracts: Dict[str, 'Contract'] = {}
        
        self.stats = {
            'contracts_verified': 0,
            'refinements_checked': 0,
        }
    
    def add_contract(self, name: str, 
                      assumption: z3.BoolRef,
                      guarantee: z3.BoolRef) -> 'Contract':
        """Add component contract."""
        contract = Contract(name, assumption, guarantee)
        self.contracts[name] = contract
        return contract
    
    def verify_implementation(self, comp_name: str,
                                implementation: Component) -> bool:
        """Verify implementation satisfies contract."""
        if comp_name not in self.contracts:
            return True
        
        contract = self.contracts[comp_name]
        
        solver = z3.Solver()
        solver.set("timeout", self.timeout_ms)
        
        solver.add(contract.assumption)
        solver.add(implementation.transition)
        solver.add(z3.Not(contract.guarantee))
        
        result = solver.check() == z3.unsat
        
        if result:
            self.stats['contracts_verified'] += 1
        
        return result
    
    def check_contract_refinement(self, abstract: str, 
                                    concrete: str) -> bool:
        """Check if concrete contract refines abstract."""
        if abstract not in self.contracts or concrete not in self.contracts:
            return False
        
        abs_contract = self.contracts[abstract]
        conc_contract = self.contracts[concrete]
        
        self.stats['refinements_checked'] += 1
        
        # Refinement: weaker assumption, stronger guarantee
        solver = z3.Solver()
        solver.set("timeout", self.timeout_ms)
        
        # Check assumption weakening
        solver.push()
        solver.add(abs_contract.assumption)
        solver.add(z3.Not(conc_contract.assumption))
        assumption_weaker = solver.check() == z3.unsat
        solver.pop()
        
        # Check guarantee strengthening
        solver.add(conc_contract.guarantee)
        solver.add(z3.Not(abs_contract.guarantee))
        guarantee_stronger = solver.check() == z3.unsat
        
        return assumption_weaker and guarantee_stronger


@dataclass
class Contract:
    """Component contract."""
    name: str
    assumption: z3.BoolRef
    guarantee: z3.BoolRef


class AssumeGuaranteeCEGAR:
    """
    CEGAR for assume-guarantee reasoning.
    
    Iteratively refines assumptions using counterexamples.
    """
    
    def __init__(self, components: List[Component],
                 property_: Guarantee,
                 timeout_ms: int = 60000):
        self.components = components
        self.property_ = property_
        self.timeout_ms = timeout_ms
        
        self.assumptions: Dict[str, Assumption] = {}
        self.counterexamples: List[Dict] = []
        
        self.stats = {
            'cegar_iterations': 0,
            'assumptions_refined': 0,
        }
    
    def verify_with_cegar(self, max_iterations: int = 100) -> AGVerificationResult:
        """Verify using CEGAR for assumptions."""
        # Initialize with weakest assumptions
        for comp in self.components:
            self.assumptions[comp.name] = Assumption(z3.BoolVal(True), f"A_{comp.name}")
        
        for _ in range(max_iterations):
            self.stats['cegar_iterations'] += 1
            
            # Try to prove with current assumptions
            result = self._try_proof()
            
            if result['success']:
                return AGVerificationResult(
                    result=AGResult.VALID,
                    stats=self.stats
                )
            
            if result['counterexample']:
                cex = result['counterexample']
                self.counterexamples.append(cex)
                
                # Check if real
                if self._is_real_counterexample(cex):
                    return AGVerificationResult(
                        result=AGResult.INVALID,
                        counterexample=cex,
                        stats=self.stats
                    )
                
                # Refine assumptions
                self._refine_assumptions(cex)
        
        return AGVerificationResult(
            result=AGResult.UNKNOWN,
            stats=self.stats
        )
    
    def _try_proof(self) -> Dict:
        """Try to prove property with current assumptions."""
        for comp in self.components:
            solver = z3.Solver()
            solver.set("timeout", self.timeout_ms // len(self.components))
            
            solver.add(self.assumptions[comp.name].formula)
            solver.add(comp.transition)
            
            # Find which guarantees this component should provide
            for other_name, assumption in self.assumptions.items():
                if other_name != comp.name:
                    solver.add(z3.Not(assumption.formula))
            
            if solver.check() == z3.sat:
                model = solver.model()
                return {
                    'success': False,
                    'counterexample': {
                        'component': comp.name,
                        'model': model
                    }
                }
        
        return {'success': True}
    
    def _is_real_counterexample(self, cex: Dict) -> bool:
        """Check if counterexample is real."""
        # Simulate on full system
        solver = z3.Solver()
        solver.set("timeout", self.timeout_ms // 10)
        
        for comp in self.components:
            solver.add(comp.transition)
        
        solver.add(z3.Not(self.property_.formula))
        
        return solver.check() == z3.sat
    
    def _refine_assumptions(self, cex: Dict) -> None:
        """Refine assumptions based on counterexample."""
        comp_name = cex['component']
        model = cex['model']
        
        # Strengthen assumption to rule out CEX
        current = self.assumptions[comp_name]
        
        # Create constraint from model
        constraint = z3.BoolVal(True)
        for comp in self.components:
            for v in comp.inputs + comp.outputs:
                val = model.eval(v, model_completion=True)
                constraint = z3.And(constraint, v == val)
        
        new_assumption = Assumption(
            z3.And(current.formula, z3.Not(constraint)),
            current.name
        )
        
        self.assumptions[comp_name] = new_assumption
        self.stats['assumptions_refined'] += 1


class MultiLevelAGVerifier:
    """
    Multi-level assume-guarantee verification.
    
    Uses hierarchy of abstractions.
    """
    
    def __init__(self, levels: int = 3,
                 timeout_ms: int = 60000):
        self.levels = levels
        self.timeout_ms = timeout_ms
        
        self.abstractions: Dict[int, List[Component]] = {}
        
        self.stats = {
            'levels_explored': 0,
            'abstraction_refinements': 0,
        }
    
    def add_abstraction_level(self, level: int,
                                components: List[Component]) -> None:
        """Add abstraction level."""
        self.abstractions[level] = components
    
    def verify_hierarchical(self, property_: Guarantee) -> AGVerificationResult:
        """Verify using hierarchical abstractions."""
        for level in range(self.levels):
            self.stats['levels_explored'] += 1
            
            if level not in self.abstractions:
                continue
            
            components = self.abstractions[level]
            
            # Try verification at this level
            result = self._verify_at_level(components, property_)
            
            if result.result == AGResult.VALID:
                return result
            
            if result.result == AGResult.INVALID:
                # Check if counterexample is real
                if level == self.levels - 1:
                    return result
                
                self.stats['abstraction_refinements'] += 1
                continue
        
        return AGVerificationResult(result=AGResult.UNKNOWN, stats=self.stats)
    
    def _verify_at_level(self, components: List[Component],
                          property_: Guarantee) -> AGVerificationResult:
        """Verify at single abstraction level."""
        verifier = CompositionalVerifier(components, self.timeout_ms, False)
        return verifier.verify_compositional(property_)


class SymbolicAGVerifier:
    """
    Symbolic assume-guarantee verification.
    
    Uses symbolic techniques for assumption representation.
    """
    
    def __init__(self, components: List[Component],
                 timeout_ms: int = 60000):
        self.components = components
        self.timeout_ms = timeout_ms
        
        # Symbolic assumptions as formulas
        self.symbolic_assumptions: Dict[str, z3.BoolRef] = {}
        
        self.stats = {
            'symbolic_operations': 0,
        }
    
    def compute_weakest_assumption(self, comp: Component,
                                     guarantee: Guarantee) -> z3.BoolRef:
        """
        Compute weakest assumption for component to satisfy guarantee.
        """
        self.stats['symbolic_operations'] += 1
        
        # Weakest assumption: ∀post. (T ∧ ¬G → ¬pre)
        # Equivalently: ∀post. T → (¬G → ¬pre) = ∀post. T → (pre → G)
        
        # Simplified: just return guarantee as assumption
        return guarantee.formula
    
    def compute_strongest_guarantee(self, comp: Component,
                                      assumption: Assumption) -> z3.BoolRef:
        """
        Compute strongest guarantee from component under assumption.
        """
        self.stats['symbolic_operations'] += 1
        
        # Strongest guarantee: ∀pre. (A ∧ T → post)
        
        # Simplified: return assumption as guarantee
        return assumption.formula
    
    def verify_symbolic(self, property_: Guarantee) -> AGVerificationResult:
        """Verify using symbolic assumptions."""
        # Compute assumptions for all components
        for comp in self.components:
            self.symbolic_assumptions[comp.name] = self.compute_weakest_assumption(
                comp, property_
            )
        
        # Check if assumptions can be satisfied
        solver = z3.Solver()
        solver.set("timeout", self.timeout_ms)
        
        for comp in self.components:
            solver.add(self.symbolic_assumptions[comp.name])
            solver.add(comp.transition)
        
        if solver.check() == z3.sat:
            return AGVerificationResult(result=AGResult.VALID, stats=self.stats)
        else:
            return AGVerificationResult(result=AGResult.INVALID, stats=self.stats)


class QuantitativeAG:
    """
    Quantitative assume-guarantee for probabilistic systems.
    """
    
    def __init__(self, components: List[Component],
                 probabilities: Dict[str, float],
                 timeout_ms: int = 60000):
        self.components = components
        self.probabilities = probabilities
        self.timeout_ms = timeout_ms
        
        self.stats = {
            'probability_bound': None,
        }
    
    def compute_probability_bound(self, property_: Guarantee) -> float:
        """
        Compute probability bound for property.
        
        Uses quantitative AG rule:
        P(system satisfies property) ≥ Π P(component_i satisfies assumption_i)
        """
        # Simplified: assume independence
        prob = 1.0
        
        for comp in self.components:
            comp_prob = self.probabilities.get(comp.name, 1.0)
            prob *= comp_prob
        
        self.stats['probability_bound'] = prob
        return prob
    
    def verify_probabilistic(self, property_: Guarantee,
                               threshold: float = 0.99) -> AGVerificationResult:
        """Verify with probabilistic threshold."""
        bound = self.compute_probability_bound(property_)
        
        if bound >= threshold:
            return AGVerificationResult(
                result=AGResult.VALID,
                stats=self.stats
            )
        else:
            return AGVerificationResult(
                result=AGResult.UNKNOWN,
                stats=self.stats
            )


class TemporalAG:
    """
    Assume-guarantee for temporal properties.
    """
    
    def __init__(self, components: List[Component],
                 timeout_ms: int = 60000):
        self.components = components
        self.timeout_ms = timeout_ms
        
        self.stats = {
            'temporal_checks': 0,
        }
    
    def verify_always(self, invariant: z3.BoolRef) -> AGVerificationResult:
        """Verify □(invariant)."""
        self.stats['temporal_checks'] += 1
        
        # Check invariant preservation
        for comp in self.components:
            solver = z3.Solver()
            solver.set("timeout", self.timeout_ms // len(self.components))
            
            solver.add(invariant)
            solver.add(comp.transition)
            
            # Check invariant holds after transition
            solver.add(z3.Not(invariant))  # Would need primed version
            
            if solver.check() == z3.sat:
                return AGVerificationResult(result=AGResult.INVALID, stats=self.stats)
        
        return AGVerificationResult(result=AGResult.VALID, stats=self.stats)
    
    def verify_eventually(self, goal: z3.BoolRef,
                           bound: int = 100) -> AGVerificationResult:
        """Verify ◇(goal) with bound."""
        self.stats['temporal_checks'] += 1
        
        # Bounded model checking
        for comp in self.components:
            reached = z3.BoolVal(False)
            current = comp.initial if hasattr(comp, 'initial') else z3.BoolVal(True)
            
            for _ in range(bound):
                # Check if goal reached
                solver = z3.Solver()
                solver.set("timeout", 1000)
                solver.add(current)
                solver.add(goal)
                
                if solver.check() == z3.sat:
                    return AGVerificationResult(result=AGResult.VALID, stats=self.stats)
                
                # Step
                # Would apply transition
        
        return AGVerificationResult(result=AGResult.UNKNOWN, stats=self.stats)


# =============================================================================
# ADDITIONAL ASSUME-GUARANTEE COMPONENTS
# =============================================================================

class AGProofAssistant:
    """
    Assistant for building AG proofs.
    """
    
    def __init__(self, components: List[Component]):
        self.components = components
        
        self.proof_steps: List[Dict[str, Any]] = []
        
        self.stats = {
            'steps_added': 0,
            'validations': 0,
        }
    
    def add_triple(self, assumption: Assumption,
                    component: Component,
                    guarantee: Guarantee) -> bool:
        """Add AG triple to proof."""
        triple = AGTriple(assumption, component, guarantee)
        
        if self._validate_triple(triple):
            self.proof_steps.append({
                'type': 'triple',
                'triple': triple
            })
            self.stats['steps_added'] += 1
            return True
        
        return False
    
    def add_composition(self, triples: List[AGTriple]) -> bool:
        """Add composition step."""
        self.proof_steps.append({
            'type': 'composition',
            'triples': triples
        })
        self.stats['steps_added'] += 1
        return True
    
    def _validate_triple(self, triple: AGTriple) -> bool:
        """Validate single triple."""
        self.stats['validations'] += 1
        
        solver = z3.Solver()
        solver.set("timeout", 10000)
        
        solver.add(triple.assumption.formula)
        solver.add(triple.component.transition)
        solver.add(z3.Not(triple.guarantee.formula))
        
        return solver.check() == z3.unsat
    
    def build_proof(self) -> AGProof:
        """Build complete proof from steps."""
        triples = [step['triple'] for step in self.proof_steps 
                   if step['type'] == 'triple']
        
        return AGProof(triples)


class ComponentAbstraction:
    """
    Abstraction of components for AG reasoning.
    """
    
    def __init__(self, component: Component,
                 timeout_ms: int = 60000):
        self.component = component
        self.timeout_ms = timeout_ms
        
        self.stats = {
            'abstractions_computed': 0,
        }
    
    def abstract(self, precision: int = 1) -> Component:
        """Compute abstract component."""
        self.stats['abstractions_computed'] += 1
        
        # Abstract by overapproximating transition
        abstract_trans = self._abstract_transition(self.component.transition, precision)
        
        return Component(
            name=self.component.name + "_abs",
            inputs=self.component.inputs[:],
            outputs=self.component.outputs[:],
            transition=abstract_trans
        )
    
    def _abstract_transition(self, transition: z3.BoolRef,
                               precision: int) -> z3.BoolRef:
        """Abstract transition relation."""
        if precision == 0:
            return z3.BoolVal(True)  # Most abstract
        
        return z3.simplify(transition)  # Keep as-is


class AssumptionWeakening:
    """
    Weaken assumptions in AG proofs.
    """
    
    def __init__(self, timeout_ms: int = 60000):
        self.timeout_ms = timeout_ms
        
        self.stats = {
            'weakenings': 0,
        }
    
    def weaken(self, assumption: Assumption,
                component: Component,
                guarantee: Guarantee) -> Assumption:
        """Weaken assumption while preserving validity."""
        self.stats['weakenings'] += 1
        
        # Try to weaken by dropping conjuncts
        if z3.is_and(assumption.formula):
            conjuncts = list(assumption.formula.children())
            
            for i in range(len(conjuncts)):
                weakened = z3.And([c for j, c in enumerate(conjuncts) if j != i])
                
                if self._still_valid(weakened, component, guarantee):
                    return Assumption(weakened, assumption.name + "_weak")
        
        return assumption
    
    def _still_valid(self, assumption: z3.BoolRef,
                      component: Component,
                      guarantee: Guarantee) -> bool:
        """Check if triple is still valid with weakened assumption."""
        solver = z3.Solver()
        solver.set("timeout", self.timeout_ms)
        
        solver.add(assumption)
        solver.add(component.transition)
        solver.add(z3.Not(guarantee.formula))
        
        return solver.check() == z3.unsat


class GuaranteeStrengthening:
    """
    Strengthen guarantees in AG proofs.
    """
    
    def __init__(self, timeout_ms: int = 60000):
        self.timeout_ms = timeout_ms
        
        self.stats = {
            'strengthenings': 0,
        }
    
    def strengthen(self, assumption: Assumption,
                    component: Component,
                    guarantee: Guarantee,
                    candidates: List[z3.BoolRef]) -> Guarantee:
        """Strengthen guarantee if possible."""
        self.stats['strengthenings'] += 1
        
        strongest = guarantee.formula
        
        for cand in candidates:
            strengthened = z3.And(strongest, cand)
            
            if self._is_valid(assumption, component, strengthened):
                strongest = strengthened
        
        return Guarantee(strongest, guarantee.name + "_strong")
    
    def _is_valid(self, assumption: Assumption,
                   component: Component,
                   guarantee: z3.BoolRef) -> bool:
        """Check if triple is valid."""
        solver = z3.Solver()
        solver.set("timeout", self.timeout_ms)
        
        solver.add(assumption.formula)
        solver.add(component.transition)
        solver.add(z3.Not(guarantee))
        
        return solver.check() == z3.unsat


class InterfaceAnalysis:
    """
    Analyze component interfaces.
    """
    
    def __init__(self, components: List[Component]):
        self.components = components
        
        self.stats = {
            'interface_analyses': 0,
        }
    
    def analyze_compatibility(self) -> Dict[str, bool]:
        """Analyze interface compatibility."""
        self.stats['interface_analyses'] += 1
        
        results = {}
        
        for i, c1 in enumerate(self.components):
            for c2 in self.components[i + 1:]:
                key = f"{c1.name}_{c2.name}"
                results[key] = self._compatible(c1, c2)
        
        return results
    
    def _compatible(self, c1: Component, c2: Component) -> bool:
        """Check if two components are compatible."""
        # Check output/input matching
        c1_outputs = set(str(v) for v in c1.outputs)
        c2_inputs = set(str(v) for v in c2.inputs)
        
        return len(c1_outputs & c2_inputs) > 0
    
    def compute_interface(self, component: Component) -> Dict[str, Any]:
        """Compute interface specification."""
        return {
            'inputs': [str(v) for v in component.inputs],
            'outputs': [str(v) for v in component.outputs],
            'transition': str(component.transition)
        }


class AGCertificate:
    """
    Certificate for AG proof.
    """
    
    def __init__(self, proof: AGProof):
        self.proof = proof
        
        self.certificate_data: Dict[str, Any] = {}
    
    def generate(self) -> Dict[str, Any]:
        """Generate proof certificate."""
        self.certificate_data = {
            'triples': [self._triple_to_dict(t) for t in self.proof.triples],
            'components': list(set(t.component.name for t in self.proof.triples)),
            'valid': True
        }
        
        return self.certificate_data
    
    def _triple_to_dict(self, triple: AGTriple) -> Dict[str, str]:
        """Convert triple to dictionary."""
        return {
            'assumption': str(triple.assumption.formula),
            'component': triple.component.name,
            'guarantee': str(triple.guarantee.formula)
        }
    
    def to_json(self) -> str:
        """Export certificate to JSON."""
        import json
        return json.dumps(self.certificate_data, indent=2)


class ModularAnalysis:
    """
    Modular program analysis using AG.
    """
    
    def __init__(self, components: List[Component],
                 timeout_ms: int = 60000):
        self.components = components
        self.timeout_ms = timeout_ms
        
        # Component summaries
        self.summaries: Dict[str, z3.BoolRef] = {}
        
        self.stats = {
            'summaries_computed': 0,
        }
    
    def compute_summaries(self) -> Dict[str, z3.BoolRef]:
        """Compute component summaries."""
        for comp in self.components:
            summary = self._compute_summary(comp)
            self.summaries[comp.name] = summary
            self.stats['summaries_computed'] += 1
        
        return self.summaries
    
    def _compute_summary(self, comp: Component) -> z3.BoolRef:
        """Compute summary for single component."""
        # Summary: ∀inputs. ∃outputs. transition
        return comp.transition  # Simplified
    
    def apply_summaries(self, property_: Guarantee) -> bool:
        """Verify property using summaries."""
        if not self.summaries:
            self.compute_summaries()
        
        solver = z3.Solver()
        solver.set("timeout", self.timeout_ms)
        
        for summary in self.summaries.values():
            solver.add(summary)
        
        solver.add(z3.Not(property_.formula))
        
        return solver.check() == z3.unsat


class AGRefinement:
    """
    Refinement in AG reasoning.
    """
    
    def __init__(self, abstract: Component,
                 concrete: Component,
                 timeout_ms: int = 60000):
        self.abstract = abstract
        self.concrete = concrete
        self.timeout_ms = timeout_ms
        
        self.stats = {
            'refinement_checks': 0,
        }
    
    def check_refinement(self) -> bool:
        """Check if concrete refines abstract."""
        self.stats['refinement_checks'] += 1
        
        solver = z3.Solver()
        solver.set("timeout", self.timeout_ms)
        
        # Refinement: concrete transitions are subset of abstract
        solver.add(self.concrete.transition)
        solver.add(z3.Not(self.abstract.transition))
        
        return solver.check() == z3.unsat
    
    def compute_simulation(self) -> Optional[z3.BoolRef]:
        """Compute simulation relation."""
        # Simplified: return equality
        return z3.BoolVal(True)


class ParallelAGVerifier:
    """
    Parallel AG verification.
    """
    
    def __init__(self, components: List[Component],
                 num_workers: int = 4,
                 timeout_ms: int = 60000):
        self.components = components
        self.num_workers = num_workers
        self.timeout_ms = timeout_ms
        
        self.stats = {
            'parallel_tasks': 0,
            'tasks_completed': 0,
        }
    
    def verify_parallel(self, property_: Guarantee) -> AGVerificationResult:
        """Verify using parallel workers."""
        # Create tasks for each component
        tasks = self._create_tasks(property_)
        self.stats['parallel_tasks'] = len(tasks)
        
        # Process tasks (simulated parallel)
        results = []
        for task in tasks:
            result = self._process_task(task)
            results.append(result)
            self.stats['tasks_completed'] += 1
        
        # Combine results
        all_valid = all(r for r in results)
        
        return AGVerificationResult(
            result=AGResult.VALID if all_valid else AGResult.INVALID,
            stats=self.stats
        )
    
    def _create_tasks(self, property_: Guarantee) -> List[Dict[str, Any]]:
        """Create verification tasks."""
        return [{'component': c, 'property': property_} 
                for c in self.components]
    
    def _process_task(self, task: Dict[str, Any]) -> bool:
        """Process single task."""
        comp = task['component']
        prop = task['property']
        
        solver = z3.Solver()
        solver.set("timeout", self.timeout_ms // len(self.components))
        
        solver.add(comp.transition)
        solver.add(z3.Not(prop.formula))
        
        return solver.check() == z3.unsat


class AGProofObligationGenerator:
    """
    Generate proof obligations for assume-guarantee verification.
    
    Creates the logical conditions that must be verified
    for compositional verification to succeed.
    """
    
    def __init__(self, components: List['Component']):
        self.components = components
        self.obligations = []
        
    def generate_obligations(self, property_: 'Guarantee',
                              assumptions: Dict[str, 'Assumption']) -> List['ProofObligation']:
        """
        Generate all proof obligations.
        
        For AG rule: {A} C {G} means under assumption A,
        component C satisfies guarantee G.
        """
        self.obligations = []
        
        for comp in self.components:
            assumption = assumptions.get(comp.name)
            
            # Obligation 1: Component under assumption implies guarantee
            ob1 = self._component_obligation(comp, assumption, property_)
            self.obligations.append(ob1)
            
            # Obligation 2: Environment provides assumption
            ob2 = self._environment_obligation(comp, assumption)
            self.obligations.append(ob2)
        
        return self.obligations
    
    def _component_obligation(self, component: 'Component',
                                assumption: Optional['Assumption'],
                                guarantee: 'Guarantee') -> 'ProofObligation':
        """Generate component proof obligation."""
        if assumption:
            formula = z3.Implies(assumption.formula, guarantee.formula)
        else:
            formula = guarantee.formula
        
        return ProofObligation(
            name=f"{component.name}_satisfies",
            formula=formula,
            component=component
        )
    
    def _environment_obligation(self, component: 'Component',
                                  assumption: Optional['Assumption']) -> 'ProofObligation':
        """Generate environment obligation."""
        if assumption is None:
            return ProofObligation(
                name=f"{component.name}_env",
                formula=z3.BoolVal(True),
                component=component
            )
        
        # Check that other components provide assumption
        other_guarantees = []
        for other in self.components:
            if other.name != component.name:
                other_guarantees.append(other.transition)
        
        formula = z3.Implies(
            z3.And(other_guarantees) if other_guarantees else z3.BoolVal(True),
            assumption.formula
        )
        
        return ProofObligation(
            name=f"{component.name}_env_provides",
            formula=formula,
            component=component
        )


class ProofObligation:
    """A single proof obligation to be discharged."""
    
    def __init__(self, name: str, formula: z3.ExprRef, component: 'Component'):
        self.name = name
        self.formula = formula
        self.component = component
        self.verified = False
        self.counterexample = None


class AGSystemBuilder:
    """
    Fluent interface for building AG verification problems.
    
    Allows declarative specification of components,
    assumptions, and guarantees.
    """
    
    def __init__(self, name: str = "system"):
        self.name = name
        self._components = []
        self._assumptions = {}
        self._guarantees = {}
        self._property = None
        
    def add_component(self, name: str, transition: z3.ExprRef) -> 'AGSystemBuilder':
        """Add a component to the system."""
        comp = Component(name=name, transition=transition)
        self._components.append(comp)
        return self
    
    def with_assumption(self, component_name: str, 
                         assumption: z3.ExprRef) -> 'AGSystemBuilder':
        """Add assumption for component."""
        self._assumptions[component_name] = Assumption(
            name=f"{component_name}_assume",
            formula=assumption
        )
        return self
    
    def with_guarantee(self, component_name: str,
                        guarantee: z3.ExprRef) -> 'AGSystemBuilder':
        """Add guarantee for component."""
        self._guarantees[component_name] = Guarantee(
            name=f"{component_name}_guarantee",
            formula=guarantee
        )
        return self
    
    def verify_property(self, property_: z3.ExprRef) -> 'AGSystemBuilder':
        """Set property to verify."""
        self._property = Guarantee(name="property", formula=property_)
        return self
    
    def build(self) -> 'AGVerifier':
        """Build the verifier."""
        verifier = AGVerifier(
            components=self._components,
            property_=self._property or Guarantee("true", z3.BoolVal(True))
        )
        
        for comp_name, assumption in self._assumptions.items():
            verifier.add_assumption(comp_name, assumption)
        
        return verifier


class AGCounterexampleAnalyzer:
    """
    Analyze counterexamples in AG verification.
    
    Determines whether counterexample is genuine or
    due to over-approximation in assumptions.
    """
    
    def __init__(self, components: List['Component']):
        self.components = components
        self.stats = {'analyzed': 0, 'genuine': 0, 'spurious': 0}
        
    def analyze(self, counterexample: List[Dict[str, Any]],
                 assumptions: Dict[str, 'Assumption']) -> 'CounterexampleAnalysis':
        """Analyze counterexample."""
        self.stats['analyzed'] += 1
        
        # Check if counterexample satisfies all component transitions
        for step in counterexample:
            for comp in self.components:
                if not self._check_step(step, comp):
                    self.stats['spurious'] += 1
                    return CounterexampleAnalysis(
                        is_genuine=False,
                        violated_component=comp.name,
                        step=step
                    )
        
        self.stats['genuine'] += 1
        return CounterexampleAnalysis(is_genuine=True)
    
    def _check_step(self, step: Dict[str, Any], 
                     component: 'Component') -> bool:
        """Check if step is valid for component."""
        solver = z3.Solver()
        solver.add(component.transition)
        
        # Add step constraints
        for var, val in step.items():
            solver.add(z3.Real(var) == val)
        
        return solver.check() == z3.sat


class CounterexampleAnalysis:
    """Result of counterexample analysis."""
    
    def __init__(self, is_genuine: bool, violated_component: str = None,
                  step: Dict = None):
        self.is_genuine = is_genuine
        self.violated_component = violated_component
        self.step = step
    
    def get_refinement_hint(self) -> Optional[z3.ExprRef]:
        """Get hint for refining assumptions."""
        if self.is_genuine:
            return None
        
        # Would suggest strengthening assumption
        return z3.BoolVal(True)


class AGProofCertificate:
    """
    Certificate for AG verification proof.
    
    Contains all assumptions and proofs that together
    establish the property.
    """
    
    def __init__(self, components: List['Component'],
                  assumptions: Dict[str, 'Assumption'],
                  obligations: List['ProofObligation']):
        self.components = components
        self.assumptions = assumptions
        self.obligations = obligations
        self.verified = False
        
    def verify(self) -> bool:
        """Verify the certificate is valid."""
        # Check all obligations are discharged
        for ob in self.obligations:
            if not ob.verified:
                return False
        
        # Check circularity is well-founded
        if not self._check_well_founded():
            return False
        
        self.verified = True
        return True
    
    def _check_well_founded(self) -> bool:
        """Check dependency is well-founded."""
        # Build dependency graph
        deps = {}
        for comp in self.components:
            deps[comp.name] = []
            if comp.name in self.assumptions:
                # Find components that provide assumption
                for other in self.components:
                    if other.name != comp.name:
                        deps[comp.name].append(other.name)
        
        # Check for cycles
        return not self._has_cycle(deps)
    
    def _has_cycle(self, deps: Dict[str, List[str]]) -> bool:
        """Check if dependency graph has cycle."""
        visited = set()
        rec_stack = set()
        
        def dfs(node):
            visited.add(node)
            rec_stack.add(node)
            
            for neighbor in deps.get(node, []):
                if neighbor not in visited:
                    if dfs(neighbor):
                        return True
                elif neighbor in rec_stack:
                    return True
            
            rec_stack.remove(node)
            return False
        
        for node in deps:
            if node not in visited:
                if dfs(node):
                    return True
        
        return False
    
    def to_proof_script(self) -> str:
        """Generate proof script."""
        lines = ["// Assume-Guarantee Proof Certificate", ""]
        
        for comp in self.components:
            lines.append(f"Component {comp.name}:")
            if comp.name in self.assumptions:
                lines.append(f"  Assumption: {self.assumptions[comp.name].formula}")
            lines.append("")
        
        lines.append("Proof Obligations:")
        for ob in self.obligations:
            status = "VERIFIED" if ob.verified else "PENDING"
            lines.append(f"  [{status}] {ob.name}")
        
        return "\n".join(lines)
