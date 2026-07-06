"""
Unified Synthesis Engine for Barrier Certificate Verification.

This module provides the top-level orchestration layer that composes
all 20 SOTA paper implementations into a unified verification engine.

The synthesis engine intelligently selects and combines techniques from:

    FOUNDATIONS (Papers #5-8):
        - Positivstellensatz, SOS/SDP, Lasserre, Sparse SOS
        
    CERTIFICATE CORE (Papers #1-4):
        - Hybrid barriers, Stochastic barriers, SOS Safety, SOSTOOLS
        
    ABSTRACTION (Papers #12-14, #16):
        - CEGAR, Predicate abstraction, Boolean programs, IMPACT
        
    LEARNING (Papers #17-19):
        - ICE learning, Houdini, SyGuS synthesis
        
    ADVANCED (Papers #9-11, #15, #20):
        - DSOS/SDSOS, IC3/PDR, CHC, IMC, Assume-guarantee

Architecture:

    ┌─────────────────────────────────────────────────────────────┐
    │                    SYNTHESIS ENGINE                          │
    │                  Unified Orchestrator                        │
    ├─────────────────────────────────────────────────────────────┤
    │                                                              │
    │  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐          │
    │  │ FOUNDATIONS │  │CERT. CORE   │  │ ABSTRACTION │          │
    │  │ Papers #5-8 │  │ Papers #1-4 │  │Papers #12-16│          │
    │  └──────┬──────┘  └──────┬──────┘  └──────┬──────┘          │
    │         │                │                │                  │
    │         └────────────────┼────────────────┘                  │
    │                          │                                   │
    │  ┌───────────────────────┼───────────────────────┐          │
    │  │                       ▼                       │          │
    │  │     ┌─────────────────────────────────────┐   │          │
    │  │     │       STRATEGY SELECTOR             │   │          │
    │  │     │  - Problem classification           │   │          │
    │  │     │  - Technique selection              │   │          │
    │  │     │  - Portfolio execution              │   │          │
    │  │     └─────────────────────────────────────┘   │          │
    │  │                       │                       │          │
    │  └───────────────────────┼───────────────────────┘          │
    │                          │                                   │
    │  ┌─────────────┐  ┌──────┴──────┐  ┌─────────────┐          │
    │  │  LEARNING   │  │   VERIFY    │  │  ADVANCED   │          │
    │  │Papers #17-19│  │   & CERT    │  │Papers #9-15 │          │
    │  └─────────────┘  └─────────────┘  └──#20────────┘          │
    │                                                              │
    └─────────────────────────────────────────────────────────────┘

Usage:
    from barriers.synthesis_engine import UnifiedSynthesisEngine
    
    engine = UnifiedSynthesisEngine()
    result = engine.verify(system, property)
    # or
    certificate = engine.synthesize_barrier(initial, safe, unsafe, dynamics)
"""

from __future__ import annotations

import z3
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple, Set, Any, Union, Callable
from enum import Enum, auto
import logging
import time

# Import from all layers
from .foundations import (
    Polynomial, SemialgebraicSet, Monomial,
    QuadraticModule, SOSDecomposition, SOSDecomposer,
    PutinarCertificate, PutinarProver,
    LasserreHierarchySolver, SparseSOSDecomposer,
    PolynomialCertificateEngine, CertificateType, PolynomialCertificate
)

from .certificate_core import (
    SystemType, ContinuousDynamics, DiscreteDynamics,
    HybridMode, HybridTransition, HybridAutomaton, StochasticDynamics,
    BarrierConditions, HybridBarrierConditions, StochasticBarrierConditions,
    BarrierTemplate, MultiModeBarrierTemplate,
    SOSSafetyChecker, HybridBarrierCertificate, HybridBarrierSynthesizer,
    StochasticBarrierCertificate, StochasticBarrierSynthesizer,
    SOSTOOLSFramework, BarrierCertificateEngine
)

from .abstraction import (
    Predicate, AbstractState, PredicateAbstraction,
    BooleanProgram, BooleanProgramExecutor,
    LazyAbstraction, ARTNode,
    CEGARResult, Counterexample, CEGARLoop,
    BarrierAbstraction, AbstractionRefinementEngine
)

from .learning import (
    DataPoint, ICEExample,
    ICELearner, ICETeacher,
    HoudiniInference, HoudiniBarrierInference,
    SyGuSGrammar, SyGuSSynthesizer,
    LearningMethod, LearningBasedEngine
)

from .advanced import (
    DSOSDecomposition, SDSOSDecomposition, DSOSRelaxation,
    Frame, IC3Engine,
    HornClause, SpacerCHC,
    InterpolationEngine, IMCVerifier,
    Component, AGContract, AssumeGuaranteeVerifier,
    AdvancedMethod, AdvancedVerificationEngine
)

logger = logging.getLogger(__name__)


# =============================================================================
# PROBLEM CLASSIFICATION
# =============================================================================

class ProblemType(Enum):
    """Types of verification problems."""
    CONTINUOUS_SAFETY = auto()  # Continuous dynamics, safety property
    DISCRETE_SAFETY = auto()  # Discrete dynamics, safety property
    HYBRID_SAFETY = auto()  # Hybrid system, safety property
    STOCHASTIC_SAFETY = auto()  # Stochastic system, probabilistic safety
    POLYNOMIAL_POSITIVITY = auto()  # Prove polynomial positive
    INVARIANT_SYNTHESIS = auto()  # Find inductive invariant
    REACHABILITY = auto()  # Compute reachable states
    COMPOSITIONAL = auto()  # Multi-component system


class ProblemSize(Enum):
    """Size classification of problems."""
    TINY = auto()  # < 3 vars, degree 2
    SMALL = auto()  # 3-5 vars, degree 4
    MEDIUM = auto()  # 5-10 vars, degree 6
    LARGE = auto()  # 10-50 vars
    HUGE = auto()  # > 50 vars


@dataclass
class ProblemAnalysis:
    """Analysis of a verification problem."""
    problem_type: ProblemType
    problem_size: ProblemSize
    n_vars: int
    max_degree: int
    is_sparse: bool  # Has sparse structure
    is_linear: bool  # Linear dynamics
    has_symmetry: bool  # Has symmetry
    num_modes: int  # For hybrid systems
    num_components: int  # For compositional
    
    # Recommended approaches
    recommended_methods: List[str] = field(default_factory=list)
    estimated_difficulty: float = 0.5  # 0 = easy, 1 = hard


class ProblemClassifier:
    """
    Classify verification problems for technique selection.
    """
    
    def __init__(self):
        self.stats = {
            'problems_classified': 0,
        }
    
    def classify(self, problem: Dict[str, Any]) -> ProblemAnalysis:
        """
        Analyze and classify a verification problem.
        """
        self.stats['problems_classified'] += 1
        
        # Extract problem characteristics
        n_vars = problem.get('n_vars', 2)
        max_degree = problem.get('max_degree', 4)
        dynamics_type = problem.get('dynamics_type', 'continuous')
        num_modes = problem.get('num_modes', 1)
        num_components = problem.get('num_components', 1)
        
        # Determine problem type
        if dynamics_type == 'hybrid':
            problem_type = ProblemType.HYBRID_SAFETY
        elif dynamics_type == 'stochastic':
            problem_type = ProblemType.STOCHASTIC_SAFETY
        elif dynamics_type == 'discrete':
            problem_type = ProblemType.DISCRETE_SAFETY
        elif num_components > 1:
            problem_type = ProblemType.COMPOSITIONAL
        else:
            problem_type = ProblemType.CONTINUOUS_SAFETY
        
        # Determine size
        if n_vars < 3 and max_degree <= 2:
            problem_size = ProblemSize.TINY
        elif n_vars <= 5 and max_degree <= 4:
            problem_size = ProblemSize.SMALL
        elif n_vars <= 10 and max_degree <= 6:
            problem_size = ProblemSize.MEDIUM
        elif n_vars <= 50:
            problem_size = ProblemSize.LARGE
        else:
            problem_size = ProblemSize.HUGE
        
        # Check for structure
        is_sparse = self._check_sparsity(problem)
        is_linear = max_degree <= 1
        has_symmetry = self._check_symmetry(problem)
        
        # Recommend methods
        methods = self._recommend_methods(
            problem_type, problem_size, is_sparse, is_linear, has_symmetry
        )
        
        # Estimate difficulty
        difficulty = self._estimate_difficulty(
            problem_size, max_degree, num_modes, is_sparse
        )
        
        return ProblemAnalysis(
            problem_type=problem_type,
            problem_size=problem_size,
            n_vars=n_vars,
            max_degree=max_degree,
            is_sparse=is_sparse,
            is_linear=is_linear,
            has_symmetry=has_symmetry,
            num_modes=num_modes,
            num_components=num_components,
            recommended_methods=methods,
            estimated_difficulty=difficulty
        )
    
    def _check_sparsity(self, problem: Dict[str, Any]) -> bool:
        """Check if problem has sparse structure."""
        # Heuristic: check if polynomials have limited variable interaction
        n_vars = problem.get('n_vars', 2)
        return n_vars > 5  # Assume sparsity for larger problems
    
    def _check_symmetry(self, problem: Dict[str, Any]) -> bool:
        """Check for symmetry in problem."""
        # Placeholder - would analyze dynamics structure
        return False
    
    def _recommend_methods(self, problem_type: ProblemType,
                            size: ProblemSize,
                            is_sparse: bool,
                            is_linear: bool,
                            has_symmetry: bool) -> List[str]:
        """Recommend verification methods."""
        methods = []
        
        if problem_type == ProblemType.CONTINUOUS_SAFETY:
            if size in [ProblemSize.TINY, ProblemSize.SMALL]:
                methods.extend(['sos_safety', 'putinar', 'barrier_synthesis'])
            elif is_sparse:
                methods.extend(['sparse_sos', 'dsos', 'ice_learning'])
            else:
                methods.extend(['lasserre', 'dsos', 'houdini'])
        
        elif problem_type == ProblemType.HYBRID_SAFETY:
            methods.extend(['hybrid_barrier', 'ic3', 'cegar'])
        
        elif problem_type == ProblemType.STOCHASTIC_SAFETY:
            methods.extend(['stochastic_barrier', 'sos_safety'])
        
        elif problem_type == ProblemType.DISCRETE_SAFETY:
            methods.extend(['ic3', 'chc', 'predicate_abstraction'])
        
        elif problem_type == ProblemType.COMPOSITIONAL:
            methods.extend(['assume_guarantee', 'ic3', 'chc'])
        
        if is_linear:
            methods.insert(0, 'linear_analysis')
        
        return methods
    
    def _estimate_difficulty(self, size: ProblemSize,
                              degree: int,
                              num_modes: int,
                              is_sparse: bool) -> float:
        """Estimate problem difficulty (0-1)."""
        base = {
            ProblemSize.TINY: 0.1,
            ProblemSize.SMALL: 0.3,
            ProblemSize.MEDIUM: 0.5,
            ProblemSize.LARGE: 0.7,
            ProblemSize.HUGE: 0.9,
        }.get(size, 0.5)
        
        # Adjust for degree
        degree_factor = min(1.0, degree / 10.0)
        
        # Adjust for modes
        mode_factor = min(0.3, 0.05 * num_modes)
        
        # Sparsity helps
        sparsity_bonus = -0.1 if is_sparse else 0
        
        return min(1.0, base + 0.2 * degree_factor + mode_factor + sparsity_bonus)


# =============================================================================
# STRATEGY EXECUTION
# =============================================================================

@dataclass
class VerificationResult:
    """Result of verification."""
    status: str  # 'safe', 'unsafe', 'unknown'
    certificate: Any = None  # Proof certificate if safe
    counterexample: Any = None  # Counterexample if unsafe
    method_used: str = ""
    time_seconds: float = 0.0
    stats: Dict[str, Any] = field(default_factory=dict)


class Strategy:
    """
    A verification strategy combining multiple techniques.
    """
    
    def __init__(self, name: str, timeout_ms: int = 60000):
        self.name = name
        self.timeout_ms = timeout_ms
        self.steps: List[Tuple[str, Callable]] = []
    
    def add_step(self, name: str, method: Callable) -> None:
        """Add step to strategy."""
        self.steps.append((name, method))
    
    def execute(self, problem: Dict[str, Any]) -> VerificationResult:
        """Execute strategy on problem."""
        start_time = time.time()
        
        for step_name, method in self.steps:
            try:
                result = method(problem)
                if result and result.status != 'unknown':
                    result.method_used = step_name
                    result.time_seconds = time.time() - start_time
                    return result
            except Exception as e:
                logger.warning(f"Strategy step {step_name} failed: {e}")
                continue
        
        return VerificationResult(
            status='unknown',
            method_used=self.name,
            time_seconds=time.time() - start_time
        )


class PortfolioExecutor:
    """
    Execute multiple strategies in portfolio mode.
    """
    
    def __init__(self, timeout_ms: int = 300000):
        self.timeout_ms = timeout_ms
        self.strategies: List[Strategy] = []
        
        self.stats = {
            'portfolios_run': 0,
            'total_time_ms': 0,
        }
    
    def add_strategy(self, strategy: Strategy) -> None:
        """Add strategy to portfolio."""
        self.strategies.append(strategy)
    
    def run(self, problem: Dict[str, Any]) -> VerificationResult:
        """Run portfolio on problem."""
        self.stats['portfolios_run'] += 1
        start = time.time()
        
        best_result = VerificationResult(status='unknown')
        
        for strategy in self.strategies:
            remaining = self.timeout_ms - int((time.time() - start) * 1000)
            if remaining <= 0:
                break
            
            strategy.timeout_ms = remaining // len(self.strategies)
            result = strategy.execute(problem)
            
            if result.status == 'safe':
                self.stats['total_time_ms'] += int((time.time() - start) * 1000)
                return result
            elif result.status == 'unsafe':
                best_result = result
        
        self.stats['total_time_ms'] += int((time.time() - start) * 1000)
        return best_result


# =============================================================================
# UNIFIED SYNTHESIS ENGINE
# =============================================================================

class UnifiedSynthesisEngine:
    """
    Unified orchestrator for all 20 SOTA paper implementations.
    
    MAIN INTERFACE for the entire barrier synthesis framework.
    
    This engine:
    1. Analyzes the verification problem
    2. Selects appropriate techniques
    3. Executes verification/synthesis
    4. Returns certificates or counterexamples
    """
    
    def __init__(self, timeout_ms: int = 300000,
                 verbose: bool = False):
        self.timeout_ms = timeout_ms
        self.verbose = verbose
        
        # Problem analysis
        self.classifier = ProblemClassifier()
        
        # Layer engines
        self.foundations = PolynomialCertificateEngine(2, 6, timeout_ms // 5)
        self.certificate_core = BarrierCertificateEngine(2, 'continuous', 6, timeout_ms // 3)
        self.abstraction = AbstractionRefinementEngine([], 100, timeout_ms // 3)
        self.learning = LearningBasedEngine(2, 4, timeout_ms // 3)
        self.advanced = AdvancedVerificationEngine(timeout_ms // 2)
        
        # Portfolio
        self.portfolio = PortfolioExecutor(timeout_ms)
        self._build_portfolio()
        
        # Statistics
        self.stats = {
            'total_queries': 0,
            'safe': 0,
            'unsafe': 0,
            'unknown': 0,
            'total_time_ms': 0,
            'method_usage': {},
        }
    
    def _build_portfolio(self) -> None:
        """Build default verification portfolio."""
        
        # Strategy 1: Direct SOS
        sos_strategy = Strategy("sos_direct", self.timeout_ms // 5)
        sos_strategy.add_step("sos_safety", self._run_sos_safety)
        sos_strategy.add_step("putinar", self._run_putinar)
        self.portfolio.add_strategy(sos_strategy)
        
        # Strategy 2: Learning-based
        learning_strategy = Strategy("learning", self.timeout_ms // 5)
        learning_strategy.add_step("ice_learning", self._run_ice)
        learning_strategy.add_step("houdini", self._run_houdini)
        self.portfolio.add_strategy(learning_strategy)
        
        # Strategy 3: Model checking
        mc_strategy = Strategy("model_checking", self.timeout_ms // 5)
        mc_strategy.add_step("ic3", self._run_ic3)
        mc_strategy.add_step("chc", self._run_chc)
        self.portfolio.add_strategy(mc_strategy)
        
        # Strategy 4: Relaxations
        relax_strategy = Strategy("relaxations", self.timeout_ms // 5)
        relax_strategy.add_step("dsos", self._run_dsos)
        relax_strategy.add_step("sparse_sos", self._run_sparse_sos)
        self.portfolio.add_strategy(relax_strategy)
    
    # =========================================================================
    # MAIN INTERFACE METHODS
    # =========================================================================
    
    def verify(self, system: Dict[str, Any],
                property: Dict[str, Any]) -> VerificationResult:
        """
        Verify safety property of system.
        
        Args:
            system: System description (dynamics, initial, safe regions)
            property: Safety property to verify
        
        Returns:
            VerificationResult with status, certificate, and statistics
        """
        start_time = time.time()
        self.stats['total_queries'] += 1
        
        # Analyze problem
        problem = {**system, **property}
        analysis = self.classifier.classify(problem)
        
        if self.verbose:
            logger.info(f"Problem type: {analysis.problem_type}")
            logger.info(f"Problem size: {analysis.problem_size}")
            logger.info(f"Recommended: {analysis.recommended_methods}")
        
        # Build problem dict for strategies
        problem_dict = self._build_problem_dict(system, property, analysis)
        
        # Run portfolio
        result = self.portfolio.run(problem_dict)
        
        # Update stats
        elapsed = time.time() - start_time
        self.stats['total_time_ms'] += int(elapsed * 1000)
        self.stats[result.status] = self.stats.get(result.status, 0) + 1
        self.stats['method_usage'][result.method_used] = \
            self.stats['method_usage'].get(result.method_used, 0) + 1
        
        return result
    
    def synthesize_barrier(self, initial: SemialgebraicSet,
                            safe: SemialgebraicSet,
                            unsafe: SemialgebraicSet,
                            dynamics: ContinuousDynamics) -> Optional[Polynomial]:
        """
        Synthesize barrier certificate.
        
        High-level interface that automatically selects technique.
        """
        start_time = time.time()
        self.stats['total_queries'] += 1
        
        n_vars = dynamics.n_vars
        
        # Update engines with correct dimensions
        self.certificate_core = BarrierCertificateEngine(
            n_vars, 'continuous', 6, self.timeout_ms // 2
        )
        self.learning = LearningBasedEngine(n_vars, 4, self.timeout_ms // 3)
        
        # Try certificate core first
        result = self.certificate_core.synthesize(initial, safe, unsafe, dynamics)
        if result is not None:
            self.stats['safe'] += 1
            self.stats['method_usage']['certificate_core'] = \
                self.stats['method_usage'].get('certificate_core', 0) + 1
            return result
        
        # Try learning-based
        conditions = BarrierConditions(initial=initial, safe=safe, unsafe=unsafe)
        result = self.learning.synthesize_barrier(conditions, dynamics)
        if result is not None:
            self.stats['safe'] += 1
            self.stats['method_usage']['learning'] = \
                self.stats['method_usage'].get('learning', 0) + 1
            return result
        
        self.stats['unknown'] += 1
        return None
    
    def synthesize_hybrid_barrier(self, automaton: HybridAutomaton,
                                    conditions: HybridBarrierConditions
                                    ) -> Optional[HybridBarrierCertificate]:
        """
        Synthesize barrier certificate for hybrid system.
        """
        self.stats['total_queries'] += 1
        
        synth = HybridBarrierSynthesizer(
            automaton.n_vars, 4, self.timeout_ms
        )
        
        result = synth.synthesize(automaton, conditions)
        
        if result is not None:
            self.stats['safe'] += 1
            self.stats['method_usage']['hybrid_barrier'] = \
                self.stats['method_usage'].get('hybrid_barrier', 0) + 1
        else:
            self.stats['unknown'] += 1
        
        return result
    
    def synthesize_stochastic_barrier(self, dynamics: StochasticDynamics,
                                        conditions: StochasticBarrierConditions
                                        ) -> Optional[StochasticBarrierCertificate]:
        """
        Synthesize barrier certificate for stochastic system.
        """
        self.stats['total_queries'] += 1
        
        synth = StochasticBarrierSynthesizer(
            dynamics.n_vars, 4, self.timeout_ms
        )
        
        result = synth.synthesize(dynamics, conditions)
        
        if result is not None:
            self.stats['safe'] += 1
            self.stats['method_usage']['stochastic_barrier'] = \
                self.stats['method_usage'].get('stochastic_barrier', 0) + 1
        else:
            self.stats['unknown'] += 1
        
        return result
    
    def prove_polynomial_positive(self, polynomial: Polynomial,
                                    constraints: Optional[List[Polynomial]] = None
                                    ) -> Optional[PolynomialCertificate]:
        """
        Prove polynomial positivity (possibly on constrained set).
        """
        self.stats['total_queries'] += 1
        
        self.foundations = PolynomialCertificateEngine(
            polynomial.n_vars, polynomial.degree, self.timeout_ms
        )
        
        result = self.foundations.prove_positivity(polynomial, constraints)
        
        if result is not None:
            self.stats['safe'] += 1
            self.stats['method_usage']['foundations'] = \
                self.stats['method_usage'].get('foundations', 0) + 1
        else:
            self.stats['unknown'] += 1
        
        return result
    
    def verify_compositional(self, components: List[Component],
                               contracts: List[AGContract]) -> VerificationResult:
        """
        Verify system compositionally using assume-guarantee.
        """
        self.stats['total_queries'] += 1
        
        status, invariant = self.advanced.verify_compositional(components, contracts)
        
        result = VerificationResult(
            status=status,
            certificate=invariant,
            method_used='assume_guarantee'
        )
        
        self.stats[status] = self.stats.get(status, 0) + 1
        self.stats['method_usage']['assume_guarantee'] = \
            self.stats['method_usage'].get('assume_guarantee', 0) + 1
        
        return result
    
    # =========================================================================
    # STRATEGY IMPLEMENTATIONS
    # =========================================================================
    
    def _build_problem_dict(self, system: Dict[str, Any],
                             property: Dict[str, Any],
                             analysis: ProblemAnalysis) -> Dict[str, Any]:
        """Build unified problem dictionary."""
        return {
            'system': system,
            'property': property,
            'analysis': analysis,
            'n_vars': analysis.n_vars,
            'max_degree': analysis.max_degree,
            'timeout_ms': self.timeout_ms,
        }
    
    def _run_sos_safety(self, problem: Dict[str, Any]) -> VerificationResult:
        """Run SOS safety checking using Papers #1-10."""
        system = problem.get('system', {})
        property_dict = problem.get('property', {})
        n_vars = problem.get('n_vars', 2)
        
        # Extract conditions
        initial = system.get('initial')
        safe = system.get('safe')
        unsafe = property_dict.get('avoid', system.get('unsafe'))
        dynamics = system.get('dynamics')
        
        # ENHANCED: Try all Papers #1-10 for Python bugs
        bug_type = system.get('bug_type')
        bug_variable = system.get('bug_variable')
        summary = system.get('crash_summary')
        
        if bug_type and bug_variable and summary:
            logger.debug(f"[SOS Safety] Trying Papers #1-10 for {bug_type} on {bug_variable}")
            
            # Try Papers #1-5 first
            try:
                from .papers_1_to_5_complete import Papers1to5UnifiedEngine
                engine1to5 = Papers1to5UnifiedEngine()
                is_safe, paper_name, certificate = engine1to5.verify_safety(
                    bug_type, bug_variable, summary
                )
                if is_safe:
                    logger.info(f"[{paper_name}] ✓ SUCCESS!")
                    return VerificationResult(
                        status='safe',
                        certificate=certificate,
                        method_used=paper_name
                    )
                else:
                    logger.debug(f"[Papers #1-5] All returned False")
            except Exception as e:
                logger.debug(f"[Papers #1-5] Exception: {e}")
            
            # Try Papers #6-10 as fallback
            try:
                from .papers_6_to_10_complete import Papers6to10UnifiedEngine
                engine6to10 = Papers6to10UnifiedEngine()
                is_safe, paper_name, certificate = engine6to10.verify_safety(
                    bug_type, bug_variable, summary
                )
                if is_safe:
                    logger.info(f"[{paper_name}] ✓ SUCCESS!")
                    return VerificationResult(
                        status='safe',
                        certificate=certificate,
                        method_used=paper_name
                    )
                else:
                    logger.debug(f"[Papers #6-10] All returned False")
            except Exception as e:
                logger.debug(f"[Papers #6-10] Exception: {e}")
            
            # Try Papers #11-15 as fallback
            try:
                from .papers_11_to_15_complete import Papers11to15UnifiedEngine
                engine11to15 = Papers11to15UnifiedEngine()
                is_safe, paper_name, certificate = engine11to15.verify_safety(
                    bug_type, bug_variable, summary
                )
                if is_safe:
                    logger.info(f"[{paper_name}] ✓ SUCCESS!")
                    return VerificationResult(
                        status='safe',
                        certificate=certificate,
                        method_used=paper_name
                    )
                else:
                    logger.debug(f"[Papers #11-15] All returned False")
            except Exception as e:
                logger.debug(f"[Papers #11-15] Exception: {e}")
            
            # Try Papers #16-20 as final fallback
            try:
                from .papers_16_to_20_complete import Papers16to20UnifiedEngine
                engine16to20 = Papers16to20UnifiedEngine()
                is_safe, paper_name, certificate = engine16to20.verify_safety(
                    bug_type, bug_variable, summary
                )
                if is_safe:
                    logger.info(f"[{paper_name}] ✓ SUCCESS!")
                    return VerificationResult(
                        status='safe',
                        certificate=certificate,
                        method_used=paper_name
                    )
                else:
                    logger.debug(f"[Papers #16-20] All returned False")
            except Exception as e:
                logger.debug(f"[Papers #16-20] Exception: {e}")
        else:
            logger.debug(f"[SOS Safety] Missing context: bug_type={bug_type}, bug_variable={bug_variable}, summary={summary is not None}")
        
        # Fallback to original SOS safety checking
        if not all([initial, safe, unsafe, dynamics]):
            return VerificationResult(status='unknown')
        
        checker = SOSSafetyChecker(n_vars, 6, problem.get('timeout_ms', 60000))
        conditions = BarrierConditions(initial=initial, safe=safe, unsafe=unsafe)
        
        status, barrier = checker.check_safety(conditions, dynamics)
        
        return VerificationResult(
            status=status,
            certificate=barrier,
            method_used='sos_safety_paper3'
        )
    
    def _run_putinar(self, problem: Dict[str, Any]) -> VerificationResult:
        """Run Putinar representation proving."""
        system = problem.get('system', {})
        n_vars = problem.get('n_vars', 2)
        
        # Would need polynomial to prove positive
        # This is a placeholder
        return VerificationResult(status='unknown')
    
    def _run_ice(self, problem: Dict[str, Any]) -> VerificationResult:
        """Run ICE learning."""
        system = problem.get('system', {})
        n_vars = problem.get('n_vars', 2)
        
        initial = system.get('initial')
        safe = system.get('safe')
        unsafe = system.get('unsafe')
        dynamics = system.get('dynamics')
        
        if not all([initial, safe, unsafe, dynamics]):
            return VerificationResult(status='unknown')
        
        engine = LearningBasedEngine(n_vars, 4, problem.get('timeout_ms', 60000),
                                      LearningMethod.ICE)
        conditions = BarrierConditions(initial=initial, safe=safe, unsafe=unsafe)
        
        barrier = engine.synthesize_barrier(conditions, dynamics)
        
        if barrier is not None:
            return VerificationResult(
                status='safe',
                certificate=barrier,
                method_used='ice_learning'
            )
        
        return VerificationResult(status='unknown')
    
    def _run_houdini(self, problem: Dict[str, Any]) -> VerificationResult:
        """Run Houdini inference."""
        system = problem.get('system', {})
        n_vars = problem.get('n_vars', 2)
        
        initial = system.get('initial')
        safe = system.get('safe')
        unsafe = system.get('unsafe')
        dynamics = system.get('dynamics')
        
        if not all([initial, safe, unsafe, dynamics]):
            return VerificationResult(status='unknown')
        
        houdini = HoudiniBarrierInference(n_vars, 4)
        conditions = BarrierConditions(initial=initial, safe=safe, unsafe=unsafe)
        
        barrier = houdini.infer(conditions, dynamics)
        
        if barrier is not None:
            return VerificationResult(
                status='safe',
                certificate=barrier,
                method_used='houdini'
            )
        
        return VerificationResult(status='unknown')
    
    def _run_ic3(self, problem: Dict[str, Any]) -> VerificationResult:
        """Run IC3/PDR."""
        system = problem.get('system', {})
        
        initial_z3 = system.get('initial_z3')
        trans_z3 = system.get('transition_z3')
        bad_z3 = system.get('bad_z3')
        variables = system.get('variables', [])
        
        if not all([initial_z3, trans_z3, bad_z3, variables]):
            return VerificationResult(status='unknown')
        
        engine = IC3Engine(variables, problem.get('timeout_ms', 60000))
        status, invariant = engine.check_safety(initial_z3, trans_z3, bad_z3)
        
        return VerificationResult(
            status=status,
            certificate=invariant,
            method_used='ic3'
        )
    
    def _run_chc(self, problem: Dict[str, Any]) -> VerificationResult:
        """Run CHC/Spacer."""
        system = problem.get('system', {})
        
        initial_z3 = system.get('initial_z3')
        trans_z3 = system.get('transition_z3')
        bad_z3 = system.get('bad_z3')
        variables = system.get('variables', [])
        
        if not all([initial_z3, trans_z3, bad_z3, variables]):
            return VerificationResult(status='unknown')
        
        chc = SpacerCHC(problem.get('timeout_ms', 60000))
        
        # Setup CHC
        sorts = [v.sort() for v in variables]
        chc.declare_predicate('Inv', sorts)
        chc.add_init_clause(initial_z3, 'Inv', variables)
        
        primed = [z3.Const(f"{v}'", v.sort()) for v in variables]
        chc.add_trans_clause('Inv', trans_z3, variables, primed)
        chc.add_safe_clause('Inv', z3.Not(bad_z3), variables)
        
        status, interps = chc.solve()
        
        result_status = 'safe' if status == 'sat' else ('unsafe' if status == 'unsat' else 'unknown')
        
        return VerificationResult(
            status=result_status,
            certificate=interps.get('Inv') if interps else None,
            method_used='chc'
        )
    
    def _run_dsos(self, problem: Dict[str, Any]) -> VerificationResult:
        """Run DSOS relaxation."""
        system = problem.get('system', {})
        n_vars = problem.get('n_vars', 2)
        
        # Would need barrier template and conditions
        # This is a placeholder showing how DSOS would be integrated
        return VerificationResult(status='unknown')
    
    def _run_sparse_sos(self, problem: Dict[str, Any]) -> VerificationResult:
        """Run sparse SOS."""
        system = problem.get('system', {})
        n_vars = problem.get('n_vars', 2)
        
        # Placeholder
        return VerificationResult(status='unknown')
    
    # =========================================================================
    # UTILITY METHODS
    # =========================================================================
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get comprehensive statistics."""
        return {
            **self.stats,
            'classifier': self.classifier.stats,
            'portfolio': self.portfolio.stats,
        }
    
    def reset_statistics(self) -> None:
        """Reset all statistics."""
        self.stats = {
            'total_queries': 0,
            'safe': 0,
            'unsafe': 0,
            'unknown': 0,
            'total_time_ms': 0,
            'method_usage': {},
        }


# =============================================================================
# CONVENIENCE FUNCTIONS
# =============================================================================

def synthesize_barrier(n_vars: int,
                        initial: List[Polynomial],
                        safe: List[Polynomial],
                        unsafe: List[Polynomial],
                        vector_field: List[Polynomial],
                        max_degree: int = 4,
                        timeout_ms: int = 60000) -> Optional[Polynomial]:
    """
    Convenience function for barrier synthesis.
    
    Args:
        n_vars: Number of state variables
        initial: Constraints defining initial region (g_i >= 0)
        safe: Constraints defining safe region
        unsafe: Constraints defining unsafe region
        vector_field: Polynomial dynamics dx/dt = f(x)
        max_degree: Maximum degree for barrier template
        timeout_ms: Timeout in milliseconds
    
    Returns:
        Barrier polynomial if found, None otherwise
    """
    engine = UnifiedSynthesisEngine(timeout_ms=timeout_ms)
    
    initial_set = SemialgebraicSet(n_vars, initial)
    safe_set = SemialgebraicSet(n_vars, safe)
    unsafe_set = SemialgebraicSet(n_vars, unsafe)
    dynamics = ContinuousDynamics(n_vars, vector_field)
    
    return engine.synthesize_barrier(initial_set, safe_set, unsafe_set, dynamics)


def verify_safety(system_dict: Dict[str, Any],
                   property_dict: Dict[str, Any],
                   timeout_ms: int = 60000) -> VerificationResult:
    """
    Convenience function for safety verification.
    """
    engine = UnifiedSynthesisEngine(timeout_ms=timeout_ms)
    return engine.verify(system_dict, property_dict)


# =============================================================================
# EXPORTS
# =============================================================================

__all__ = [
    # Problem classification
    'ProblemType',
    'ProblemSize',
    'ProblemAnalysis',
    'ProblemClassifier',
    
    # Strategy execution
    'VerificationResult',
    'Strategy',
    'PortfolioExecutor',
    
    # Main engine
    'UnifiedSynthesisEngine',
    
    # Convenience functions
    'synthesize_barrier',
    'verify_safety',
]
