"""
Barriers: Composable Barrier Certificate Synthesis Framework.

This module provides a unified framework for barrier certificate synthesis
and verification, integrating 20 SOTA papers organized into composable layers.

ARCHITECTURE OVERVIEW
=====================

The framework is organized into five conceptual layers that naturally
compose together:

    ┌─────────────────────────────────────────────────────────────┐
    │                    SYNTHESIS ENGINE                          │
    │                  (Unified Orchestrator)                      │
    ├─────────────────────────────────────────────────────────────┤
    │                                                              │
    │  ┌─────────────────────────────────────────────────────────┐│
    │  │                  LAYER 5: ADVANCED                       ││
    │  │  Papers #9, #10, #11, #15, #20                          ││
    │  │  DSOS/SDSOS, IC3/PDR, CHC, IMC, Assume-Guarantee       ││
    │  └─────────────────────────────────────────────────────────┘│
    │                          │                                   │
    │  ┌─────────────────────────────────────────────────────────┐│
    │  │                  LAYER 4: LEARNING                       ││
    │  │  Papers #17, #18, #19                                   ││
    │  │  ICE Learning, Houdini, SyGuS                           ││
    │  └─────────────────────────────────────────────────────────┘│
    │                          │                                   │
    │  ┌─────────────────────────────────────────────────────────┐│
    │  │                 LAYER 3: ABSTRACTION                     ││
    │  │  Papers #12, #13, #14, #16                              ││
    │  │  CEGAR, Predicate Abstraction, Boolean Programs, IMPACT ││
    │  └─────────────────────────────────────────────────────────┘│
    │                          │                                   │
    │  ┌─────────────────────────────────────────────────────────┐│
    │  │              LAYER 2: CERTIFICATE CORE                   ││
    │  │  Papers #1, #2, #3, #4                                  ││
    │  │  Hybrid Barriers, Stochastic Barriers, SOS Safety       ││
    │  └─────────────────────────────────────────────────────────┘│
    │                          │                                   │
    │  ┌─────────────────────────────────────────────────────────┐│
    │  │              LAYER 1: FOUNDATIONS                        ││
    │  │  Papers #5, #6, #7, #8                                  ││
    │  │  Positivstellensatz, SOS/SDP, Lasserre, Sparse SOS      ││
    │  └─────────────────────────────────────────────────────────┘│
    │                                                              │
    └─────────────────────────────────────────────────────────────┘


PAPER ORGANIZATION
==================

Layer 1 - Mathematical Foundations (Papers #5-8):
    #5: Putinar Positivstellensatz - Polynomial positivity on semialgebraic sets
    #6: SOS via SDP (Parrilo) - Semidefinite programming for SOS
    #7: Lasserre Hierarchy - Moment-SOS duality
    #8: Sparse SOS - Exploiting correlative sparsity

Layer 2 - Barrier Certificate Core (Papers #1-4):
    #1: Hybrid Barrier Certificates - Multi-mode systems
    #2: Stochastic Barrier Certificates - Probabilistic safety
    #3: SOS Safety - Emptiness checking via SOS
    #4: SOSTOOLS - Engineering framework

Layer 3 - Abstraction & Refinement (Papers #12-14, #16):
    #12: CEGAR - Counterexample-guided abstraction refinement
    #13: Predicate Abstraction - Boolean abstraction via predicates
    #14: Boolean Programs - Finite-state program abstraction
    #16: IMPACT/Lazy Abstraction - On-demand refinement

Layer 4 - Learning-Based Synthesis (Papers #17-19):
    #17: ICE Learning - Implication counterexamples
    #18: Houdini - Conjunctive inference by fixpoint
    #19: SyGuS - Syntax-guided synthesis

Layer 5 - Advanced Verification (Papers #9-11, #15, #20):
    #9: DSOS/SDSOS - LP/SOCP relaxations
    #10: IC3/PDR - Property-directed reachability
    #11: Spacer/CHC - Constrained Horn clauses
    #15: Interpolation/IMC - Craig interpolation for model checking
    #20: Assume-Guarantee - Compositional reasoning


USAGE
=====

Quick Start:
    from barriers import UnifiedSynthesisEngine, synthesize_barrier
    
    # Using the unified engine
    engine = UnifiedSynthesisEngine()
    result = engine.verify(system, property)
    
    # Or direct synthesis
    barrier = synthesize_barrier(n_vars=2, initial=[...], safe=[...], 
                                  unsafe=[...], vector_field=[...])

Layer-Specific Access:
    from barriers.foundations import (
        PolynomialCertificateEngine,
        SOSDecomposer,
        LasserreHierarchySolver,
    )
    
    from barriers.certificate_core import (
        HybridBarrierSynthesizer,
        StochasticBarrierSynthesizer,
        BarrierCertificateEngine,
    )
    
    from barriers.learning import (
        ICELearner,
        HoudiniBarrierInference,
        SyGuSSynthesizer,
    )
"""

from __future__ import annotations

# =============================================================================
# LAYER 1: MATHEMATICAL FOUNDATIONS (Papers #5-8)
# =============================================================================
# Core polynomial certificate machinery providing the mathematical bedrock.

from .foundations import (
    # Fundamental types
    Monomial,
    Polynomial,
    SemialgebraicSet,
    
    # Quadratic module (Paper #5)
    QuadraticModule,
    
    # SOS decomposition (Paper #6)
    SOSDecomposition,
    SOSDecomposer,
    
    # Putinar representation (Papers #5 + #6)
    PutinarCertificate,
    PutinarProver,
    
    # Lasserre hierarchy (Paper #7)
    MomentMatrix,
    LocalizingMatrix,
    LasserreRelaxation,
    LasserreHierarchySolver,
    
    # Sparse SOS (Paper #8)
    VariableInteractionGraph,
    ChordalExtension,
    SparseSOSDecomposer,
    
    # Unified engine
    CertificateType,
    PolynomialCertificate,
    PolynomialCertificateEngine,
)


# =============================================================================
# LAYER 2: BARRIER CERTIFICATE CORE (Papers #1-4)
# =============================================================================
# Core barrier certificate constructions building on foundations.

from .certificate_core import (
    # System types
    SystemType,
    ContinuousDynamics,
    DiscreteDynamics,
    HybridMode,
    HybridTransition,
    HybridAutomaton,
    StochasticDynamics,
    
    # Barrier conditions
    BarrierConditions,
    HybridBarrierConditions,
    StochasticBarrierConditions,
    
    # Templates
    BarrierTemplate,
    MultiModeBarrierTemplate,
    
    # SOS Safety (Paper #3)
    SOSSafetyChecker,
    
    # Hybrid Barriers (Paper #1)
    HybridBarrierCertificate,
    HybridBarrierSynthesizer,
    
    # Stochastic Barriers (Paper #2)
    StochasticBarrierCertificate,
    StochasticBarrierSynthesizer,
    
    # SOSTOOLS Framework (Paper #4)
    SOSTOOLSFramework,
    
    # Unified Engine
    BarrierCertificateEngine,
)


# =============================================================================
# LAYER 3: ABSTRACTION & REFINEMENT (Papers #12-14, #16)
# =============================================================================
# Abstraction techniques for managing verification complexity.

from .abstraction import (
    # Predicate Abstraction (Paper #13)
    Predicate,
    AbstractState,
    PredicateAbstraction,
    
    # Boolean Programs (Paper #14)
    BooleanVariable,
    BooleanStatement,
    BooleanProcedure,
    BooleanProgram,
    BooleanProgramState,
    BooleanProgramExecutor,
    
    # Lazy Abstraction / IMPACT (Paper #16)
    ARTNode,
    LazyAbstraction,
    
    # CEGAR (Paper #12)
    CEGARResult,
    Counterexample,
    CEGARLoop,
    
    # Barrier-specific abstraction
    BarrierAbstraction,
    
    # Unified Engine
    AbstractionRefinementEngine,
)


# =============================================================================
# LAYER 4: LEARNING-BASED SYNTHESIS (Papers #17-19)
# =============================================================================
# Data-driven and learning-based certificate discovery.

from .learning import (
    # Data types
    DataPoint,
    ICEExample,
    
    # ICE Learning (Paper #17)
    ICELearner,
    ICETeacher,
    
    # Houdini Inference (Paper #18)
    HoudiniAnnotation,
    HoudiniInference,
    HoudiniBarrierInference,
    
    # SyGuS Synthesis (Paper #19)
    SyGuSGrammar,
    SyGuSConstraint,
    SyGuSSynthesizer,
    
    # Unified Engine
    LearningMethod,
    LearningBasedEngine,
)


# =============================================================================
# LAYER 5: ADVANCED VERIFICATION (Papers #9-11, #15, #20)
# =============================================================================
# Advanced techniques complementing core synthesis.

from .advanced import (
    # DSOS/SDSOS (Paper #9)
    DecompositionType,
    DSOSDecomposition,
    SDSOSDecomposition,
    DSOSRelaxation,
    
    # IC3/PDR (Paper #10)
    Frame,
    ProofObligation,
    IC3Engine,
    
    # Spacer/CHC (Paper #11)
    HornClause,
    SpacerCHC,
    
    # Interpolation/IMC (Paper #15)
    InterpolationEngine,
    IMCVerifier,
    
    # Assume-Guarantee (Paper #20)
    Component,
    AGContract,
    AssumeGuaranteeVerifier,
    
    # Unified Engine
    AdvancedMethod,
    AdvancedVerificationEngine,
)


# =============================================================================
# UNIFIED SYNTHESIS ENGINE
# =============================================================================
# Top-level orchestrator integrating all layers.

from .synthesis_engine import (
    # Problem classification
    ProblemType,
    ProblemSize,
    ProblemAnalysis,
    ProblemClassifier,
    
    # Strategy execution
    VerificationResult,
    Strategy,
    PortfolioExecutor,
    
    # Main engine
    UnifiedSynthesisEngine,
    
    # Convenience functions
    synthesize_barrier,
    verify_safety,
)


# =============================================================================
# LEGACY COMPATIBILITY LAYER
# =============================================================================
# Imports from original implementation for backward compatibility.

from .invariants import (
    BarrierFunction,
    BarrierCertificate,
    InductivenessResult,
    InductivenessChecker,
    linear_combination_barrier,
)

from .templates import (
    stack_depth_barrier,
    variable_upper_bound_barrier,
    variable_lower_bound_barrier,
    variable_range_barrier,
    iteration_count_barrier,
    constant_barrier,
    conjunction_barrier,
    extract_local_variable,
    conditional_guard_barrier,
    loop_range_barrier,
    disjunction_barrier,
    collection_size_barrier,
    progress_measure_barrier,
    invariant_region_barrier,
)

from .synthesis import (
    SynthesisConfig,
    SynthesisResult,
    BarrierSynthesizer,
    synthesize_barrier_for_bug_type,
)

from .ranking import (
    RankingFunction,
    RankingFunctionCertificate,
    TerminationProofResult,
    TerminationChecker,
    linear_ranking_function,
    simple_counter_ranking,
    lexicographic_ranking,
)

from .cegis import (
    CEGISConfig,
    CEGISResult,
    CEGISBarrierSynthesizer,
    synthesize_barrier_cegis,
)


# =============================================================================
# EXPORTS
# =============================================================================

__all__ = [
    # =========================================================================
    # Layer 1: Foundations (Papers #5-8)
    # =========================================================================
    'Monomial',
    'Polynomial',
    'SemialgebraicSet',
    'QuadraticModule',
    'SOSDecomposition',
    'SOSDecomposer',
    'PutinarCertificate',
    'PutinarProver',
    'MomentMatrix',
    'LocalizingMatrix',
    'LasserreRelaxation',
    'LasserreHierarchySolver',
    'VariableInteractionGraph',
    'ChordalExtension',
    'SparseSOSDecomposer',
    'CertificateType',
    'PolynomialCertificate',
    'PolynomialCertificateEngine',
    
    # =========================================================================
    # Layer 2: Certificate Core (Papers #1-4)
    # =========================================================================
    'SystemType',
    'ContinuousDynamics',
    'DiscreteDynamics',
    'HybridMode',
    'HybridTransition',
    'HybridAutomaton',
    'StochasticDynamics',
    'BarrierConditions',
    'HybridBarrierConditions',
    'StochasticBarrierConditions',
    'BarrierTemplate',
    'MultiModeBarrierTemplate',
    'SOSSafetyChecker',
    'HybridBarrierCertificate',
    'HybridBarrierSynthesizer',
    'StochasticBarrierCertificate',
    'StochasticBarrierSynthesizer',
    'SOSTOOLSFramework',
    'BarrierCertificateEngine',
    
    # =========================================================================
    # Layer 3: Abstraction (Papers #12-14, #16)
    # =========================================================================
    'Predicate',
    'AbstractState',
    'PredicateAbstraction',
    'BooleanVariable',
    'BooleanStatement',
    'BooleanProcedure',
    'BooleanProgram',
    'BooleanProgramState',
    'BooleanProgramExecutor',
    'ARTNode',
    'LazyAbstraction',
    'CEGARResult',
    'Counterexample',
    'CEGARLoop',
    'BarrierAbstraction',
    'AbstractionRefinementEngine',
    
    # =========================================================================
    # Layer 4: Learning (Papers #17-19)
    # =========================================================================
    'DataPoint',
    'ICEExample',
    'ICELearner',
    'ICETeacher',
    'HoudiniAnnotation',
    'HoudiniInference',
    'HoudiniBarrierInference',
    'SyGuSGrammar',
    'SyGuSConstraint',
    'SyGuSSynthesizer',
    'LearningMethod',
    'LearningBasedEngine',
    
    # =========================================================================
    # Layer 5: Advanced (Papers #9-11, #15, #20)
    # =========================================================================
    'DecompositionType',
    'DSOSDecomposition',
    'SDSOSDecomposition',
    'DSOSRelaxation',
    'Frame',
    'ProofObligation',
    'IC3Engine',
    'HornClause',
    'SpacerCHC',
    'InterpolationEngine',
    'IMCVerifier',
    'Component',
    'AGContract',
    'AssumeGuaranteeVerifier',
    'AdvancedMethod',
    'AdvancedVerificationEngine',
    
    # =========================================================================
    # Unified Synthesis Engine
    # =========================================================================
    'ProblemType',
    'ProblemSize',
    'ProblemAnalysis',
    'ProblemClassifier',
    'VerificationResult',
    'Strategy',
    'PortfolioExecutor',
    'UnifiedSynthesisEngine',
    'synthesize_barrier',
    'verify_safety',
    
    # =========================================================================
    # Legacy Compatibility
    # =========================================================================
    'BarrierFunction',
    'BarrierCertificate',
    'InductivenessResult',
    'InductivenessChecker',
    'linear_combination_barrier',
    'stack_depth_barrier',
    'variable_upper_bound_barrier',
    'variable_lower_bound_barrier',
    'variable_range_barrier',
    'iteration_count_barrier',
    'constant_barrier',
    'conjunction_barrier',
    'extract_local_variable',
    'conditional_guard_barrier',
    'loop_range_barrier',
    'disjunction_barrier',
    'collection_size_barrier',
    'progress_measure_barrier',
    'invariant_region_barrier',
    'SynthesisConfig',
    'SynthesisResult',
    'BarrierSynthesizer',
    'synthesize_barrier_for_bug_type',
    'RankingFunction',
    'RankingFunctionCertificate',
    'TerminationProofResult',
    'TerminationChecker',
    'linear_ranking_function',
    'simple_counter_ranking',
    'lexicographic_ranking',
    'CEGISConfig',
    'CEGISResult',
    'CEGISBarrierSynthesizer',
    'synthesize_barrier_cegis',
]
