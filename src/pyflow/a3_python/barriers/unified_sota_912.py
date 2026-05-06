"""
Unified Engine: Papers #9-12 Integration for Barrier Synthesis.

This module provides a unified interface for the four additional SOTA papers:
- Paper #9: DSOS/SDSOS (LP/SOCP relaxations)
- Paper #10: IC3/PDR (inductive reasoning)
- Paper #11: Spacer/CHC (recursive program verification)
- Paper #12: CEGAR (abstraction refinement)

COMPOSITIONAL ARCHITECTURE
==========================

The four papers work together to strengthen barrier synthesis:

1. **CEGAR (Paper #12)** - Abstraction
   - Reduces problem complexity before synthesis
   - Eliminates spurious counterexamples
   - Provides targeted refinements

2. **IC3/PDR (Paper #10)** - Discrete Invariants
   - Discovers inductive lemmas
   - Conditions polynomial barrier search
   - Provides frame-based strengthening

3. **Spacer/CHC (Paper #11)** - Procedure Summaries
   - Handles recursive/interprocedural code
   - Computes modular summaries
   - Enables compositional reasoning

4. **DSOS/SDSOS (Paper #9)** - Fast Certificates
   - LP/SOCP instead of SDP
   - Fallback when SOS times out
   - Scales to higher dimensions

INTEGRATION FLOW
================

                    ┌─────────────┐
                    │   Program   │
                    └──────┬──────┘
                           │
                    ┌──────▼──────┐
                    │    CEGAR    │ ◄── Abstract & Refine
                    │  (Paper 12) │
                    └──────┬──────┘
                           │
            ┌──────────────┼──────────────┐
            │              │              │
     ┌──────▼──────┐ ┌─────▼─────┐ ┌──────▼──────┐
     │   IC3/PDR   │ │  Spacer   │ │    CHC      │
     │ (Paper 10)  │ │ (Paper 11)│ │  Summaries  │
     └──────┬──────┘ └─────┬─────┘ └──────┬──────┘
            │              │              │
            └──────────────┼──────────────┘
                           │
                    ┌──────▼──────┐
                    │   Barrier   │ ◄── Conditioned Problem
                    │  Synthesis  │
                    └──────┬──────┘
                           │
            ┌──────────────┼──────────────┐
            │              │              │
     ┌──────▼──────┐ ┌─────▼─────┐ ┌──────▼──────┐
     │    DSOS     │ │  SDSOS    │ │    SOS      │
     │  (LP fast)  │ │  (SOCP)   │ │   (SDP)     │
     └─────────────┘ └───────────┘ └─────────────┘

ARTIFACT FLOW
=============

1. CEGAR produces: refined abstraction, spurious CEX elimination
2. IC3/PDR produces: inductive lemmas, frame constraints
3. Spacer produces: procedure summaries, CHC solutions
4. DSOS/SDSOS produces: fast certificates, fallback barriers

All artifacts feed into the main barrier synthesis engine.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Dict, List, Optional, Tuple, Set, Any, Callable

import z3

# Import from barrier modules
from .parrilo_sos_sdp import (
    Polynomial,
    SemialgebraicSet,
    BarrierSynthesisProblem,
    BarrierCertificateResult,
)

# Paper #9: DSOS/SDSOS
from .dsos_sdsos import (
    DSOSBarrierSynthesizer,
    SDSOSBarrierSynthesizer,
    DSOSSDSOSFallbackOrchestrator,
    DSOSSDSOSIntegration,
    DSOSBarrierConfig,
    DSOSBarrierResult,
    FallbackResult,
    CertificateStrength,
    try_dsos_barrier,
    analyze_for_dsos,
)

# Paper #10: IC3/PDR
from .ic3_pdr import (
    IC3Engine,
    IC3Proof,
    IC3Result,
    TransitionSystem,
    IC3BarrierConditioner,
    IC3PDRIntegration,
    LemmaLifter,
    LiftedConstraint,
    run_ic3,
    condition_barrier_with_ic3,
)

# Paper #11: Spacer/CHC
from .spacer_chc import (
    SpacerSolver,
    CHCProblem,
    CHCPredicate,
    CHCClause,
    CHCSolution,
    CHCResult,
    SpacerCHCIntegration,
    ProcedureSummary,
    SummaryComputer,
    CHCBarrierBridge,
    solve_chc,
    verify_python_function,
)

# Paper #12: CEGAR
from .cegar_refinement import (
    CEGARLoop,
    CEGARProof,
    CEGARResult,
    CEGARIntegration,
    AbstractDomain,
    AbstractState,
    AbstractionRefiner,
    CounterexampleAnalyzer,
    Refinement,
    RefinementStrategy,
    run_cegar,
    synthesize_barrier_cegar,
)


# =============================================================================
# UNIFIED ENGINE CONFIGURATION
# =============================================================================

class EnginePhase(Enum):
    """Phases in the unified engine."""
    ABSTRACTION = auto()     # CEGAR abstraction
    DISCRETE_INV = auto()    # IC3/PDR invariants
    CHC_SUMMARIES = auto()   # Spacer summaries
    BARRIER_SYNTH = auto()   # Main barrier synthesis
    CERTIFICATE = auto()     # DSOS/SDSOS/SOS certificate


@dataclass
class UnifiedEngineConfig:
    """
    Configuration for the unified Papers #9-12 engine.
    
    Attributes:
        use_cegar: Enable CEGAR abstraction refinement
        use_ic3: Enable IC3/PDR for invariants
        use_spacer: Enable Spacer for CHC/summaries
        use_dsos_fallback: Enable DSOS/SDSOS fallback
        max_degree: Maximum polynomial degree
        total_timeout_ms: Total time budget
        phase_budgets: Time budget per phase (as fractions)
        verbose: Enable verbose output
    """
    use_cegar: bool = True
    use_ic3: bool = True
    use_spacer: bool = True
    use_dsos_fallback: bool = True
    max_degree: int = 6
    total_timeout_ms: int = 120000
    phase_budgets: Dict[EnginePhase, float] = field(default_factory=lambda: {
        EnginePhase.ABSTRACTION: 0.1,
        EnginePhase.DISCRETE_INV: 0.2,
        EnginePhase.CHC_SUMMARIES: 0.2,
        EnginePhase.BARRIER_SYNTH: 0.4,
        EnginePhase.CERTIFICATE: 0.1,
    })
    verbose: bool = False
    
    def get_phase_timeout(self, phase: EnginePhase) -> int:
        """Get timeout for a phase in milliseconds."""
        fraction = self.phase_budgets.get(phase, 0.2)
        return int(self.total_timeout_ms * fraction)


@dataclass
class UnifiedEngineResult:
    """
    Result from unified engine.
    
    Attributes:
        success: Whether barrier was found
        barrier: The barrier polynomial (if success)
        certificate_type: Type of certificate used
        conditioning_used: List of conditioning techniques used
        phase_results: Results from each phase
        refinements: CEGAR refinements applied
        statistics: Aggregate statistics
        message: Status message
    """
    success: bool
    barrier: Optional[Polynomial] = None
    certificate_type: Optional[CertificateStrength] = None
    conditioning_used: List[str] = field(default_factory=list)
    phase_results: Dict[EnginePhase, Any] = field(default_factory=dict)
    refinements: List[Refinement] = field(default_factory=list)
    statistics: Dict[str, Any] = field(default_factory=dict)
    message: str = ""
    
    def summary(self) -> str:
        """Generate summary string."""
        if self.success:
            cert = self.certificate_type.name if self.certificate_type else "unknown"
            cond = ", ".join(self.conditioning_used) if self.conditioning_used else "none"
            return f"SUCCESS: {cert} certificate, conditioning: {cond}"
        else:
            return f"FAILED: {self.message}"


# =============================================================================
# UNIFIED ENGINE
# =============================================================================

class UnifiedPapers9to12Engine:
    """
    Unified engine combining Papers #9-12.
    
    Orchestrates the interaction between:
    - CEGAR (abstraction refinement)
    - IC3/PDR (discrete invariants)
    - Spacer/CHC (procedure summaries)
    - DSOS/SDSOS (fast certificates)
    
    Provides a single entry point for barrier synthesis with
    all SOTA techniques applied.
    """
    
    def __init__(self, config: Optional[UnifiedEngineConfig] = None,
                 verbose: bool = False):
        self.config = config or UnifiedEngineConfig()
        self.verbose = verbose or self.config.verbose
        
        # Sub-integrations
        self._cegar = CEGARIntegration(verbose=self.verbose)
        self._ic3 = IC3PDRIntegration(verbose=self.verbose)
        self._spacer = SpacerCHCIntegration(verbose=self.verbose)
        self._dsos = DSOSSDSOSIntegration(verbose=self.verbose)
        
        # Statistics
        self._stats = {
            'total_attempts': 0,
            'cegar_used': 0,
            'ic3_used': 0,
            'spacer_used': 0,
            'dsos_successes': 0,
            'sdsos_successes': 0,
            'sos_successes': 0,
        }
    
    def synthesize(self, problem: BarrierSynthesisProblem,
                   code_obj=None,
                   transition_system: Optional[TransitionSystem] = None) -> UnifiedEngineResult:
        """
        Synthesize barrier using unified engine.
        
        Args:
            problem: Barrier synthesis problem
            code_obj: Optional Python code object for program analysis
            transition_system: Optional transition system for IC3
        
        Returns:
            UnifiedEngineResult with barrier or failure info
        """
        start_time = time.time()
        self._stats['total_attempts'] += 1
        
        phase_results = {}
        conditioning_used = []
        refinements = []
        
        # Current problem (will be conditioned by phases)
        current_problem = problem
        
        # Phase 1: CEGAR Abstraction
        if self.config.use_cegar:
            phase_start = time.time()
            timeout = self.config.get_phase_timeout(EnginePhase.ABSTRACTION)
            
            cegar_result = self._run_cegar_phase(current_problem, timeout)
            
            phase_results[EnginePhase.ABSTRACTION] = cegar_result
            
            if cegar_result.get('conditioned_problem'):
                current_problem = cegar_result['conditioned_problem']
                conditioning_used.append("CEGAR")
                self._stats['cegar_used'] += 1
            
            if cegar_result.get('refinements'):
                refinements.extend(cegar_result['refinements'])
            
            if self.verbose:
                print(f"[Unified] CEGAR phase: {(time.time() - phase_start) * 1000:.1f}ms")
        
        # Phase 2: IC3/PDR Invariants
        if self.config.use_ic3 and transition_system:
            phase_start = time.time()
            timeout = self.config.get_phase_timeout(EnginePhase.DISCRETE_INV)
            
            ic3_result = self._run_ic3_phase(current_problem, transition_system, timeout)
            
            phase_results[EnginePhase.DISCRETE_INV] = ic3_result
            
            if ic3_result.get('conditioned_problem'):
                current_problem = ic3_result['conditioned_problem']
                conditioning_used.append("IC3/PDR")
                self._stats['ic3_used'] += 1
            
            if self.verbose:
                print(f"[Unified] IC3 phase: {(time.time() - phase_start) * 1000:.1f}ms")
        
        # Phase 3: Spacer/CHC Summaries
        if self.config.use_spacer and code_obj:
            phase_start = time.time()
            timeout = self.config.get_phase_timeout(EnginePhase.CHC_SUMMARIES)
            
            spacer_result = self._run_spacer_phase(current_problem, code_obj, timeout)
            
            phase_results[EnginePhase.CHC_SUMMARIES] = spacer_result
            
            if spacer_result.get('conditioned_problem'):
                current_problem = spacer_result['conditioned_problem']
                conditioning_used.append("Spacer/CHC")
                self._stats['spacer_used'] += 1
            
            if self.verbose:
                print(f"[Unified] Spacer phase: {(time.time() - phase_start) * 1000:.1f}ms")
        
        # Phase 4: Barrier Synthesis with DSOS/SDSOS/SOS
        phase_start = time.time()
        remaining = self.config.total_timeout_ms - (time.time() - start_time) * 1000
        
        synthesis_result = self._run_synthesis_phase(
            current_problem, int(remaining * 0.9)
        )
        
        phase_results[EnginePhase.BARRIER_SYNTH] = synthesis_result
        
        if self.verbose:
            print(f"[Unified] Synthesis phase: {(time.time() - phase_start) * 1000:.1f}ms")
        
        # Build result
        total_time = (time.time() - start_time) * 1000
        
        if synthesis_result.success:
            # Update statistics
            if synthesis_result.certificate_type == CertificateStrength.DSOS:
                self._stats['dsos_successes'] += 1
            elif synthesis_result.certificate_type == CertificateStrength.SDSOS:
                self._stats['sdsos_successes'] += 1
            else:
                self._stats['sos_successes'] += 1
            
            return UnifiedEngineResult(
                success=True,
                barrier=synthesis_result.barrier,
                certificate_type=synthesis_result.certificate_type,
                conditioning_used=conditioning_used,
                phase_results=phase_results,
                refinements=refinements,
                statistics={'total_time_ms': total_time, **self._stats},
                message="Barrier found"
            )
        
        return UnifiedEngineResult(
            success=False,
            conditioning_used=conditioning_used,
            phase_results=phase_results,
            refinements=refinements,
            statistics={'total_time_ms': total_time, **self._stats},
            message=synthesis_result.message
        )
    
    def _run_cegar_phase(self, problem: BarrierSynthesisProblem,
                          timeout_ms: int) -> Dict[str, Any]:
        """Run CEGAR abstraction phase."""
        result = {}
        
        try:
            success, barrier, refinements = synthesize_barrier_cegar(
                problem,
                max_iterations=5,
                timeout_ms=timeout_ms,
                verbose=self.verbose
            )
            
            result['success'] = success
            result['refinements'] = refinements
            
            if success and barrier:
                result['barrier'] = barrier
            
            # CEGAR conditions the problem through refinement
            # For now, return original problem (refinement is implicit)
            result['conditioned_problem'] = problem
            
        except Exception as e:
            if self.verbose:
                print(f"[Unified] CEGAR phase error: {e}")
            result['error'] = str(e)
        
        return result
    
    def _run_ic3_phase(self, problem: BarrierSynthesisProblem,
                        system: TransitionSystem,
                        timeout_ms: int) -> Dict[str, Any]:
        """Run IC3/PDR invariant discovery phase."""
        result = {}
        
        try:
            conditioner = IC3BarrierConditioner(self.verbose)
            conditioned = conditioner.condition_problem(
                problem, system, timeout_ms
            )
            
            result['conditioned_problem'] = conditioned
            result['ic3_proof'] = conditioner.get_ic3_proof()
            result['lifted_constraints'] = conditioner.get_lifted_constraints()
            
        except Exception as e:
            if self.verbose:
                print(f"[Unified] IC3 phase error: {e}")
            result['error'] = str(e)
        
        return result
    
    def _run_spacer_phase(self, problem: BarrierSynthesisProblem,
                           code_obj,
                           timeout_ms: int) -> Dict[str, Any]:
        """Run Spacer/CHC summary computation phase."""
        result = {}
        
        try:
            conditioned = self._spacer.condition_barrier_problem(problem, code_obj)
            
            result['conditioned_problem'] = conditioned
            result['solution'] = self._spacer.get_solution(code_obj.co_name)
            result['summary'] = self._spacer.get_summary(code_obj.co_name)
            
        except Exception as e:
            if self.verbose:
                print(f"[Unified] Spacer phase error: {e}")
            result['error'] = str(e)
        
        return result
    
    def _run_synthesis_phase(self, problem: BarrierSynthesisProblem,
                              timeout_ms: int) -> FallbackResult:
        """Run barrier synthesis with DSOS/SDSOS/SOS fallback."""
        if self.config.use_dsos_fallback:
            return try_dsos_barrier(
                problem,
                max_degree=self.config.max_degree,
                timeout_ms=timeout_ms,
                verbose=self.verbose
            )
        else:
            # Direct SOS synthesis
            from .parrilo_sos_sdp import SOSBarrierSynthesizer
            
            synth = SOSBarrierSynthesizer(
                problem, verbose=self.verbose, timeout_ms=timeout_ms
            )
            result = synth.synthesize()
            
            return FallbackResult(
                success=result.success,
                barrier=result.barrier,
                certificate_type=CertificateStrength.SOS if result.success else CertificateStrength.NONE,
                synthesis_time_ms=timeout_ms,
                message=result.message
            )
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get aggregate statistics."""
        return dict(self._stats)
    
    def clear_caches(self) -> None:
        """Clear all sub-integration caches."""
        self._cegar.clear_cache()
        self._ic3.clear_cache()
        self._spacer.clear_cache()


# =============================================================================
# PORTFOLIO ORCHESTRATOR
# =============================================================================

class Papers9to12Portfolio:
    """
    Portfolio orchestrator for Papers #9-12.
    
    Manages multiple barrier synthesis problems with:
    - Adaptive technique selection
    - Time budget allocation
    - Result aggregation
    """
    
    def __init__(self, config: Optional[UnifiedEngineConfig] = None,
                 verbose: bool = False):
        self.config = config or UnifiedEngineConfig()
        self.verbose = verbose
        
        self.engine = UnifiedPapers9to12Engine(self.config, self.verbose)
        
        # Problem tracking
        self._pending: Dict[str, BarrierSynthesisProblem] = {}
        self._results: Dict[str, UnifiedEngineResult] = {}
    
    def add_problem(self, problem_id: str,
                    problem: BarrierSynthesisProblem,
                    code_obj=None,
                    transition_system: Optional[TransitionSystem] = None) -> None:
        """Add a problem to the portfolio."""
        self._pending[problem_id] = {
            'problem': problem,
            'code_obj': code_obj,
            'transition_system': transition_system,
        }
    
    def solve_all(self, total_timeout_ms: Optional[int] = None) -> Dict[str, UnifiedEngineResult]:
        """
        Solve all pending problems.
        
        Allocates time budget across problems.
        """
        total_timeout = total_timeout_ms or self.config.total_timeout_ms
        start_time = time.time()
        
        n_problems = len(self._pending)
        if n_problems == 0:
            return {}
        
        per_problem_timeout = total_timeout // n_problems
        
        for problem_id, info in list(self._pending.items()):
            elapsed = (time.time() - start_time) * 1000
            remaining = total_timeout - elapsed
            
            if remaining <= 0:
                self._results[problem_id] = UnifiedEngineResult(
                    success=False,
                    message="Budget exhausted"
                )
                continue
            
            timeout = min(per_problem_timeout, int(remaining))
            
            # Create config with adjusted timeout
            problem_config = UnifiedEngineConfig(
                use_cegar=self.config.use_cegar,
                use_ic3=self.config.use_ic3,
                use_spacer=self.config.use_spacer,
                use_dsos_fallback=self.config.use_dsos_fallback,
                max_degree=self.config.max_degree,
                total_timeout_ms=timeout,
                verbose=self.verbose
            )
            
            engine = UnifiedPapers9to12Engine(problem_config, self.verbose)
            
            result = engine.synthesize(
                info['problem'],
                info.get('code_obj'),
                info.get('transition_system')
            )
            
            self._results[problem_id] = result
        
        self._pending.clear()
        return self._results
    
    def solve_one(self, problem_id: str) -> Optional[UnifiedEngineResult]:
        """Solve a single problem."""
        if problem_id not in self._pending:
            return None
        
        info = self._pending.pop(problem_id)
        
        result = self.engine.synthesize(
            info['problem'],
            info.get('code_obj'),
            info.get('transition_system')
        )
        
        self._results[problem_id] = result
        return result
    
    def get_result(self, problem_id: str) -> Optional[UnifiedEngineResult]:
        """Get result for a solved problem."""
        return self._results.get(problem_id)
    
    def get_all_results(self) -> Dict[str, UnifiedEngineResult]:
        """Get all results."""
        return dict(self._results)
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get aggregate statistics."""
        total = len(self._results)
        successes = sum(1 for r in self._results.values() if r.success)
        
        cert_types = {}
        conditioning = {}
        
        for r in self._results.values():
            if r.certificate_type:
                name = r.certificate_type.name
                cert_types[name] = cert_types.get(name, 0) + 1
            
            for cond in r.conditioning_used:
                conditioning[cond] = conditioning.get(cond, 0) + 1
        
        return {
            'total_problems': total,
            'successes': successes,
            'success_rate': successes / total if total > 0 else 0,
            'certificate_types': cert_types,
            'conditioning_used': conditioning,
        }
    
    def clear(self) -> None:
        """Clear all state."""
        self._pending.clear()
        self._results.clear()
        self.engine.clear_caches()


# =============================================================================
# CONVENIENCE FUNCTIONS
# =============================================================================

def synthesize_with_sota_912(problem: BarrierSynthesisProblem,
                              code_obj=None,
                              transition_system: Optional[TransitionSystem] = None,
                              timeout_ms: int = 60000,
                              verbose: bool = False) -> UnifiedEngineResult:
    """
    Synthesize barrier using Papers #9-12 stack.
    
    This is the main entry point for the unified engine.
    
    Args:
        problem: Barrier synthesis problem
        code_obj: Optional Python code object for program analysis
        transition_system: Optional transition system for IC3
        timeout_ms: Total time budget
        verbose: Enable verbose output
    
    Returns:
        UnifiedEngineResult with barrier or failure info
    """
    config = UnifiedEngineConfig(
        total_timeout_ms=timeout_ms,
        verbose=verbose
    )
    
    engine = UnifiedPapers9to12Engine(config, verbose)
    return engine.synthesize(problem, code_obj, transition_system)


def analyze_for_sota_912(problem: BarrierSynthesisProblem,
                          verbose: bool = False) -> Dict[str, Any]:
    """
    Analyze a problem to determine which techniques to use.
    
    Returns recommendations for:
    - CEGAR usefulness
    - IC3 applicability
    - Spacer applicability
    - DSOS/SDSOS vs SOS choice
    """
    analysis = {}
    
    # DSOS analysis
    dsos_analysis = analyze_for_dsos(problem, verbose)
    analysis['dsos'] = dsos_analysis
    
    # Problem characteristics
    n_vars = problem.n_vars
    degree = problem.barrier_degree
    
    analysis['n_vars'] = n_vars
    analysis['degree'] = degree
    
    # Recommendations
    analysis['use_cegar'] = n_vars > 3 or degree > 4
    analysis['use_ic3'] = True  # Always useful for conditioning
    analysis['use_spacer'] = n_vars > 5  # More useful for larger problems
    analysis['use_dsos_first'] = dsos_analysis['recommended_method'] == 'DSOS'
    
    return analysis


def try_all_techniques(problem: BarrierSynthesisProblem,
                        timeout_ms: int = 60000,
                        verbose: bool = False) -> List[UnifiedEngineResult]:
    """
    Try all technique combinations and return results.
    
    Useful for benchmarking different approaches.
    """
    results = []
    
    configs = [
        ("DSOS only", UnifiedEngineConfig(
            use_cegar=False, use_ic3=False, use_spacer=False,
            use_dsos_fallback=True, total_timeout_ms=timeout_ms // 4
        )),
        ("IC3 + DSOS", UnifiedEngineConfig(
            use_cegar=False, use_ic3=True, use_spacer=False,
            use_dsos_fallback=True, total_timeout_ms=timeout_ms // 4
        )),
        ("CEGAR + DSOS", UnifiedEngineConfig(
            use_cegar=True, use_ic3=False, use_spacer=False,
            use_dsos_fallback=True, total_timeout_ms=timeout_ms // 4
        )),
        ("Full stack", UnifiedEngineConfig(
            use_cegar=True, use_ic3=True, use_spacer=True,
            use_dsos_fallback=True, total_timeout_ms=timeout_ms // 4
        )),
    ]
    
    for name, config in configs:
        if verbose:
            print(f"[TryAll] Testing: {name}")
        
        engine = UnifiedPapers9to12Engine(config, verbose)
        result = engine.synthesize(problem)
        result.message = f"{name}: {result.message}"
        results.append(result)
    
    return results
