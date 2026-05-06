"""
Unified SOS Integration: Papers #6, #7, #8 Combined.

This module provides a unified interface for the three SOS-based
barrier synthesis techniques:

- Paper #6: Parrilo SOS-SDP (basic SOS encoding)
- Paper #7: Lasserre Hierarchy (staged deepening)
- Paper #8: Sparse SOS (clique decomposition)

COMPOSITIONAL ARCHITECTURE
==========================

The three papers work together in a portfolio strategy:

1. **Sparsity Analysis** (Paper #8):
   - Analyze problem structure
   - Decompose if beneficial
   - Guide decision on sparse vs dense

2. **Staged Deepening** (Paper #7):
   - Start with low degree
   - Increase only when needed
   - Extract counterexample hints from failures

3. **Core SOS Encoding** (Paper #6):
   - Encode each subproblem as SOS
   - Handle Positivstellensatz certificates
   - Interface with Z3 solver

INTEGRATION WITH KITCHEN-SINK ORCHESTRATOR
==========================================

This module provides a single entry point `try_sos_barrier` that:
1. Analyzes sparsity
2. Chooses strategy (sparse/dense, degree schedule)
3. Runs synthesis with appropriate method
4. Returns result with proof certificate

The orchestrator can call this once and get the best result the
SOS stack can produce within the given budget.

ARTIFACT FLOW
=============

Inputs:
- BarrierSynthesisProblem (from program model extraction)
- Optional: code object for program-aware sparsity
- Time budget

Outputs:
- BarrierCertificateResult with:
  - Barrier polynomial (if success)
  - Positivstellensatz certificates
  - Counterexample candidates (if failure)
  - Statistics for debugging

The result can be:
- Fed back to CEGIS for refinement
- Used to prune explored paths
- Combined with other proof artifacts
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Dict, List, Optional, Tuple, Any

from .parrilo_sos_sdp import (
    Polynomial,
    SemialgebraicSet,
    BarrierSynthesisProblem,
    BarrierCertificateResult,
    SOSBarrierSynthesizer,
    ParriloSOSIntegration,
    ProgramSOSModel,
)

from .lasserre_hierarchy import (
    LasserreBarrierConfig,
    LasserreBarrierResult,
    LasserreBarrierSynthesizer,
    LasserreIntegration,
    HierarchySchedule,
    StagedDeepeningConfig,
    StagedDeepeningOrchestrator,
)

from .sparse_sos import (
    SparseBarrierConfig,
    SparseBarrierResult,
    SparseBarrierSynthesizer,
    SparseSOSIntegration,
    VariableInteractionInfo,
    ProgramSparsityExtractor,
    CompositionalBarrierSynthesizer,
    CompositionalBarrierResult,
)


class SOSStrategy(Enum):
    """Strategy for SOS barrier synthesis."""
    SPARSE_FIRST = auto()     # Try sparse, fall back to dense
    DENSE_ONLY = auto()       # Only use dense encoding
    ADAPTIVE = auto()         # Choose based on problem structure
    COMPOSITIONAL = auto()    # Decompose into components
    HIERARCHY = auto()        # Use Lasserre hierarchy for degree selection


@dataclass
class UnifiedSOSConfig:
    """
    Configuration for unified SOS synthesis.
    
    Attributes:
        strategy: Which strategy to use
        max_degree: Maximum barrier polynomial degree
        timeout_ms: Total time budget
        sparsity_threshold: Max clique size ratio for sparse strategy
        hierarchy_levels: Number of Lasserre hierarchy levels
        use_program_sparsity: Extract sparsity from code structure
        parallel_subproblems: Solve subproblems in parallel
        verbose: Print progress information
    """
    strategy: SOSStrategy = SOSStrategy.ADAPTIVE
    max_degree: int = 6
    timeout_ms: int = 60000
    sparsity_threshold: float = 0.7
    hierarchy_levels: int = 4
    use_program_sparsity: bool = True
    parallel_subproblems: bool = False
    verbose: bool = False


@dataclass
class UnifiedSOSResult:
    """
    Result from unified SOS synthesis.
    
    Combines results from different strategies with unified interface.
    
    Attributes:
        success: Whether a barrier was found
        barrier: The barrier polynomial (if success)
        strategy_used: Which strategy succeeded
        degree_used: Polynomial degree of barrier
        sparsity_stats: Statistics about sparsity exploitation
        hierarchy_stats: Statistics about degree hierarchy
        counterexample_candidates: Points for CEGIS refinement
        proof_certificate: Formal proof certificate (if available)
        synthesis_time_ms: Total time spent
        message: Status message
    """
    success: bool
    barrier: Optional[Polynomial] = None
    strategy_used: Optional[SOSStrategy] = None
    degree_used: int = 0
    sparsity_stats: Optional[Dict[str, Any]] = None
    hierarchy_stats: Optional[Dict[str, Any]] = None
    counterexample_candidates: List[List[float]] = field(default_factory=list)
    proof_certificate: Optional[str] = None
    synthesis_time_ms: float = 0.0
    message: str = ""
    
    def summary(self) -> str:
        """Generate summary string."""
        if self.success:
            strategy = self.strategy_used.name if self.strategy_used else "unknown"
            return (f"UNIFIED SOS SUCCESS: {strategy}, degree {self.degree_used}, "
                    f"{self.synthesis_time_ms:.1f}ms")
        else:
            return f"UNIFIED SOS FAILED: {self.message}"
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            'success': self.success,
            'barrier': str(self.barrier) if self.barrier else None,
            'strategy_used': self.strategy_used.name if self.strategy_used else None,
            'degree_used': self.degree_used,
            'sparsity_stats': self.sparsity_stats,
            'hierarchy_stats': self.hierarchy_stats,
            'counterexample_count': len(self.counterexample_candidates),
            'synthesis_time_ms': self.synthesis_time_ms,
            'message': self.message,
        }


class UnifiedSOSSynthesizer:
    """
    Unified barrier synthesizer combining Papers #6, #7, #8.
    
    Provides a single interface that automatically chooses and combines
    the best strategy based on problem structure and configuration.
    """
    
    def __init__(self, config: Optional[UnifiedSOSConfig] = None):
        self.config = config or UnifiedSOSConfig()
        
        # Sub-integrations
        self._parrilo = ParriloSOSIntegration(verbose=self.config.verbose)
        self._lasserre = LasserreIntegration(verbose=self.config.verbose)
        self._sparse = SparseSOSIntegration(verbose=self.config.verbose)
    
    def synthesize(self, problem: BarrierSynthesisProblem,
                   code_obj=None) -> UnifiedSOSResult:
        """
        Synthesize barrier using unified SOS stack.
        
        Args:
            problem: Barrier synthesis problem
            code_obj: Optional Python code object for program-aware sparsity
        
        Returns:
            UnifiedSOSResult with barrier or failure information
        """
        start_time = time.time()
        
        if self.config.strategy == SOSStrategy.ADAPTIVE:
            return self._adaptive_synthesis(problem, code_obj, start_time)
        elif self.config.strategy == SOSStrategy.SPARSE_FIRST:
            return self._sparse_first_synthesis(problem, code_obj, start_time)
        elif self.config.strategy == SOSStrategy.DENSE_ONLY:
            return self._dense_synthesis(problem, start_time)
        elif self.config.strategy == SOSStrategy.COMPOSITIONAL:
            return self._compositional_synthesis(problem, start_time)
        elif self.config.strategy == SOSStrategy.HIERARCHY:
            return self._hierarchy_synthesis(problem, start_time)
        else:
            return UnifiedSOSResult(
                success=False,
                message=f"Unknown strategy: {self.config.strategy}"
            )
    
    def _adaptive_synthesis(self, problem: BarrierSynthesisProblem,
                            code_obj, start_time: float) -> UnifiedSOSResult:
        """
        Adaptive strategy: analyze problem and choose best approach.
        """
        # Step 1: Analyze sparsity structure
        sparsity_stats = self._sparse.analyze_sparsity(problem)
        
        if self.config.verbose:
            print(f"[UnifiedSOS] Sparsity: {sparsity_stats['n_cliques']} cliques, "
                  f"max size {sparsity_stats['max_clique_size']}/{problem.n_vars}")
        
        # Step 2: Choose strategy based on structure
        if sparsity_stats['sparse_beneficial']:
            # Sparse decomposition is worth it
            result = self._sparse_first_synthesis(problem, code_obj, start_time)
            if result.success:
                return result
            # Fall through to hierarchy if sparse failed
        
        # Step 3: Use Lasserre hierarchy for degree selection
        elapsed = (time.time() - start_time) * 1000
        remaining = self.config.timeout_ms - elapsed
        
        if remaining > 1000:
            return self._hierarchy_synthesis(problem, start_time, sparsity_stats)
        
        # Last resort: dense at max degree
        return self._dense_synthesis(problem, start_time, sparsity_stats)
    
    def _sparse_first_synthesis(self, problem: BarrierSynthesisProblem,
                                 code_obj, start_time: float) -> UnifiedSOSResult:
        """
        Try sparse synthesis first, fall back to dense.
        """
        # Extract program sparsity if available
        program_sparsity = None
        if code_obj and self.config.use_program_sparsity:
            program_sparsity = self._sparse.extract_program_sparsity(code_obj)
        
        # Try sparse
        sparse_config = SparseBarrierConfig(
            max_degree=self.config.max_degree,
            use_program_sparsity=self.config.use_program_sparsity,
            fallback_to_dense=False,
            timeout_per_clique_ms=self.config.timeout_ms // 4
        )
        
        sparse_result = self._sparse.try_sparse_proof(
            problem,
            code_obj=code_obj,
            config=sparse_config,
            timeout_ms=self.config.timeout_ms // 2
        )
        
        if sparse_result.success:
            return UnifiedSOSResult(
                success=True,
                barrier=sparse_result.barrier,
                strategy_used=SOSStrategy.SPARSE_FIRST,
                degree_used=self.config.max_degree,
                sparsity_stats=sparse_result.sparsity_stats,
                synthesis_time_ms=sparse_result.synthesis_time_ms,
                message="Sparse synthesis succeeded"
            )
        
        # Fall back to dense with remaining time
        elapsed = (time.time() - start_time) * 1000
        remaining = self.config.timeout_ms - elapsed
        
        if remaining > 1000:
            return self._dense_synthesis(problem, start_time, sparse_result.sparsity_stats)
        
        return UnifiedSOSResult(
            success=False,
            sparsity_stats=sparse_result.sparsity_stats,
            synthesis_time_ms=(time.time() - start_time) * 1000,
            message="Sparse failed, insufficient time for dense fallback"
        )
    
    def _dense_synthesis(self, problem: BarrierSynthesisProblem,
                         start_time: float,
                         sparsity_stats: Optional[Dict[str, Any]] = None) -> UnifiedSOSResult:
        """
        Dense SOS synthesis using Parrilo encoding.
        """
        elapsed = (time.time() - start_time) * 1000
        remaining = int(self.config.timeout_ms - elapsed)
        
        synthesizer = SOSBarrierSynthesizer(
            problem,
            verbose=self.config.verbose,
            timeout_ms=remaining
        )
        
        result = synthesizer.synthesize()
        
        return UnifiedSOSResult(
            success=result.success,
            barrier=result.barrier,
            strategy_used=SOSStrategy.DENSE_ONLY,
            degree_used=problem.barrier_degree,
            sparsity_stats=sparsity_stats,
            synthesis_time_ms=(time.time() - start_time) * 1000,
            message=result.message
        )
    
    def _compositional_synthesis(self, problem: BarrierSynthesisProblem,
                                  start_time: float) -> UnifiedSOSResult:
        """
        Compositional synthesis: decompose and solve separately.
        """
        comp_result = self._sparse.try_compositional_proof(
            problem,
            timeout_ms=self.config.timeout_ms
        )
        
        return UnifiedSOSResult(
            success=comp_result.success,
            barrier=comp_result.global_barrier,
            strategy_used=SOSStrategy.COMPOSITIONAL,
            degree_used=self.config.max_degree,
            synthesis_time_ms=comp_result.synthesis_time_ms,
            message="Compositional " + ("succeeded" if comp_result.success else "failed")
        )
    
    def _hierarchy_synthesis(self, problem: BarrierSynthesisProblem,
                              start_time: float,
                              sparsity_stats: Optional[Dict[str, Any]] = None) -> UnifiedSOSResult:
        """
        Lasserre hierarchy synthesis with staged deepening.
        """
        elapsed = (time.time() - start_time) * 1000
        remaining = int(self.config.timeout_ms - elapsed)
        
        result = self._lasserre.try_lasserre_proof(
            problem,
            max_degree=self.config.max_degree,
            timeout_ms=remaining
        )
        
        # Extract counterexample candidates
        candidates = []
        for ce in result.candidate_counterexamples:
            candidates.append(ce)
        
        hierarchy_stats = {
            'levels_tried': result.levels_tried,
            'degree_used': result.degree_used,
        }
        
        return UnifiedSOSResult(
            success=result.success,
            barrier=result.barrier,
            strategy_used=SOSStrategy.HIERARCHY,
            degree_used=result.degree_used,
            sparsity_stats=sparsity_stats,
            hierarchy_stats=hierarchy_stats,
            counterexample_candidates=candidates,
            synthesis_time_ms=(time.time() - start_time) * 1000,
            message=result.message
        )


# =============================================================================
# KITCHEN-SINK ORCHESTRATOR INTERFACE
# =============================================================================

class SOSPortfolioOrchestrator:
    """
    Portfolio orchestrator for SOS-based verification.
    
    Manages the interaction between:
    - Multiple barrier synthesis problems
    - Different SOS strategies
    - Time budget allocation
    - Result aggregation
    
    This is the main interface for the kitchen-sink orchestrator.
    """
    
    def __init__(self, config: Optional[UnifiedSOSConfig] = None,
                 verbose: bool = False):
        self.config = config or UnifiedSOSConfig()
        self.config.verbose = verbose or self.config.verbose
        
        self.synthesizer = UnifiedSOSSynthesizer(self.config)
        
        # Tracking state
        self._results: Dict[str, UnifiedSOSResult] = {}
        self._pending: Dict[str, BarrierSynthesisProblem] = {}
        self._counterexamples: List[Tuple[str, List[float]]] = []
    
    def add_problem(self, problem_id: str,
                    problem: BarrierSynthesisProblem) -> None:
        """Add a problem to the portfolio."""
        self._pending[problem_id] = problem
    
    def add_from_program_model(self, problem_id: str,
                                model: ProgramSOSModel,
                                epsilon: float = 0.01,
                                barrier_degree: int = 2) -> None:
        """Add a problem from a program model."""
        problem = model.to_synthesis_problem(epsilon, barrier_degree)
        self.add_problem(problem_id, problem)
    
    def solve_all(self, total_timeout_ms: Optional[int] = None) -> Dict[str, UnifiedSOSResult]:
        """
        Solve all pending problems.
        
        Allocates time budget across problems and uses staged deepening.
        """
        total_timeout = total_timeout_ms or self.config.timeout_ms
        start_time = time.time()
        
        n_problems = len(self._pending)
        if n_problems == 0:
            return {}
        
        # Simple round-robin allocation for now
        per_problem_timeout = total_timeout // n_problems
        
        for problem_id, problem in self._pending.items():
            elapsed = (time.time() - start_time) * 1000
            remaining = total_timeout - elapsed
            
            if remaining <= 0:
                self._results[problem_id] = UnifiedSOSResult(
                    success=False,
                    message="Budget exhausted"
                )
                continue
            
            timeout = min(per_problem_timeout, int(remaining))
            
            # Override config timeout
            config = UnifiedSOSConfig(
                strategy=self.config.strategy,
                max_degree=self.config.max_degree,
                timeout_ms=timeout,
                verbose=self.config.verbose
            )
            
            synth = UnifiedSOSSynthesizer(config)
            result = synth.synthesize(problem)
            
            self._results[problem_id] = result
            
            # Collect counterexamples
            for ce in result.counterexample_candidates:
                self._counterexamples.append((problem_id, ce))
        
        self._pending.clear()
        return self._results
    
    def solve_one(self, problem_id: str,
                  code_obj=None) -> Optional[UnifiedSOSResult]:
        """Solve a single problem by ID."""
        if problem_id not in self._pending:
            return None
        
        problem = self._pending.pop(problem_id)
        result = self.synthesizer.synthesize(problem, code_obj)
        self._results[problem_id] = result
        
        return result
    
    def get_result(self, problem_id: str) -> Optional[UnifiedSOSResult]:
        """Get result for a solved problem."""
        return self._results.get(problem_id)
    
    def get_all_results(self) -> Dict[str, UnifiedSOSResult]:
        """Get all results."""
        return dict(self._results)
    
    def get_counterexamples(self) -> List[Tuple[str, List[float]]]:
        """Get all counterexample candidates from failed attempts."""
        return list(self._counterexamples)
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get aggregate statistics."""
        total_problems = len(self._results)
        successes = sum(1 for r in self._results.values() if r.success)
        total_time = sum(r.synthesis_time_ms for r in self._results.values())
        
        strategies_used = {}
        for r in self._results.values():
            if r.strategy_used:
                name = r.strategy_used.name
                strategies_used[name] = strategies_used.get(name, 0) + 1
        
        return {
            'total_problems': total_problems,
            'successes': successes,
            'success_rate': successes / total_problems if total_problems > 0 else 0,
            'total_time_ms': total_time,
            'strategies_used': strategies_used,
            'counterexamples_collected': len(self._counterexamples),
        }
    
    def clear(self) -> None:
        """Clear all state."""
        self._results.clear()
        self._pending.clear()
        self._counterexamples.clear()


# =============================================================================
# CONVENIENCE FUNCTIONS
# =============================================================================

def try_sos_barrier(problem: BarrierSynthesisProblem,
                    code_obj=None,
                    max_degree: int = 6,
                    timeout_ms: int = 30000,
                    strategy: SOSStrategy = SOSStrategy.ADAPTIVE,
                    verbose: bool = False) -> UnifiedSOSResult:
    """
    Try SOS-based barrier synthesis.
    
    This is the main entry point for one-shot barrier synthesis.
    
    Args:
        problem: Barrier synthesis problem
        code_obj: Optional Python code object for program-aware sparsity
        max_degree: Maximum polynomial degree
        timeout_ms: Time budget
        strategy: Which strategy to use
        verbose: Print progress
    
    Returns:
        UnifiedSOSResult with barrier or failure info
    """
    config = UnifiedSOSConfig(
        strategy=strategy,
        max_degree=max_degree,
        timeout_ms=timeout_ms,
        verbose=verbose
    )
    
    synthesizer = UnifiedSOSSynthesizer(config)
    return synthesizer.synthesize(problem, code_obj)


def analyze_problem_for_sos(problem: BarrierSynthesisProblem,
                            verbose: bool = False) -> Dict[str, Any]:
    """
    Analyze a problem to determine best SOS strategy.
    
    Returns recommendations for:
    - Suggested strategy
    - Expected difficulty
    - Estimated time
    """
    sparse = SparseSOSIntegration(verbose=verbose)
    stats = sparse.analyze_sparsity(problem)
    
    # Recommend strategy
    if stats['sparse_beneficial']:
        suggested = SOSStrategy.SPARSE_FIRST
        difficulty = "medium" if stats['treewidth'] < 5 else "hard"
    elif problem.n_vars <= 5:
        suggested = SOSStrategy.HIERARCHY
        difficulty = "easy"
    else:
        suggested = SOSStrategy.ADAPTIVE
        difficulty = "hard"
    
    # Estimate time (rough heuristic)
    base_time = 100  # ms per degree
    if stats['sparse_beneficial']:
        estimated_time = base_time * stats['max_clique_size'] ** 2
    else:
        estimated_time = base_time * problem.n_vars ** 2
    
    return {
        'sparsity_stats': stats,
        'suggested_strategy': suggested,
        'difficulty': difficulty,
        'estimated_time_ms': estimated_time,
    }
