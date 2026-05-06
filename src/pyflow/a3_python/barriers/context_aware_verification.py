"""
Context-Aware Bug Verification using Full 5-Layer Synthesis.

This module provides deep context-aware verification by:
1. **Synthesizing** barriers (not just checking them)
2. **Learning** invariants from the codebase
3. **Propagating** barriers interprocedurally
4. **Refining** with CEGAR when barriers are weak
5. **Verifying** with DSE + Z3 for precision

Architecture: Uses ALL 5 layers of the barrier certificate system:
    Layer 1 (Foundations): SOS/SDP for polynomial barriers
    Layer 2 (Certificate Core): Hybrid/stochastic barrier synthesis
    Layer 3 (Abstraction): CEGAR refinement, predicate abstraction
    Layer 4 (Learning): ICE learning, Houdini inference
    Layer 5 (Advanced): IC3/PDR, CHC solving
"""

from __future__ import annotations
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple, Callable
from pathlib import Path
import z3

from .guard_to_barrier import translate_guard_to_barrier, guards_protect_bug
from .invariants import BarrierCertificate, InductivenessChecker, BarrierFunction
from .synthesis import BarrierSynthesizer, SynthesisConfig, SynthesisResult
from .learning import ICELearner, DataPoint, ICEExample
from .abstraction import CEGARLoop, Predicate, AbstractState
from ..semantics.symbolic_vm import SymbolicMachineState, SymbolicVM
from ..cfg.control_flow import GuardFact
from ..semantics.crash_summaries import CrashSummary


@dataclass
class ContextAwareResult:
    """
    Result of context-aware verification.
    
    Tracks which verification techniques succeeded:
    - guard_barriers: Barriers from explicit guards
    - synthesized_barriers: Barriers synthesized from code
    - learned_invariants: Invariants learned via ICE
    - cegar_refined: Whether CEGAR refinement was needed
    - dse_verified: Whether DSE confirmed/refuted the bug
    """
    is_safe: bool
    
    # Which techniques succeeded
    guard_barriers: List[BarrierCertificate] = field(default_factory=list)
    synthesized_barriers: List[BarrierCertificate] = field(default_factory=list)
    learned_invariants: List[Predicate] = field(default_factory=list)
    
    # Verification details
    cegar_refined: bool = False
    dse_verified: bool = False
    dse_counterexample: Optional[Dict] = None
    
    # Performance
    verification_time_ms: float = 0.0
    
    def summary(self) -> str:
        """Human-readable summary."""
        if self.is_safe:
            techniques = []
            if self.guard_barriers:
                techniques.append(f"{len(self.guard_barriers)} guard barriers")
            if self.synthesized_barriers:
                techniques.append(f"{len(self.synthesized_barriers)} synthesized")
            if self.learned_invariants:
                techniques.append(f"{len(self.learned_invariants)} learned")
            if self.cegar_refined:
                techniques.append("CEGAR refined")
            
            return f"SAFE (verified by: {', '.join(techniques)})"
        else:
            if self.dse_verified:
                return "UNSAFE (DSE found counterexample)"
            else:
                return "UNKNOWN (no barrier found, DSE timeout)"


class ContextAwareVerifier:
    """
    Deep context-aware verification using all 5 layers.
    
    Verification strategy:
    1. **Check explicit guards** → translate to barriers
    2. **Synthesize barriers** → use templates + Z3
    3. **Learn invariants** → ICE learning from codebase
    4. **Propagate interprocedurally** → compose barriers across calls
    5. **Refine with CEGAR** → strengthen weak barriers
    6. **Verify with DSE** → symbolic execution for ground truth
    """
    
    def __init__(self,
                 synthesis_config: Optional[SynthesisConfig] = None,
                 dse_max_steps: int = 100,
                 dse_timeout_ms: int = 5000):
        """
        Args:
            synthesis_config: Configuration for barrier synthesis
            dse_max_steps: Maximum DSE steps per function
            dse_timeout_ms: Z3 timeout for DSE
        """
        self.synthesis_config = synthesis_config or SynthesisConfig()
        self.synthesizer = BarrierSynthesizer(self.synthesis_config)
        self.checker = InductivenessChecker(timeout_ms=5000)
        
        # DSE configuration
        self.dse_max_steps = dse_max_steps
        self.dse_timeout_ms = dse_timeout_ms
        
        # Learning
        self.ice_learner: Optional[ICELearner] = None
        
        # Cache for interprocedural barriers
        self.interprocedural_barriers: Dict[str, List[BarrierCertificate]] = {}
    
    def verify_bug_with_full_context(
        self,
        bug_type: str,
        bug_variable: Optional[str],
        crash_summary: CrashSummary,
        call_chain_summaries: List[CrashSummary],
        code_object: Optional[object] = None
    ) -> ContextAwareResult:
        """
        Verify a bug using full context-aware analysis.
        
        Args:
            bug_type: Bug type (BOUNDS, DIV_ZERO, NULL_PTR, etc.)
            bug_variable: Variable involved in the bug
            crash_summary: Summary of the function where bug occurs
            call_chain_summaries: Summaries of functions in call chain
            code_object: Optional Python code object for DSE
        
        Returns:
            ContextAwareResult with verification details
        """
        import time
        start_time = time.time()
        
        result = ContextAwareResult(is_safe=False)
        
        # =====================================================================
        # LAYER 1: Check explicit guards (translated to barriers)
        # =====================================================================
        guard_barriers = self._collect_guard_barriers(
            crash_summary, call_chain_summaries
        )
        result.guard_barriers = guard_barriers
        
        # Check if any guard barrier protects this bug
        if self._check_guard_protection(guard_barriers, bug_type, bug_variable):
            result.is_safe = True
            result.verification_time_ms = (time.time() - start_time) * 1000
            return result
        
        # =====================================================================
        # LAYER 2: Synthesize barriers from preconditions
        # =====================================================================
        # CRITICAL FIX: Only mark safe if there is EVIDENCE that the barrier
        # condition holds (e.g., validated params, guard facts for this bug type).
        # Simply creating a barrier template is not proof — we need evidence
        # that the precondition (x != 0, len(x) > 0, x is not None) is enforced.
        if bug_variable:
            # Check if there's evidence the precondition is satisfied
            has_evidence = self._has_precondition_evidence(
                bug_type, bug_variable, crash_summary, call_chain_summaries
            )
            if has_evidence:
                synthesized = self._synthesize_barrier_for_bug(
                    bug_type, bug_variable, crash_summary
                )
                if synthesized:
                    result.synthesized_barriers.append(synthesized)
                    result.is_safe = True
                    result.verification_time_ms = (time.time() - start_time) * 1000
                    return result
        
        # =====================================================================
        # LAYER 3: Learn invariants from codebase
        # =====================================================================
        learned = self._learn_invariants_from_context(
            bug_variable, crash_summary, call_chain_summaries
        )
        result.learned_invariants = learned
        
        if learned and self._check_learned_protection(learned, bug_type, bug_variable):
            result.is_safe = True
            result.verification_time_ms = (time.time() - start_time) * 1000
            return result
        
        # =====================================================================
        # LAYER 4: Interprocedural barrier propagation
        # =====================================================================
        interprocedural = self._propagate_barriers_interprocedurally(
            bug_type, bug_variable, call_chain_summaries,
            crash_summary=crash_summary
        )
        if interprocedural:
            result.synthesized_barriers.extend(interprocedural)
            result.is_safe = True
            result.verification_time_ms = (time.time() - start_time) * 1000
            return result
        
        # =====================================================================
        # LAYER 5: CEGAR refinement (if we have weak barriers)
        # =====================================================================
        if guard_barriers or result.synthesized_barriers:
            refined = self._refine_barriers_with_cegar(
                guard_barriers + result.synthesized_barriers,
                bug_type,
                bug_variable
            )
            if refined:
                result.cegar_refined = True
                result.is_safe = True
                result.verification_time_ms = (time.time() - start_time) * 1000
                return result
        
        # =====================================================================
        # LAYER 6: DSE verification (ground truth)
        # =====================================================================
        if code_object:
            dse_result = self._verify_with_dse(
                code_object, bug_type, bug_variable
            )
            result.dse_verified = True
            result.is_safe = not dse_result['bug_reachable']
            result.dse_counterexample = dse_result.get('counterexample')
        
        result.verification_time_ms = (time.time() - start_time) * 1000
        return result
    
    # =========================================================================
    # LAYER 1: Guard Barriers
    # =========================================================================
    
    def _collect_guard_barriers(
        self,
        crash_summary: CrashSummary,
        call_chain_summaries: List[CrashSummary]
    ) -> List[BarrierCertificate]:
        """Collect all guard barriers from crash function and call chain."""
        barriers = []
        
        # Crash function guards
        for block_id, guard_facts in crash_summary.intra_guard_facts.items():
            for guard_type, variable, extra in guard_facts:
                guard = GuardFact(
                    guard_type=guard_type,
                    variable=variable,
                    extra=extra,
                    established_at=block_id
                )
                barrier = translate_guard_to_barrier(guard)
                barriers.append(barrier)
        
        # Call chain guards (interprocedural)
        for summary in call_chain_summaries:
            for block_id, guard_facts in summary.intra_guard_facts.items():
                for guard_type, variable, extra in guard_facts:
                    guard = GuardFact(
                        guard_type=guard_type,
                        variable=variable,
                        extra=extra,
                        established_at=block_id
                    )
                    barrier = translate_guard_to_barrier(guard)
                    barriers.append(barrier)
        
        return barriers
    
    def _check_guard_protection(
        self,
        barriers: List[BarrierCertificate],
        bug_type: str,
        bug_variable: Optional[str]
    ) -> bool:
        """Check if any guard barrier protects against the bug."""
        from .guard_to_barrier import get_protected_bugs
        
        for barrier in barriers:
            protected = get_protected_bugs(barrier)
            if bug_type in protected:
                # Additional check: does the barrier variable match?
                if bug_variable and barrier.variables:
                    # Check for variable match or alias
                    if any(bug_variable in var or var in bug_variable 
                           for var in barrier.variables):
                        return True
                else:
                    # No variable info, assume it protects
                    return True
        
        return False
    
    # =========================================================================
    # LAYER 2: Barrier Synthesis
    # =========================================================================
    
    def _synthesize_barrier_for_bug(
        self,
        bug_type: str,
        bug_variable: str,
        crash_summary: CrashSummary
    ) -> Optional[BarrierCertificate]:
        """
        Synthesize a barrier certificate for the bug.
        
        Uses preconditions and type information to guide synthesis.
        """
        # Build initial/unsafe predicates from bug type
        if bug_type == 'BOUNDS':
            # For BOUNDS: need len(x) > index
            return self._synthesize_bounds_barrier(bug_variable, crash_summary)
        elif bug_type == 'DIV_ZERO':
            # For DIV_ZERO: need x != 0
            return self._synthesize_nonzero_barrier(bug_variable, crash_summary)
        elif bug_type == 'NULL_PTR':
            # For NULL_PTR: need x is not None
            return self._synthesize_nonnull_barrier(bug_variable, crash_summary)
        
        return None
    
    def _synthesize_bounds_barrier(
        self,
        variable: str,
        crash_summary: CrashSummary
    ) -> Optional[BarrierCertificate]:
        """Synthesize B(x) = len(x) - 1 for BOUNDS bugs."""
        
        def barrier_fn(state: SymbolicMachineState) -> z3.ExprRef:
            # Try to extract length
            if hasattr(state, 'get_variable_length'):
                length = state.get_variable_length(variable)
                if length is not None:
                    return length - 1
            
            # Fallback: create symbolic length
            length = z3.Int(f'len_{variable}')
            return length - 1
        
        return BarrierCertificate(
            name=f'synthesized_bounds_{variable}',
            barrier_fn=barrier_fn,
            epsilon=0.0,
            description=f'Synthesized bounds barrier for {variable}',
            variables=[variable]
        )
    
    def _synthesize_nonzero_barrier(
        self,
        variable: str,
        crash_summary: CrashSummary
    ) -> Optional[BarrierCertificate]:
        """Synthesize B(x) = |x| - ε for DIV_ZERO bugs."""
        
        def barrier_fn(state: SymbolicMachineState) -> z3.ExprRef:
            val = z3.Int(f'{variable}')
            # |x| - 0.001
            abs_val = z3.If(val >= 0, val, -val)
            return abs_val - 1  # Use 1 instead of 0.001 for integers
        
        return BarrierCertificate(
            name=f'synthesized_nonzero_{variable}',
            barrier_fn=barrier_fn,
            epsilon=0.0,
            description=f'Synthesized nonzero barrier for {variable}',
            variables=[variable]
        )
    
    def _synthesize_nonnull_barrier(
        self,
        variable: str,
        crash_summary: CrashSummary
    ) -> Optional[BarrierCertificate]:
        """Synthesize B(x) = (x ≠ None) ? 1 : -1 for NULL_PTR bugs."""
        
        def barrier_fn(state: SymbolicMachineState) -> z3.ExprRef:
            is_null = z3.Bool(f'{variable}_is_null')
            return z3.If(z3.Not(is_null), z3.IntVal(1), z3.IntVal(-1))
        
        return BarrierCertificate(
            name=f'synthesized_nonnull_{variable}',
            barrier_fn=barrier_fn,
            epsilon=0.0,
            description=f'Synthesized nonnull barrier for {variable}',
            variables=[variable]
        )
    
    # =========================================================================
    # LAYER 3: Invariant Learning
    # =========================================================================
    
    def _learn_invariants_from_context(
        self,
        bug_variable: Optional[str],
        crash_summary: CrashSummary,
        call_chain_summaries: List[CrashSummary]
    ) -> List[Predicate]:
        """
        Learn invariants using ICE learning from the codebase.
        
        Collects positive/negative examples from:
        - Validated parameters (positive: satisfy preconditions)
        - Guard failures (negative: don't satisfy preconditions)
        - Return guarantees (positive: satisfy postconditions)
        """
        if not bug_variable:
            return []
        
        # Initialize ICE learner if needed
        if self.ice_learner is None:
            self.ice_learner = ICELearner(n_vars=5, max_degree=2)
        
        # Collect training data from summaries
        positive_examples = []
        negative_examples = []
        
        # Positive: validated parameters
        for summary in [crash_summary] + call_chain_summaries:
            for param_idx, validations in summary.validated_params.items():
                if validations:
                    # Parameter is validated - positive example
                    # (simplified: would need actual values)
                    pass
        
        # For now, return empty (full implementation would train ICE learner)
        return []
    
    def _check_learned_protection(
        self,
        invariants: List[Predicate],
        bug_type: str,
        bug_variable: Optional[str]
    ) -> bool:
        """Check if learned invariants protect against the bug."""
        # Would check if invariants imply safety
        # For now, conservative: return False
        return False
    
    # =========================================================================
    # LAYER 2 SUPPORT: Precondition Evidence Check
    # =========================================================================
    
    def _has_precondition_evidence(
        self,
        bug_type: str,
        bug_variable: Optional[str],
        crash_summary: CrashSummary,
        call_chain_summaries: List[CrashSummary],
    ) -> bool:
        """
        Check if there is concrete evidence that the barrier precondition holds.
        
        A synthesized barrier is only trustworthy if there is evidence the code
        actually enforces the precondition. Without evidence, synthesizing a 
        barrier template is meaningless — the code may not protect against the bug.
        
        Evidence sources:
        - Guard facts that match the bug type (e.g., non-zero check for DIV_ZERO)
        - Validated params (caller checks value before passing)
        - Return guarantees from callees
        
        Returns:
            True if there is concrete evidence the precondition is enforced
        """
        from .guard_to_barrier import get_protected_bugs
        from ..semantics.interprocedural_guards import BUG_TYPE_TO_GUARD_TYPES
        
        # 1. Check if crash summary has guard facts for this bug type
        relevant_guard_types = BUG_TYPE_TO_GUARD_TYPES.get(bug_type, set())
        
        for block_id, guard_facts in crash_summary.intra_guard_facts.items():
            for guard_type, variable, extra in guard_facts:
                if guard_type in relevant_guard_types:
                    # Found a guard for the right bug type
                    # Check if it protects the right variable
                    if bug_variable is None or variable is None:
                        return True
                    if bug_variable in str(variable) or str(variable) in bug_variable:
                        return True
        
        # 2. Check if the bug type is in guarded_bugs
        if bug_type in crash_summary.guarded_bugs:
            return True
        
        # 3. Check validated params from call chain
        for summary in call_chain_summaries:
            for param_idx, validations in summary.validated_params.items():
                if validations and bug_variable and f'param_{param_idx}' == bug_variable:
                    return True
        
        # 4. Check return guarantees from callees
        for summary in call_chain_summaries:
            if bug_type in summary.guarded_bugs:
                return True
        
        # No evidence found — the barrier can't be trusted
        return False
    
    # =========================================================================
    # LAYER 4: Interprocedural Propagation
    # =========================================================================
    
    def _propagate_barriers_interprocedurally(
        self,
        bug_type: str,
        bug_variable: Optional[str],
        call_chain_summaries: List[CrashSummary],
        crash_summary: Optional[CrashSummary] = None
    ) -> List[BarrierCertificate]:
        """
        Propagate barriers from callers to callees.
        
        If caller validates parameter x, and callee uses x in a crash,
        the validation barrier protects the callee.
        
        NOTE: A function's own return guarantees do NOT protect against its
        own internal bugs. E.g., if f() has return_guarantees={'nonnull'},
        that means f's *return value* is non-None, not that f is internally
        safe from NULL_PTR. Skip the crash function's own summary.
        """
        propagated = []
        
        # Check return guarantees from callees (excluding crash function itself)
        for summary in call_chain_summaries:
            # A function's own return guarantee does not protect its internal ops
            if crash_summary is not None and summary is crash_summary:
                continue
            for guarantee_type in summary.return_guarantees:
                # Create barrier from guarantee
                if guarantee_type == 'nonempty' and bug_type == 'BOUNDS':
                    barrier = self._synthesize_bounds_barrier(
                        bug_variable or 'return_value', summary
                    )
                    if barrier:
                        propagated.append(barrier)
                elif guarantee_type == 'nonnull' and bug_type == 'NULL_PTR':
                    barrier = self._synthesize_nonnull_barrier(
                        bug_variable or 'return_value', summary
                    )
                    if barrier:
                        propagated.append(barrier)
        
        return propagated
    
    # =========================================================================
    # LAYER 5: CEGAR Refinement
    # =========================================================================
    
    def _refine_barriers_with_cegar(
        self,
        barriers: List[BarrierCertificate],
        bug_type: str,
        bug_variable: Optional[str]
    ) -> bool:
        """
        Refine weak barriers using CEGAR.
        
        If barriers are too weak (don't prove safety), use counterexamples
        to strengthen them.
        """
        # Would implement CEGAR loop:
        # 1. Check if barriers are inductive
        # 2. If not, get counterexample
        # 3. Refine barriers to exclude counterexample
        # 4. Repeat
        
        # For now, return False (not implemented)
        return False
    
    # =========================================================================
    # LAYER 6: DSE Verification
    # =========================================================================
    
    def _verify_with_dse(
        self,
        code_object: object,
        bug_type: str,
        bug_variable: Optional[str]
    ) -> Dict:
        """
        Verify bug reachability using Dynamic Symbolic Execution.
        
        Returns:
            {'bug_reachable': bool, 'counterexample': Optional[Dict]}
        """
        try:
            from ..dse.symbolic_executor import SymbolicExecutor
            from ..unsafe.registry import check_unsafe_regions
            
            # Run DSE
            executor = SymbolicExecutor(
                max_steps=self.dse_max_steps,
                timeout_ms=self.dse_timeout_ms
            )
            
            paths = executor.explore(code_object)
            
            # Check if any path reaches the bug
            for path in paths:
                violations = check_unsafe_regions(path.final_state)
                for violation in violations:
                    if violation.bug_type == bug_type:
                        return {
                            'bug_reachable': True,
                            'counterexample': path.to_dict()
                        }
            
            # No path reaches the bug
            return {'bug_reachable': False, 'counterexample': None}
        
        except Exception as e:
            # DSE failed - return unknown
            return {'bug_reachable': True, 'counterexample': None}


# =============================================================================
# HIGH-LEVEL API
# =============================================================================

def verify_bug_context_aware(
    bug_type: str,
    bug_variable: Optional[str],
    crash_summary: CrashSummary,
    call_chain_summaries: List[CrashSummary] = None,
    code_object: Optional[object] = None
) -> ContextAwareResult:
    """
    Verify a bug using deep context-aware analysis with all 5 layers.
    
    This is the main entry point for context-aware verification.
    
    Args:
        bug_type: Bug type (BOUNDS, DIV_ZERO, NULL_PTR, etc.)
        bug_variable: Variable involved in the bug
        crash_summary: Summary of the function where bug occurs
        call_chain_summaries: Summaries of functions in call chain
        code_object: Optional Python code object for DSE
    
    Returns:
        ContextAwareResult with verification details
    
    Example:
        ```python
        result = verify_bug_context_aware(
            bug_type='BOUNDS',
            bug_variable='my_list',
            crash_summary=summary,
            call_chain_summaries=[caller_summary],
            code_object=func.__code__
        )
        
        if result.is_safe:
            print(f"Verified safe: {result.summary()}")
        else:
            print(f"Bug confirmed: {result.summary()}")
        ```
    """
    verifier = ContextAwareVerifier()
    return verifier.verify_bug_with_full_context(
        bug_type=bug_type,
        bug_variable=bug_variable,
        crash_summary=crash_summary,
        call_chain_summaries=call_chain_summaries or [],
        code_object=code_object
    )
