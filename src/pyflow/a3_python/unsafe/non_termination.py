"""
NON_TERMINATION: Non-terminating loops/recursion (infinite loops).

Unsafe region: program execution that does not terminate (infinite loop or
unbounded recursion).

This is proven via ranking functions: we show that a measure decreases on
every loop iteration/recursive call, and is bounded below. If no such
ranking function exists (or we can find a cycle with no decrease), the
program may not terminate.

Termination is represented as a barrier certificate problem:
- Ranking function R: S → ℕ (or ℝ≥0)
- Step: ∀s,s'. (s → s' ∧ inLoop(s)) ⇒ R(s') < R(s)
- BoundedBelow: ∀s. R(s) ≥ 0

If we find a trace where R does not decrease (or find a back-edge cycle
where the ranking function increases), we have NON_TERMINATION.

Detection Strategy:
1. Identify loops in CFG (back-edges)
2. Extract loop variables from bytecode
3. Synthesize ranking functions via templates
4. If ranking function found → TERMINATES (SAFE)
5. If bounded exploration finds infinite loop → NON_TERMINATION (BUG)
6. Otherwise → UNKNOWN
"""

from typing import Optional, Callable, Tuple
import z3
from ..barriers.ranking_synthesis import synthesize_ranking_for_loop, RankingSynthesisConfig
from ..semantics.symbolic_vm import SymbolicMachineState


def is_unsafe_non_termination(state) -> bool:
    """
    Unsafe predicate U_NON_TERMINATION(σ).
    
    Returns True if the machine state σ represents non-termination:
    - Loop back-edge taken with ranking function not decreasing
    - Recursion depth unbounded
    - Explicit infinite loop detection (future: cycle detection in CFG trace)
    
    For now, we detect:
    1. Excessive iteration count (> MAX_ITERATIONS threshold)
    2. Ranking function not decreasing on back-edge
    
    Note: This is undecidable in general. We use bounded checking and
    ranking function synthesis. Absence of a ranking function does NOT
    prove non-termination (we report UNKNOWN in that case).
    """
    # Strategy 1: Check if we've exceeded a reasonable iteration bound
    # This is a bounded check - not a proof, but a practical heuristic
    # for finding likely non-termination
    if hasattr(state, 'iteration_count'):
        # Configurable threshold - represents "too many iterations"
        MAX_ITERATIONS = 10000
        if state.iteration_count > MAX_ITERATIONS:
            return True
    
    # Strategy 2: Check if ranking function decreased
    # This requires tracking ranking function values across transitions
    if hasattr(state, 'ranking_function_failed'):
        if state.ranking_function_failed:
            return True
    
    # Strategy 3: Check for explicit infinite loop marker
    # (set by symbolic execution when detecting a loop with no progress)
    if hasattr(state, 'infinite_loop_detected'):
        if state.infinite_loop_detected:
            return True
    
    return False


def extract_counterexample(state, path_trace: list[str]) -> dict:
    """
    Extract a witness trace for NON_TERMINATION bug.
    
    Returns a dictionary with:
    - bug_type: "NON_TERMINATION"
    - trace: list of executed instructions
    - final_state: description of the non-terminating state
    - loop_info: information about the detected loop/recursion
    - ranking_function_trace: if available, shows R(s) values
    """
    loop_info = {}
    
    if hasattr(state, 'iteration_count'):
        loop_info['iteration_count'] = state.iteration_count
    
    if hasattr(state, 'ranking_function_trace'):
        loop_info['ranking_function_trace'] = state.ranking_function_trace
    
    if hasattr(state, 'loop_back_edge_pc'):
        loop_info['loop_back_edge'] = state.loop_back_edge_pc
    
    return {
        "bug_type": "NON_TERMINATION",
        "trace": path_trace,
        "final_state": {
            "halted": state.halted if hasattr(state, 'halted') else False,
            "frame_count": len(state.frame_stack) if hasattr(state, 'frame_stack') else 0,
        },
        "loop_info": loop_info,
        "path_condition": str(state.path_condition) if hasattr(state, 'path_condition') else None,
        "explanation": "Program execution exceeds iteration bound or ranking function fails to decrease"
    }


def check_termination_via_ranking(
    state_builder: Callable[[], SymbolicMachineState],
    loop_back_edge: Callable[[SymbolicMachineState, SymbolicMachineState], z3.ExprRef],
    variable_extractors: list[Tuple[str, Callable[[SymbolicMachineState], z3.ExprRef]]],
    config: Optional[RankingSynthesisConfig] = None
) -> Tuple[str, Optional[dict]]:
    """
    Check termination by synthesizing a ranking function.
    
    Args:
        state_builder: Creates fresh symbolic state
        loop_back_edge: Encodes s →loop s' transition
        variable_extractors: Loop variables for ranking synthesis
        config: Optional synthesis configuration
    
    Returns:
        (verdict, proof_or_counterexample) where:
        - verdict: "TERMINATES", "NON_TERMINATION", or "UNKNOWN"
        - proof_or_counterexample: dict with ranking function or counterexample
    
    Semantics:
    - TERMINATES: Found ranking function R with proof that R(s') < R(s) on loop edges
    - NON_TERMINATION: Found counterexample trace where loop doesn't progress
    - UNKNOWN: Could not synthesize ranking function (does NOT imply non-termination)
    """
    result = synthesize_ranking_for_loop(
        state_builder,
        loop_back_edge,
        variable_extractors,
        config
    )
    
    if result.success:
        # Found a ranking function → program terminates
        return "TERMINATES", {
            "verdict": "SAFE",
            "ranking_function": {
                "name": result.ranking.name,
                "description": result.ranking.description,
                "variables": result.ranking.variables,
            },
            "proof": {
                "bounded_below_holds": result.termination_proof.bounded_below_holds,
                "decreasing_holds": result.termination_proof.decreasing_holds,
                "verification_time_ms": result.termination_proof.verification_time_ms,
            },
            "templates_tried": result.templates_tried,
            "synthesis_time_ms": result.synthesis_time_ms,
        }
    else:
        # Could not find a ranking function
        # This does NOT prove non-termination (absence of evidence ≠ evidence of absence)
        return "UNKNOWN", {
            "verdict": "UNKNOWN",
            "reason": "No ranking function found within template budget",
            "templates_tried": result.templates_tried,
            "synthesis_time_ms": result.synthesis_time_ms,
            "note": "Absence of ranking function does not prove non-termination"
        }


def prove_termination(
    code_obj,
    loop_pc: int,
    max_templates: int = 50
) -> dict:
    """
    High-level API: prove termination of a loop at given PC.
    
    Args:
        code_obj: Python code object containing the loop
        loop_pc: Program counter of loop back-edge
        max_templates: Maximum ranking function templates to try
    
    Returns:
        Dictionary with verdict (TERMINATES/NON_TERMINATION/UNKNOWN) and proof/witness
    
    This is a convenience wrapper that:
    1. Extracts loop variables from bytecode
    2. Builds symbolic state
    3. Encodes loop back-edge transition
    4. Calls check_termination_via_ranking
    """
    # TODO: Implement loop variable extraction from bytecode
    # For now, return UNKNOWN
    return {
        "verdict": "UNKNOWN",
        "reason": "Loop variable extraction not yet implemented",
        "note": "Future work: extract loop counters from bytecode automatically"
    }
