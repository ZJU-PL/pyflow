"""
STACK_OVERFLOW: Runaway recursion leading to RecursionError.

Unsafe region: machine state where the call frame stack depth exceeds
Python's recursion limit, causing RecursionError.

Semantic definition:
- U_STACK_OVERFLOW(σ) = len(σ.frame_stack) > MAX_RECURSION_DEPTH
- Python's default is sys.getrecursionlimit() (typically 1000)
- RecursionError is raised when this limit is exceeded

This is distinct from:
- NON_TERMINATION: infinite loops that don't grow the stack
- PANIC: general unhandled exceptions (RecursionError is specific)

For verification:
- SAFE requires proving bounded recursion depth (ranking function on call depth)
- BUG is demonstrated by reaching depth > limit
"""

from typing import Optional
import sys


# Python's default recursion limit (can be changed with sys.setrecursionlimit)
DEFAULT_RECURSION_LIMIT = 1000


def is_unsafe_stack_overflow(state, recursion_limit: Optional[int] = None) -> bool:
    """
    Unsafe predicate U_STACK_OVERFLOW(σ).
    
    Returns True if the machine state σ has:
    - Frame stack depth exceeding the recursion limit
    
    Args:
        state: MachineState with frame_stack
        recursion_limit: Override for the recursion limit (default: sys.getrecursionlimit())
    
    Semantic definition:
        U_STACK_OVERFLOW(σ) ⟺ |σ.frame_stack| > limit
    
    Note: In real CPython, RecursionError is raised before exactly hitting the limit
    to leave room for cleanup. We check for exceeding the limit.
    """
    if recursion_limit is None:
        recursion_limit = sys.getrecursionlimit()
    
    # Check if frame stack depth exceeds limit
    return len(state.frame_stack) > recursion_limit


def extract_counterexample(state, path_trace: list[str], recursion_limit: Optional[int] = None) -> dict:
    """
    Extract a witness trace for STACK_OVERFLOW bug.
    
    Returns a dictionary with:
    - bug_type: "STACK_OVERFLOW"
    - trace: list of executed instructions
    - final_state: description of the unsafe state
    - recursion_depth: actual depth when overflow detected
    - recursion_limit: the limit that was exceeded
    - path_condition: the Z3 path constraint (if available)
    """
    if recursion_limit is None:
        recursion_limit = sys.getrecursionlimit()
    
    return {
        "bug_type": "STACK_OVERFLOW",
        "trace": path_trace,
        "final_state": {
            "recursion_depth": len(state.frame_stack),
            "recursion_limit": recursion_limit,
            "depth_exceeded_by": len(state.frame_stack) - recursion_limit,
            "halted": state.halted,
            "exception": getattr(state, 'exception', None)
        },
        "path_condition": str(state.path_condition) if hasattr(state, 'path_condition') else None
    }
