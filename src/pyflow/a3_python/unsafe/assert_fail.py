"""
ASSERT_FAIL: Uncaught AssertionError (unhandled assertion failure).

Unsafe region: machine state where an AssertionError exception is raised
and propagates out of the current call frame without being caught.

This is a pure Python semantics bug class (no native boundary).
"""

from typing import Optional
import z3


def is_unsafe_assert_fail(state) -> bool:
    """
    Unsafe predicate U_ASSERT_FAIL(σ).
    
    Returns True if the machine state σ has:
    - An uncaught AssertionError exception (state.exception == "AssertionError")
    - No catch guard established (g_catch(AssertionError) not set)
    
    Note: This is the semantic definition - an AssertionError that escapes
    all handlers is a bug (program crashes with uncaught exception).
    A caught AssertionError (with g_catch guard) is NOT unsafe.
    """
    if state.exception == "AssertionError":
        # Check if exception is caught by a handler
        # Guard system: g_catch(AssertionError) is established when jumping to handler
        if hasattr(state, 'has_catch_guard') and state.has_catch_guard("AssertionError"):
            return False  # Exception is caught, not unsafe
        return True  # Exception is uncaught, unsafe
    return False


def extract_counterexample(state, path_trace: list[str]) -> dict:
    """
    Extract a witness trace for ASSERT_FAIL bug.
    
    Returns a dictionary with:
    - bug_type: "ASSERT_FAIL"
    - trace: list of executed instructions
    - final_state: description of the unsafe state
    - path_condition: the Z3 path constraint (if available)
    """
    return {
        "bug_type": "ASSERT_FAIL",
        "trace": path_trace,
        "final_state": {
            "exception": state.exception,
            "frame_count": len(state.frame_stack),
            "halted": state.halted
        },
        "path_condition": str(state.path_condition) if hasattr(state, 'path_condition') else None
    }
