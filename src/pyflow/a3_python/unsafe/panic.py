"""
PANIC: General unhandled exception (program crashes due to uncaught exception).

Unsafe region: machine state where any exception is raised and propagates out
of the current call frame without being caught.

This is distinct from specific exception types like ASSERT_FAIL or DIV_ZERO:
- PANIC is a "no-crash" contract violation: the program should not terminate 
  with any uncaught exception.
- Other bug types focus on specific semantic errors (assert, division, bounds, etc.)

For a rigorous verifier, PANIC is the catch-all for exception-based crashes
that aren't captured by more specific bug classes.

Note: This overlaps with specific exception types but captures the general
"unhandled exception = program crash" property. In practice, you may want to
report both (e.g., "DIV_ZERO detected, which also violates PANIC property").
"""

from typing import Optional
import z3


# Specific exception types covered by other bug classes
SPECIFIC_BUG_EXCEPTIONS = {
    "AssertionError",      # ASSERT_FAIL
    "ZeroDivisionError",   # DIV_ZERO
    "IndexError",          # BOUNDS
    "KeyError",            # BOUNDS
    "AttributeError",      # NULL_PTR (for None.attr)
    "TypeError",           # TYPE_CONFUSION (when semantically uncaught)
}


def is_unsafe_panic(state) -> bool:
    """
    Unsafe predicate U_PANIC(σ).
    
    Returns True if the machine state σ has:
    - An uncaught exception (state.exception is not None)
    - No catch guard established for this exception type
    
    Semantic definition: Any exception that escapes all handlers is a PANIC.
    
    This predicate checks:
    - If `state.exception` is set AND there's no g_catch(exception_type) guard,
      then the exception is unhandled and the program crashes.
    - Exception-handler execution is modeled inside `SymbolicVM` (via the exception table
      and handler opcodes). When jumping to a handler, g_catch(exception_type) is established.
    - Caught exceptions (with g_catch guard) are NOT unsafe.
    """
    exc = getattr(state, "exception", None)
    if exc is None:
        return False
    # Internal sentinel used for pruning; not a program crash.
    if exc == "InfeasiblePath":
        return False
    # Internal VM errors — not real Python exceptions
    if exc in ("StackUnderflow", "StackOverflow_internal"):
        return False
    
    # Check if exception is caught by a handler
    # Guard system: g_catch(exception_type) is established when jumping to handler
    if hasattr(state, 'has_catch_guard') and state.has_catch_guard(exc):
        return False  # Exception is caught, not unsafe
    
    return True  # Exception is uncaught, unsafe


def is_unsafe_panic_non_specific(state) -> bool:
    """
    Helper: Check for PANIC that isn't covered by specific bug classes.
    
    This is useful for testing PANIC independently of other bug types.
    Returns True only for exceptions not in SPECIFIC_BUG_EXCEPTIONS.
    """
    if state.exception is not None:
        # Only mark as PANIC if not a specific bug class exception
        if state.exception not in SPECIFIC_BUG_EXCEPTIONS:
            return True
    return False


def extract_counterexample(state, path_trace: list[str]) -> dict:
    """
    Extract a witness trace for PANIC bug.
    
    Returns a dictionary with:
    - bug_type: "PANIC"
    - trace: list of executed instructions
    - final_state: description of the unsafe state
    - path_condition: the Z3 path constraint (if available)
    """
    return {
        "bug_type": "PANIC",
        "trace": path_trace,
        "final_state": {
            "exception": state.exception,
            "exception_is_specific": state.exception in SPECIFIC_BUG_EXCEPTIONS,
            "frame_count": len(state.frame_stack),
            "halted": state.halted
        },
        "path_condition": str(state.path_condition) if hasattr(state, 'path_condition') else None
    }
