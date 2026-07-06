"""
INTEGER_OVERFLOW: Overflow at Python↔native fixed-width boundary.

Unsafe region: machine state where a Python integer is converted to a
fixed-width representation (e.g., struct.pack, array, ctypes) and the value
is outside the target type's range.

Python integers are arbitrary precision, but INTEGER_OVERFLOW occurs when:
1. Explicit conversion to fixed-width types (int8, int32, uint64, etc.)
2. FFI boundary operations (ctypes, C extensions)
3. Explicit overflow-checking operations (if modeled)

This is primarily a **boundary bug class**: the unsafe region is at call sites
to functions that perform fixed-width conversion/storage.
"""

from typing import Optional
import z3


def is_unsafe_integer_overflow(state) -> bool:
    """
    Unsafe predicate U_INTEGER_OVERFLOW(σ).
    
    Returns True if the machine state σ has:
    - integer_overflow_reached flag set to True, indicating a value outside
      the range of a fixed-width target type
    - OR exception == "OverflowError" (from explicit overflow detection)
    
    Note: The symbolic VM tracks overflow feasibility when calling functions
    that perform fixed-width conversions (e.g., struct.pack, ctypes operations).
    """
    if hasattr(state, 'integer_overflow_reached') and state.integer_overflow_reached:
        return True
    if state.exception == "OverflowError":
        return True
    return False


def extract_counterexample(state, path_trace: list[str]) -> dict:
    """
    Extract a witness trace for INTEGER_OVERFLOW bug.
    
    Returns a dictionary with:
    - bug_type: "INTEGER_OVERFLOW"
    - trace: list of executed instructions
    - final_state: description of the unsafe state
    - path_condition: the Z3 path constraint (if available)
    """
    return {
        "bug_type": "INTEGER_OVERFLOW",
        "trace": path_trace,
        "final_state": {
            "exception": state.exception,
            "integer_overflow_reached": getattr(state, 'integer_overflow_reached', False),
            "frame_count": len(state.frame_stack),
            "halted": state.halted,
            "overflow_details": getattr(state, 'overflow_details', None)
        },
        "path_condition": str(state.path_condition) if hasattr(state, 'path_condition') else None
    }
