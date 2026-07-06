"""
FP_DOMAIN: Floating-point domain errors (math domain errors).

Unsafe region: machine state where a floating-point operation receives
invalid domain inputs and raises ValueError (for domain errors).

Python math domain errors include:
- sqrt(negative) → ValueError
- log(non-positive) → ValueError
- acos/asin outside [-1, 1] → ValueError
- atan2(0, 0) → ValueError (or domain error)
- Complex operations that produce invalid results

This is a pure Python semantics bug class tracking math domain violations.
"""

from typing import Optional
import z3


def is_unsafe_fp_domain(state) -> bool:
    """
    Unsafe predicate U_FP_DOMAIN(σ).
    
    Returns True if the machine state σ has:
    - fp_domain_error_reached flag set to True, indicating a math domain
      error on the current symbolic path
    - OR exception == "ValueError" with domain-error context (from math module)
    
    Also checks catch guard: if ValueError is caught, no bug reported.
    
    Note: The symbolic VM tracks math domain feasibility during function calls
    to math.sqrt, math.log, etc. This predicate captures that semantic state.
    """
    # Check if catch guard for ValueError is established
    if hasattr(state, 'has_catch_guard') and state.has_catch_guard("ValueError"):
        return False

    if hasattr(state, 'fp_domain_error_reached') and state.fp_domain_error_reached:
        return True
    
    # Check if we have a ValueError that came from math domain violation
    if state.exception == "ValueError":
        # If we have domain error context, it's unsafe
        if hasattr(state, 'domain_error_context') and state.domain_error_context:
            return True
    
    return False


def extract_counterexample(state, path_trace: list[str]) -> dict:
    """
    Extract a witness trace for FP_DOMAIN bug.
    
    Returns a dictionary with:
    - bug_type: "FP_DOMAIN"
    - trace: list of executed instructions
    - final_state: description of the unsafe state
    - path_condition: the Z3 path constraint (if available)
    - domain_context: what math operation failed (if available)
    """
    return {
        "bug_type": "FP_DOMAIN",
        "trace": path_trace,
        "final_state": {
            "exception": state.exception,
            "fp_domain_error_reached": getattr(state, 'fp_domain_error_reached', False),
            "domain_error_context": getattr(state, 'domain_error_context', None),
            "frame_count": len(state.frame_stack),
            "halted": state.halted
        },
        "path_condition": str(state.path_condition) if hasattr(state, 'path_condition') else None
    }
