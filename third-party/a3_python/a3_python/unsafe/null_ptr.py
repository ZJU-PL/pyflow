"""
NULL_PTR: None misuse / null pointer dereference.

Unsafe region: machine state where None is used in a context that requires
a non-None value, leading to AttributeError, TypeError, or similar errors.

This is a pure Python semantics bug class. None misuse includes:
- Calling methods on None (AttributeError)
- Using None in subscript operations (TypeError: 'NoneType' object is not subscriptable)
- Using None in arithmetic operations (TypeError: unsupported operand type(s))
- Using None where a callable is expected (TypeError: 'NoneType' object is not callable)

At the native boundary, this maps to null pointer dereference in C extensions.

GUARD INTEGRATION (barrier-certificate-theory.tex §10.4):
The unsafe region U_none_attr is:
  U_none_attr := { s | π == π_attr ∧ ν_recv == 0 }
where ν_recv = 1 iff receiver is not None.

If g_nonnull(recv) is established, the access is SAFE.
"""

from typing import Optional
import z3


def is_unsafe_null_ptr(state) -> bool:
    """
    Unsafe predicate U_NULL_PTR(σ).
    
    Returns True if the machine state σ has:
    - none_misuse_reached flag set to True, indicating a None value was used
      in an operation that requires a non-None object
    - OR exception in ("AttributeError", "TypeError") with evidence of None misuse
    
    GUARD CHECK: If g_nonnull is established for the receiver variable,
    the operation is considered safe even if symbolically underconstrained.
    
    Note: The symbolic VM should track None usage during operations.
    This predicate captures the semantic state where None dereference occurs.
    """
    # Check if nonnull guard is established for the receiver
    if hasattr(state, 'none_misuse_context') and state.none_misuse_context:
        receiver_var = state.none_misuse_context.get('receiver_var')
        if receiver_var and hasattr(state, 'has_nonnull_guard'):
            if state.has_nonnull_guard(receiver_var):
                # Guard established: receiver was checked for None
                return False
    
    if hasattr(state, 'none_misuse_reached') and state.none_misuse_reached:
        return True
    
    # AttributeError from None dereference
    if state.exception == "AttributeError":
        # In full implementation, would check if the target was None
        # For now, conservatively treat all AttributeErrors as potential None misuse
        return True
    
    # TypeError from None misuse (subscript, call, arithmetic on None)
    if state.exception == "TypeError":
        # Check if we have additional context showing None was involved
        if hasattr(state, 'last_operation_target'):
            # If the target of the last operation was None, it's NULL_PTR
            from ..z3model.values import SymbolicValue
            if isinstance(state.last_operation_target, SymbolicValue):
                # Would need to check if tag is NONE
                # For now, flag as potential NULL_PTR
                return True
        # Conservative: some TypeErrors may be None-related
        return False
    
    return False


def is_guarded_access(state, receiver_var: Optional[str] = None) -> bool:
    """
    Check if an access is protected by a nonnull guard.
    
    Returns True if g_nonnull(receiver_var) is established, meaning
    there's a dominating check that receiver is not None.
    """
    if not hasattr(state, 'has_nonnull_guard'):
        return False
    
    if receiver_var:
        return state.has_nonnull_guard(receiver_var)
    
    # Check context if available
    if hasattr(state, 'none_misuse_context') and state.none_misuse_context:
        var = state.none_misuse_context.get('receiver_var')
        if var:
            return state.has_nonnull_guard(var)
    
    return False


def extract_counterexample(state, path_trace: list[str]) -> dict:
    """
    Extract a witness trace for NULL_PTR bug.
    
    Returns a dictionary with:
    - bug_type: "NULL_PTR"
    - trace: list of executed instructions
    - final_state: description of the unsafe state
    - path_condition: the Z3 path constraint (if available)
    - guard_info: information about guards checked (NEW)
    """
    result = {
        "bug_type": "NULL_PTR",
        "trace": path_trace,
        "final_state": {
            "exception": state.exception,
            "none_misuse_reached": getattr(state, 'none_misuse_reached', False),
            "last_operation": getattr(state, 'last_operation', None),
            "frame_count": len(state.frame_stack),
            "halted": state.halted
        },
        "path_condition": str(state.path_condition) if hasattr(state, 'path_condition') else None
    }
    
    # Include guard information
    if hasattr(state, 'established_guards'):
        nonnull_guards = {k: v for k, v in state.established_guards.items() if k.startswith('nonnull:')}
        if nonnull_guards:
            result['guard_info'] = {
                'nonnull_guards': nonnull_guards,
                'guard_protected': is_guarded_access(state)
            }
    
    return result
