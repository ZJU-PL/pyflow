"""
BOUNDS: Index out of bounds / key error (IndexError/KeyError).

Unsafe region: machine state where a subscript operation accesses an invalid
index/key, raising IndexError (for sequences) or KeyError (for dicts).

This is a pure Python semantics bug class. Bounds violations include:
- List/tuple indexing with out-of-bounds index
- Dictionary access with missing key
- String indexing with out-of-bounds index

GUARD INTEGRATION (barrier-certificate-theory.tex §10.7):
The unsafe region U_oob is:
  U_oob := { s | π == π_subscr ∧ (i < 0 ∨ i ≥ len(seq)) ∧ g_bounds(seq,i)==0 }

If g_bounds(seq, i) is established, the access is SAFE.
Bounds guards are established by patterns like:
- if i < len(seq): ...
- if 0 <= i < len(seq): ...
- for i in range(len(seq)): ...
"""

from typing import Optional
import z3


def is_unsafe_bounds(state) -> bool:
    """
    Unsafe predicate U_BOUNDS(σ).
    
    Returns True if the machine state σ has:
    - index_out_of_bounds flag set to True, indicating an out-of-bounds access
      on the current symbolic path
    - OR exception == "IndexError" (uncaught)
    - OR exception == "KeyError" (uncaught)
    
    GUARD CHECK: If g_bounds is established for the (container, index) pair,
    the access is considered safe. Also checks catch guard for handler coverage.
    
    Note: The symbolic VM tracks bounds violations during BINARY_OP (subscript)
    execution. This predicate captures that semantic state.
    """
    # Check for catch guard: if IndexError/KeyError is caught by handler, not unsafe
    if hasattr(state, 'has_catch_guard'):
        if state.has_catch_guard("IndexError") or state.has_catch_guard("KeyError"):
            return False
    
    # Check if bounds guard is established
    if hasattr(state, 'bounds_context') and state.bounds_context:
        container = state.bounds_context.get('container_var')
        index = state.bounds_context.get('index_var')
        if container and index and hasattr(state, 'has_bounds_guard'):
            if state.has_bounds_guard(container, index):
                # Guard established: index proven in-bounds
                return False
    
    if hasattr(state, 'index_out_of_bounds') and state.index_out_of_bounds:
        return True
    if state.exception in ("IndexError", "KeyError"):
        return True
    return False


def is_guarded_access(state, container_var: Optional[str] = None, index_var: Optional[str] = None) -> bool:
    """
    Check if a subscript access is protected by a bounds guard.
    
    Returns True if g_bounds(container, index) is established.
    """
    if not hasattr(state, 'has_bounds_guard'):
        return False
    
    if container_var and index_var:
        return state.has_bounds_guard(container_var, index_var)
    
    # Check context if available
    if hasattr(state, 'bounds_context') and state.bounds_context:
        container = state.bounds_context.get('container_var')
        index = state.bounds_context.get('index_var')
        if container and index:
            return state.has_bounds_guard(container, index)
    
    return False


def extract_counterexample(state, path_trace: list[str]) -> dict:
    """
    Extract a witness trace for BOUNDS bug.
    
    Returns a dictionary with:
    - bug_type: "BOUNDS"
    - trace: list of executed instructions
    - final_state: description of the unsafe state
    - path_condition: the Z3 path constraint (if available)
    - guard_info: information about bounds guards (NEW)
    """
    result = {
        "bug_type": "BOUNDS",
        "trace": path_trace,
        "final_state": {
            "exception": state.exception,
            "index_out_of_bounds": getattr(state, 'index_out_of_bounds', False),
            "frame_count": len(state.frame_stack),
            "halted": state.halted
        },
        "path_condition": str(state.path_condition) if hasattr(state, 'path_condition') else None
    }
    
    # Include bounds context if available
    if hasattr(state, 'bounds_context') and state.bounds_context:
        result['context'] = state.bounds_context
    
    # Include guard information
    if hasattr(state, 'established_guards'):
        bounds_guards = {k: v for k, v in state.established_guards.items() if k.startswith('bounds:')}
        if bounds_guards:
            result['guard_info'] = {
                'bounds_guards': bounds_guards,
                'guard_protected': is_guarded_access(state)
            }
    
    return result
