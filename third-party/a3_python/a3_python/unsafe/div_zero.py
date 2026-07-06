"""
DIV_ZERO: Division by zero (ZeroDivisionError).

Unsafe region: machine state where a division/modulo operation with zero
divisor is executed, raising ZeroDivisionError.

This is a pure Python semantics bug class. Division by zero includes:
- True division (/)
- Floor division (//)
- Modulo (%)

GUARD INTEGRATION (barrier-certificate-theory.tex §10.5):
The unsafe region U_div0 is:
  U_div0 := { s | π == π_div ∧ d == 0 ∧ (g_div(d) == 0) }

If g_div(d) is established (divisor proven non-zero by earlier check),
then the division is SAFE even if symbolic execution can't prove d != 0.
"""

from typing import Optional
import z3


def is_unsafe_div_zero(state) -> bool:
    """
    Unsafe predicate U_DIV_ZERO(σ).
    
    Returns True if the machine state σ has:
    - div_by_zero_reached flag set to True, indicating a division by zero
      on the current symbolic path
    - OR exception == "ZeroDivisionError" (uncaught)
    
    GUARD CHECK: If g_div is established for the divisor variable, the
    division is considered safe even if symbolically unconstrained.
    Also checks catch guard: if ZeroDivisionError is caught by handler,
    no bug reported.
    
    Note: The symbolic VM already tracks division-by-zero feasibility
    during BINARY_OP execution. This predicate captures that semantic state.
    """
    # Check if catch guard for ZeroDivisionError is established
    # (exception is caught by try/except)
    if hasattr(state, 'has_catch_guard') and state.has_catch_guard("ZeroDivisionError"):
        return False
    
    # Check if div guard is established
    if hasattr(state, 'div_by_zero_context') and state.div_by_zero_context:
        divisor_var = state.div_by_zero_context.get('divisor_var')
        if divisor_var and hasattr(state, 'has_div_guard'):
            if state.has_div_guard(divisor_var):
                # Guard established: divisor was checked != 0 earlier
                return False
    
    if hasattr(state, 'div_by_zero_reached') and state.div_by_zero_reached:
        return True
    if state.exception == "ZeroDivisionError":
        return True
    return False


def is_guarded_div(state, divisor_var: Optional[str] = None) -> bool:
    """
    Check if division is protected by a guard.
    
    Returns True if g_div(divisor_var) is established, meaning
    there's a dominating check that the divisor != 0.
    """
    if not hasattr(state, 'has_div_guard'):
        return False
    
    if divisor_var:
        return state.has_div_guard(divisor_var)
    
    # Check context if available
    if hasattr(state, 'div_by_zero_context') and state.div_by_zero_context:
        var = state.div_by_zero_context.get('divisor_var')
        if var:
            return state.has_div_guard(var)
    
    return False


def extract_counterexample(state, path_trace: list[str]) -> dict:
    """
    Extract a witness trace for DIV_ZERO bug.
    
    Returns a dictionary with:
    - bug_type: "DIV_ZERO"
    - trace: list of executed instructions
    - final_state: description of the unsafe state
    - path_condition: the Z3 path constraint (if available)
    - context: semantic information about the division operation (NEW)
    - guard_info: information about guards checked (NEW)
    """
    counterexample = {
        "bug_type": "DIV_ZERO",
        "trace": path_trace,
        "final_state": {
            "exception": state.exception,
            "div_by_zero_reached": getattr(state, 'div_by_zero_reached', False),
            "frame_count": len(state.frame_stack),
            "halted": state.halted
        },
        "path_condition": str(state.path_condition) if hasattr(state, 'path_condition') else None
    }
    
    # Include precise context if available (operation, location, operands)
    if hasattr(state, 'div_by_zero_context') and state.div_by_zero_context:
        counterexample['context'] = state.div_by_zero_context
    
    # Include guard information for debugging
    if hasattr(state, 'established_guards'):
        div_guards = {k: v for k, v in state.established_guards.items() if k.startswith('div:')}
        if div_guards:
            counterexample['guard_info'] = {
                'div_guards': div_guards,
                'guard_protected': is_guarded_div(state)
            }
    
    return counterexample
