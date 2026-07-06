"""
CODE_INJECTION (CWE-094): Tainted data in eval/exec.

Unsafe region U_code := { s | π == π_eval ∧ τ(code_string) == 1 }

Note: There is rarely a valid sanitizer for code injection - critical severity.

Sources: User input, HTTP parameters, file content
Sinks: eval(), exec(), compile(), __import__()
"""

from a3_python.z3model.taint import SinkType


def is_unsafe_code_injection(state) -> bool:
    """
    Unsafe predicate U_CODE_INJECTION(σ).
    
    Returns True if:
    - At code evaluation sink (eval, exec, compile)
    - Code argument has untrusted taint τ=1
    
    Note: This is almost always a critical bug - there's no safe way
    to sanitize arbitrary code for execution.
    """
    if hasattr(state, 'security_violations'):
        for violation in state.security_violations:
            if violation.sink_type == SinkType.CODE_EVAL:
                return True
    
    if hasattr(state, 'code_injection_detected') and state.code_injection_detected:
        return True
    
    return False


def extract_counterexample(state, path_trace: list) -> dict:
    """Extract counterexample for code injection."""
    result = {
        "bug_type": "CODE_INJECTION",
        "cwe": "CWE-094",
        "severity": "critical",
        "location": "unknown",
        "taint_sources": [],
        "code_snippet": None,
        "message": "Critical: untrusted data passed to eval/exec",
        "barrier_info": {
            "unsafe_region": "U_code := { s | at_eval_sink ∧ τ(code)=1 }",
            "barrier_template": "B = δ_eval · ((1-τ) - ½)",
            "required_guard": "Never pass untrusted input to eval/exec"
        }
    }
    
    if hasattr(state, 'security_violations'):
        for v in state.security_violations:
            if v.sink_type == SinkType.CODE_EVAL:
                result["location"] = v.sink_location
                result["taint_sources"] = [
                    {"source": l.source_type.name, "location": l.source_location}
                    for l in v.taint_sources
                ]
                result["message"] = v.message
                break
    
    if path_trace:
        result["path_trace_suffix"] = path_trace[-10:]
    
    return result
