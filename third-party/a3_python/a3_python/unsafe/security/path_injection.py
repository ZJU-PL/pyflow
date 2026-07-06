"""
PATH_INJECTION / PATH_TRAVERSAL (CWE-022): Tainted data in file paths.

Unsafe region U_path := { s | π == π_file_op ∧ τ(filepath) == 1 ∧ ¬g_path_validated }

Sources: User input, HTTP parameters, URL paths
Sinks: open(), os.remove(), shutil.copy(), send_file()
Sanitizers: os.path.basename(), realpath+startswith, secure_filename()
"""

from a3_python.z3model.taint import SinkType


def is_unsafe_path_injection(state) -> bool:
    """
    Unsafe predicate U_PATH_INJECTION(σ).
    
    Returns True if:
    - At file operation sink
    - Path argument has untrusted taint τ=1
    - Path has not been validated (basename, realpath check, etc.)
    """
    if hasattr(state, 'security_violations'):
        for violation in state.security_violations:
            if violation.sink_type == SinkType.FILE_PATH:
                return True
    
    if hasattr(state, 'path_injection_detected') and state.path_injection_detected:
        return True
    
    return False


def extract_counterexample(state, path_trace: list) -> dict:
    """Extract counterexample for path injection."""
    result = {
        "bug_type": "PATH_INJECTION",
        "cwe": "CWE-022",
        "severity": "high",
        "location": "unknown",
        "taint_sources": [],
        "path_snippet": None,
        "message": "Potential path traversal: untrusted data in file path",
        "barrier_info": {
            "unsafe_region": "U_path := { s | at_file_sink ∧ τ(path)=1 ∧ ¬validated }",
            "barrier_template": "B = δ_file · (validated + (1-τ) - ½)",
            "required_guard": "os.path.basename() or realpath+startswith check"
        }
    }
    
    if hasattr(state, 'security_violations'):
        for v in state.security_violations:
            if v.sink_type == SinkType.FILE_PATH:
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
