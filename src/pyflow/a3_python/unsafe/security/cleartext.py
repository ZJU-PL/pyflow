"""
CLEARTEXT_LOGGING (CWE-532) / CLEARTEXT_STORAGE (CWE-312): Sensitive data exposure.

These use sensitivity taint σ instead of untrusted taint τ.

Unsafe region U_cleartext := { s | π == π_log/store ∧ σ(value) == 1 ∧ ¬Encrypted }

Sources: Password fields, API keys, credentials
Sinks: logging.*, print(), file.write()
Sanitizers: Hashing, encryption
"""

from a3_python.z3model.taint import SinkType


def is_unsafe_cleartext_logging(state) -> bool:
    """
    Unsafe predicate U_CLEARTEXT_LOGGING(σ).
    
    Returns True if:
    - At logging sink
    - Logged value has sensitivity taint σ=1
    - Value not hashed/encrypted
    """
    if hasattr(state, 'security_violations'):
        for violation in state.security_violations:
            if violation.sink_type == SinkType.LOG_OUTPUT:
                return True
    
    if hasattr(state, 'cleartext_logging_detected') and state.cleartext_logging_detected:
        return True
    
    return False


def is_unsafe_cleartext_storage(state) -> bool:
    """
    Unsafe predicate U_CLEARTEXT_STORAGE(σ).
    
    Returns True if:
    - At storage sink (file write, database)
    - Stored value has sensitivity taint σ=1
    - Value not encrypted
    """
    if hasattr(state, 'security_violations'):
        for violation in state.security_violations:
            if violation.sink_type == SinkType.FILE_WRITE:
                return True
    
    if hasattr(state, 'cleartext_storage_detected') and state.cleartext_storage_detected:
        return True
    
    return False


def extract_counterexample(state, path_trace: list) -> dict:
    """Extract counterexample for cleartext exposure."""
    # Determine which type
    bug_type = "CLEARTEXT_LOGGING"
    cwe = "CWE-532"
    sink_type = SinkType.LOG_OUTPUT
    
    if hasattr(state, 'security_violations'):
        for v in state.security_violations:
            if v.sink_type == SinkType.FILE_WRITE:
                bug_type = "CLEARTEXT_STORAGE"
                cwe = "CWE-312"
                sink_type = SinkType.FILE_WRITE
                break
    
    result = {
        "bug_type": bug_type,
        "cwe": cwe,
        "severity": "medium",
        "location": "unknown",
        "taint_sources": [],
        "data_type": "sensitive",
        "message": f"Sensitive data written without encryption: {bug_type}",
        "barrier_info": {
            "unsafe_region": "U_cleartext := { s | at_output_sink ∧ σ(data)=1 ∧ ¬encrypted }",
            "barrier_template": "B = δ_output · (encrypted + (1-σ) - ½)",
            "required_guard": "Hash passwords with bcrypt/PBKDF2, encrypt other sensitive data"
        }
    }
    
    if hasattr(state, 'security_violations'):
        for v in state.security_violations:
            if v.sink_type in (SinkType.LOG_OUTPUT, SinkType.FILE_WRITE):
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
