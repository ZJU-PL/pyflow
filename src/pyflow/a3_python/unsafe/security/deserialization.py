"""
UNSAFE_DESERIALIZATION (CWE-502): Tainted data in unsafe deserializers.

Unsafe region U_deser := { s | π == π_deserialize ∧ τ(data) == 1 ∧ DeserializerIsUnsafe }

Sources: Network data, file content, HTTP bodies
Sinks: pickle.loads(), yaml.load() without SafeLoader, marshal.loads()
Sanitizers: yaml.safe_load(), json.loads()
"""

from a3_python.z3model.taint import SinkType


def is_unsafe_deserialization(state) -> bool:
    """
    Unsafe predicate U_UNSAFE_DESERIALIZATION(σ).
    
    Returns True if:
    - At deserialization sink (pickle, yaml, marshal)
    - Data has untrusted taint τ=1
    - Deserializer is not a safe variant (yaml.safe_load, json.loads)
    """
    if hasattr(state, 'security_violations'):
        for violation in state.security_violations:
            if violation.sink_type == SinkType.DESERIALIZE:
                return True
    
    if hasattr(state, 'deserialization_detected') and state.deserialization_detected:
        return True
    
    return False


def extract_counterexample(state, path_trace: list) -> dict:
    """Extract counterexample for unsafe deserialization."""
    result = {
        "bug_type": "UNSAFE_DESERIALIZATION",
        "cwe": "CWE-502",
        "severity": "critical",
        "location": "unknown",
        "taint_sources": [],
        "deserializer": "unknown",
        "message": "Critical: untrusted data passed to unsafe deserializer (potential RCE)",
        "barrier_info": {
            "unsafe_region": "U_deser := { s | at_deser_sink ∧ τ(data)=1 ∧ unsafe_deser }",
            "barrier_template": "B = δ_deser · ((1-unsafe) + (1-τ) - ½)",
            "required_guard": "Use yaml.safe_load() or json.loads() for untrusted data"
        }
    }
    
    if hasattr(state, 'security_violations'):
        for v in state.security_violations:
            if v.sink_type == SinkType.DESERIALIZE:
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
