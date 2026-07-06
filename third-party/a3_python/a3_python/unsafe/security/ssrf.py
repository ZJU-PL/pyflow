"""
SSRF (CWE-918): Server-Side Request Forgery.

Unsafe region U_ssrf := { s | π == π_http_request ∧ τ(url) == 1 ∧ ¬g_url_validated }

Sources: User input, HTTP parameters
Sinks: requests.get(), urllib.urlopen(), httpx.get()
Sanitizers: URL allowlist validation, schema validation
"""

from a3_python.z3model.taint import SinkType


def is_unsafe_ssrf(state) -> bool:
    """
    Unsafe predicate U_SSRF(σ).
    
    Returns True if:
    - At HTTP request sink (server making request)
    - URL has untrusted taint τ=1
    - URL not validated against allowlist
    """
    if hasattr(state, 'security_violations'):
        for violation in state.security_violations:
            if violation.sink_type == SinkType.HTTP_REQUEST:
                return True
    
    if hasattr(state, 'ssrf_detected') and state.ssrf_detected:
        return True
    
    return False


def extract_counterexample(state, path_trace: list) -> dict:
    """Extract counterexample for SSRF."""
    result = {
        "bug_type": "SSRF",
        "cwe": "CWE-918",
        "severity": "high",
        "location": "unknown",
        "taint_sources": [],
        "url_snippet": None,
        "full_control": True,  # Full URL vs partial (path only)
        "message": "Potential SSRF: untrusted URL in server-side request",
        "barrier_info": {
            "unsafe_region": "U_ssrf := { s | at_request_sink ∧ τ(url)=1 ∧ ¬validated }",
            "barrier_template": "B = δ_request · (validated + (1-τ) - ½)",
            "required_guard": "URL allowlist or internal-only network restriction"
        }
    }
    
    if hasattr(state, 'security_violations'):
        for v in state.security_violations:
            if v.sink_type == SinkType.HTTP_REQUEST:
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
