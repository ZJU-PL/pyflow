"""
XSS / REFLECTED_XSS (CWE-079): Tainted data in HTML output.

Unsafe region U_xss := { s | π == π_html_output ∧ τ(content) == 1 ∧ ¬AutoEscaped ∧ ¬g_escaped }

Sources: HTTP parameters, user input
Sinks: HttpResponse(), render_template_string(), f"<div>{user_input}</div>"
Sanitizers: html.escape(), markupsafe.escape(), template autoescape
"""

from a3_python.z3model.taint import SinkType


def is_unsafe_xss(state) -> bool:
    """
    Unsafe predicate U_XSS(σ).
    
    Returns True if:
    - At HTML output sink
    - Content has untrusted taint τ=1
    - Not using template autoescape
    - Content not HTML-escaped
    """
    if hasattr(state, 'security_violations'):
        for violation in state.security_violations:
            if violation.sink_type == SinkType.HTML_OUTPUT:
                return True
    
    if hasattr(state, 'xss_detected') and state.xss_detected:
        return True
    
    return False


def extract_counterexample(state, path_trace: list) -> dict:
    """Extract counterexample for XSS."""
    result = {
        "bug_type": "REFLECTED_XSS",
        "cwe": "CWE-079",
        "severity": "high",
        "location": "unknown",
        "taint_sources": [],
        "content_snippet": None,
        "autoescape_enabled": False,
        "message": "Potential XSS: untrusted data in HTML output without escaping",
        "barrier_info": {
            "unsafe_region": "U_xss := { s | at_html_sink ∧ τ(content)=1 ∧ ¬escaped }",
            "barrier_template": "B = δ_html · (escaped + autoescape + (1-τ) - ½)",
            "required_guard": "html.escape() or template autoescape"
        }
    }
    
    if hasattr(state, 'security_violations'):
        for v in state.security_violations:
            if v.sink_type == SinkType.HTML_OUTPUT:
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
