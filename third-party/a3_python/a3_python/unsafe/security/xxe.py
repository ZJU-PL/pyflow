"""
XXE (CWE-611): XML External Entity Injection.

Unsafe region U_xxe := { s | π == π_xml_parse ∧ τ(xml_input) == 1 ∧ ExternalEntitiesEnabled }

Sources: HTTP bodies, file content, network data
Sinks: xml.etree.parse(), lxml.etree.parse()
Sanitizers: defusedxml, parser with resolve_entities=False
"""

from a3_python.z3model.taint import SinkType


def is_unsafe_xxe(state) -> bool:
    """
    Unsafe predicate U_XXE(σ).
    
    Returns True if:
    - At XML parsing sink
    - XML input has untrusted taint τ=1
    - Parser allows external entity expansion
    """
    if hasattr(state, 'security_violations'):
        for violation in state.security_violations:
            if violation.sink_type == SinkType.XML_PARSE:
                return True
    
    if hasattr(state, 'xxe_detected') and state.xxe_detected:
        return True
    
    return False


def extract_counterexample(state, path_trace: list) -> dict:
    """Extract counterexample for XXE."""
    result = {
        "bug_type": "XXE",
        "cwe": "CWE-611",
        "severity": "high",
        "location": "unknown",
        "taint_sources": [],
        "parser": "unknown",
        "external_entities_enabled": True,
        "message": "Potential XXE: parsing untrusted XML with external entities enabled",
        "barrier_info": {
            "unsafe_region": "U_xxe := { s | at_xml_sink ∧ τ(xml)=1 ∧ entities_enabled }",
            "barrier_template": "B = δ_xml · ((1-entities) + (1-τ) - ½)",
            "required_guard": "Use defusedxml or disable external entities"
        }
    }
    
    if hasattr(state, 'security_violations'):
        for v in state.security_violations:
            if v.sink_type == SinkType.XML_PARSE:
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
