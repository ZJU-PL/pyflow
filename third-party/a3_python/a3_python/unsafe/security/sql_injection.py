"""
SQL_INJECTION (CWE-089): Tainted data in SQL queries.

Unsafe region U_sqli := { s | π == π_sql_execute ∧ τ(query_string) == 1 ∧ ¬Parameterized(call) }

Sources: request.GET, request.POST, input(), os.environ, etc.
Sinks: cursor.execute, Model.objects.raw, engine.execute, etc.
Sanitizers: Parameterized queries, ORM with proper escaping

Mode A (pure symbolic): Check taint bit τ(query) at SQL execution sinks
Mode B (concolic): Optional concrete SQL parsing to validate
"""

from typing import Optional
from a3_python.z3model.taint import SinkType, TaintState


def is_unsafe_sql_injection(state) -> bool:
    """
    Unsafe predicate U_SQL_INJECTION(σ).
    
    Returns True if:
    - Currently at a SQL execution sink (cursor.execute, etc.)
    - Query string argument has untrusted taint τ=1
    - Call is not using parameterized query form
    
    Barrier template:
    B_sqli = (1 - δ_sql(π)) · M + δ_sql(π) · (Parameterized + (1-τ(query)) - ½)
    """
    # Check for security violations tracked by VM
    if hasattr(state, 'security_violations'):
        for violation in state.security_violations:
            if violation.sink_type == SinkType.SQL_EXECUTE:
                return True
    
    # Check taint tracking flags
    if hasattr(state, 'sql_injection_detected') and state.sql_injection_detected:
        return True
    
    # Check generic security sink flags
    if hasattr(state, 'at_security_sink') and state.at_security_sink:
        if hasattr(state, 'current_sink_type') and state.current_sink_type == SinkType.SQL_EXECUTE:
            if hasattr(state, 'sink_arg_tainted') and state.sink_arg_tainted:
                if not getattr(state, 'sink_parameterized', False):
                    return True
    
    return False


def extract_counterexample(state, path_trace: list) -> dict:
    """
    Extract counterexample information for SQL injection bug.
    
    Returns dict with:
    - bug_type: "SQL_INJECTION"
    - cwe: "CWE-089"
    - location: Sink location (file:line)
    - taint_sources: Where the tainted data came from
    - query_snippet: The tainted query (if available)
    - message: Human-readable description
    - barrier_info: Barrier certificate details for synthesis
    """
    result = {
        "bug_type": "SQL_INJECTION",
        "cwe": "CWE-089",
        "severity": "critical",
        "location": "unknown",
        "taint_sources": [],
        "query_snippet": None,
        "parameterized": False,
        "message": "Potential SQL injection: untrusted data in SQL query without parameterization",
        "barrier_info": {
            "unsafe_region": "U_sqli := { s | at_sql_sink ∧ τ(query)=1 ∧ ¬Parameterized }",
            "barrier_template": "B = δ_sql · (Parameterized + (1-τ) - ½)",
            "required_guard": "Parameterized query or τ(query)=0"
        }
    }
    
    # Extract details from security violations
    if hasattr(state, 'security_violations'):
        for v in state.security_violations:
            if v.sink_type == SinkType.SQL_EXECUTE:
                result["location"] = v.sink_location
                result["taint_sources"] = [
                    {"source": l.source_type.name, "location": l.source_location}
                    for l in v.taint_sources
                ]
                result["message"] = v.message
                break
    
    # Extract from state attributes
    if hasattr(state, 'sql_sink_location'):
        result["location"] = state.sql_sink_location
    if hasattr(state, 'sql_query_snippet'):
        result["query_snippet"] = state.sql_query_snippet
    if hasattr(state, 'sql_taint_sources'):
        result["taint_sources"] = state.sql_taint_sources
    
    # Add path trace
    if path_trace:
        result["path_trace_suffix"] = path_trace[-10:]  # Last 10 steps
    
    return result
