"""
Additional security bug modules.

LDAP_INJECTION (CWE-090), XPATH_INJECTION (CWE-643), NOSQL_INJECTION (CWE-943),
REGEX_INJECTION (CWE-730), URL_REDIRECT (CWE-601), HEADER_INJECTION (CWE-113)
"""

from a3_python.z3model.taint import SinkType


# ============================================================================
# LDAP_INJECTION (CWE-090)
# ============================================================================

def is_unsafe_ldap_injection(state) -> bool:
    """Unsafe predicate for LDAP injection."""
    if hasattr(state, 'security_violations'):
        for v in state.security_violations:
            if v.sink_type == SinkType.LDAP_QUERY:
                return True
    return getattr(state, 'ldap_injection_detected', False)


def extract_ldap_injection_counterexample(state, path_trace: list) -> dict:
    """Extract counterexample for LDAP injection."""
    return {
        "bug_type": "LDAP_INJECTION",
        "cwe": "CWE-090",
        "severity": "high",
        "location": "unknown",
        "message": "Potential LDAP injection: untrusted data in LDAP filter",
        "barrier_info": {
            "unsafe_region": "U_ldap := { s | at_ldap_sink ∧ τ(filter)=1 }"
        }
    }


# ============================================================================
# XPATH_INJECTION (CWE-643)
# ============================================================================

def is_unsafe_xpath_injection(state) -> bool:
    """Unsafe predicate for XPath injection."""
    if hasattr(state, 'security_violations'):
        for v in state.security_violations:
            if v.sink_type == SinkType.XPATH_QUERY:
                return True
    return getattr(state, 'xpath_injection_detected', False)


def extract_xpath_injection_counterexample(state, path_trace: list) -> dict:
    """Extract counterexample for XPath injection."""
    return {
        "bug_type": "XPATH_INJECTION",
        "cwe": "CWE-643",
        "severity": "high",
        "location": "unknown",
        "message": "Potential XPath injection: untrusted data in XPath expression",
        "barrier_info": {
            "unsafe_region": "U_xpath := { s | at_xpath_sink ∧ τ(expr)=1 }"
        }
    }


# ============================================================================
# NOSQL_INJECTION (CWE-943)
# ============================================================================

def is_unsafe_nosql_injection(state) -> bool:
    """Unsafe predicate for NoSQL injection."""
    if hasattr(state, 'security_violations'):
        for v in state.security_violations:
            if v.sink_type == SinkType.NOSQL_QUERY:
                return True
    return getattr(state, 'nosql_injection_detected', False)


def extract_nosql_injection_counterexample(state, path_trace: list) -> dict:
    """Extract counterexample for NoSQL injection."""
    return {
        "bug_type": "NOSQL_INJECTION",
        "cwe": "CWE-943",
        "severity": "high",
        "location": "unknown",
        "message": "Potential NoSQL injection: untrusted data in query operators",
        "barrier_info": {
            "unsafe_region": "U_nosql := { s | at_nosql_sink ∧ τ(query)=1 }"
        }
    }


# ============================================================================
# REGEX_INJECTION (CWE-730)
# ============================================================================

def is_unsafe_regex_injection(state) -> bool:
    """Unsafe predicate for regex injection (ReDoS)."""
    if hasattr(state, 'security_violations'):
        for v in state.security_violations:
            if v.sink_type == SinkType.REGEX_PATTERN:
                return True
    return getattr(state, 'regex_injection_detected', False)


def extract_regex_injection_counterexample(state, path_trace: list) -> dict:
    """Extract counterexample for regex injection."""
    return {
        "bug_type": "REGEX_INJECTION",
        "cwe": "CWE-730",
        "severity": "medium",
        "location": "unknown",
        "message": "Potential ReDoS: untrusted regex pattern",
        "barrier_info": {
            "unsafe_region": "U_regex := { s | at_regex_sink ∧ τ(pattern)=1 ∧ ¬re.escape }"
        }
    }


# ============================================================================
# URL_REDIRECT (CWE-601)
# ============================================================================

def is_unsafe_url_redirect(state) -> bool:
    """Unsafe predicate for open redirect."""
    if hasattr(state, 'security_violations'):
        for v in state.security_violations:
            if v.sink_type == SinkType.REDIRECT_URL:
                return True
    return getattr(state, 'url_redirect_detected', False)


def extract_url_redirect_counterexample(state, path_trace: list) -> dict:
    """Extract counterexample for URL redirect."""
    return {
        "bug_type": "URL_REDIRECT",
        "cwe": "CWE-601",
        "severity": "medium",
        "location": "unknown",
        "message": "Potential open redirect: untrusted URL in redirect",
        "barrier_info": {
            "unsafe_region": "U_redirect := { s | at_redirect_sink ∧ τ(url)=1 ∧ ¬validated }"
        }
    }


# ============================================================================
# HEADER_INJECTION (CWE-113)
# ============================================================================

def is_unsafe_header_injection(state) -> bool:
    """Unsafe predicate for HTTP header injection."""
    if hasattr(state, 'security_violations'):
        for v in state.security_violations:
            if v.sink_type == SinkType.HEADER_SET:
                return True
    return getattr(state, 'header_injection_detected', False)


def extract_header_injection_counterexample(state, path_trace: list) -> dict:
    """Extract counterexample for header injection."""
    return {
        "bug_type": "HEADER_INJECTION",
        "cwe": "CWE-113",
        "severity": "high",
        "location": "unknown",
        "message": "Potential HTTP header injection: untrusted data with newlines",
        "barrier_info": {
            "unsafe_region": "U_header := { s | at_header_sink ∧ τ(value)=1 ∧ contains_newline }"
        }
    }


# ============================================================================
# COOKIE_INJECTION (CWE-020)
# ============================================================================

def is_unsafe_cookie_injection(state) -> bool:
    """Unsafe predicate for cookie injection."""
    if hasattr(state, 'security_violations'):
        for v in state.security_violations:
            if v.sink_type == SinkType.COOKIE_VALUE:
                return True
    return getattr(state, 'cookie_injection_detected', False)


def extract_cookie_injection_counterexample(state, path_trace: list) -> dict:
    """Extract counterexample for cookie injection."""
    return {
        "bug_type": "COOKIE_INJECTION",
        "cwe": "CWE-020",
        "severity": "medium",
        "location": "unknown",
        "message": "Potential cookie injection: untrusted data in cookie value",
        "barrier_info": {
            "unsafe_region": "U_cookie := { s | at_cookie_sink ∧ τ(value)=1 }"
        }
    }
