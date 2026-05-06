"""
Regex-related security bug detectors (barrier-certificate-theory.md §11).

Bug Types:
- REDOS (CWE-730): Exponential backtracking ReDoS
- POLYNOMIAL_REDOS (CWE-730): Polynomial ReDoS on untrusted input
- BAD_TAG_FILTER (CWE-116): Bypassable HTML tag filtering regex
- INCOMPLETE_HOSTNAME_REGEXP (CWE-020): Unescaped dot in hostname regex
- OVERLY_LARGE_RANGE (CWE-020): Overly permissive regex range
"""

from typing import Any, Optional


# ============================================================================
# REDOS (CWE-730): py/redos
# ============================================================================

def is_unsafe_redos(state) -> bool:
    """
    Check if state is in unsafe region for ReDoS.
    
    Unsafe region (static):
    U_redos := { s | π == π_regex ∧ HasExponentialBacktracking(pattern) }
    
    Note: This is pattern-based, not taint-based.
    """
    return getattr(state, 'redos_detected', False)


def extract_redos_counterexample(state, trace: list[str]) -> dict:
    """Extract counterexample for ReDoS vulnerability."""
    return {
        "bug_type": "REDOS",
        "cwe": "CWE-730",
        "query_id": "py/redos",
        "description": "Regex with exponential backtracking causes DoS",
        "trace": trace,
        "regex_site": getattr(state, 'redos_site', None),
        "pattern": getattr(state, 'redos_pattern', None),
        "mitigation": "Use atomic groups, possessive quantifiers, or simpler patterns"
    }


# ============================================================================
# POLYNOMIAL_REDOS (CWE-730): py/polynomial-redos
# ============================================================================

def is_unsafe_polynomial_redos(state) -> bool:
    """
    Check if state is in unsafe region for polynomial ReDoS.
    
    Unsafe region:
    U_polyredos := { s | π == π_regex ∧ τ(input_string) == 1 ∧ HasPolynomialBacktracking(pattern) }
    """
    return getattr(state, 'polynomial_redos_detected', False)


def extract_polynomial_redos_counterexample(state, trace: list[str]) -> dict:
    """Extract counterexample for polynomial ReDoS vulnerability."""
    return {
        "bug_type": "POLYNOMIAL_REDOS",
        "cwe": "CWE-730",
        "query_id": "py/polynomial-redos",
        "description": "Polynomial-time regex on untrusted input",
        "trace": trace,
        "regex_site": getattr(state, 'polynomial_redos_site', None),
        "pattern": getattr(state, 'polynomial_redos_pattern', None),
        "mitigation": "Use simpler patterns or limit input length"
    }


# ============================================================================
# BAD_TAG_FILTER (CWE-116): py/bad-tag-filter
# ============================================================================

def is_unsafe_bad_tag_filter(state) -> bool:
    """
    Check if state is in unsafe region for bad HTML tag filter.
    
    Unsafe region (static regex analysis):
    U_bad_tag := { s | π == π_regex_replace ∧ LooksLikeHtmlFilter(pattern) ∧ IsBypassable(pattern) }
    """
    return getattr(state, 'bad_tag_filter_detected', False)


def extract_bad_tag_filter_counterexample(state, trace: list[str]) -> dict:
    """Extract counterexample for bad tag filter vulnerability."""
    return {
        "bug_type": "BAD_TAG_FILTER",
        "cwe": "CWE-116",
        "query_id": "py/bad-tag-filter",
        "description": "HTML tag filtering via regex is bypassable",
        "trace": trace,
        "filter_site": getattr(state, 'bad_tag_filter_site', None),
        "pattern": getattr(state, 'bad_tag_filter_pattern', None),
        "mitigation": "Use proper HTML sanitization library like bleach"
    }


# ============================================================================
# INCOMPLETE_HOSTNAME_REGEXP (CWE-020): py/incomplete-hostname-regexp
# ============================================================================

def is_unsafe_incomplete_hostname_regexp(state) -> bool:
    """
    Check if state is in unsafe region for incomplete hostname regex.
    
    Unsafe region (static):
    U_hostname := { s | π == π_hostname_check ∧ HasUnescapedDot(pattern) }
    """
    return getattr(state, 'incomplete_hostname_regexp_detected', False)


def extract_incomplete_hostname_regexp_counterexample(state, trace: list[str]) -> dict:
    """Extract counterexample for incomplete hostname regexp vulnerability."""
    return {
        "bug_type": "INCOMPLETE_HOSTNAME_REGEXP",
        "cwe": "CWE-020",
        "query_id": "py/incomplete-hostname-regexp",
        "description": "Hostname regex with unescaped dot matches more than intended",
        "trace": trace,
        "check_site": getattr(state, 'incomplete_hostname_regexp_site', None),
        "pattern": getattr(state, 'incomplete_hostname_regexp_pattern', None),
        "mitigation": "Escape dots with \\\\. in hostname patterns"
    }


# ============================================================================
# OVERLY_LARGE_RANGE (CWE-020): py/overly-large-range
# ============================================================================

def is_unsafe_overly_large_range(state) -> bool:
    """
    Check if state is in unsafe region for overly large regex range.
    
    Unsafe region (static):
    U_large_range := { s | π == π_regex ∧ HasOverlyLargeRange(pattern) }
    
    Example: [A-z] includes special characters between Z and a in ASCII.
    """
    return getattr(state, 'overly_large_range_detected', False)


def extract_overly_large_range_counterexample(state, trace: list[str]) -> dict:
    """Extract counterexample for overly large range vulnerability."""
    return {
        "bug_type": "OVERLY_LARGE_RANGE",
        "cwe": "CWE-020",
        "query_id": "py/overly-large-range",
        "description": "Regex character range matches more than intended",
        "trace": trace,
        "regex_site": getattr(state, 'overly_large_range_site', None),
        "pattern": getattr(state, 'overly_large_range_pattern', None),
        "mitigation": "Use [A-Za-z] instead of [A-z]"
    }


# ============================================================================
# INCOMPLETE_URL_SUBSTRING_SANITIZATION (CWE-020): py/incomplete-url-substring-sanitization
# ============================================================================

def is_unsafe_incomplete_url_substring_sanitization(state) -> bool:
    """
    Check if state is in unsafe region for incomplete URL sanitization.
    
    Unsafe region (static):
    U_url_substr := { s | π == π_url_check ∧ UsesSubstringMatching(check) }
    """
    return getattr(state, 'incomplete_url_substring_sanitization_detected', False)


def extract_incomplete_url_substring_sanitization_counterexample(state, trace: list[str]) -> dict:
    """Extract counterexample for incomplete URL sanitization vulnerability."""
    return {
        "bug_type": "INCOMPLETE_URL_SUBSTRING_SANITIZATION",
        "cwe": "CWE-020",
        "query_id": "py/incomplete-url-substring-sanitization",
        "description": "URL validation via substring matching is bypassable",
        "trace": trace,
        "check_site": getattr(state, 'incomplete_url_substring_sanitization_site', None),
        "mitigation": "Use proper URL parsing with urlparse and scheme/host validation"
    }
