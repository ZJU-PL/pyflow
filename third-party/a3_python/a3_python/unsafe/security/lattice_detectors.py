"""
Security Bug Detectors with Z3 Lattice Integration (leak_theory.md §3).

This module provides unsafe region predicates for all 47 CodeQL security bug types,
implemented using the full taint product lattice L = P(T) × P(K) × P(T).

Each bug type is defined as an unsafe region U_k ⊆ S:
    U_k = { s | pc = π_sink ∧ ¬Safe_k(ℓ_arg) }

Where Safe_k(ℓ) = (τ = ∅) ∨ (k ∈ κ) for injection bugs
And   Safe_k(ℓ) = (σ = ∅) ∨ (k ∈ κ) for sensitivity bugs

Mode A (pure symbolic): Sound over-approximation using symbolic taint
Mode B (concolic): Validated with concrete values (does not affect verdicts)
"""

from __future__ import annotations
from dataclasses import dataclass
from typing import Optional, List, Dict, Any, Callable
import z3

from a3_python.z3model.taint_lattice import (
    SourceType, SinkType,
    TaintLabel, SymbolicTaintLabel,
    SecurityBugType, CODEQL_BUG_TYPES,
    SecurityViolation, create_violation,
    create_unsafe_region_constraint, create_barrier_certificate,
    tau_zero, kappa_zero, sigma_zero,
    TAU_WIDTH, KAPPA_WIDTH, SIGMA_WIDTH,
)


# ============================================================================
# UNSAFE REGION PREDICATE TYPE
# ============================================================================

@dataclass
class UnsafeRegionPredicate:
    """
    Predicate defining an unsafe region for a security bug type.
    
    The predicate checks if a machine state is in the unsafe region.
    """
    bug_type: str
    cwe: str
    sink_type: SinkType
    
    # Predicate function: state -> bool
    is_unsafe: Callable[[Any], bool]
    
    # Z3 constraint generator: state -> z3.BoolRef
    create_constraint: Callable[[Any], Optional[z3.BoolRef]]
    
    # Counterexample extractor
    extract_counterexample: Callable[[Any], Dict]


# ============================================================================
# GENERIC DETECTOR FACTORY
# ============================================================================

def create_lattice_detector(
    bug_type_name: str,
    state_flag: str = None,
    taint_attribute: str = None
) -> UnsafeRegionPredicate:
    """
    Factory for creating unsafe region predicates from CODEQL_BUG_TYPES.
    
    Args:
        bug_type_name: Key into CODEQL_BUG_TYPES
        state_flag: Optional attribute name to check on state (e.g., 'sql_injection_detected')
        taint_attribute: Optional attribute for direct taint label access
    
    Returns:
        UnsafeRegionPredicate with is_unsafe, create_constraint, and extract_counterexample
    """
    bug_type = CODEQL_BUG_TYPES.get(bug_type_name)
    if bug_type is None:
        raise ValueError(f"Unknown bug type: {bug_type_name}")
    
    def is_unsafe(state: Any) -> bool:
        """Check if state is in the unsafe region (concrete check)."""
        # First check state flag if available
        if state_flag and hasattr(state, state_flag):
            if getattr(state, state_flag):
                return True
        
        # Check security violations
        if hasattr(state, 'security_violations'):
            for v in state.security_violations:
                if v.bug_type == bug_type_name:
                    return True
        
        # Check security tracker
        if hasattr(state, 'security_tracker') and state.security_tracker:
            for v in state.security_tracker.violations:
                if v.bug_type == bug_type_name:
                    return True
        
        # Check taint label directly if available
        if taint_attribute and hasattr(state, taint_attribute):
            label = getattr(state, taint_attribute)
            if isinstance(label, TaintLabel):
                return not label.is_safe_for_sink(bug_type.sink_type)
        
        return False
    
    def create_constraint(state: Any) -> Optional[z3.BoolRef]:
        """Create Z3 constraint for the unsafe region (symbolic check)."""
        # Get symbolic taint label if available
        symbolic_label = None
        
        if hasattr(state, 'security_tracker') and state.security_tracker:
            tracker = state.security_tracker
            if hasattr(tracker, 'symbolic_labels'):
                # Get the most recent symbolic label from sink argument
                # This is a simplification - in practice we'd track per-sink
                for vid, label in tracker.symbolic_labels.items():
                    if isinstance(label, SymbolicTaintLabel):
                        symbolic_label = label
                        break
        
        if symbolic_label is None:
            return None
        
        # Create unsafe region constraint
        return create_unsafe_region_constraint(bug_type, symbolic_label)
    
    def extract_counterexample(state: Any) -> Dict:
        """Extract counterexample information for bug report."""
        result = {
            'bug_type': bug_type_name,
            'cwe': bug_type.cwe,
            'description': bug_type.description,
        }
        
        # Get violation details
        if hasattr(state, 'security_violations'):
            for v in state.security_violations:
                if v.bug_type == bug_type_name:
                    result['location'] = v.sink_location
                    result['sources'] = v.get_source_summary()
                    result['message'] = v.message
                    if v.counterexample:
                        result['concrete_values'] = v.counterexample
                    break
        
        return result
    
    return UnsafeRegionPredicate(
        bug_type=bug_type_name,
        cwe=bug_type.cwe,
        sink_type=bug_type.sink_type,
        is_unsafe=is_unsafe,
        create_constraint=create_constraint,
        extract_counterexample=extract_counterexample
    )


# ============================================================================
# INJECTION BUG DETECTORS (check τ)
# ============================================================================

# SQL Injection family
SQL_INJECTION_DETECTOR = create_lattice_detector(
    "SQL_INJECTION", "sql_injection_detected"
)

SQLI_WITH_FORMAT_DETECTOR = create_lattice_detector(
    "SQLI_WITH_FORMAT", "sql_injection_detected"
)

# Command Injection family
COMMAND_INJECTION_DETECTOR = create_lattice_detector(
    "COMMAND_INJECTION", "command_injection_detected"
)

SHELL_COMMAND_CONSTRUCTION_DETECTOR = create_lattice_detector(
    "SHELL_COMMAND_CONSTRUCTION", "command_injection_detected"
)

# Code Injection family
CODE_INJECTION_DETECTOR = create_lattice_detector(
    "CODE_INJECTION", "code_injection_detected"
)

EVAL_INJECTION_DETECTOR = create_lattice_detector(
    "EVAL_INJECTION", "code_injection_detected"
)

EXEC_INJECTION_DETECTOR = create_lattice_detector(
    "EXEC_INJECTION", "code_injection_detected"
)

# Path Traversal family
PATH_INJECTION_DETECTOR = create_lattice_detector(
    "PATH_INJECTION", "path_injection_detected"
)

TARSLIP_DETECTOR = create_lattice_detector(
    "TARSLIP", "path_injection_detected"
)

ZIPSLIP_DETECTOR = create_lattice_detector(
    "ZIPSLIP", "path_injection_detected"
)

# LDAP Injection
LDAP_INJECTION_DETECTOR = create_lattice_detector(
    "LDAP_INJECTION", "ldap_injection_detected"
)

# XPath Injection
XPATH_INJECTION_DETECTOR = create_lattice_detector(
    "XPATH_INJECTION", "xpath_injection_detected"
)

# NoSQL Injection
NOSQL_INJECTION_DETECTOR = create_lattice_detector(
    "NOSQL_INJECTION", "nosql_injection_detected"
)

# ReDoS family
REGEX_INJECTION_DETECTOR = create_lattice_detector(
    "REGEX_INJECTION", "regex_injection_detected"
)

POLYNOMIAL_REDOS_DETECTOR = create_lattice_detector(
    "POLYNOMIAL_REDOS", "regex_injection_detected"
)

EXPONENTIAL_REDOS_DETECTOR = create_lattice_detector(
    "EXPONENTIAL_REDOS", "regex_injection_detected"
)

# SSRF family
SSRF_DETECTOR = create_lattice_detector(
    "SSRF", "ssrf_detected"
)

FULL_SSRF_DETECTOR = create_lattice_detector(
    "FULL_SSRF", "ssrf_detected"
)

PARTIAL_SSRF_DETECTOR = create_lattice_detector(
    "PARTIAL_SSRF", "ssrf_detected"
)

# XXE family
XXE_DETECTOR = create_lattice_detector(
    "XXE", "xxe_detected"
)

XXE_LOCAL_FILE_DETECTOR = create_lattice_detector(
    "XXE_LOCAL_FILE", "xxe_detected"
)

XML_BOMB_DETECTOR = create_lattice_detector(
    "XML_BOMB", "xml_bomb_detected"
)

# Deserialization family
UNSAFE_DESERIALIZATION_DETECTOR = create_lattice_detector(
    "UNSAFE_DESERIALIZATION", "deserialization_detected"
)

PICKLE_INJECTION_DETECTOR = create_lattice_detector(
    "PICKLE_INJECTION", "deserialization_detected"
)

YAML_INJECTION_DETECTOR = create_lattice_detector(
    "YAML_INJECTION", "deserialization_detected"
)

# Header Injection
HEADER_INJECTION_DETECTOR = create_lattice_detector(
    "HEADER_INJECTION", "header_injection_detected"
)

# XSS family
REFLECTED_XSS_DETECTOR = create_lattice_detector(
    "REFLECTED_XSS", "xss_detected"
)

STORED_XSS_DETECTOR = create_lattice_detector(
    "STORED_XSS", "xss_detected"
)

DOM_XSS_DETECTOR = create_lattice_detector(
    "DOM_XSS", "xss_detected"
)

# Open Redirect family
URL_REDIRECT_DETECTOR = create_lattice_detector(
    "URL_REDIRECT", "redirect_detected"
)

UNVALIDATED_REDIRECT_DETECTOR = create_lattice_detector(
    "UNVALIDATED_REDIRECT", "redirect_detected"
)

# Template Injection family
TEMPLATE_INJECTION_DETECTOR = create_lattice_detector(
    "TEMPLATE_INJECTION", "xss_detected"
)

JINJA2_INJECTION_DETECTOR = create_lattice_detector(
    "JINJA2_INJECTION", "xss_detected"
)

# Log Forging
LOG_INJECTION_DETECTOR = create_lattice_detector(
    "LOG_INJECTION", "log_injection_detected"
)

# Email Header Injection
EMAIL_INJECTION_DETECTOR = create_lattice_detector(
    "EMAIL_INJECTION", "header_injection_detected"
)


# ============================================================================
# SENSITIVE DATA EXPOSURE DETECTORS (check σ)
# ============================================================================

CLEARTEXT_LOGGING_DETECTOR = create_lattice_detector(
    "CLEARTEXT_LOGGING", "cleartext_logging_detected"
)

CLEARTEXT_STORAGE_DETECTOR = create_lattice_detector(
    "CLEARTEXT_STORAGE", "cleartext_storage_detected"
)

CLEARTEXT_TRANSMISSION_DETECTOR = create_lattice_detector(
    "CLEARTEXT_TRANSMISSION", "cleartext_transmission_detected"
)

STACK_TRACE_EXPOSURE_DETECTOR = create_lattice_detector(
    "STACK_TRACE_EXPOSURE", "stack_trace_exposure_detected"
)

INFORMATION_EXPOSURE_DETECTOR = create_lattice_detector(
    "INFORMATION_EXPOSURE", "information_exposure_detected"
)


# ============================================================================
# CRYPTOGRAPHIC ISSUE DETECTORS
# ============================================================================

WEAK_CRYPTO_DETECTOR = create_lattice_detector(
    "WEAK_CRYPTO", "weak_crypto_detected"
)

WEAK_SENSITIVE_DATA_HASHING_DETECTOR = create_lattice_detector(
    "WEAK_SENSITIVE_DATA_HASHING", "weak_sensitive_data_hashing_detected"
)

HARDCODED_CREDENTIALS_DETECTOR = create_lattice_detector(
    "HARDCODED_CREDENTIALS", "hardcoded_credentials_detected"
)

WEAK_RANDOM_DETECTOR = create_lattice_detector(
    "WEAK_RANDOM", "weak_random_detected"
)

INSECURE_HASH_DETECTOR = create_lattice_detector(
    "INSECURE_HASH", "insecure_hash_detected"
)


# ============================================================================
# RESOURCE CONTROL DETECTORS
# ============================================================================

RESOURCE_EXHAUSTION_DETECTOR = create_lattice_detector(
    "RESOURCE_EXHAUSTION", "resource_exhaustion_detected"
)

IMPROPER_PRIVILEGE_DETECTOR = create_lattice_detector(
    "IMPROPER_PRIVILEGE", "improper_privilege_detected"
)

INSECURE_PERMISSIONS_DETECTOR = create_lattice_detector(
    "INSECURE_PERMISSIONS", "insecure_permissions_detected"
)


# ============================================================================
# DETECTOR REGISTRY
# ============================================================================

# Map from bug type name to detector
SECURITY_DETECTORS: Dict[str, UnsafeRegionPredicate] = {
    # SQL Injection
    "SQL_INJECTION": SQL_INJECTION_DETECTOR,
    "SQLI_WITH_FORMAT": SQLI_WITH_FORMAT_DETECTOR,
    
    # Command Injection
    "COMMAND_INJECTION": COMMAND_INJECTION_DETECTOR,
    "SHELL_COMMAND_CONSTRUCTION": SHELL_COMMAND_CONSTRUCTION_DETECTOR,
    
    # Code Injection
    "CODE_INJECTION": CODE_INJECTION_DETECTOR,
    "EVAL_INJECTION": EVAL_INJECTION_DETECTOR,
    "EXEC_INJECTION": EXEC_INJECTION_DETECTOR,
    
    # Path Traversal
    "PATH_INJECTION": PATH_INJECTION_DETECTOR,
    "TARSLIP": TARSLIP_DETECTOR,
    "ZIPSLIP": ZIPSLIP_DETECTOR,
    
    # LDAP Injection
    "LDAP_INJECTION": LDAP_INJECTION_DETECTOR,
    
    # XPath Injection
    "XPATH_INJECTION": XPATH_INJECTION_DETECTOR,
    
    # NoSQL Injection
    "NOSQL_INJECTION": NOSQL_INJECTION_DETECTOR,
    
    # ReDoS
    "REGEX_INJECTION": REGEX_INJECTION_DETECTOR,
    "POLYNOMIAL_REDOS": POLYNOMIAL_REDOS_DETECTOR,
    "EXPONENTIAL_REDOS": EXPONENTIAL_REDOS_DETECTOR,
    
    # SSRF
    "SSRF": SSRF_DETECTOR,
    "FULL_SSRF": FULL_SSRF_DETECTOR,
    "PARTIAL_SSRF": PARTIAL_SSRF_DETECTOR,
    
    # XXE
    "XXE": XXE_DETECTOR,
    "XXE_LOCAL_FILE": XXE_LOCAL_FILE_DETECTOR,
    "XML_BOMB": XML_BOMB_DETECTOR,
    
    # Deserialization
    "UNSAFE_DESERIALIZATION": UNSAFE_DESERIALIZATION_DETECTOR,
    "PICKLE_INJECTION": PICKLE_INJECTION_DETECTOR,
    "YAML_INJECTION": YAML_INJECTION_DETECTOR,
    
    # Header Injection
    "HEADER_INJECTION": HEADER_INJECTION_DETECTOR,
    
    # XSS
    "REFLECTED_XSS": REFLECTED_XSS_DETECTOR,
    "STORED_XSS": STORED_XSS_DETECTOR,
    "DOM_XSS": DOM_XSS_DETECTOR,
    
    # Open Redirect
    "URL_REDIRECT": URL_REDIRECT_DETECTOR,
    "UNVALIDATED_REDIRECT": UNVALIDATED_REDIRECT_DETECTOR,
    
    # Template Injection
    "TEMPLATE_INJECTION": TEMPLATE_INJECTION_DETECTOR,
    "JINJA2_INJECTION": JINJA2_INJECTION_DETECTOR,
    
    # Log Forging
    "LOG_INJECTION": LOG_INJECTION_DETECTOR,
    
    # Email Header Injection
    "EMAIL_INJECTION": EMAIL_INJECTION_DETECTOR,
    
    # Sensitive Data Exposure
    "CLEARTEXT_LOGGING": CLEARTEXT_LOGGING_DETECTOR,
    "CLEARTEXT_STORAGE": CLEARTEXT_STORAGE_DETECTOR,
    "CLEARTEXT_TRANSMISSION": CLEARTEXT_TRANSMISSION_DETECTOR,
    "STACK_TRACE_EXPOSURE": STACK_TRACE_EXPOSURE_DETECTOR,
    "INFORMATION_EXPOSURE": INFORMATION_EXPOSURE_DETECTOR,
    
    # Cryptographic Issues
    "WEAK_CRYPTO": WEAK_CRYPTO_DETECTOR,
    "HARDCODED_CREDENTIALS": HARDCODED_CREDENTIALS_DETECTOR,
    "WEAK_RANDOM": WEAK_RANDOM_DETECTOR,
    "INSECURE_HASH": INSECURE_HASH_DETECTOR,
    
    # Resource Control
    "RESOURCE_EXHAUSTION": RESOURCE_EXHAUSTION_DETECTOR,
    "IMPROPER_PRIVILEGE": IMPROPER_PRIVILEGE_DETECTOR,
    "INSECURE_PERMISSIONS": INSECURE_PERMISSIONS_DETECTOR,
}


def get_detector(bug_type: str) -> Optional[UnsafeRegionPredicate]:
    """Get detector for a specific bug type."""
    return SECURITY_DETECTORS.get(bug_type)


def get_all_detectors() -> Dict[str, UnsafeRegionPredicate]:
    """Get all security detectors."""
    return SECURITY_DETECTORS.copy()


def check_all_security_bugs(state: Any) -> List[str]:
    """
    Check state against all security bug detectors.
    
    Returns list of detected bug type names.
    """
    detected = []
    for bug_type, detector in SECURITY_DETECTORS.items():
        if detector.is_unsafe(state):
            detected.append(bug_type)
    return detected


# ============================================================================
# BACKWARD COMPATIBILITY: is_unsafe_* functions for registry
# ============================================================================

def is_unsafe_sql_injection(state: Any) -> bool:
    return SQL_INJECTION_DETECTOR.is_unsafe(state)

def is_unsafe_command_injection(state: Any) -> bool:
    return COMMAND_INJECTION_DETECTOR.is_unsafe(state)

def is_unsafe_code_injection(state: Any) -> bool:
    return CODE_INJECTION_DETECTOR.is_unsafe(state)

def is_unsafe_path_injection(state: Any) -> bool:
    return PATH_INJECTION_DETECTOR.is_unsafe(state)

def is_unsafe_ldap_injection(state: Any) -> bool:
    return LDAP_INJECTION_DETECTOR.is_unsafe(state)

def is_unsafe_xpath_injection(state: Any) -> bool:
    return XPATH_INJECTION_DETECTOR.is_unsafe(state)

def is_unsafe_nosql_injection(state: Any) -> bool:
    return NOSQL_INJECTION_DETECTOR.is_unsafe(state)

def is_unsafe_regex_injection(state: Any) -> bool:
    return REGEX_INJECTION_DETECTOR.is_unsafe(state)

def is_unsafe_ssrf(state: Any) -> bool:
    return SSRF_DETECTOR.is_unsafe(state)

def is_unsafe_xxe(state: Any) -> bool:
    return XXE_DETECTOR.is_unsafe(state)

def is_unsafe_xml_bomb(state: Any) -> bool:
    return XML_BOMB_DETECTOR.is_unsafe(state)

def is_unsafe_deserialization(state: Any) -> bool:
    return UNSAFE_DESERIALIZATION_DETECTOR.is_unsafe(state)

def is_unsafe_header_injection(state: Any) -> bool:
    return HEADER_INJECTION_DETECTOR.is_unsafe(state)

def is_unsafe_xss(state: Any) -> bool:
    return REFLECTED_XSS_DETECTOR.is_unsafe(state)

def is_unsafe_url_redirect(state: Any) -> bool:
    return URL_REDIRECT_DETECTOR.is_unsafe(state)

def is_unsafe_template_injection(state: Any) -> bool:
    return TEMPLATE_INJECTION_DETECTOR.is_unsafe(state)

def is_unsafe_log_injection(state: Any) -> bool:
    return LOG_INJECTION_DETECTOR.is_unsafe(state)

def is_unsafe_email_injection(state: Any) -> bool:
    return EMAIL_INJECTION_DETECTOR.is_unsafe(state)

def is_unsafe_cleartext_logging(state: Any) -> bool:
    return CLEARTEXT_LOGGING_DETECTOR.is_unsafe(state)

def is_unsafe_cleartext_storage(state: Any) -> bool:
    return CLEARTEXT_STORAGE_DETECTOR.is_unsafe(state)

def is_unsafe_cleartext_transmission(state: Any) -> bool:
    return CLEARTEXT_TRANSMISSION_DETECTOR.is_unsafe(state)

def is_unsafe_stack_trace_exposure(state: Any) -> bool:
    return STACK_TRACE_EXPOSURE_DETECTOR.is_unsafe(state)

def is_unsafe_information_exposure(state: Any) -> bool:
    return INFORMATION_EXPOSURE_DETECTOR.is_unsafe(state)

def is_unsafe_weak_crypto(state: Any) -> bool:
    return WEAK_CRYPTO_DETECTOR.is_unsafe(state)

def is_unsafe_weak_sensitive_data_hashing(state: Any) -> bool:
    return WEAK_SENSITIVE_DATA_HASHING_DETECTOR.is_unsafe(state)

def is_unsafe_hardcoded_credentials(state: Any) -> bool:
    return HARDCODED_CREDENTIALS_DETECTOR.is_unsafe(state)

def is_unsafe_weak_random(state: Any) -> bool:
    return WEAK_RANDOM_DETECTOR.is_unsafe(state)

def is_unsafe_insecure_hash(state: Any) -> bool:
    return INSECURE_HASH_DETECTOR.is_unsafe(state)

def is_unsafe_resource_exhaustion(state: Any) -> bool:
    return RESOURCE_EXHAUSTION_DETECTOR.is_unsafe(state)

def is_unsafe_improper_privilege(state: Any) -> bool:
    return IMPROPER_PRIVILEGE_DETECTOR.is_unsafe(state)

def is_unsafe_insecure_permissions(state: Any) -> bool:
    return INSECURE_PERMISSIONS_DETECTOR.is_unsafe(state)


# Counterexample extractors
def extract_counterexample_generic(state: Any, bug_type: str) -> Dict:
    detector = SECURITY_DETECTORS.get(bug_type)
    if detector:
        return detector.extract_counterexample(state)
    return {}

extract_counterexample_sql_injection = lambda s: extract_counterexample_generic(s, "SQL_INJECTION")
extract_counterexample_command_injection = lambda s: extract_counterexample_generic(s, "COMMAND_INJECTION")
extract_counterexample_code_injection = lambda s: extract_counterexample_generic(s, "CODE_INJECTION")
extract_counterexample_path_injection = lambda s: extract_counterexample_generic(s, "PATH_INJECTION")
extract_counterexample_ldap_injection = lambda s: extract_counterexample_generic(s, "LDAP_INJECTION")
extract_counterexample_xpath_injection = lambda s: extract_counterexample_generic(s, "XPATH_INJECTION")
extract_counterexample_nosql_injection = lambda s: extract_counterexample_generic(s, "NOSQL_INJECTION")
extract_counterexample_regex_injection = lambda s: extract_counterexample_generic(s, "REGEX_INJECTION")
extract_counterexample_ssrf = lambda s: extract_counterexample_generic(s, "SSRF")
extract_counterexample_xxe = lambda s: extract_counterexample_generic(s, "XXE")
extract_counterexample_deserialization = lambda s: extract_counterexample_generic(s, "UNSAFE_DESERIALIZATION")
extract_counterexample_header_injection = lambda s: extract_counterexample_generic(s, "HEADER_INJECTION")
extract_counterexample_xss = lambda s: extract_counterexample_generic(s, "REFLECTED_XSS")
extract_counterexample_url_redirect = lambda s: extract_counterexample_generic(s, "URL_REDIRECT")
extract_counterexample_template_injection = lambda s: extract_counterexample_generic(s, "TEMPLATE_INJECTION")
extract_counterexample_log_injection = lambda s: extract_counterexample_generic(s, "LOG_INJECTION")
extract_counterexample_cleartext_logging = lambda s: extract_counterexample_generic(s, "CLEARTEXT_LOGGING")
extract_counterexample_cleartext_storage = lambda s: extract_counterexample_generic(s, "CLEARTEXT_STORAGE")
extract_counterexample_weak_crypto = lambda s: extract_counterexample_generic(s, "WEAK_CRYPTO")
extract_counterexample_weak_sensitive_data_hashing = lambda s: extract_counterexample_generic(s, "WEAK_SENSITIVE_DATA_HASHING")


# ============================================================================
# EXPORTS
# ============================================================================

__all__ = [
    # Predicate type
    'UnsafeRegionPredicate',
    
    # Factory
    'create_lattice_detector',
    
    # Registry
    'SECURITY_DETECTORS',
    'get_detector',
    'get_all_detectors',
    'check_all_security_bugs',
    
    # Individual detectors (for direct access)
    'SQL_INJECTION_DETECTOR',
    'COMMAND_INJECTION_DETECTOR',
    'CODE_INJECTION_DETECTOR',
    'PATH_INJECTION_DETECTOR',
    'LDAP_INJECTION_DETECTOR',
    'XPATH_INJECTION_DETECTOR',
    'NOSQL_INJECTION_DETECTOR',
    'REGEX_INJECTION_DETECTOR',
    'SSRF_DETECTOR',
    'XXE_DETECTOR',
    'UNSAFE_DESERIALIZATION_DETECTOR',
    'HEADER_INJECTION_DETECTOR',
    'REFLECTED_XSS_DETECTOR',
    'URL_REDIRECT_DETECTOR',
    'TEMPLATE_INJECTION_DETECTOR',
    'LOG_INJECTION_DETECTOR',
    'CLEARTEXT_LOGGING_DETECTOR',
    'CLEARTEXT_STORAGE_DETECTOR',
    'WEAK_CRYPTO_DETECTOR',
    'WEAK_SENSITIVE_DATA_HASHING_DETECTOR',
    
    # Backward-compatible is_unsafe functions
    'is_unsafe_sql_injection',
    'is_unsafe_command_injection',
    'is_unsafe_code_injection',
    'is_unsafe_path_injection',
    'is_unsafe_xss',
    'is_unsafe_ssrf',
    'is_unsafe_deserialization',
    'is_unsafe_xxe',
    'is_unsafe_cleartext_logging',
    'is_unsafe_cleartext_storage',
    'is_unsafe_weak_crypto',
    'is_unsafe_weak_sensitive_data_hashing',
]
