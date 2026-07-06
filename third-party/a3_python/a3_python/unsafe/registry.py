"""
Registry of unsafe regions (20 core + 47 security + 17 exception + 24 semantic bug types).

Maps bug type names to predicates and counterexample extractors.

ITERATION 700: Added fine-grained exception bug types instead of just PANIC.
Each exception type now maps to specific kitchensink barrier verification strategy.
See exception_bugs.py for the full mapping and barrier-theoretic foundation.

ITERATION 701: Added 24 semantic bug types from kitchensink_taxonomy.py:
- 5 contract bugs (PRECONDITION_VIOLATION, etc.)
- 6 temporal bugs (USE_BEFORE_INIT, USE_AFTER_CLOSE, etc.)
- 5 data flow bugs (UNVALIDATED_INPUT, UNCHECKED_RETURN, etc.)
- 4 protocol bugs (ITERATOR_PROTOCOL, CONTEXT_MANAGER_PROTOCOL, etc.)
- 4 resource bugs (MEMORY_EXHAUSTION, CPU_EXHAUSTION, etc.)
"""

from typing import Callable, Optional
from . import assert_fail, div_zero, bounds, null_ptr, type_confusion, panic, stack_overflow, memory_leak, non_termination, iterator_invalid, fp_domain, integer_overflow, use_after_free, double_free, uninit_memory, data_race, deadlock, send_sync, info_leak, timing_channel

# Import fine-grained exception bug types
from .exception_bugs import (
    ExceptionBugType,
    EXCEPTION_PREDICATES,
    classify_exception,
    KITCHENSINK_STRATEGIES,
    verify_exception_with_kitchensink,
)

# Import security bug modules
from .security import (
    sql_injection, command_injection, code_injection, path_injection,
    xss, ssrf, deserialization, xxe, cleartext,
    injection, config, xml, regex, filesystem, webapp, crypto
)

# Security bug types (exported for filtering in analyzer)
# ITERATION 499: Moved to module level so analyzer can import it
SECURITY_BUG_TYPES = {
    "SQL_INJECTION", "COMMAND_INJECTION", "CODE_INJECTION", "PATH_INJECTION",
    "REFLECTED_XSS", "SSRF", "UNSAFE_DESERIALIZATION", "XXE",
    "CLEARTEXT_LOGGING", "CLEARTEXT_STORAGE",
    "LDAP_INJECTION", "XPATH_INJECTION", "NOSQL_INJECTION", "REGEX_INJECTION",
    "URL_REDIRECT", "HEADER_INJECTION", "COOKIE_INJECTION",
    "FLASK_DEBUG", "INSECURE_COOKIE", "WEAK_CRYPTO", "HARDCODED_CREDENTIALS",
    "INSECURE_PROTOCOL", "CERT_VALIDATION_DISABLED",
    "XML_BOMB", "TAR_SLIP", "JINJA2_AUTOESCAPE_FALSE",
    "REDOS", "POLYNOMIAL_REDOS", "BAD_TAG_FILTER", "INCOMPLETE_HOSTNAME_REGEXP",
    "OVERLY_LARGE_RANGE", "INCOMPLETE_URL_SUBSTRING_SANITIZATION",
    "INSECURE_TEMPORARY_FILE", "WEAK_FILE_PERMISSIONS", "PARTIAL_SSRF",
    "BIND_TO_ALL_INTERFACES", "MISSING_HOST_KEY_VALIDATION",
    "CSRF_PROTECTION_DISABLED", "STACK_TRACE_EXPOSURE", "LOG_INJECTION",
    "UNSAFE_SHELL_COMMAND_CONSTRUCTION", "PAM_AUTHORIZATION_BYPASS",
    "UNTRUSTED_DATA_TO_EXTERNAL_API",
    "WEAK_CRYPTO_KEY", "BROKEN_CRYPTO_ALGORITHM", "WEAK_SENSITIVE_DATA_HASHING",
    "INSECURE_DEFAULT_PROTOCOL"
}


# Registry: bug_type -> (predicate, extractor)
# predicate: state -> bool
# extractor: (state, trace) -> dict
# Order matters: specific bugs should be checked before catch-all bugs like PANIC
UNSAFE_PREDICATES: dict[str, tuple[Callable, Callable]] = {
    # ========== Core Error Bug Types (20) ==========
    "ASSERT_FAIL": (assert_fail.is_unsafe_assert_fail, assert_fail.extract_counterexample),
    "DIV_ZERO": (div_zero.is_unsafe_div_zero, div_zero.extract_counterexample),
    "FP_DOMAIN": (fp_domain.is_unsafe_fp_domain, fp_domain.extract_counterexample),
    "INTEGER_OVERFLOW": (integer_overflow.is_unsafe_integer_overflow, integer_overflow.extract_counterexample),
    "BOUNDS": (bounds.is_unsafe_bounds, bounds.extract_counterexample),
    "NULL_PTR": (null_ptr.is_unsafe_null_ptr, null_ptr.extract_counterexample),
    "TYPE_CONFUSION": (type_confusion.is_unsafe_type_confusion, type_confusion.extract_counterexample),
    "STACK_OVERFLOW": (stack_overflow.is_unsafe_stack_overflow, stack_overflow.extract_counterexample),
    "MEMORY_LEAK": (memory_leak.is_unsafe_memory_leak, memory_leak.extract_counterexample),
    "NON_TERMINATION": (non_termination.is_unsafe_non_termination, non_termination.extract_counterexample),
    "ITERATOR_INVALID": (iterator_invalid.is_unsafe_iterator_invalid, iterator_invalid.extract_counterexample),
    "USE_AFTER_FREE": (use_after_free.is_unsafe_use_after_free, use_after_free.extract_counterexample),
    "DOUBLE_FREE": (double_free.is_unsafe_double_free, double_free.extract_counterexample),
    "UNINIT_MEMORY": (uninit_memory.is_unsafe_uninit_memory, uninit_memory.extract_counterexample),
    "DATA_RACE": (data_race.is_unsafe_data_race, data_race.extract_counterexample),
    "DEADLOCK": (deadlock.is_unsafe_deadlock, deadlock.extract_counterexample),
    "SEND_SYNC": (send_sync.is_unsafe_send_sync, send_sync.extract_counterexample),
    "INFO_LEAK": (info_leak.is_unsafe_info_leak, info_leak.extract_counterexample),
    "TIMING_CHANNEL": (timing_channel.is_unsafe_timing_channel, timing_channel.extract_counterexample),
    
    # ========== Security Bug Types (from CodeQL - barrier-certificate-theory.md §11) ==========
    
    # Injection bugs
    "SQL_INJECTION": (sql_injection.is_unsafe_sql_injection, sql_injection.extract_counterexample),
    "COMMAND_INJECTION": (command_injection.is_unsafe_command_injection, command_injection.extract_counterexample),
    "CODE_INJECTION": (code_injection.is_unsafe_code_injection, code_injection.extract_counterexample),
    "PATH_INJECTION": (path_injection.is_unsafe_path_injection, path_injection.extract_counterexample),
    
    # Web security bugs
    "REFLECTED_XSS": (xss.is_unsafe_xss, xss.extract_counterexample),
    
    # Network security bugs
    "SSRF": (ssrf.is_unsafe_ssrf, ssrf.extract_counterexample),
    
    # Serialization bugs
    "UNSAFE_DESERIALIZATION": (deserialization.is_unsafe_deserialization, deserialization.extract_counterexample),
    "XXE": (xxe.is_unsafe_xxe, xxe.extract_counterexample),
    
    # Sensitive data exposure
    "CLEARTEXT_LOGGING": (cleartext.is_unsafe_cleartext_logging, cleartext.extract_counterexample),
    "CLEARTEXT_STORAGE": (cleartext.is_unsafe_cleartext_storage, cleartext.extract_counterexample),
    
    # Additional injection bugs (from injection.py)
    "LDAP_INJECTION": (injection.is_unsafe_ldap_injection, injection.extract_ldap_injection_counterexample),
    "XPATH_INJECTION": (injection.is_unsafe_xpath_injection, injection.extract_xpath_injection_counterexample),
    "NOSQL_INJECTION": (injection.is_unsafe_nosql_injection, injection.extract_nosql_injection_counterexample),
    "REGEX_INJECTION": (injection.is_unsafe_regex_injection, injection.extract_regex_injection_counterexample),
    "URL_REDIRECT": (injection.is_unsafe_url_redirect, injection.extract_url_redirect_counterexample),
    "HEADER_INJECTION": (injection.is_unsafe_header_injection, injection.extract_header_injection_counterexample),
    "COOKIE_INJECTION": (injection.is_unsafe_cookie_injection, injection.extract_cookie_injection_counterexample),
    
    # Configuration-based security bugs (from config.py)
    "FLASK_DEBUG": (config.is_unsafe_flask_debug, config.extract_flask_debug_counterexample),
    "INSECURE_COOKIE": (config.is_unsafe_insecure_cookie, config.extract_insecure_cookie_counterexample),
    "WEAK_CRYPTO": (config.is_unsafe_weak_crypto, config.extract_weak_crypto_counterexample),
    "HARDCODED_CREDENTIALS": (config.is_unsafe_hardcoded_credentials, config.extract_hardcoded_credentials_counterexample),
    "INSECURE_PROTOCOL": (config.is_unsafe_insecure_protocol, config.extract_insecure_protocol_counterexample),
    "CERT_VALIDATION_DISABLED": (config.is_unsafe_cert_validation_disabled, config.extract_cert_validation_disabled_counterexample),
    
    # XML-related bugs (from xml.py)
    "XML_BOMB": (xml.is_unsafe_xml_bomb, xml.extract_xml_bomb_counterexample),
    "TAR_SLIP": (xml.is_unsafe_tar_slip, xml.extract_tar_slip_counterexample),
    "JINJA2_AUTOESCAPE_FALSE": (xml.is_unsafe_jinja2_autoescape_false, xml.extract_jinja2_autoescape_false_counterexample),
    
    # Regex-related bugs (from regex.py)
    "REDOS": (regex.is_unsafe_redos, regex.extract_redos_counterexample),
    "POLYNOMIAL_REDOS": (regex.is_unsafe_polynomial_redos, regex.extract_polynomial_redos_counterexample),
    "BAD_TAG_FILTER": (regex.is_unsafe_bad_tag_filter, regex.extract_bad_tag_filter_counterexample),
    "INCOMPLETE_HOSTNAME_REGEXP": (regex.is_unsafe_incomplete_hostname_regexp, regex.extract_incomplete_hostname_regexp_counterexample),
    "OVERLY_LARGE_RANGE": (regex.is_unsafe_overly_large_range, regex.extract_overly_large_range_counterexample),
    "INCOMPLETE_URL_SUBSTRING_SANITIZATION": (regex.is_unsafe_incomplete_url_substring_sanitization, regex.extract_incomplete_url_substring_sanitization_counterexample),
    
    # Filesystem bugs (from filesystem.py)
    "INSECURE_TEMPORARY_FILE": (filesystem.is_unsafe_insecure_temporary_file, filesystem.extract_insecure_temporary_file_counterexample),
    "WEAK_FILE_PERMISSIONS": (filesystem.is_unsafe_weak_file_permissions, filesystem.extract_weak_file_permissions_counterexample),
    "PARTIAL_SSRF": (filesystem.is_unsafe_partial_ssrf, filesystem.extract_partial_ssrf_counterexample),
    "BIND_TO_ALL_INTERFACES": (filesystem.is_unsafe_bind_to_all_interfaces, filesystem.extract_bind_to_all_interfaces_counterexample),
    "MISSING_HOST_KEY_VALIDATION": (filesystem.is_unsafe_missing_host_key_validation, filesystem.extract_missing_host_key_validation_counterexample),
    
    # Web application bugs (from webapp.py)
    "CSRF_PROTECTION_DISABLED": (webapp.is_unsafe_csrf_protection_disabled, webapp.extract_csrf_protection_disabled_counterexample),
    "STACK_TRACE_EXPOSURE": (webapp.is_unsafe_stack_trace_exposure, webapp.extract_stack_trace_exposure_counterexample),
    "LOG_INJECTION": (webapp.is_unsafe_log_injection, webapp.extract_log_injection_counterexample),
    "UNSAFE_SHELL_COMMAND_CONSTRUCTION": (webapp.is_unsafe_shell_command_construction, webapp.extract_unsafe_shell_command_construction_counterexample),
    "PAM_AUTHORIZATION_BYPASS": (webapp.is_unsafe_pam_authorization_bypass, webapp.extract_pam_authorization_bypass_counterexample),
    "UNTRUSTED_DATA_TO_EXTERNAL_API": (webapp.is_unsafe_untrusted_data_to_external_api, webapp.extract_untrusted_data_to_external_api_counterexample),
    
    # Cryptography bugs (from crypto.py)
    "WEAK_CRYPTO_KEY": (crypto.is_unsafe_weak_crypto_key, crypto.extract_weak_crypto_key_counterexample),
    "BROKEN_CRYPTO_ALGORITHM": (crypto.is_unsafe_broken_crypto_algorithm, crypto.extract_broken_crypto_algorithm_counterexample),
    "WEAK_SENSITIVE_DATA_HASHING": (crypto.is_unsafe_weak_sensitive_data_hashing, crypto.extract_weak_sensitive_data_hashing_counterexample),
    "INSECURE_DEFAULT_PROTOCOL": (crypto.is_unsafe_insecure_default_protocol, crypto.extract_insecure_default_protocol_counterexample),
    
    # ========== Fine-Grained Exception Bug Types (from exception_bugs.py) ==========
    # ITERATION 700: Instead of just PANIC, classify by exception type with
    # specific kitchensink barrier verification strategies for each.
    #
    # Each exception type maps to optimal SOTA papers:
    # - VALUE_ERROR: Predicate Abstraction (#13) + ICE (#17)
    # - RUNTIME_ERROR: CEGAR (#12) + Assume-Guarantee (#20)
    # - FILE_NOT_FOUND: IC3/PDR (#10) + Stochastic (#2)
    # - PERMISSION_ERROR: Assume-Guarantee (#20) + CHC (#11)
    # - OS_ERROR: CEGAR (#12) + Spacer/CHC (#11)
    # - IO_ERROR: Stochastic Barriers (#2)
    # - IMPORT_ERROR: Houdini (#18) + IC3/PDR (#10)
    # - NAME_ERROR: Predicate Abstraction (#13) + IMC (#15)
    # - UNBOUND_LOCAL: SOS-SDP (#6) + IMC (#15)
    # - TIMEOUT_ERROR: Ranking Functions + Stochastic (#2)
    # - CONNECTION_ERROR: Stochastic Barriers (#2) + Assume-Guarantee (#20)
    # - UNICODE_ERROR: Predicate Abstraction (#13) + ICE (#17)
    # See exception_bugs.py for full documentation.
    **EXCEPTION_PREDICATES,
    
    # Catch-all for truly custom exceptions (check last)
    "PANIC": (panic.is_unsafe_panic, panic.extract_counterexample),
}

# ============================================================================
# SEMANTIC BUG TYPES (24 types) - Kitchensink-powered verification
# ============================================================================
# These bug types are NOT checked via predicates but via semantic verification
# using the kitchensink orchestrator. They are listed here for completeness.

SEMANTIC_BUG_TYPES = {
    # Contract bugs (5)
    "PRECONDITION_VIOLATION",
    "POSTCONDITION_VIOLATION",
    "INVARIANT_VIOLATION",
    "REPRESENTATION_INVARIANT",
    "LISKOV_VIOLATION",
    
    # Temporal bugs (6)
    "USE_BEFORE_INIT",
    "USE_AFTER_CLOSE",
    "DOUBLE_CLOSE",
    "MISSING_CLEANUP",
    "ORDER_VIOLATION",
    "CONCURRENT_MODIFICATION",
    
    # Data flow bugs (5)
    "UNVALIDATED_INPUT",
    "UNCHECKED_RETURN",
    "IGNORED_EXCEPTION",
    "PARTIAL_INIT",
    "STALE_VALUE",
    
    # Protocol bugs (4)
    "ITERATOR_PROTOCOL",
    "CONTEXT_MANAGER_PROTOCOL",
    "DESCRIPTOR_PROTOCOL",
    "CALLABLE_PROTOCOL",
    
    # Resource bugs (4)
    "MEMORY_EXHAUSTION",
    "CPU_EXHAUSTION",
    "DISK_EXHAUSTION",
    "HANDLE_EXHAUSTION",
}


def check_unsafe_regions(state, path_trace: list[str]) -> Optional[dict]:
    """
    Check if the given state satisfies any unsafe predicate.
    
    Returns counterexample dict if unsafe, None otherwise.
    This is the core "BUG detection" entry point.
    
    CRITICAL: Check security bugs BEFORE error bugs like PANIC.
    Security violations (CODE_INJECTION, SQL_INJECTION, etc.) are more specific
    and critical than generic exception crashes. A tainted eval() call is a 
    CODE_INJECTION even if it also raises an exception (PANIC).
    
    NOTE: For backward compatibility, returns only the FIRST bug found.
    Use check_all_unsafe_regions() to get all bugs.
    """
    bugs = check_all_unsafe_regions(state, path_trace)
    return bugs[0] if bugs else None


def check_all_unsafe_regions(state, path_trace: list[str]) -> list[dict]:
    """
    Check if the given state satisfies any unsafe predicate.
    
    Returns list of ALL bug counterexamples found (may be empty).
    This enables multi-sink detection where a single value triggers multiple bugs.
    
    Example: logging.info(password) triggers both LOG_INJECTION and CLEARTEXT_LOGGING.
    
    CRITICAL: Check security bugs BEFORE error bugs like PANIC.
    Security violations (CODE_INJECTION, SQL_INJECTION, etc.) are more specific
    and critical than generic exception crashes. A tainted eval() call is a 
    CODE_INJECTION even if it also raises an exception (PANIC).
    """
    bugs_found = []
    
    # DEBUG: Check which predicates are true
    import sys
    import os
    debug = os.environ.get('EXEC_TRACE') == '1'  # Enable with EXEC_TRACE=1
    if debug:
        print("\n=== DEBUG check_all_unsafe_regions ===", file=sys.stderr)
        print(f"Exception: {getattr(state, 'exception', None)}", file=sys.stderr)
        print(f"code_injection_detected: {getattr(state, 'code_injection_detected', False)}", file=sys.stderr)
        if hasattr(state, 'security_violations'):
            print(f"Security violations: {len(state.security_violations)}", file=sys.stderr)
            for v in state.security_violations:
                print(f"  - {v.sink_type}", file=sys.stderr)
    
    # Phase 1: Check ALL security bugs (collect all, don't return early)
    # Use module-level SECURITY_BUG_TYPES defined at top of file
    for bug_type, (predicate, extractor) in UNSAFE_PREDICATES.items():
        if bug_type in SECURITY_BUG_TYPES and predicate(state):
            if debug:
                print(f"SECURITY BUG DETECTED: {bug_type}", file=sys.stderr)
            counterexample = extractor(state, path_trace)
            counterexample['module_init_phase'] = state.module_init_phase
            counterexample['import_count'] = state.import_count
            bugs_found.append(counterexample)
    
    # Phase 2: If no security bugs, check error bugs
    # (Only check error bugs if no security bugs found, to avoid duplication)
    if not bugs_found:
        for bug_type, (predicate, extractor) in UNSAFE_PREDICATES.items():
            if bug_type not in SECURITY_BUG_TYPES and predicate(state):
                if debug:
                    print(f"ERROR BUG DETECTED: {bug_type}", file=sys.stderr)
                counterexample = extractor(state, path_trace)
                counterexample['module_init_phase'] = state.module_init_phase
                counterexample['import_count'] = state.import_count
                bugs_found.append(counterexample)
                break  # Only return first error bug
    
    if debug and bugs_found:
        print(f"*** {len(bugs_found)} BUG(S) DETECTED ***", file=sys.stderr)
        for bug in bugs_found:
            print(f"  - {bug['bug_type']}", file=sys.stderr)
    
    return bugs_found


def list_implemented_bug_types() -> list[str]:
    """Return list of currently implemented bug types."""
    return list(UNSAFE_PREDICATES.keys())


def get_all_unsafe_predicates() -> dict[str, Callable]:
    """
    Return all unsafe predicates as a dict: bug_type -> predicate_fn.
    
    Used for barrier synthesis to construct the full unsafe region U.
    """
    return {bug_type: predicate for bug_type, (predicate, _) in UNSAFE_PREDICATES.items()}
