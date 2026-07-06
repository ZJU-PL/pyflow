"""
Security bug detection modules (barrier-certificate-theory.md §11).

This package contains unsafe region predicates for all 47 CodeQL security queries.
Each module defines:
- is_unsafe_<bug_type>(state) -> bool: Check if state is in unsafe region
- extract_counterexample(state, trace) -> dict: Extract bug details

Mode A (pure symbolic): Sound over-approximation using taint bits
Mode B (concolic): Optional concrete validation for diagnostics
"""

# Core injection bugs
from .sql_injection import is_unsafe_sql_injection, extract_counterexample as extract_sql_injection
from .command_injection import is_unsafe_command_injection, extract_counterexample as extract_command_injection
from .code_injection import is_unsafe_code_injection, extract_counterexample as extract_code_injection
from .path_injection import is_unsafe_path_injection, extract_counterexample as extract_path_injection

# Web security bugs
from .xss import is_unsafe_xss, extract_counterexample as extract_xss
from .ssrf import is_unsafe_ssrf, extract_counterexample as extract_ssrf

# Serialization/XML bugs
from .deserialization import is_unsafe_deserialization, extract_counterexample as extract_deserialization
from .xxe import is_unsafe_xxe, extract_counterexample as extract_xxe

# Sensitive data exposure
from .cleartext import is_unsafe_cleartext_logging, is_unsafe_cleartext_storage, extract_counterexample as extract_cleartext

# Additional injection bugs
from .injection import (
    is_unsafe_ldap_injection, extract_ldap_injection_counterexample,
    is_unsafe_xpath_injection, extract_xpath_injection_counterexample,
    is_unsafe_nosql_injection, extract_nosql_injection_counterexample,
    is_unsafe_regex_injection, extract_regex_injection_counterexample,
    is_unsafe_url_redirect, extract_url_redirect_counterexample,
    is_unsafe_header_injection, extract_header_injection_counterexample,
    is_unsafe_cookie_injection, extract_cookie_injection_counterexample,
)

# Configuration-based bugs
from .config import (
    is_unsafe_flask_debug, extract_flask_debug_counterexample,
    is_unsafe_insecure_cookie, extract_insecure_cookie_counterexample,
    is_unsafe_weak_crypto, extract_weak_crypto_counterexample,
    is_unsafe_hardcoded_credentials, extract_hardcoded_credentials_counterexample,
    is_unsafe_insecure_protocol, extract_insecure_protocol_counterexample,
    is_unsafe_cert_validation_disabled, extract_cert_validation_disabled_counterexample,
)

# XML-related bugs
from .xml import (
    is_unsafe_xml_bomb, extract_xml_bomb_counterexample,
    is_unsafe_tar_slip, extract_tar_slip_counterexample,
    is_unsafe_jinja2_autoescape_false, extract_jinja2_autoescape_false_counterexample,
)

# Regex-related bugs
from .regex import (
    is_unsafe_redos, extract_redos_counterexample,
    is_unsafe_polynomial_redos, extract_polynomial_redos_counterexample,
    is_unsafe_bad_tag_filter, extract_bad_tag_filter_counterexample,
    is_unsafe_incomplete_hostname_regexp, extract_incomplete_hostname_regexp_counterexample,
    is_unsafe_overly_large_range, extract_overly_large_range_counterexample,
    is_unsafe_incomplete_url_substring_sanitization, extract_incomplete_url_substring_sanitization_counterexample,
)

# Filesystem-related bugs
from .filesystem import (
    is_unsafe_insecure_temporary_file, extract_insecure_temporary_file_counterexample,
    is_unsafe_weak_file_permissions, extract_weak_file_permissions_counterexample,
    is_unsafe_partial_ssrf, extract_partial_ssrf_counterexample,
    is_unsafe_bind_to_all_interfaces, extract_bind_to_all_interfaces_counterexample,
    is_unsafe_missing_host_key_validation, extract_missing_host_key_validation_counterexample,
)

# Web application bugs
from .webapp import (
    is_unsafe_csrf_protection_disabled, extract_csrf_protection_disabled_counterexample,
    is_unsafe_stack_trace_exposure, extract_stack_trace_exposure_counterexample,
    is_unsafe_log_injection, extract_log_injection_counterexample,
    is_unsafe_shell_command_construction, extract_unsafe_shell_command_construction_counterexample,
    is_unsafe_pam_authorization_bypass, extract_pam_authorization_bypass_counterexample,
    is_unsafe_untrusted_data_to_external_api, extract_untrusted_data_to_external_api_counterexample,
)

# Cryptography bugs
from .crypto import (
    is_unsafe_weak_crypto_key, extract_weak_crypto_key_counterexample,
    is_unsafe_broken_crypto_algorithm, extract_broken_crypto_algorithm_counterexample,
    is_unsafe_weak_sensitive_data_hashing, extract_weak_sensitive_data_hashing_counterexample,
    is_unsafe_insecure_default_protocol, extract_insecure_default_protocol_counterexample,
)

__all__ = [
    # Core injection
    'is_unsafe_sql_injection', 'extract_sql_injection',
    'is_unsafe_command_injection', 'extract_command_injection',
    'is_unsafe_code_injection', 'extract_code_injection',
    'is_unsafe_path_injection', 'extract_path_injection',
    
    # Web security
    'is_unsafe_xss', 'extract_xss',
    'is_unsafe_ssrf', 'extract_ssrf',
    
    # Serialization
    'is_unsafe_deserialization', 'extract_deserialization',
    'is_unsafe_xxe', 'extract_xxe',
    
    # Sensitive data
    'is_unsafe_cleartext_logging', 'is_unsafe_cleartext_storage', 'extract_cleartext',
    
    # Additional injection
    'is_unsafe_ldap_injection', 'extract_ldap_injection_counterexample',
    'is_unsafe_xpath_injection', 'extract_xpath_injection_counterexample',
    'is_unsafe_nosql_injection', 'extract_nosql_injection_counterexample',
    'is_unsafe_regex_injection', 'extract_regex_injection_counterexample',
    'is_unsafe_url_redirect', 'extract_url_redirect_counterexample',
    'is_unsafe_header_injection', 'extract_header_injection_counterexample',
    'is_unsafe_cookie_injection', 'extract_cookie_injection_counterexample',
    
    # Configuration bugs
    'is_unsafe_flask_debug', 'extract_flask_debug_counterexample',
    'is_unsafe_insecure_cookie', 'extract_insecure_cookie_counterexample',
    'is_unsafe_weak_crypto', 'extract_weak_crypto_counterexample',
    'is_unsafe_hardcoded_credentials', 'extract_hardcoded_credentials_counterexample',
    'is_unsafe_insecure_protocol', 'extract_insecure_protocol_counterexample',
    'is_unsafe_cert_validation_disabled', 'extract_cert_validation_disabled_counterexample',
    
    # XML-related
    'is_unsafe_xml_bomb', 'extract_xml_bomb_counterexample',
    'is_unsafe_tar_slip', 'extract_tar_slip_counterexample',
    'is_unsafe_jinja2_autoescape_false', 'extract_jinja2_autoescape_false_counterexample',
    
    # Regex-related
    'is_unsafe_redos', 'extract_redos_counterexample',
    'is_unsafe_polynomial_redos', 'extract_polynomial_redos_counterexample',
    'is_unsafe_bad_tag_filter', 'extract_bad_tag_filter_counterexample',
    'is_unsafe_incomplete_hostname_regexp', 'extract_incomplete_hostname_regexp_counterexample',
    'is_unsafe_overly_large_range', 'extract_overly_large_range_counterexample',
    'is_unsafe_incomplete_url_substring_sanitization', 'extract_incomplete_url_substring_sanitization_counterexample',
    
    # Filesystem
    'is_unsafe_insecure_temporary_file', 'extract_insecure_temporary_file_counterexample',
    'is_unsafe_weak_file_permissions', 'extract_weak_file_permissions_counterexample',
    'is_unsafe_partial_ssrf', 'extract_partial_ssrf_counterexample',
    'is_unsafe_bind_to_all_interfaces', 'extract_bind_to_all_interfaces_counterexample',
    'is_unsafe_missing_host_key_validation', 'extract_missing_host_key_validation_counterexample',
    
    # Web application
    'is_unsafe_csrf_protection_disabled', 'extract_csrf_protection_disabled_counterexample',
    'is_unsafe_stack_trace_exposure', 'extract_stack_trace_exposure_counterexample',
    'is_unsafe_log_injection', 'extract_log_injection_counterexample',
    'is_unsafe_shell_command_construction', 'extract_unsafe_shell_command_construction_counterexample',
    'is_unsafe_pam_authorization_bypass', 'extract_pam_authorization_bypass_counterexample',
    'is_unsafe_untrusted_data_to_external_api', 'extract_untrusted_data_to_external_api_counterexample',
    
    # Cryptography
    'is_unsafe_weak_crypto_key', 'extract_weak_crypto_key_counterexample',
    'is_unsafe_broken_crypto_algorithm', 'extract_broken_crypto_algorithm_counterexample',
    'is_unsafe_weak_sensitive_data_hashing', 'extract_weak_sensitive_data_hashing_counterexample',
    'is_unsafe_insecure_default_protocol', 'extract_insecure_default_protocol_counterexample',
]
