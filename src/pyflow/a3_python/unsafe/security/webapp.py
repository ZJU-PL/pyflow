"""
Web application security bug detectors (barrier-certificate-theory.md §11).

Bug Types:
- CSRF_PROTECTION_DISABLED (CWE-352): CSRF protection disabled
- STACK_TRACE_EXPOSURE (CWE-209): Stack trace exposed to user
- LOG_INJECTION (CWE-117): User input in log entries
- UNSAFE_SHELL_COMMAND_CONSTRUCTION (CWE-078): Shell command from library input
"""

from typing import Any, Optional


# ============================================================================
# CSRF_PROTECTION_DISABLED (CWE-352): py/csrf-protection-disabled
# ============================================================================

def is_unsafe_csrf_protection_disabled(state) -> bool:
    """
    Check if state is in unsafe region for CSRF protection disabled.
    
    Unsafe region (static):
    U_csrf := { s | π == π_csrf_setting ∧ csrf_verification == False }
    """
    return getattr(state, 'csrf_protection_disabled_detected', False)


def extract_csrf_protection_disabled_counterexample(state, trace: list[str]) -> dict:
    """Extract counterexample for CSRF protection disabled vulnerability."""
    return {
        "bug_type": "CSRF_PROTECTION_DISABLED",
        "cwe": "CWE-352",
        "query_id": "py/csrf-protection-disabled",
        "description": "CSRF protection disabled or weakened",
        "trace": trace,
        "csrf_site": getattr(state, 'csrf_protection_disabled_site', None),
        "mitigation": "Enable CSRF protection middleware"
    }


# ============================================================================
# STACK_TRACE_EXPOSURE (CWE-209): py/stack-trace-exposure
# ============================================================================

def is_unsafe_stack_trace_exposure(state) -> bool:
    """
    Check if state is in unsafe region for stack trace exposure.
    
    Unsafe region:
    U_stacktrace := { s | π == π_response ∧ StackTraceFlowsTo(content) }
    """
    return getattr(state, 'stack_trace_exposure_detected', False)


def extract_stack_trace_exposure_counterexample(state, trace: list[str]) -> dict:
    """Extract counterexample for stack trace exposure vulnerability."""
    return {
        "bug_type": "STACK_TRACE_EXPOSURE",
        "cwe": "CWE-209",
        "query_id": "py/stack-trace-exposure",
        "description": "Stack trace information exposed to external user",
        "trace": trace,
        "response_site": getattr(state, 'stack_trace_exposure_site', None),
        "mitigation": "Catch exceptions and return generic error messages in production"
    }


# ============================================================================
# LOG_INJECTION (CWE-117): py/log-injection
# ============================================================================

def is_unsafe_log_injection(state) -> bool:
    """
    Check if state is in unsafe region for log injection.
    
    Unsafe region:
    U_log_inject := { s | π == π_log ∧ τ(logged_value) == 1 ∧ ContainsNewline(logged_value) }
    """
    return getattr(state, 'log_injection_detected', False)


def extract_log_injection_counterexample(state, trace: list[str]) -> dict:
    """Extract counterexample for log injection vulnerability."""
    return {
        "bug_type": "LOG_INJECTION",
        "cwe": "CWE-117",
        "query_id": "py/log-injection",
        "description": "User input in log entries enables log forging",
        "trace": trace,
        "log_site": getattr(state, 'log_injection_site', None),
        "tainted_value": getattr(state, 'log_injection_value', None),
        "mitigation": "Sanitize user input before logging (remove newlines)"
    }


# ============================================================================
# UNSAFE_SHELL_COMMAND_CONSTRUCTION (CWE-078): py/shell-command-constructed-from-input
# ============================================================================

def is_unsafe_shell_command_construction(state) -> bool:
    """
    Check if state is in unsafe region for unsafe shell command construction.
    
    Same pattern as COMMAND_INJECTION but sources include library inputs.
    """
    return getattr(state, 'unsafe_shell_command_construction_detected', False)


def extract_unsafe_shell_command_construction_counterexample(state, trace: list[str]) -> dict:
    """Extract counterexample for unsafe shell command construction vulnerability."""
    return {
        "bug_type": "UNSAFE_SHELL_COMMAND_CONSTRUCTION",
        "cwe": "CWE-078",
        "query_id": "py/shell-command-constructed-from-input",
        "description": "Shell command constructed from library input",
        "trace": trace,
        "shell_site": getattr(state, 'unsafe_shell_command_construction_site', None),
        "tainted_input": getattr(state, 'unsafe_shell_command_construction_input', None),
        "mitigation": "Use shlex.quote() or pass arguments as list without shell=True"
    }


# ============================================================================
# PAM_AUTHORIZATION_BYPASS (CWE-285): py/pam-auth-bypass
# ============================================================================

def is_unsafe_pam_authorization_bypass(state) -> bool:
    """
    Check if state is in unsafe region for PAM authorization bypass.
    
    Unsafe region (static):
    U_pam := { s | π == π_pam_auth ∧ ¬FollowedByAcctMgmt(call) }
    """
    return getattr(state, 'pam_authorization_bypass_detected', False)


def extract_pam_authorization_bypass_counterexample(state, trace: list[str]) -> dict:
    """Extract counterexample for PAM authorization bypass vulnerability."""
    return {
        "bug_type": "PAM_AUTHORIZATION_BYPASS",
        "cwe": "CWE-285",
        "query_id": "py/pam-auth-bypass",
        "description": "Using pam_authenticate without pam_acct_mgmt",
        "trace": trace,
        "pam_site": getattr(state, 'pam_authorization_bypass_site', None),
        "mitigation": "Call pam_acct_mgmt after pam_authenticate"
    }


# ============================================================================
# UNTRUSTED_DATA_TO_EXTERNAL_API (CWE-020): py/untrusted-data-to-external-api
# ============================================================================

def is_unsafe_untrusted_data_to_external_api(state) -> bool:
    """
    Check if state is in unsafe region for untrusted data to external API.
    
    Unsafe region:
    U_external := { s | π == π_external_call ∧ τ(arg) == 1 ∧ ¬Validated(arg) }
    """
    return getattr(state, 'untrusted_data_to_external_api_detected', False)


def extract_untrusted_data_to_external_api_counterexample(state, trace: list[str]) -> dict:
    """Extract counterexample for untrusted data to external API vulnerability."""
    return {
        "bug_type": "UNTRUSTED_DATA_TO_EXTERNAL_API",
        "cwe": "CWE-020",
        "query_id": "py/untrusted-data-to-external-api",
        "description": "Untrusted data passed to external API without validation",
        "trace": trace,
        "api_site": getattr(state, 'untrusted_data_to_external_api_site', None),
        "api_name": getattr(state, 'untrusted_data_to_external_api_name', None),
        "mitigation": "Validate and sanitize data before passing to external APIs"
    }
