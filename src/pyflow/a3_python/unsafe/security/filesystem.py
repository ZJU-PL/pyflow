"""
File system and resource security bug detectors (barrier-certificate-theory.md §11).

Bug Types:
- INSECURE_TEMPORARY_FILE (CWE-377): Race condition in temp file creation
- WEAK_FILE_PERMISSIONS (CWE-732): Overly permissive file permissions
- PARTIAL_SSRF (CWE-918): Partial URL controlled by user
"""

from typing import Any, Optional


# ============================================================================
# INSECURE_TEMPORARY_FILE (CWE-377): py/insecure-temporary-file
# ============================================================================

def is_unsafe_insecure_temporary_file(state) -> bool:
    """
    Check if state is in unsafe region for insecure temp file.
    
    Unsafe region (static):
    U_temp := { s | π == π_temp_file ∧ func ∈ {mktemp, tmpnam, tempnam} }
    
    These functions create race conditions between name creation and file creation.
    """
    return getattr(state, 'insecure_temporary_file_detected', False)


def extract_insecure_temporary_file_counterexample(state, trace: list[str]) -> dict:
    """Extract counterexample for insecure temporary file vulnerability."""
    return {
        "bug_type": "INSECURE_TEMPORARY_FILE",
        "cwe": "CWE-377",
        "query_id": "py/insecure-temporary-file",
        "description": "Using mktemp/tmpnam creates race condition",
        "trace": trace,
        "temp_file_site": getattr(state, 'insecure_temporary_file_site', None),
        "function_used": getattr(state, 'insecure_temporary_file_func', None),
        "mitigation": "Use tempfile.mkstemp() or tempfile.NamedTemporaryFile()"
    }


# ============================================================================
# WEAK_FILE_PERMISSIONS (CWE-732): py/overly-permissive-file
# ============================================================================

def is_unsafe_weak_file_permissions(state) -> bool:
    """
    Check if state is in unsafe region for weak file permissions.
    
    Unsafe region (static):
    U_perms := { s | π == π_chmod ∧ (world_read(mode) ∨ world_write(mode)) }
    """
    return getattr(state, 'weak_file_permissions_detected', False)


def extract_weak_file_permissions_counterexample(state, trace: list[str]) -> dict:
    """Extract counterexample for weak file permissions vulnerability."""
    return {
        "bug_type": "WEAK_FILE_PERMISSIONS",
        "cwe": "CWE-732",
        "query_id": "py/overly-permissive-file",
        "description": "File created with world-readable or world-writable permissions",
        "trace": trace,
        "chmod_site": getattr(state, 'weak_file_permissions_site', None),
        "mode": getattr(state, 'weak_file_permissions_mode', None),
        "mitigation": "Use restrictive permissions (e.g., 0o600, 0o644)"
    }


# ============================================================================
# PARTIAL_SSRF (CWE-918): py/partial-ssrf
# ============================================================================

def is_unsafe_partial_ssrf(state) -> bool:
    """
    Check if state is in unsafe region for partial SSRF.
    
    Unsafe region:
    U_partial_ssrf := { s | π == π_http_request ∧ τ(url_part) == 1 ∧ g_validated == 0 }
    
    Lower severity than full SSRF since base URL is fixed.
    """
    return getattr(state, 'partial_ssrf_detected', False)


def extract_partial_ssrf_counterexample(state, trace: list[str]) -> dict:
    """Extract counterexample for partial SSRF vulnerability."""
    return {
        "bug_type": "PARTIAL_SSRF",
        "cwe": "CWE-918",
        "query_id": "py/partial-ssrf",
        "description": "Part of URL controlled by user in server-side request",
        "trace": trace,
        "request_site": getattr(state, 'partial_ssrf_site', None),
        "tainted_part": getattr(state, 'partial_ssrf_tainted_part', None),
        "mitigation": "Validate and sanitize URL path/query components"
    }


# ============================================================================
# BIND_TO_ALL_INTERFACES (CVE-2018-1281): py/bind-socket-all-network-interfaces
# ============================================================================

def is_unsafe_bind_to_all_interfaces(state) -> bool:
    """
    Check if state is in unsafe region for binding to all interfaces.
    
    Unsafe region (static):
    U_bind := { s | π == π_socket_bind ∧ host ∈ {"0.0.0.0", "", "::", "::0"} }
    """
    return getattr(state, 'bind_to_all_interfaces_detected', False)


def extract_bind_to_all_interfaces_counterexample(state, trace: list[str]) -> dict:
    """Extract counterexample for binding to all interfaces vulnerability."""
    return {
        "bug_type": "BIND_TO_ALL_INTERFACES",
        "cwe": "CVE-2018-1281",
        "query_id": "py/bind-socket-all-network-interfaces",
        "description": "Socket bound to 0.0.0.0 or :: accepts traffic from any interface",
        "trace": trace,
        "bind_site": getattr(state, 'bind_to_all_interfaces_site', None),
        "host": getattr(state, 'bind_to_all_interfaces_host', None),
        "mitigation": "Bind to specific interface (e.g., 127.0.0.1)"
    }


# ============================================================================
# MISSING_HOST_KEY_VALIDATION (CWE-295): py/paramiko-missing-host-key-validation
# ============================================================================

def is_unsafe_missing_host_key_validation(state) -> bool:
    """
    Check if state is in unsafe region for missing SSH host key validation.
    
    Unsafe region (static):
    U_hostkey := { s | π == π_set_policy ∧ policy ∈ {AutoAddPolicy, WarningPolicy} }
    """
    return getattr(state, 'missing_host_key_validation_detected', False)


def extract_missing_host_key_validation_counterexample(state, trace: list[str]) -> dict:
    """Extract counterexample for missing host key validation vulnerability."""
    return {
        "bug_type": "MISSING_HOST_KEY_VALIDATION",
        "cwe": "CWE-295",
        "query_id": "py/paramiko-missing-host-key-validation",
        "description": "SSH connection with AutoAddPolicy accepts any host key",
        "trace": trace,
        "policy_site": getattr(state, 'missing_host_key_validation_site', None),
        "policy": getattr(state, 'missing_host_key_validation_policy', None),
        "mitigation": "Use RejectPolicy or verify host keys from known_hosts"
    }
