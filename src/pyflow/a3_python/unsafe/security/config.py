"""
Configuration-based security bugs (static checks).

These bugs don't require taint tracking - they're detected statically:
- FLASK_DEBUG (CWE-215)
- INSECURE_COOKIE (CWE-614)
- CSRF_PROTECTION_DISABLED (CWE-352)
- WEAK_CRYPTO (CWE-327)
- INSECURE_PROTOCOL (CWE-327)
- HARDCODED_CREDENTIALS (CWE-798)
- BIND_TO_ALL_INTERFACES (CVE-2018-1281)
- MISSING_HOST_KEY_VALIDATION (CWE-295)
- REQUEST_WITHOUT_CERT_VALIDATION (CWE-295)
"""


def is_unsafe_flask_debug(state) -> bool:
    """Flask running with debug=True in production."""
    return getattr(state, 'flask_debug_detected', False)


def extract_flask_debug_counterexample(state, path_trace: list) -> dict:
    """Extract counterexample for Flask debug mode."""
    return {
        "bug_type": "FLASK_DEBUG",
        "cwe": "CWE-215",
        "severity": "high",
        "location": "unknown",
        "message": "Flask debug mode enabled (exposes Werkzeug debugger - RCE risk)",
        "barrier_info": {
            "unsafe_region": "U_debug := { s | flask.run(debug=True) }"
        }
    }


def is_unsafe_insecure_cookie(state) -> bool:
    """Cookie without Secure/HttpOnly flags."""
    return getattr(state, 'insecure_cookie_detected', False)


def extract_insecure_cookie_counterexample(state, path_trace: list) -> dict:
    """Extract counterexample for insecure cookie."""
    return {
        "bug_type": "INSECURE_COOKIE",
        "cwe": "CWE-614",
        "severity": "medium",
        "location": "unknown",
        "message": "Cookie set without Secure/HttpOnly/SameSite flags",
        "barrier_info": {
            "unsafe_region": "U_cookie := { s | set_cookie ∧ ¬secure_flags }"
        }
    }


def is_unsafe_weak_crypto(state) -> bool:
    """Use of weak cryptographic algorithm for sensitive data."""
    return getattr(state, 'weak_crypto_detected', False)


def extract_weak_crypto_counterexample(state, path_trace: list) -> dict:
    """Extract counterexample for weak crypto."""
    return {
        "bug_type": "WEAK_CRYPTO",
        "cwe": "CWE-327",
        "severity": "high",
        "location": "unknown",
        "message": "Weak cryptographic algorithm (MD5/SHA1 for passwords)",
        "barrier_info": {
            "unsafe_region": "U_crypto := { s | hash(sensitive) ∧ algo ∈ {MD5,SHA1} }"
        }
    }


def is_unsafe_hardcoded_credentials(state) -> bool:
    """Credentials hard-coded in source."""
    return getattr(state, 'hardcoded_credentials_detected', False)


def extract_hardcoded_credentials_counterexample(state, path_trace: list) -> dict:
    """Extract counterexample for hardcoded credentials."""
    return {
        "bug_type": "HARDCODED_CREDENTIALS",
        "cwe": "CWE-798",
        "severity": "high",
        "location": "unknown",
        "message": "Hard-coded credentials in source code",
        "barrier_info": {
            "unsafe_region": "U_hardcoded := { s | literal_at_credential_use }"
        }
    }


def is_unsafe_insecure_protocol(state) -> bool:
    """Using insecure SSL/TLS version."""
    return getattr(state, 'insecure_protocol_detected', False)


def extract_insecure_protocol_counterexample(state, path_trace: list) -> dict:
    """Extract counterexample for insecure protocol."""
    return {
        "bug_type": "INSECURE_PROTOCOL",
        "cwe": "CWE-327",
        "severity": "high",
        "location": "unknown",
        "message": "Insecure SSL/TLS version (SSLv2/SSLv3/TLS1.0/TLS1.1)",
        "barrier_info": {
            "unsafe_region": "U_tls := { s | ssl_context ∧ protocol ∈ insecure_set }"
        }
    }


def is_unsafe_cert_validation_disabled(state) -> bool:
    """Request without certificate validation."""
    return getattr(state, 'cert_validation_disabled_detected', False)


def extract_cert_validation_disabled_counterexample(state, path_trace: list) -> dict:
    """Extract counterexample for disabled cert validation."""
    return {
        "bug_type": "REQUEST_WITHOUT_CERT_VALIDATION",
        "cwe": "CWE-295",
        "severity": "high",
        "location": "unknown",
        "message": "HTTPS request with verify=False (MITM vulnerability)",
        "barrier_info": {
            "unsafe_region": "U_cert := { s | https_request ∧ verify=False }"
        }
    }
