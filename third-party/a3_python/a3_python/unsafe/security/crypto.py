"""
Cryptography security bug detectors (barrier-certificate-theory.md §11).

Bug Types:
- WEAK_CRYPTO_KEY (CWE-326): Weak cryptographic key size
- BROKEN_CRYPTO_ALGORITHM (CWE-327): Weak/broken encryption algorithm
- WEAK_SENSITIVE_DATA_HASHING (CWE-327): Non-KDF for password hashing
- INSECURE_DEFAULT_PROTOCOL (CWE-327): Unspecified SSL/TLS protocol
"""

from typing import Any, Optional


# ============================================================================
# WEAK_CRYPTO_KEY (CWE-326): py/weak-crypto-key
# ============================================================================

def is_unsafe_weak_crypto_key(state) -> bool:
    """
    Check if state is in unsafe region for weak crypto key.
    
    Unsafe region (static):
    U_weak_key := { s | π == π_keygen ∧ key_size < MinSecureSize(algorithm) }
    
    Minimum secure sizes:
    - RSA: 2048 bits
    - DSA: 2048 bits
    - EC: 256 bits (P-256 or equivalent)
    """
    return getattr(state, 'weak_crypto_key_detected', False)


def extract_weak_crypto_key_counterexample(state, trace: list[str]) -> dict:
    """Extract counterexample for weak crypto key vulnerability."""
    return {
        "bug_type": "WEAK_CRYPTO_KEY",
        "cwe": "CWE-326",
        "query_id": "py/weak-crypto-key",
        "description": "Cryptographic key size below minimum secure size",
        "trace": trace,
        "keygen_site": getattr(state, 'weak_crypto_key_site', None),
        "algorithm": getattr(state, 'weak_crypto_key_algorithm', None),
        "key_size": getattr(state, 'weak_crypto_key_size', None),
        "mitigation": "Use RSA-2048+, EC-256+, or equivalent"
    }


# ============================================================================
# BROKEN_CRYPTO_ALGORITHM (CWE-327): py/weak-cryptographic-algorithm
# ============================================================================

def is_unsafe_broken_crypto_algorithm(state) -> bool:
    """
    Check if state is in unsafe region for broken crypto algorithm.
    
    Unsafe region (static):
    U_weak_algo := { s | π == π_encrypt ∧ algorithm ∈ {DES, RC4, Blowfish_small_key, ECB_mode} }
    """
    return getattr(state, 'broken_crypto_algorithm_detected', False)


def extract_broken_crypto_algorithm_counterexample(state, trace: list[str]) -> dict:
    """Extract counterexample for broken crypto algorithm vulnerability."""
    return {
        "bug_type": "BROKEN_CRYPTO_ALGORITHM",
        "cwe": "CWE-327",
        "query_id": "py/weak-cryptographic-algorithm",
        "description": "Use of broken/weak encryption algorithm",
        "trace": trace,
        "encrypt_site": getattr(state, 'broken_crypto_algorithm_site', None),
        "algorithm": getattr(state, 'broken_crypto_algorithm_name', None),
        "mitigation": "Use AES-256-GCM or ChaCha20-Poly1305"
    }


# ============================================================================
# WEAK_SENSITIVE_DATA_HASHING (CWE-327): py/weak-sensitive-data-hashing
# ============================================================================

def is_unsafe_weak_sensitive_data_hashing(state) -> bool:
    """
    Check if state is in unsafe region for weak password hashing.
    
    Unsafe region:
    U_weak_hash := { s | π == π_hash ∧ σ(input) == 1 ∧ algorithm ∈ {MD5, SHA1, SHA256_raw} }
    
    Note: Uses sensitivity taint σ instead of untrusted taint τ.
    """
    return getattr(state, 'weak_sensitive_data_hashing_detected', False)


def extract_weak_sensitive_data_hashing_counterexample(state, trace: list[str]) -> dict:
    """Extract counterexample for weak sensitive data hashing vulnerability."""
    return {
        "bug_type": "WEAK_SENSITIVE_DATA_HASHING",
        "cwe": "CWE-327",
        "query_id": "py/weak-sensitive-data-hashing",
        "description": "Using MD5/SHA1/SHA256 (non-KDF) for password hashing",
        "trace": trace,
        "hash_site": getattr(state, 'weak_sensitive_data_hashing_site', None),
        "algorithm": getattr(state, 'weak_sensitive_data_hashing_algorithm', None),
        "mitigation": "Use bcrypt, argon2, scrypt, or PBKDF2"
    }


# ============================================================================
# INSECURE_DEFAULT_PROTOCOL (CWE-327): py/insecure-default-protocol
# ============================================================================

def is_unsafe_insecure_default_protocol(state) -> bool:
    """
    Check if state is in unsafe region for insecure default protocol.
    
    Unsafe region (static):
    U_default_tls := { s | π == π_wrap_socket ∧ ¬SpecifiedProtocol(call) }
    """
    return getattr(state, 'insecure_default_protocol_detected', False)


def extract_insecure_default_protocol_counterexample(state, trace: list[str]) -> dict:
    """Extract counterexample for insecure default protocol vulnerability."""
    return {
        "bug_type": "INSECURE_DEFAULT_PROTOCOL",
        "cwe": "CWE-327",
        "query_id": "py/insecure-default-protocol",
        "description": "Using ssl.wrap_socket() without specifying protocol",
        "trace": trace,
        "wrap_site": getattr(state, 'insecure_default_protocol_site', None),
        "mitigation": "Use ssl.create_default_context() or specify PROTOCOL_TLS_CLIENT"
    }
