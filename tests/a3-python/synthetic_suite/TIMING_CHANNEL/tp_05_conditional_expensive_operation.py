"""
TIMING_CHANNEL True Positive #5: Conditional expensive operation on secret

Bug: Expensive operation is conditionally executed based on secret value,
creating large timing differences that leak the secret.

Expected: BUG - TIMING_CHANNEL detected
"""

def verify_signature(message: bytes, signature: bytes, valid_signature: bytes) -> bool:
    """
    Vulnerable: Signature validation with early rejection on mismatch.
    """
    if len(signature) != len(valid_signature):
        # Fast path: length mismatch
        return False
    
    # Byte-by-byte comparison with early return
    for i in range(len(signature)):
        if signature[i] != valid_signature[i]:
            # Early return leaks how many bytes matched
            return False
    
    # Only reached if signature matches - expensive hash computation
    import hashlib
    message_hash = hashlib.sha256(message).digest()
    
    # Simulate expensive verification
    for _ in range(10000):
        hashlib.sha256(message_hash).digest()
    
    return True


def cache_lookup_with_secret_key(cache_key: str, secret_prefix: str) -> str:
    """
    Vulnerable: Cache lookup time depends on whether key has secret prefix.
    """
    # If key starts with secret prefix, perform expensive lookup
    if cache_key.startswith(secret_prefix):
        # Expensive path: timing reveals secret prefix match
        result = ""
        for _ in range(5000):
            result += cache_key[:10]
        return result[:100]
    
    # Fast path: simple lookup
    return "not_found"


def main():
    # Secret signature
    SECRET_SIGNATURE = b"valid_signature_bytes_here_1234567890"
    
    # Attacker can measure timing to determine signature bytes
    user_signature = b"invalid_signature"
    message = b"transaction_data"
    
    is_valid = verify_signature(message, user_signature, SECRET_SIGNATURE)
    print(f"Signature valid: {is_valid}")
    
    # Secret cache prefix
    SECRET_PREFIX = "admin_"
    
    # Timing reveals whether cache key has secret prefix
    test_key = "admin_user_123"
    result = cache_lookup_with_secret_key(test_key, SECRET_PREFIX)
    print(f"Cache result: {result[:20]}")


if __name__ == "__main__":
    main()
