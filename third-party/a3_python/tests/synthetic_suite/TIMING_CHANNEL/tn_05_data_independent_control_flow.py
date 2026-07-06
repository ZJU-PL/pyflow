"""
TIMING_CHANNEL True Negative #5: Data-independent control flow

Safe: Control flow is independent of secret data, eliminating timing side-channels.

Expected: SAFE - no timing channel
"""

def authenticate_with_rate_limiting(username: str, password: str, correct_password: str) -> bool:
    """
    Safe: Always performs same operations with rate limiting to obscure timing.
    """
    import hmac
    import time
    
    # Convert to bytes
    password_bytes = password.encode('utf-8')
    correct_bytes = correct_password.encode('utf-8')
    
    # Constant-time comparison
    is_valid = hmac.compare_digest(password_bytes, correct_bytes)
    
    # Fixed delay for all authentication attempts
    # This adds noise and prevents timing analysis
    time.sleep(0.1)  # 100ms delay for all attempts
    
    return is_valid


def cache_lookup_data_independent(cache_key: str, prefix_to_check: str) -> str:
    """
    Safe: Always performs same operations regardless of prefix match.
    """
    # Check prefix but don't branch on result
    has_prefix = cache_key.startswith(prefix_to_check)
    
    # Always perform expensive lookup (even if prefix doesn't match)
    result = ""
    for _ in range(5000):
        result += cache_key[:10]
    expensive_result = result[:100]
    
    # Also compute fast result
    fast_result = "not_found"
    
    # Use constant-time selection (both values computed)
    # In reality, use bitwise selection to avoid branch
    return expensive_result if has_prefix else fast_result


def process_secret_bits_constant_time(secret_bits: str, public_input: int) -> int:
    """
    Safe: Process all bits with same operations (no secret-dependent branching).
    """
    result = public_input
    
    # Always perform same number of operations for each bit
    for bit in secret_bits:
        # Compute both paths
        path_if_one = (result * result) % 999999937
        path_if_zero = (result * 1 + 0) % 999999937
        
        # Select based on bit without timing leak
        # (Real implementation would use bitwise masking)
        if bit == '1':
            result = path_if_one
        else:
            result = path_if_zero
    
    # Better: always do the expensive operation
    for bit in secret_bits:
        # Perform operation regardless of bit value
        result = (result * result) % 999999937
    
    return result


def main():
    # Safe authentication with rate limiting
    username = "user123"
    password = "attempt"
    SECRET_PASSWORD = "super_secret_password"
    
    is_valid = authenticate_with_rate_limiting(username, password, SECRET_PASSWORD)
    print(f"Authentication result: {is_valid}")
    
    # Safe cache lookup
    cache_key = "admin_user_123"
    prefix = "admin_"
    
    result = cache_lookup_data_independent(cache_key, prefix)
    print(f"Cache result: {result[:20]}")
    
    # Safe bit processing
    SECRET_BITS = "101101"
    public_data = 12345
    
    output = process_secret_bits_constant_time(SECRET_BITS, public_data)
    print(f"Processed result: {output}")


if __name__ == "__main__":
    main()
