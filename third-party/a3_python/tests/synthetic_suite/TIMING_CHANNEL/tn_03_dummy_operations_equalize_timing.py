"""
TIMING_CHANNEL True Negative #3: Dummy operations to equalize timing

Safe: All code paths perform equivalent operations to eliminate timing differences,
preventing timing side-channel attacks.

Expected: SAFE - no timing channel
"""

def check_permission_safe(user_id: int, admin_flag: bool) -> bool:
    """
    Safe: Both branches perform equivalent work to prevent timing leak.
    """
    # Admin path
    admin_result = True
    admin_dummy_work = 0
    for i in range(1000):
        admin_dummy_work += i * user_id % 997
    
    # Non-admin path
    non_admin_result = False
    permissions = []
    for i in range(1000):
        permissions.append(i * user_id % 997)
    non_admin_result = user_id in permissions
    
    # Select result without timing leak
    # Both paths always execute, timing is constant
    if admin_flag:
        return admin_result
    else:
        return non_admin_result


def verify_signature_safe(signature: bytes, valid_signature: bytes) -> bool:
    """
    Safe: Always performs full comparison regardless of early mismatch.
    """
    import hmac
    
    # Constant-time length comparison
    if len(signature) != len(valid_signature):
        # Pad to same length for constant-time processing
        max_len = max(len(signature), len(valid_signature))
        signature = signature.ljust(max_len, b'\x00')
        valid_signature = valid_signature.ljust(max_len, b'\x00')
    
    # Constant-time byte comparison using hmac.compare_digest
    return hmac.compare_digest(signature, valid_signature)


def main():
    # Safe permission check - timing independent of admin status
    user_id = 42
    is_admin = True
    
    result = check_permission_safe(user_id, is_admin)
    print(f"Permission granted: {result}")
    
    # Safe signature verification
    signature = b"test_signature_bytes"
    valid = b"valid_signature_here"
    
    is_valid = verify_signature_safe(signature, valid)
    print(f"Signature valid: {is_valid}")


if __name__ == "__main__":
    main()
