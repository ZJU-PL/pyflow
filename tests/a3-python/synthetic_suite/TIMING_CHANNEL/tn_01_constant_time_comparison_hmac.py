"""
TIMING_CHANNEL True Negative #1: Constant-time comparison (hmac.compare_digest)

Safe: Uses hmac.compare_digest for constant-time comparison,
preventing timing side-channel attacks.

Expected: SAFE - no timing channel
"""

import hmac


def check_password_safe(user_input: str, correct_password: str) -> bool:
    """
    Safe: hmac.compare_digest performs constant-time comparison.
    """
    # Convert to bytes for comparison
    user_bytes = user_input.encode('utf-8')
    correct_bytes = correct_password.encode('utf-8')
    
    # Constant-time comparison: timing doesn't leak password information
    return hmac.compare_digest(user_bytes, correct_bytes)


def verify_token_safe(user_token: bytes, server_token: bytes) -> bool:
    """
    Safe: Constant-time token verification.
    """
    # hmac.compare_digest is designed for cryptographic comparisons
    # Timing is independent of where inputs differ
    return hmac.compare_digest(user_token, server_token)


def main():
    # Secret password
    SECRET_PASSWORD = "super_secret_password_12345"
    
    # Safe: timing doesn't reveal password information
    user_attempt = "wrong_password"
    
    if check_password_safe(user_attempt, SECRET_PASSWORD):
        print("Access granted")
    else:
        print("Access denied")
    
    # Safe token verification
    SECRET_TOKEN = b"abcdef1234567890ghijklmnopqrstuv"
    user_token = b"invalid_token"
    
    if verify_token_safe(user_token, SECRET_TOKEN):
        print("Token valid")
    else:
        print("Token invalid")


if __name__ == "__main__":
    main()
