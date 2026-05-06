"""
INFO_LEAK True Negative #5: Exception handling without secret exposure

Ground truth: SAFE
Reason: Exceptions are caught and sanitized; secrets never appear in output.
Bug type: INFO_LEAK
Safe pattern: Defensive exception handling with secret scrubbing.
"""

def sign_message_safe(message: str, private_key: str) -> str:
    """Sign message with safe error handling"""
    try:
        if not message:
            # SAFE: Generic error without secret
            raise ValueError("Cannot sign empty message")
        
        # Simulate signing
        signature = f"signed_{message}"
        return signature
    except ValueError:
        # SAFE: Re-raise without including secret in any way
        print("Error: Invalid message for signing")
        raise ValueError("Signing failed") from None  # No traceback chain

if __name__ == "__main__":
    pk = "-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKC..."  # Secret
    try:
        result = sign_message_safe("", pk)
    except ValueError as e:
        # SAFE: Error message and traceback don't contain private key
        print(f"Caught error: {e}")
