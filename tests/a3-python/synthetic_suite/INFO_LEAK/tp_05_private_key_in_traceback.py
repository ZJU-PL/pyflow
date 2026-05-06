"""
INFO_LEAK True Positive #5: Private key in exception traceback

Ground truth: BUG
Reason: Private key is in local variable scope when exception occurs, appears in traceback.
Bug type: INFO_LEAK
Unsafe operation: Secret in scope when exception is raised (traceback includes local vars).
"""

def sign_message(message: str, private_key: str) -> str:
    """Sign message with private key"""
    # BUG: Private key is in local scope when exception occurs
    if not message:
        raise ValueError(f"Cannot sign empty message (key: {private_key})")
    
    # Simulate signing
    signature = f"signed_{message}_with_{private_key}"
    return signature

if __name__ == "__main__":
    pk = "-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKC..."  # Taint source: private key
    try:
        result = sign_message("", pk)  # Empty message triggers exception
    except ValueError as e:
        import traceback
        # Traceback will include private_key local variable
        traceback.print_exc()  # BUG: Traceback with secret flows to console
