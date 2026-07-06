"""
INFO_LEAK True Positive #1: Secret logged to console

Ground truth: BUG
Reason: API key (secret) is directly logged to console output, creating an information leak.
Bug type: INFO_LEAK
Unsafe operation: Logging sensitive credential to standard output sink.
"""

import logging

def authenticate_user(username: str, api_key: str) -> bool:
    """Authenticate with API key"""
    # BUG: Logging secret to console
    logging.basicConfig(level=logging.DEBUG)
    logging.debug(f"Authenticating user {username} with API key: {api_key}")
    
    # Simulate authentication
    return api_key == "secret_key_12345"

if __name__ == "__main__":
    user = "alice"
    key = "secret_key_12345"  # Taint source: secret
    result = authenticate_user(user, key)
    print(f"Authentication result: {result}")
