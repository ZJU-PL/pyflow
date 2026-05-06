"""
INFO_LEAK True Negative #1: Secrets masked in logs

Ground truth: SAFE
Reason: Secret is explicitly masked/redacted before logging.
Bug type: INFO_LEAK
Safe pattern: Masking sensitive values before output.
"""

import logging

def authenticate_user_safe(username: str, api_key: str) -> bool:
    """Authenticate with API key (safe logging)"""
    logging.basicConfig(level=logging.DEBUG)
    
    # SAFE: Mask the secret before logging
    masked_key = api_key[:4] + "****" + api_key[-4:] if len(api_key) > 8 else "****"
    logging.debug(f"Authenticating user {username} with API key: {masked_key}")
    
    return api_key == "secret_key_12345"

if __name__ == "__main__":
    user = "alice"
    key = "secret_key_12345"  # Secret
    result = authenticate_user_safe(user, key)
    print(f"Authentication result: {result}")  # Only masked version in output
