"""
INFO_LEAK True Negative #2: Sensitive data redacted from error messages

Ground truth: SAFE
Reason: Error messages never include actual password, only metadata.
Bug type: INFO_LEAK
Safe pattern: Sanitized error messages without secrets.
"""

def login_safe(username: str, password: str) -> bool:
    """Login with secure error messages"""
    valid_users = {"alice": "pass123", "bob": "secret456"}
    
    # SAFE: Error messages don't include password
    if username not in valid_users:
        raise ValueError(f"Invalid login for user {username}")
    
    if valid_users[username] != password:
        raise ValueError(f"Authentication failed for user {username}")
    
    return True

if __name__ == "__main__":
    try:
        result = login_safe("alice", "wrongpass")  # Secret password
    except ValueError as e:
        print(f"Error: {e}")  # SAFE: No password in error message
