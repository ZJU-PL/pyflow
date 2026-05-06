"""
INFO_LEAK True Positive #2: Password in error message

Ground truth: BUG
Reason: Password is included in error message that may be logged, displayed, or propagated.
Bug type: INFO_LEAK
Unsafe operation: Including secret in exception message text.
"""

def login(username: str, password: str) -> bool:
    """Login with username and password"""
    valid_users = {"alice": "pass123", "bob": "secret456"}
    
    if username not in valid_users:
        # BUG: Password leaked in error message
        raise ValueError(f"Invalid login for user {username} with password {password}")
    
    if valid_users[username] != password:
        # BUG: Password leaked in error message
        raise ValueError(f"Wrong password {password} for user {username}")
    
    return True

if __name__ == "__main__":
    try:
        result = login("alice", "wrongpass")  # Taint source: secret password
    except ValueError as e:
        print(f"Error: {e}")  # Error message containing password flows to sink
