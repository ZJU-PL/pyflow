"""
TIMING_CHANNEL True Positive #2: Length-dependent string comparison

Bug: Direct string equality (==) for secrets short-circuits on length mismatch,
creating timing side-channel that reveals secret length.

Expected: BUG - TIMING_CHANNEL detected
"""

def verify_token(user_token: str, server_token: str) -> bool:
    """
    Vulnerable: Built-in == operator short-circuits, leaking length.
    """
    # Python's == will return False immediately if lengths differ
    # Timing reveals secret token length
    return user_token == server_token


def authenticate_api_request(request_token: str) -> bool:
    """API authentication with timing vulnerability."""
    SECRET_API_TOKEN = "abcdef1234567890ghijklmnopqrstuv"
    
    # Attacker can measure timing to determine:
    # 1. Token length (by trying different lengths)
    # 2. Character-by-character matching (via repeated attempts)
    return verify_token(request_token, SECRET_API_TOKEN)


def main():
    import sys
    if len(sys.argv) < 2:
        print("Usage: script.py <token>")
        sys.exit(1)
    
    user_token = sys.argv[1]
    
    if authenticate_api_request(user_token):
        print("Authenticated")
    else:
        print("Authentication failed")


if __name__ == "__main__":
    main()
