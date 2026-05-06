"""
INFO_LEAK True Positive #4: Authentication token in logged HTTP headers

Ground truth: BUG
Reason: Full HTTP headers including Authorization are logged, leaking bearer token.
Bug type: INFO_LEAK
Unsafe operation: Logging complete headers dict including secret token.
"""

import logging

def send_authenticated_request(token: str, data: dict) -> None:
    """Send request with authentication token"""
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json"
    }
    
    # BUG: Logging headers including secret token
    logging.basicConfig(level=logging.DEBUG)
    logging.debug(f"Sending request with headers: {headers}")
    
    print(f"Request sent with data: {data}")

if __name__ == "__main__":
    auth_token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.secret"  # Taint source: JWT token
    send_authenticated_request(auth_token, {"action": "update"})
