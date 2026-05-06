"""
INFO_LEAK True Negative #3: Secure credential handling (Authorization header)

Ground truth: SAFE
Reason: API key passed in Authorization header (not in URL), headers not logged.
Bug type: INFO_LEAK
Safe pattern: Using headers for secrets, not logging sensitive headers.
"""

def make_api_request_safe(api_key: str, endpoint: str) -> str:
    """Make API request with key in header (safe)"""
    # SAFE: API key in Authorization header, not in URL
    url = f"https://api.example.com/{endpoint}"
    headers = {"Authorization": f"Bearer {api_key}"}
    
    # Log only non-sensitive parts
    print(f"Making request to: {url}")  # SAFE: No secret in URL
    print(f"Headers count: {len(headers)}")  # SAFE: Not logging actual headers
    
    # Simulate request
    return f"Response from {url}"

if __name__ == "__main__":
    secret_key = "sk_live_abc123def456"  # Secret
    response = make_api_request_safe(secret_key, "users")
    print(response)  # SAFE: No secret leaked to output
