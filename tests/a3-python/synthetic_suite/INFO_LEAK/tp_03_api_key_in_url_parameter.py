"""
INFO_LEAK True Positive #3: API key in URL parameter

Ground truth: BUG
Reason: API key is embedded in URL which may be logged by proxies, servers, browsers (history/cache).
Bug type: INFO_LEAK
Unsafe operation: Secret embedded in URL (high-visibility sink).
"""

def make_api_request(api_key: str, endpoint: str) -> str:
    """Make API request with key in URL"""
    # BUG: API key in URL (will appear in logs, history, referer headers)
    url = f"https://api.example.com/{endpoint}?api_key={api_key}"
    
    print(f"Making request to: {url}")  # URL with secret flows to output sink
    
    # Simulate request (in real code, this would use requests library)
    return f"Response from {url}"

if __name__ == "__main__":
    secret_key = "sk_live_abc123def456"  # Taint source: API secret
    response = make_api_request(secret_key, "users")
    print(response)
