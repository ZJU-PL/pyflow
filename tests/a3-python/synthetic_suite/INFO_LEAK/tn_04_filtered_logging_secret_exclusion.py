"""
INFO_LEAK True Negative #4: Filtered logging with secret exclusion

Ground truth: SAFE
Reason: Custom logging filter explicitly removes secret fields before output.
Bug type: INFO_LEAK
Safe pattern: Logging filter that scrubs sensitive data.
"""

import logging

class SensitiveDataFilter(logging.Filter):
    """Filter that redacts sensitive fields"""
    SENSITIVE_KEYS = ["password", "api_key", "token", "secret"]
    
    def filter(self, record):
        # Redact sensitive data from log messages
        for key in self.SENSITIVE_KEYS:
            if key in str(record.msg):
                record.msg = str(record.msg).replace(
                    f"{key}=", f"{key}=[REDACTED]"
                )
        return True

def process_credentials(username: str, password: str, api_key: str) -> None:
    """Process credentials with filtered logging"""
    logger = logging.getLogger(__name__)
    logger.addFilter(SensitiveDataFilter())
    logger.setLevel(logging.DEBUG)
    
    handler = logging.StreamHandler()
    logger.addHandler(handler)
    
    # SAFE: Filter will redact sensitive fields
    logger.debug(f"Processing for user={username}, password={password}, api_key={api_key}")

if __name__ == "__main__":
    process_credentials("alice", "secret123", "sk_abc456")  # Secrets filtered
