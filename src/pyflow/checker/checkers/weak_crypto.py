"""
Weak Cryptography Detection.

This module provides security tests that detect weak cryptographic practices,
including:
- Weak key sizes (e.g., AES keys < 128 bits)
- Weak hash functions (MD5, SHA1)
- Insecure cryptographic primitives

**Test IDs:**
- B303: Weak cryptographic key sizes
- B304: Weak hash functions (MD5, SHA1)

**Note:** Many weak crypto checks are also handled by the blacklist system
(e.g., MD5, SHA1, weak ciphers). These tests provide additional checks for
specific scenarios like key size validation.
"""

# Check for weak cryptographic practices
import ast

from ..core import issue
from ..core import test_properties as test


def weak_crypto_issue():
    """
    Create a generic weak crypto issue.
    
    Returns:
        Issue object with MEDIUM severity, HIGH confidence
    """
    return issue.Issue(
        severity="MEDIUM",
        confidence="HIGH",
        cwe=issue.Cwe.BROKEN_CRYPTO,
        text="Use of weak cryptographic primitive.",
    )


@test.checks("Call")
@test.with_id("B303")
def weak_cryptographic_key(context):
    """
    Check for weak cryptographic key sizes.
    
    Validates AES key sizes to ensure they meet minimum security requirements.
    AES keys should be at least 128 bits for security.
    
    Args:
        context: Context object with call information
        
    Returns:
        Issue object if weak key size detected, None otherwise
    """
    if context.call_function_name_qual in ["Crypto.Cipher.AES.new", "AES.new"]:
        # Check for weak key sizes (< 128 bits)
        key_size = context.get_call_arg_value("key_size")
        if key_size and int(key_size) < 128:
            return weak_crypto_issue()


@test.checks("Call")
@test.with_id("B304")
def weak_hash_functions(context):
    """
    Check for weak hash functions.
    
    Detects use of cryptographically weak hash functions (MD5, SHA1)
    which are vulnerable to collision attacks and should not be used
    for security purposes.
    
    Args:
        context: Context object with call information
        
    Returns:
        Issue object if weak hash function detected, None otherwise
        
    Note:
        This is a fallback check. Most weak hash functions are also
        caught by the blacklist system (B303).
    """
    if context.call_function_name_qual in ["hashlib.md5", "hashlib.sha1"]:
        return issue.Issue(
            severity="MEDIUM",
            confidence="HIGH",
            cwe=issue.Cwe.BROKEN_CRYPTO,
            text="Use of insecure MD4, MD5, or SHA1 hash function.",
        )
