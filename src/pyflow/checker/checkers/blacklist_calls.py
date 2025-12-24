"""
Blacklist Checker for Function Calls.

This module provides a security test that checks function calls against
a blacklist of dangerous functions. The blacklist includes functions
known to have security implications such as:
- Deserialization functions (pickle.loads, marshal.load)
- Weak cryptography (MD5, SHA1, weak ciphers)
- Command injection (eval)
- Insecure protocols (telnet, FTP)
- XML vulnerabilities
- And many more...

**Test ID Range:** B301-B323

**How It Works:**
1. Extracts the fully qualified function name from the call
2. Checks against the blacklist using pattern matching
3. Returns an Issue if a match is found

**Blacklist Patterns:**
Supports both exact matches and wildcard patterns (e.g., "pickle.*")
"""

# Blacklist checker for function calls
# Based on blacklist system
import ast

from ..core import blacklist
from ..core import test_properties as test


@test.checks("Call")
@test.with_id("B301-B323")
def check_blacklisted_calls(context):
    """
    Check for blacklisted function calls.
    
    This test checks if a function call matches any pattern in the
    call blacklist. If a match is found, returns a security issue
    with HIGH confidence (blacklist matches are considered reliable).
    
    Args:
        context: Context object with call information
        
    Returns:
        Issue object if blacklisted, None otherwise
    """
    qualname = getattr(context, 'call_function_name_qual', None)
    return blacklist.blacklist_manager.check_blacklist("Call", qualname, context) if qualname else None
