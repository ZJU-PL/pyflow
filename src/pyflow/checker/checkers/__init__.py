"""
Security Checkers.

This package contains individual security test modules. Each checker module
implements specific security tests using the @checks and @with_id decorators
to register tests for specific node types.

**Checker Modules:**
- blacklist_calls: Checks for blacklisted function calls
- blacklist_imports: Checks for blacklisted module imports
- class_pollution: Detects class pollution vulnerabilities
- exec_use: Detects dangerous exec/eval usage
- hardcoded_password: Detects hardcoded passwords
- shell_injection: Detects shell injection vulnerabilities
- sql_injection: Detects SQL injection vulnerabilities
- weak_crypto: Detects weak cryptography usage

**Test Registration:**
Tests are registered using decorators:
- @checks("Call"): Register for Call nodes
- @with_id("B301"): Assign test ID

**Test Function Signature:**
Tests take a Context object and optionally a config dictionary:
```python
@checks("Call")
@with_id("B301")
def my_test(context, config=None):
    # Check for security issue
    if issue_found:
        return Issue(...)
    return None
```
"""
