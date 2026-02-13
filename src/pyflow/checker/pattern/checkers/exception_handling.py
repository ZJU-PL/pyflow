"""
Exception Handling Pattern Checks.

This module provides security tests that detect dangerous exception handling
patterns that may hide errors or security issues.

**Test IDs:**
- B108: try_except_pass - Exception swallowing with pass
- B110: try_except_raise - Re-raising caught exceptions improperly
- B112: try_except_continue - Continuing after exception in loop
"""

import ast
import re

from ..core import issue
from ..core import test_properties as test


# Exception types that should not be silently swallowed
CRITICAL_EXCEPTIONS = [
    "KeyboardInterrupt",
    "SystemExit",
    "GeneratorExit",
    "BaseException",
]


def _get_exception_handlers(node):
    """
    Extract exception handlers from a try statement.

    Returns a list of (exception_type, handler_body) tuples.
    """
    handlers = []
    for handler in node.handlers:
        if handler.type:
            # Get exception type name
            if isinstance(handler.type, ast.Name):
                exc_type = handler.type.id
            elif isinstance(handler.type, ast.Attribute):
                exc_type = handler.type.attr
            else:
                exc_type = None
        else:
            exc_type = None  # bare except clause

        handlers.append((exc_type, handler.body))
    return handlers


def _is_pass_statement(body):
    """Check if body is just a pass statement."""
    # body is a list of statements, not a single node
    return len(body) == 1 and isinstance(body[0], ast.Pass)


def _is_continue_statement(body):
    """Check if body contains continue statement."""
    # body is a list of statements, not a single node
    for node in body:
        for child in ast.walk(node):
            if isinstance(child, ast.Continue):
                return True
    return False


def _contains_dangerous_exceptions(handlers):
    """Check if handlers catch critical exceptions."""
    for exc_type, _ in handlers:
        if exc_type in CRITICAL_EXCEPTIONS:
            return True
        if exc_type == "Exception" and exc_type not in [
            "OSError",
            "ValueError",
            "TypeError",
        ]:
            return True
    return False


@test.checks("Try")
@test.with_id("B108")
def try_except_pass(context):
    """
    Check for try-except blocks that silently swallow exceptions with pass.

    This pattern hides errors and can:
    - Mask security failures
    - Hide authentication errors
    - Conceal data corruption
    - Make debugging extremely difficult

    Examples:
        try:
            dangerous_operation()
        except Exception:
            pass  # BAD: Silently swallowing

    Args:
        context: Context object with try statement information

    Returns:
        Issue object if dangerous pattern detected, None otherwise
    """
    node = context.node

    handlers = _get_exception_handlers(node)
    for exc_type, body in handlers:
        if _is_pass_statement(body):
            # Check if this is catching a broad exception type
            if exc_type is None or exc_type in ["Exception", "BaseException"]:
                return issue.Issue(
                    severity="MEDIUM",
                    confidence="HIGH",
                    cwe=issue.Cwe.IMPROPER_ERROR_HANDLING,
                    text="Try-except block with a bare 'except:' clause and 'pass' statement. "
                    "This pattern silently swallows all exceptions and may hide important "
                    "errors or security failures. Consider logging the exception or "
                    "removing the try-except block entirely.",
                )
            else:
                return issue.Issue(
                    severity="LOW",
                    confidence="MEDIUM",
                    cwe=issue.Cwe.IMPROPER_ERROR_HANDLING,
                    text=f"Try-except block with 'except {exc_type}: pass'. "
                    "This pattern silently swallows {exc_type} exceptions. "
                    "Consider logging the exception or handling it appropriately.",
                )


@test.checks("Try")
@test.with_id("B109")
def try_except_pass_password(context):
    """
    Check for try-except blocks that swallow exceptions in authentication.

    Silently swallowing authentication-related exceptions may indicate:
    - Intentional security bypass
        - Accidentally hiding real errors

    Args:
        context: Context object with try statement information

    Returns:
        Issue object if dangerous pattern detected, None otherwise
    """
    node = context.node

    # Keywords that indicate auth/security context
    AUTH_KEYWORDS = [
        "password",
        "auth",
        "login",
        "credential",
        "secret",
        "token",
        "verify",
        "check",
        "permission",
        "admin",
        "user",
        "session",
    ]

    # Check parent context for auth-related names
    parent = getattr(node, "_bandit_parent", None)
    parent_name = None

    if parent:
        if isinstance(parent, ast.FunctionDef):
            parent_name = parent.name.lower()
        elif isinstance(parent, ast.ClassDef):
            parent_name = parent.name.lower()

    handlers = _get_exception_handlers(node)
    for exc_type, body in handlers:
        if _is_pass_statement(body):
            # Check if this is in an authentication context
            if parent_name and any(kw in parent_name for kw in AUTH_KEYWORDS):
                return issue.Issue(
                    severity="HIGH",
                    confidence="MEDIUM",
                    cwe=issue.Cwe.WEAK_CREDENTIALS,
                    text="Try-except-pass pattern in authentication context. "
                    "Silently swallowing exceptions during authentication may "
                    "mask failed security checks or hide authentication errors.",
                )

    return None


@test.checks("Try")
@test.with_id("B110")
def try_except_raise(context):
    """
    Check for improper exception re-raising patterns.

    Anti-patterns:
    - Bare 'raise' outside except clause
    - Raising generic Exception/BaseException instead of specific type
    - Losing the original traceback

    Args:
        context: Context object with try statement information

    Returns:
        Issue object if dangerous pattern detected, None otherwise
    """
    node = context.node

    handlers = _get_exception_handlers(node)
    for exc_type, body in handlers:
        for stmt in body:
            # Check for bare raise (outside except clause context)
            if isinstance(stmt, ast.Raise):
                # raise without argument outside except clause
                if stmt.exc is None:
                    # This is valid within an except clause, not here
                    pass

                # Check for raising generic exceptions
                elif stmt.exc and isinstance(stmt.exc, ast.Name):
                    exc_name = stmt.exc.id
                    if exc_name in ["Exception", "BaseException", "GeneralException"]:
                        return issue.Issue(
                            severity="LOW",
                            confidence="MEDIUM",
                            cwe=issue.Cwe.IMPROPER_ERROR_HANDLING,
                            text=f"Raising generic exception '{exc_name}'. "
                            "Consider raising a more specific exception type "
                            "to provide better error information.",
                        )

    return None


@test.checks("Try")
@test.with_id("B112")
def try_except_continue(context):
    """
    Check for try-except with continue in loop.

    This pattern can:
    - Skip processing silently
    - Hide errors in batch operations
    - Make data validation failures invisible

    Args:
        context: Context object with try statement information

    Returns:
        Issue object if dangerous pattern detected, None otherwise
    """
    node = context.node

    handlers = _get_exception_handlers(node)
    for exc_type, body in handlers:
        if _is_continue_statement(body):
            # Check if this is a broad exception type
            if exc_type is None or exc_type in ["Exception", "BaseException"]:
                return issue.Issue(
                    severity="MEDIUM",
                    confidence="HIGH",
                    cwe=issue.Cwe.IMPROPER_ERROR_HANDLING,
                    text="Try-except block with continue statement. "
                    "This pattern silently skips items in a loop when exceptions occur. "
                    "Consider logging the exception or handling it explicitly.",
                )
            else:
                return issue.Issue(
                    severity="LOW",
                    confidence="MEDIUM",
                    cwe=issue.Cwe.IMPROPER_ERROR_HANDLING,
                    text=f"Try-except block with continue for {exc_type}. "
                    "This pattern silently skips processing on exception. "
                    "Consider logging or explicit error handling.",
                )

    return None


@test.checks("Try")
@test.with_id("B113")
def try_except_generic(context):
    """
    Check for catching overly broad exceptions.

    Catching Exception or BaseException can hide real problems:
    - Catching KeyboardInterrupt (user pressed Ctrl+C)
    - Catching SystemExit (sys.exit() called)
    - Catching MemoryError (out of memory)
    - Catching RecursionError (infinite recursion)

    Args:
        context: Context object with try statement information

    Returns:
        Issue object if dangerous pattern detected, None otherwise
    """
    node = context.node

    handlers = _get_exception_handlers(node)
    for exc_type, body in handlers:
        if exc_type in ["Exception", "BaseException"]:
            if not _is_pass_statement(body) and not _is_continue_statement(body):
                return issue.Issue(
                    severity="LOW",
                    confidence="MEDIUM",
                    cwe=issue.Cwe.IMPROPER_ERROR_HANDLING,
                    text="Try-except block catches generic 'Exception' or 'BaseException'. "
                    "Consider catching more specific exception types to avoid "
                    "hiding unexpected errors like KeyboardInterrupt or SystemExit.",
                )

    return None
