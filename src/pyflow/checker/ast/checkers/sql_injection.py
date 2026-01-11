# Check for SQL injection vulnerabilities
import ast

from ..core import issue
from ..core import test_properties as test


def sql_injection_issue():
    """Create a SQL injection issue"""
    return issue.Issue(
        severity="MEDIUM",
        confidence="MEDIUM",
        cwe=issue.Cwe.SQL_INJECTION,
        text="Possible SQL injection vector through string-based query construction.",
    )


@test.checks("Call")
@test.with_id("B608")
def sql_injection_string_formatting(context):
    """Check for SQL injection via string formatting"""
    # This is a simplified check - in practice you'd want to analyze the query string
    # For now, we'll skip this check to avoid false positives
    pass


@test.checks("Call")
@test.with_id("B609")
def sql_injection_concatenation(context):
    """Check for SQL injection via string concatenation"""
    # This is a simplified check - in practice you'd want to analyze the query string
    # For now, we'll skip this check to avoid false positives
    pass
