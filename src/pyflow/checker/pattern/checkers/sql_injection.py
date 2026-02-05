# Check for SQL injection vulnerabilities
import ast
import re

from ..core import issue
from ..core import test_properties as test

# SQL keywords that indicate dangerous operations
SQL_DANGEROUS_KEYWORDS = [
    "SELECT", "INSERT", "UPDATE", "DELETE", "DROP", "ALTER", "CREATE", "TRUNCATE",
    "EXEC", "EXECUTE", "UNION", "GRANT", "REVOKE", "SHUTDOWN", "DELETE", "xp_",
]

# String formatting patterns that could lead to SQL injection
SQL_STRING_FORMAT_PATTERNS = [
    "%",  # % formatting
    "{",  # .format() or f-string
    "+",  # string concatenation
]

# Function names that commonly execute SQL
SQL_EXECUTION_FUNCTIONS = [
    "execute", "executemany", "executescript", "cursor",
    "execute_sql", "run_query", "query", "raw_query",
]


def sql_injection_issue(text="Possible SQL injection vector through string-based query construction."):
    """Create a SQL injection issue"""
    return issue.Issue(
        severity="MEDIUM",
        confidence="MEDIUM",
        cwe=issue.Cwe.SQL_INJECTION,
        text=text,
    )


def _get_string(node):
    """Extract string value from AST node"""
    if isinstance(node, ast.Str):
        return node.s
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    return None


def _is_sql_related_call(context):
    """Check if the call is related to SQL execution"""
    func_name = context.call_function_name_qual or ""
    # Check for common SQL execution patterns
    return any(keyword in func_name.lower() for keyword in SQL_EXECUTION_FUNCTIONS)


def _check_string_for_sql(text):
    """Check if a string contains SQL-related content"""
    text_upper = text.upper()
    # Check for dangerous SQL keywords
    for keyword in SQL_DANGEROUS_KEYWORDS:
        if keyword in text_upper:
            return True
    return False


def _check_for_string_formatting(node):
    """Check if a node involves string formatting"""
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Mod):
        return True
    if isinstance(node, ast.Call):
        func_name = ""
        if isinstance(node.func, ast.Name):
            func_name = node.func.id
        elif isinstance(node.func, ast.Attribute):
            func_name = node.func.attr
        return func_name in ["format", "join"]
    if isinstance(node, ast.JoinedStr):  # f-string
        return True
    return False


@test.checks("Call")
@test.with_id("B608")
def sql_injection_string_formatting(context):
    """Check for SQL injection via string formatting"""
    # Only check calls that look like SQL execution
    if not _is_sql_related_call(context):
        return None
    
    # Check string arguments for formatting patterns
    for arg in context.node.args:
        arg_str = _get_string(arg)
        if arg_str and _check_string_for_sql(arg_str):
            if _check_for_string_formatting(context.node):
                return sql_injection_issue()
        
        # Check if arg is a formatted string with SQL content
        if isinstance(arg, (ast.BinOp, ast.Call, ast.JoinedStr)):
            # Look for SQL keywords in formatted strings
            if isinstance(arg, ast.BinOp) and isinstance(arg.op, ast.Mod):
                # % formatting
                left_str = _get_string(arg.left)
                if left_str and _check_string_for_sql(left_str):
                    return sql_injection_issue()
    
    # Check keyword arguments
    for kw in context.node.keywords:
        if kw.arg and ("sql" in kw.arg.lower() or "query" in kw.arg.lower()):
            kw_str = _get_string(kw.value)
            if kw_str and _check_string_for_sql(kw_str):
                if _check_for_string_formatting(kw.value):
                    return sql_injection_issue()
    
    return None


@test.checks("Call")
@test.with_id("B609")
def sql_injection_concatenation(context):
    """Check for SQL injection via string concatenation"""
    # Only check calls that look like SQL execution
    if not _is_sql_related_call(context):
        return None
    
    # Check for string concatenation in arguments
    for arg in context.node.args:
        if isinstance(arg, ast.BinOp) and isinstance(arg.op, ast.Add):
            # String concatenation found
            left_str = _get_string(arg.left)
            right_str = _get_string(arg.right)
            
            # Check if any part contains SQL
            if (left_str and _check_string_for_sql(left_str)) or \
               (right_str and _check_string_for_sql(right_str)):
                return sql_injection_issue(
                    "Possible SQL injection via string concatenation. "
                    "Use parameterized queries instead."
                )
    
    # Check keyword arguments for concatenation
    for kw in context.node.keywords:
        if kw.arg and ("sql" in kw.arg.lower() or "query" in kw.arg.lower()):
            if isinstance(kw.value, ast.BinOp) and isinstance(kw.value.op, ast.Add):
                return sql_injection_issue(
                    "Possible SQL injection via string concatenation in keyword argument. "
                    "Use parameterized queries instead."
                )
    
    return None
