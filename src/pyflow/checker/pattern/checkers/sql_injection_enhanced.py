"""
SQL Injection Pattern Checks.

This module provides enhanced SQL injection detection including ORM patterns.

**Test IDs:**
- B610: Django ORM extra() with user input
- B611: SQLAlchemy raw SQL with string formatting
- B612: SQLAlchemy text() with string formatting
- B613: Dynamic table/column names
"""

import ast
import re

from ..core import issue
from ..core import test_properties as test


# SQL execution functions
DJANGO_ORM_FUNCTIONS = [
    "extra",
    "raw",
    "select_related",
    "prefetch_related",
]

SQLALCHEMY_FUNCTIONS = [
    "execute",
    "text",
    "session.execute",
    "connection.execute",
]

DJANGO_CURSOR_FUNCTIONS = [
    "cursor",
    "connection.cursor",
]

SQL_KEYWORDS = [
    "SELECT",
    "INSERT",
    "UPDATE",
    "DELETE",
    "DROP",
    "CREATE",
    "ALTER",
    "UNION",
    "EXEC",
    "EXECUTE",
    "GRANT",
    "REVOKE",
]


def _get_string(node):
    """Extract string value from AST node."""
    if isinstance(node, ast.Str):
        return node.s
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    return None


def _is_user_input(node):
    """Check if a node represents user input."""
    if isinstance(node, ast.Name):
        name = node.id.lower()
        suspicious_names = [
            "user",
            "input",
            "data",
            "payload",
            "request",
            "form",
            "query",
            "param",
            "arg",
            "value",
            "id",
            "name",
            "username",
            "password",
            "email",
            "search",
            "filter",
            "sort",
            "order",
        ]
        return any(sn in name for sn in suspicious_names)
    return False


def _contains_sql_keyword(text):
    """Check if text contains SQL keywords."""
    if not text:
        return False
    text_upper = text.upper()
    return any(kw in text_upper for kw in SQL_KEYWORDS)


@test.checks("Call")
@test.with_id("B610")
def django_orm_extra_injection(context):
    """
    Check for Django ORM extra() with user input.

    Django's extra() method allows raw SQL, which can be vulnerable
    to SQL injection if user input is included:

        User.objects.extra(where=[f"id = {user_input}"])  # DANGEROUS!

    Safe patterns:
        User.objects.extra(where=["id = %s"], params=[user_input])  # Safe

    Args:
        context: Context object with call information

    Returns:
        Issue object if dangerous pattern detected, None otherwise
    """
    node = context.node
    func_name = context.call_function_name_qual

    if not func_name:
        return None

    # Check if this is a Django ORM extra() call
    if "extra" in func_name:
        # Check 'where' parameter
        for kw in node.keywords:
            if kw.arg == "where":
                where_value = kw.value

                # Check if it's a formatted string
                if isinstance(where_value, ast.JoinedStr):
                    # f-string: extra(where=[f"id = {user_input}"])
                    return issue.Issue(
                        severity="HIGH",
                        confidence="HIGH",
                        cwe=issue.Cwe.SQL_INJECTION,
                        text="Django ORM extra() with f-string in 'where' parameter. "
                        "This is a SQL injection vulnerability. "
                        "Use parameterized queries instead.",
                    )

                # Check for % formatting
                if isinstance(where_value, ast.BinOp) and isinstance(
                    where_value.op, ast.Mod
                ):
                    left_str = _get_string(where_value.left)
                    if left_str and _contains_sql_keyword(left_str):
                        return issue.Issue(
                            severity="HIGH",
                            confidence="HIGH",
                            cwe=issue.Cwe.SQL_INJECTION,
                            text="Django ORM extra() with % formatting containing SQL. "
                            "This is a SQL injection vulnerability.",
                        )

                # Check for .format()
                if isinstance(where_value, ast.Call):
                    if (
                        hasattr(where_value.func, "attr")
                        and where_value.func.attr == "format"
                    ):
                        format_str = (
                            _get_string(where_value.func.value)
                            if hasattr(where_value.func, "value")
                            else None
                        )
                        if format_str and _contains_sql_keyword(format_str):
                            return issue.Issue(
                                severity="HIGH",
                                confidence="HIGH",
                                cwe=issue.Cwe.SQL_INJECTION,
                                text="Django ORM extra() with .format() containing SQL. "
                                "This is a SQL injection vulnerability.",
                            )

        # Check 'select' parameter
        for kw in node.keywords:
            if kw.arg == "select":
                select_value = kw.value
                if isinstance(select_value, ast.JoinedStr):
                    return issue.Issue(
                        severity="HIGH",
                        confidence="HIGH",
                        cwe=issue.Cwe.SQL_INJECTION,
                        text="Django ORM extra() with f-string in 'select' parameter. "
                        "This is a SQL injection vulnerability.",
                    )

    return None


@test.checks("Call")
@test.with_id("B611")
def sqlalchemy_raw_sql_injection(context):
    """
    Check for SQLAlchemy raw SQL with string formatting.

    SQLAlchemy's execute() method can be vulnerable if raw SQL
    is constructed with string formatting:

        session.execute(f"SELECT * FROM users WHERE id = {user_id}")  # DANGEROUS!

    Safe patterns:
        session.execute("SELECT * FROM users WHERE id = :id", {"id": user_id})

    Args:
        context: Context object with call information

    Returns:
        Issue object if dangerous pattern detected, None otherwise
    """
    node = context.node
    func_name = context.call_function_name_qual

    if not func_name:
        return None

    # Check if this is a SQLAlchemy execute() or text() call
    is_sqlalchemy = any(sa in func_name for sa in SQLALCHEMY_FUNCTIONS)

    if not is_sqlalchemy:
        return None

    # Check first positional argument
    if len(node.args) > 0:
        first_arg = node.args[0]

        # f-string
        if isinstance(first_arg, ast.JoinedStr):
            # Check if it contains SQL keywords
            for elt in first_arg.values:
                if isinstance(elt, ast.Constant) and isinstance(elt.value, str):
                    if _contains_sql_keyword(elt.value):
                        return issue.Issue(
                            severity="HIGH",
                            confidence="HIGH",
                            cwe=issue.Cwe.SQL_INJECTION,
                            text="SQLAlchemy execute() with f-string containing SQL keywords. "
                            "This is a SQL injection vulnerability. "
                            "Use parameterized queries with :param or ? placeholders.",
                        )

                # Check if f-string contains a variable
                if isinstance(elt, ast.FormattedValue):
                    return issue.Issue(
                        severity="HIGH",
                        confidence="MEDIUM",
                        cwe=issue.Cwe.SQL_INJECTION,
                        text="SQLAlchemy execute() with f-string. "
                        "This pattern can lead to SQL injection if "
                        "the interpolated value is user-controlled.",
                    )

        # % formatting
        if isinstance(first_arg, ast.BinOp) and isinstance(first_arg.op, ast.Mod):
            left_str = _get_string(first_arg.left)
            if left_str and _contains_sql_keyword(left_str):
                return issue.Issue(
                    severity="HIGH",
                    confidence="HIGH",
                    cwe=issue.Cwe.SQL_INJECTION,
                    text="SQLAlchemy execute() with % formatting containing SQL. "
                    "This is a SQL injection vulnerability.",
                )

        # .format()
        if isinstance(first_arg, ast.Call):
            if hasattr(first_arg.func, "attr") and first_arg.func.attr == "format":
                format_str = (
                    _get_string(first_arg.func.value)
                    if hasattr(first_arg.func, "value")
                    else None
                )
                if format_str and _contains_sql_keyword(format_str):
                    return issue.Issue(
                        severity="HIGH",
                        confidence="HIGH",
                        cwe=issue.Cwe.SQL_INJECTION,
                        text="SQLAlchemy execute() with .format() containing SQL. "
                        "This is a SQL injection vulnerability.",
                    )

    return None


@test.checks("Call")
@test.with_id("B612")
def sqlalchemy_dynamic_table_names(context):
    """
    Check for dynamic table/column names in SQL queries.

    Using string formatting for table or column names can lead to
    SQL injection:

        table_name = user_input
        session.execute(f"SELECT * FROM {table_name}")  # DANGEROUS!

    Note: Unlike values, table/column names cannot be parameterized.

    Args:
        context: Context object with call information

    Returns:
        Issue object if dangerous pattern detected, None otherwise
    """
    node = context.node
    func_name = context.call_function_name_qual

    if not func_name:
        return None

    # Check if this is a SQLAlchemy or Django cursor call
    is_sql = any(
        sa in func_name for sa in SQLALCHEMY_FUNCTIONS + DJANGO_CURSOR_FUNCTIONS
    )

    if not is_sql:
        return None

    # Check first positional argument
    if len(node.args) > 0:
        first_arg = node.args[0]

        # f-string with variables
        if isinstance(first_arg, ast.JoinedStr):
            for elt in first_arg.values:
                if isinstance(elt, ast.FormattedValue):
                    if _is_user_input(elt.value):
                        return issue.Issue(
                            severity="MEDIUM",
                            confidence="MEDIUM",
                            cwe=issue.Cwe.SQL_INJECTION,
                            text="SQL query with user-controlled table/column name. "
                            "Table and column names cannot be parameterized. "
                            "Use an allowlist of permitted names.",
                        )

    # Check keywords
    for kw in node.keywords:
        if kw.arg and "table" in kw.arg.lower() or "column" in kw.arg.lower():
            if isinstance(kw.value, ast.JoinedStr):
                return issue.Issue(
                    severity="MEDIUM",
                    confidence="MEDIUM",
                    cwe=issue.Cwe.SQL_INJECTION,
                    text="Dynamic table/column name in SQL query. "
                    "Use an allowlist of permitted names.",
                )

    return None


@test.checks("Call")
@test.with_id("B613")
def django_cursor_raw_sql(context):
    """
    Check for Django cursor raw SQL with string formatting.

    Django's cursor.execute() can be vulnerable:

        cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")  # DANGEROUS!
        cursor.execute("SELECT * FROM users WHERE id = %s" % user_id)  # DANGEROUS!

    Safe patterns:
        cursor.execute("SELECT * FROM users WHERE id = %s", [user_id])

    Args:
        context: Context object with call information

    Returns:
        Issue object if dangerous pattern detected, None otherwise
    """
    node = context.node
    func_name = context.call_function_name_qual

    if not func_name:
        return None

    # Check if this is a Django cursor execute() call
    is_cursor = any(dc in func_name for dc in DJANGO_CURSOR_FUNCTIONS)

    if not is_cursor:
        return None

    # Check first positional argument
    if len(node.args) > 0:
        first_arg = node.args[0]

        # f-string
        if isinstance(first_arg, ast.JoinedStr):
            for elt in first_arg.values:
                if isinstance(elt, ast.FormattedValue):
                    if _is_user_input(elt.value):
                        return issue.Issue(
                            severity="HIGH",
                            confidence="HIGH",
                            cwe=issue.Cwe.SQL_INJECTION,
                            text="Django cursor.execute() with f-string containing user input. "
                            "This is a SQL injection vulnerability. "
                            "Use parameterized queries with %s placeholders.",
                        )

        # % formatting
        if isinstance(first_arg, ast.BinOp) and isinstance(first_arg.op, ast.Mod):
            left_str = _get_string(first_arg.left)
            if left_str and _contains_sql_keyword(left_str):
                right = first_arg.right
                if _is_user_input(right):
                    return issue.Issue(
                        severity="HIGH",
                        confidence="HIGH",
                        cwe=issue.Cwe.SQL_INJECTION,
                        text="Django cursor.execute() with % formatting and user input. "
                        "This is a SQL injection vulnerability.",
                    )

        # .format()
        if isinstance(first_arg, ast.Call):
            if hasattr(first_arg.func, "attr") and first_arg.func.attr == "format":
                format_str = (
                    _get_string(first_arg.func.value)
                    if hasattr(first_arg.func, "value")
                    else None
                )
                if format_str and _contains_sql_keyword(format_str):
                    return issue.Issue(
                        severity="HIGH",
                        confidence="HIGH",
                        cwe=issue.Cwe.SQL_INJECTION,
                        text="Django cursor.execute() with .format() containing SQL. "
                        "This is a SQL injection vulnerability.",
                    )

    # Check if parameters are missing
    has_params = len(node.args) > 1 or any(
        kw.arg for kw in node.keywords if kw.arg in ["params", "placeholders"]
    )

    # Only check first_arg if it was defined in one of the above checks
    if (
        not has_params
        and "first_arg" in locals()
        and isinstance(first_arg, (ast.JoinedStr, ast.BinOp))
    ):
        return issue.Issue(
            severity="LOW",
            confidence="LOW",
            cwe=issue.Cwe.SQL_INJECTION,
            text="Raw SQL in execute() without parameters. "
            "Ensure this does not include user input.",
        )

    return None


@test.checks("Call")
@test.with_id("B614")
def sqlalchemy_in_operator_injection(context):
    """
    Check for SQL IN operator with user input.

    Using IN operator with string formatting can be vulnerable:

        user_ids = "1, 2, 3"
        session.execute(f"SELECT * FROM users WHERE id IN ({user_ids})")  # DANGEROUS!

    Safe patterns:
        session.execute("SELECT * FROM users WHERE id IN :ids", {"ids": user_ids})

    Args:
        context: Context object with call information

    Returns:
        Issue object if dangerous pattern detected, None otherwise
    """
    node = context.node
    func_name = context.call_function_name_qual

    if not func_name:
        return None

    is_sqlalchemy = any(sa in func_name for sa in SQLALCHEMY_FUNCTIONS)

    if not is_sqlalchemy:
        return None

    # Check first positional argument
    if len(node.args) > 0:
        first_arg = node.args[0]

        if isinstance(first_arg, ast.JoinedStr):
            # Look for IN (...)
            for elt in first_arg.values:
                if isinstance(elt, ast.Constant) and isinstance(elt.value, str):
                    if " IN " in elt.value.upper():
                        # Check if there's a formatted value
                        for inner_elt in first_arg.values:
                            if isinstance(inner_elt, ast.FormattedValue):
                                if _is_user_input(inner_elt.value):
                                    return issue.Issue(
                                        severity="HIGH",
                                        confidence="MEDIUM",
                                        cwe=issue.Cwe.SQL_INJECTION,
                                        text="SQL IN clause with user input. "
                                        "This can lead to SQL injection if "
                                        "the user input contains commas or SQL.",
                                    )

    return None


@test.checks("Call")
@test.with_id("B615")
def nosql_injection(context):
    """
    Check for NoSQL injection patterns.

    NoSQL databases can also be vulnerable to injection:

        # MongoDB
        db.users.find({"$where": f"this.username == '{user_input}'"})  # DANGEROUS!

        # Redis
        redis.execute("GET", user_input)  # DANGEROUS!

    Args:
        context: Context object with call information

    Returns:
        Issue object if dangerous pattern detected, None otherwise
    """
    node = context.node
    func_name = context.call_function_name_qual

    if not func_name:
        return None

    # Check for MongoDB $where operator
    if "find" in func_name.lower() or "$where" in str(func_name):
        if len(node.args) > 0:
            first_arg = node.args[0]

            # Check for f-string in $where
            if isinstance(first_arg, ast.JoinedStr):
                for elt in first_arg.values:
                    if isinstance(elt, ast.FormattedValue):
                        if _is_user_input(elt.value):
                            return issue.Issue(
                                severity="HIGH",
                                confidence="HIGH",
                                cwe=issue.Cwe.SQL_INJECTION,
                                text="MongoDB $where with user input. "
                                "$where executes JavaScript and is vulnerable to injection. "
                                "Use query operators like $eq instead.",
                            )

            # Check for string formatting
            if isinstance(first_arg, ast.BinOp) and isinstance(first_arg.op, ast.Mod):
                left_str = _get_string(first_arg.left)
                if left_str and "$where" in left_str:
                    return issue.Issue(
                        severity="HIGH",
                        confidence="HIGH",
                        cwe=issue.Cwe.SQL_INJECTION,
                        text="MongoDB $where with string formatting. "
                        "This is a NoSQL injection vulnerability.",
                    )

    return None
