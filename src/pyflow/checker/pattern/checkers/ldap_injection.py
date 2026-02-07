"""
LDAP injection detection checks.

Test IDs:
- B601: ldap.simple_bind with user input
- B602: ldap.initialize + simple_bind chain with user input
- B603: ldap.search with unsanitized DN/filter
- B604: ldap.add with user-controlled DN
- B605: ldap.modify with user-controlled DN
- B606: Dangerous LDAP connection string construction
"""

import ast

from ..core import issue
from ..core import test_properties as test


LDAP_BIND_FUNCTIONS = {"ldap.simple_bind", "ldap.simple_bind_s"}
LDAP_SEARCH_SUFFIXES = (".search", ".search_s", ".search_ext", ".search_st")
LDAP_ADD_SUFFIXES = (".add", ".add_s")
LDAP_MODIFY_SUFFIXES = (".modify", ".modify_s")

USER_INPUT_NAMES = {
    "input",
    "raw_input",
    "get",
    "post",
    "args",
    "values",
    "json",
    "form",
    "query",
    "request",
}

ESCAPE_FUNCTION_HINTS = (
    "ldap.filter.escape_filter_chars",
    "ldap.dn.escape_dn_chars",
    "escape_filter_chars",
    "escape_dn_chars",
)


def _ldap_issue(text, confidence="MEDIUM"):
    return issue.Issue(
        severity="HIGH",
        confidence=confidence,
        cwe=issue.Cwe.LDAP_INJECTION,
        text=text,
    )


def _name_from_node(node):
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        parent = _name_from_node(node.value)
        return f"{parent}.{node.attr}" if parent else node.attr
    return ""


def _is_user_controlled(node):
    if node is None:
        return False
    if isinstance(node, ast.Constant):
        return False
    if isinstance(node, (ast.Name, ast.Attribute, ast.Subscript)):
        return True
    if isinstance(node, ast.JoinedStr):
        return any(_is_user_controlled(v) for v in node.values)
    if isinstance(node, ast.BinOp):
        return _is_user_controlled(node.left) or _is_user_controlled(node.right)
    if isinstance(node, ast.Call):
        call_name = _name_from_node(node.func).lower()
        if any(key in call_name for key in USER_INPUT_NAMES):
            return True
        return any(_is_user_controlled(arg) for arg in node.args) or any(
            _is_user_controlled(kw.value) for kw in node.keywords
        )
    return False


def _is_escape_call(node):
    if not isinstance(node, ast.Call):
        return False
    call_name = _name_from_node(node.func).lower()
    if any(hint in call_name for hint in ESCAPE_FUNCTION_HINTS):
        return True
    return "escape" in call_name and "ldap" in call_name


def _has_ldap_scheme_literal(node):
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        value = node.value.lower()
        return "ldap://" in value or "ldaps://" in value
    if isinstance(node, ast.JoinedStr):
        return any(_has_ldap_scheme_literal(part) for part in node.values)
    if isinstance(node, ast.BinOp):
        return _has_ldap_scheme_literal(node.left) or _has_ldap_scheme_literal(node.right)
    if isinstance(node, ast.Call):
        return any(_has_ldap_scheme_literal(arg) for arg in node.args) or any(
            _has_ldap_scheme_literal(kw.value) for kw in node.keywords
        )
    return False


def _get_kwarg(node, *names):
    for kw in node.keywords:
        if kw.arg in names:
            return kw.value
    return None


def _is_bind_call_name(func_name):
    if not func_name:
        return False
    if func_name in LDAP_BIND_FUNCTIONS:
        return True
    return func_name.endswith(".simple_bind") or func_name.endswith(".simple_bind_s")


def _is_initialize_call(node):
    if not isinstance(node, ast.Call):
        return False
    func_name = _name_from_node(node.func)
    return func_name == "ldap.initialize" or func_name.endswith(".initialize")


@test.checks("Call")
@test.with_id("B601")
def ldap_simple_bind_user_input(context):
    """Detect ldap.simple_bind() calls with user-controlled credentials."""
    func_name = context.call_function_name_qual
    if not _is_bind_call_name(func_name):
        return None

    node = context.node
    username = node.args[0] if len(node.args) > 0 else _get_kwarg(node, "who", "user", "username")
    password = node.args[1] if len(node.args) > 1 else _get_kwarg(node, "cred", "pw", "password")

    if _is_user_controlled(username) or _is_user_controlled(password):
        return _ldap_issue(
            "Possible LDAP injection: simple_bind uses user-controlled username/password.",
            confidence="MEDIUM",
        )
    return None


@test.checks("Call")
@test.with_id("B602")
def ldap_initialize_and_bind_chain(context):
    """Detect ldap.initialize(...).simple_bind(...user_input...) pattern."""
    func_name = context.call_function_name_qual
    node = context.node

    if not _is_bind_call_name(func_name):
        return None
    if not isinstance(node.func, ast.Attribute):
        return None
    if not _is_initialize_call(node.func.value):
        return None

    username = node.args[0] if len(node.args) > 0 else _get_kwarg(node, "who", "user", "username")
    password = node.args[1] if len(node.args) > 1 else _get_kwarg(node, "cred", "pw", "password")
    if _is_user_controlled(username) or _is_user_controlled(password):
        return _ldap_issue(
            "Possible LDAP injection: ldap.initialize() result is bound with user-controlled credentials.",
            confidence="HIGH",
        )
    return None


@test.checks("Call")
@test.with_id("B603")
def ldap_search_unsanitized_filter(context):
    """Detect ldap.search*() with user-controlled DN/filter without escaping."""
    func_name = context.call_function_name_qual or ""
    if not func_name.endswith(LDAP_SEARCH_SUFFIXES):
        return None

    node = context.node
    base_dn = node.args[0] if len(node.args) > 0 else _get_kwarg(node, "base", "dn", "base_dn")
    filter_str = node.args[2] if len(node.args) > 2 else _get_kwarg(node, "filterstr", "filter")

    dn_user_controlled = _is_user_controlled(base_dn) and not _is_escape_call(base_dn)
    filter_user_controlled = _is_user_controlled(filter_str) and not _is_escape_call(filter_str)

    if filter_user_controlled:
        return _ldap_issue(
            "Possible LDAP injection: ldap.search filter is user-controlled and not escaped.",
            confidence="HIGH",
        )
    if dn_user_controlled:
        return _ldap_issue(
            "Possible LDAP injection: ldap.search base DN is user-controlled.",
            confidence="MEDIUM",
        )
    return None


@test.checks("Call")
@test.with_id("B604")
def ldap_add_user_controlled_dn(context):
    """Detect ldap.add*() with a user-controlled DN."""
    func_name = context.call_function_name_qual or ""
    if not func_name.endswith(LDAP_ADD_SUFFIXES):
        return None

    node = context.node
    dn_arg = node.args[0] if len(node.args) > 0 else _get_kwarg(node, "dn")

    if _is_user_controlled(dn_arg) and not _is_escape_call(dn_arg):
        return _ldap_issue(
            "Possible LDAP injection: ldap.add uses user-controlled DN.",
            confidence="HIGH",
        )
    return None


@test.checks("Call")
@test.with_id("B605")
def ldap_modify_user_controlled_dn(context):
    """Detect ldap.modify*() with a user-controlled DN."""
    func_name = context.call_function_name_qual or ""
    if not func_name.endswith(LDAP_MODIFY_SUFFIXES):
        return None

    node = context.node
    dn_arg = node.args[0] if len(node.args) > 0 else _get_kwarg(node, "dn")

    if _is_user_controlled(dn_arg) and not _is_escape_call(dn_arg):
        return _ldap_issue(
            "Possible LDAP injection: ldap.modify uses user-controlled DN.",
            confidence="HIGH",
        )
    return None


@test.checks("Call")
@test.with_id("B606")
def dangerous_ldap_connection_string(context):
    """Detect dynamic LDAP/LDAPS connection strings built from user input."""
    node = context.node
    func_name = context.call_function_name_qual or ""

    values = list(node.args) + [kw.value for kw in node.keywords]
    for value in values:
        if _has_ldap_scheme_literal(value) and _is_user_controlled(value):
            confidence = "HIGH" if "ldap.initialize" in func_name else "MEDIUM"
            return _ldap_issue(
                "Possible LDAP injection: LDAP connection string contains user-controlled input.",
                confidence=confidence,
            )
    return None
