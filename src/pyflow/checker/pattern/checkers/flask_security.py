"""
Flask Security Checks.

Detects Flask-specific security misconfigurations and vulnerabilities.

Test IDs:
- F101: Flask debug=True in production
- F102: SECRET_KEY hardcoded or weak
- F103: SESSION_COOKIE_SECURE=False
- F104: SESSION_COOKIE_HTTPONLY=False
- F105: Permanent session enabled
- F106: send_file with unsafe path
- F107: render_template_string with user input (SSTI)
- F108: Missing CSRF protection on forms
- F109: Debug mode exposes traceback
- F110: Insecure JSON response format
"""

import ast
import re

from ..core import issue
from ..core import test_properties as test


WEAK_SECRET_RE = re.compile(r"^[a-zA-Z0-9]{0,16}$")
HARDCODED_SECRET_RE = re.compile(r"secret[_-]?key\s*=\s*['\"][^'\"]+['\"]", re.IGNORECASE)


def _flask_issue(text, severity="MEDIUM", confidence="MEDIUM", cwe=None):
    cwe_id = cwe if cwe else issue.Cwe.NOTSET
    return issue.Issue(
        severity=severity,
        confidence=confidence,
        cwe=cwe_id,
        text=text,
    )


def _is_user_input(node):
    """Heuristic: check if node likely contains user input."""
    if node is None:
        return False
    if isinstance(node, ast.Name):
        name = node.id.lower()
        markers = ("user", "input", "request", "form", "body", "data", "payload", "param", "query")
        return any(marker in name for marker in markers)
    if isinstance(node, ast.Attribute):
        return _is_user_input(node.value) or any(
            marker in node.attr.lower() for marker in ("input", "get", "post", "data")
        )
    if isinstance(node, ast.Call):
        if isinstance(node.func, ast.Name) and node.func.id in ("input", "raw_input"):
            return True
        return any(_is_user_input(arg) for arg in node.args)
    if isinstance(node, ast.Subscript):
        return _is_user_input(node.value) or _is_user_input(node.slice)
    return False


def _get_string_value(node):
    """Extract string value from AST node."""
    if isinstance(node, ast.Str):
        return node.s
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    return None


@test.checks("Call")
@test.with_id("F101")
def flask_debug_in_production(context):
    """Detect Flask app with debug=True in production."""
    if context.call_function_name in ("run", "debug"):
        for kw in context.node.keywords:
            if kw.arg == "debug" and isinstance(kw.value, ast.Constant) and kw.value.value is True:
                return _flask_issue(
                    "Flask debug mode enabled - may expose sensitive debug information.",
                    severity="HIGH",
                    confidence="HIGH",
                    cwe=issue.Cwe.IMPROPER_ERROR_HANDLING,
                )
    return None


@test.checks("Assign")
@test.with_id("F102")
def flask_secret_key_issues(context):
    """Detect hardcoded or weak SECRET_KEY."""
    if context.node.targets and isinstance(context.node.targets[0], ast.Name):
        if context.node.targets[0].id == "SECRET_KEY":
            value = _get_string_value(context.node.value)
            if value:
                if HARDCODED_SECRET_RE.search(value) or WEAK_SECRET_RE.match(value):
                    return _flask_issue(
                        "Flask SECRET_KEY is hardcoded or weak - allows session forgery.",
                        severity="HIGH",
                        confidence="MEDIUM",
                        cwe=issue.Cwe.HARDCODED_SECRET,
                    )
    return None


@test.checks("Assign")
@test.with_id("F103")
def session_cookie_secure_false(context):
    """Detect SESSION_COOKIE_SECURE=False."""
    if context.node.targets and isinstance(context.node.targets[0], ast.Name):
        if context.node.targets[0].id == "SESSION_COOKIE_SECURE":
            if isinstance(context.node.value, ast.Constant) and context.node.value.value is False:
                return _flask_issue(
                    "SESSION_COOKIE_SECURE=False allows session cookies over HTTP.",
                    severity="MEDIUM",
                    confidence="HIGH",
                    cwe=issue.Cwe.CLEARTEXT_TRANSMISSION,
                )
    return None


@test.checks("Assign")
@test.with_id("F104")
def session_cookie_httponly_false(context):
    """Detect SESSION_COOKIE_HTTPONLY=False."""
    if context.node.targets and isinstance(context.node.targets[0], ast.Name):
        if context.node.targets[0].id == "SESSION_COOKIE_HTTPONLY":
            if isinstance(context.node.value, ast.Constant) and context.node.value.value is False:
                return _flask_issue(
                    "SESSION_COOKIE_HTTPONLY=False allows JavaScript access to session cookies.",
                    severity="MEDIUM",
                    confidence="HIGH",
                    cwe=issue.Cwe.XSS,
                )
    return None


@test.checks("Assign")
@test.with_id("F105")
def permanent_session_lifetime(context):
    """Detect PERMANENT_SESSION_LIFETIME setting."""
    if context.node.targets and isinstance(context.node.targets[0], ast.Name):
        if context.node.targets[0].id == "PERMANENT_SESSION_LIFETIME":
            return _flask_issue(
                "Permanent sessions increase attack window - consider using shorter lifetimes.",
                severity="LOW",
                confidence="MEDIUM",
            )
    return None


@test.checks("Call")
@test.with_id("F106")
def send_file_unsafe_path(context):
    """Detect send_file with user-controlled path."""
    if context.call_function_name_qual in ("flask.send_file", "flask.send_from_directory"):
        if context.node.args and _is_user_input(context.node.args[0]):
            return _flask_issue(
                "send_file() with user-controlled path may allow path traversal.",
                severity="HIGH",
                confidence="MEDIUM",
                cwe=issue.Cwe.PATH_TRAVERSAL,
            )
    return None


@test.checks("Call")
@test.with_id("F107")
def render_template_string_ssti(context):
    """Detect render_template_string with user input (SSTI)."""
    if context.call_function_name == "render_template_string":
        if context.node.args and _is_user_input(context.node.args[0]):
            return _flask_issue(
                "render_template_string() with user input may cause server-side template injection (SSTI).",
                severity="HIGH",
                confidence="MEDIUM",
                cwe=issue.Cwe.CODE_INJECTION,
            )
    return None


@test.checks("FunctionDef")
@test.with_id("F108")
def csrf_protection_missing(context):
    """Detect forms without CSRF protection."""
    func_name = context.node.name.lower()
    if "form" in func_name or "submit" in func_name:
        has_csrf = False
        for decorator in context.node.decorator_list:
            dec_name = ""
            if isinstance(decorator, ast.Name):
                dec_name = decorator.id
            elif isinstance(decorator, ast.Attribute):
                dec_name = decorator.attr
            if "csrf" in dec_name.lower() or "verify_token" in dec_name.lower():
                has_csrf = True
                break
        if not has_csrf:
            return _flask_issue(
                f"Form handler '{context.node.name}' may lack CSRF protection.",
                severity="MEDIUM",
                confidence="MEDIUM",
                cwe=issue.Cwe.IMPROPER_ACCESS_CONTROL,
            )
    return None


@test.checks("Call")
@test.with_id("F109")
def flask_debug_mode_traceback(context):
    """Detect Flask debug mode that exposes tracebacks."""
    if context.call_function_name == "run":
        debug_enabled = False
        for kw in context.node.keywords:
            if kw.arg == "debug" and isinstance(kw.value, ast.Constant) and kw.value.value is True:
                debug_enabled = True
        if debug_enabled:
            return _flask_issue(
                "Flask debug mode exposes detailed tracebacks and may allow PIN code exploitation.",
                severity="HIGH",
                confidence="HIGH",
                cwe=issue.Cwe.IMPROPER_ERROR_HANDLING,
            )
    return None


@test.checks("Call")
@test.with_id("F110")
def jsonify_content_type(context):
    """Detect jsonify without proper Content-Type for sensitive data."""
    if context.call_function_name == "jsonify":
        return _flask_issue(
            "Ensure jsonify responses have proper Content-Type headers for sensitive data.",
            severity="LOW",
            confidence="LOW",
        )
    return None
