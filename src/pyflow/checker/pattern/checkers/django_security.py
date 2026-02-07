"""
Django Security Checks.

Detects Django-specific security misconfigurations and vulnerabilities.

Test IDs:
- D101: DEBUG=True in settings
- D102: ALLOWED_HOSTS=['*'] or empty
- D103: Insecure SESSION_ENGINE (cached)
- D104: DEBUG_PROPAGATE_EXCEPTIONS=True
- D105: SECURE_BROWSER_XSS_FILTER=False
- D106: Using mark_safe without html.escape
- D107: QuerySet.raw() with user input
- D108: QuerySet.extra() with user input
- D109: @login_required missing on sensitive views
- D110: Password stored without hashing
"""

import ast

from ..core import issue
from ..core import test_properties as test


DANGEROUS_SESSION_ENGINES = {
    "django.contrib.sessions.backends.cached_db",
    "django.contrib.sessions.backends.cache",
    "django.contrib.sessions.backends.file",
}

INSECURE_SETTINGS = {
    "DEBUG": True,
    "DEBUG_PROPAGATE_EXCEPTIONS": True,
    "SECURE_BROWSER_XSS_FILTER": False,
    "SESSION_COOKIE_SECURE": False,
    "SESSION_COOKIE_HTTPONLY": False,
}

SENSITIVE_VIEWS = ("user", "account", "admin", "profile", "password", "credit", "payment")


def _django_issue(text, severity="MEDIUM", confidence="MEDIUM", cwe=None):
    cwe_id = cwe if cwe else issue.Cwe.NOTSET
    return issue.Issue(
        severity=severity,
        confidence=confidence,
        cwe=cwe_id,
        text=text,
    )


def _has_wildcard_hosts(assign_node):
    """Check if ALLOWED_HOSTS contains '*' or is empty."""
    if not isinstance(assign_node.value, (ast.List, ast.Tuple)):
        return False
    for elt in assign_node.value.elts:
        if isinstance(elt, ast.Constant) and elt.value in ("*", ""):
            return True
    if len(assign_node.value.elts) == 0:
        return True
    return False


def _is_user_input(node):
    """Heuristic: check if node likely contains user input."""
    if node is None:
        return False
    if isinstance(node, ast.Name):
        name = node.id.lower()
        user_markers = ("user", "input", "request", "form", "body", "data", "payload", "param", "query")
        return any(marker in name for marker in user_markers)
    if isinstance(node, ast.Attribute):
        return _is_user_input(node.value) or any(
            marker in node.attr.lower() for marker in ("input", "get", "post", "data")
        )
    if isinstance(node, ast.Call):
        func_name = ""
        if isinstance(node.func, ast.Name):
            func_name = node.func.id
        elif isinstance(node.func, ast.Attribute):
            func_name = node.func.attr
        if func_name in ("input", "raw_input"):
            return True
        return any(_is_user_input(arg) for arg in node.args)
    return False


@test.checks("Assign")
@test.with_id("D101")
def debug_true_in_settings(context):
    """Detect DEBUG=True in Django settings."""
    if context.node.targets and isinstance(context.node.targets[0], ast.Name):
        if context.node.targets[0].id == "DEBUG":
            if isinstance(context.node.value, ast.Constant) and context.node.value.value is True:
                return _django_issue(
                    "DEBUG=True in production settings may expose sensitive information.",
                    severity="HIGH",
                    confidence="HIGH",
                    cwe=issue.Cwe.IMPROPER_ERROR_HANDLING,
                )
    return None


@test.checks("Assign")
@test.with_id("D102")
def allowed_hosts_wildcard(context):
    """Detect ALLOWED_HOSTS with wildcard or empty."""
    if context.node.targets and isinstance(context.node.targets[0], ast.Name):
        if context.node.targets[0].id == "ALLOWED_HOSTS":
            if _has_wildcard_hosts(context.node):
                return _django_issue(
                    "ALLOWED_HOSTS contains wildcard '*' or is empty - allows host header poisoning.",
                    severity="MEDIUM",
                    confidence="HIGH",
                    cwe=issue.Cwe.IMPROPER_ACCESS_CONTROL,
                )
    return None


@test.checks("Assign")
@test.with_id("D103")
def insecure_session_engine(context):
    """Detect insecure SESSION_ENGINE configuration."""
    if context.node.targets and isinstance(context.node.targets[0], ast.Name):
        if context.node.targets[0].id == "SESSION_ENGINE":
            if isinstance(context.node.value, ast.Constant):
                engine = context.node.value.value
                if engine in DANGEROUS_SESSION_ENGINES:
                    return _django_issue(
                        f"Insecure SESSION_ENGINE: {engine} - may allow session hijacking.",
                        severity="MEDIUM",
                        confidence="HIGH",
                    )
    return None


@test.checks("Assign")
@test.with_id("D104")
def debug_propagate_exceptions(context):
    """Detect DEBUG_PROPAGATE_EXCEPTIONS=True."""
    if context.node.targets and isinstance(context.node.targets[0], ast.Name):
        if context.node.targets[0].id == "DEBUG_PROPAGATE_EXCEPTIONS":
            if isinstance(context.node.value, ast.Constant) and context.node.value.value is True:
                return _django_issue(
                    "DEBUG_PROPAGATE_EXCEPTIONS=True may expose sensitive stack traces.",
                    severity="MEDIUM",
                    confidence="HIGH",
                    cwe=issue.Cwe.IMPROPER_ERROR_HANDLING,
                )
    return None


@test.checks("Assign")
@test.with_id("D105")
def xss_filter_disabled(context):
    """Detect SECURE_BROWSER_XSS_FILTER=False."""
    if context.node.targets and isinstance(context.node.targets[0], ast.Name):
        if context.node.targets[0].id == "SECURE_BROWSER_XSS_FILTER":
            if isinstance(context.node.value, ast.Constant) and context.node.value.value is False:
                return _django_issue(
                    "SECURE_BROWSER_XSS_FILTER=False reduces XSS protection.",
                    severity="LOW",
                    confidence="MEDIUM",
                    cwe=issue.Cwe.XSS,
                )
    return None


@test.checks("Call")
@test.with_id("D106")
def mark_safe_without_escape(context):
    """Detect Django mark_safe() without html.escape."""
    if context.call_function_name_qual == "django.utils.safestring.mark_safe":
        if context.node.args and _is_user_input(context.node.args[0]):
            return _django_issue(
                "mark_safe() used with user input may cause XSS vulnerabilities.",
                severity="HIGH",
                confidence="MEDIUM",
                cwe=issue.Cwe.XSS,
            )
    return None


@test.checks("Call")
@test.with_id("D107")
def queryset_raw_user_input(context):
    """Detect QuerySet.raw() with user input."""
    qual = context.call_function_name_qual or ""
    if ".raw" in qual:
        if context.node.args and _is_user_input(context.node.args[0]):
            return _django_issue(
                "QuerySet.raw() with user input may allow SQL injection.",
                severity="HIGH",
                confidence="MEDIUM",
                cwe=issue.Cwe.SQL_INJECTION,
            )
    return None


@test.checks("Call")
@test.with_id("D108")
def queryset_extra_user_input(context):
    """Detect QuerySet.extra() with user input."""
    qual = context.call_function_name_qual or ""
    if qual.endswith(".extra"):
        if context.node.args or context.node.keywords:
            for arg in context.node.args:
                if _is_user_input(arg):
                    return _django_issue(
                        "QuerySet.extra() with user input may allow SQL injection.",
                        severity="HIGH",
                        confidence="MEDIUM",
                        cwe=issue.Cwe.SQL_INJECTION,
                    )
    return None


@test.checks("FunctionDef")
@test.with_id("D109")
def login_required_missing(context):
    """Detect views handling sensitive data without @login_required."""
    func_name = context.node.name.lower()
    if any(sensitive in func_name for sensitive in SENSITIVE_VIEWS):
        has_login_required = False
        for decorator in context.node.decorator_list:
            dec_name = ""
            if isinstance(decorator, ast.Name):
                dec_name = decorator.id
            elif isinstance(decorator, ast.Attribute):
                dec_name = decorator.attr
            if "login_required" in dec_name.lower():
                has_login_required = True
                break
        if not has_login_required:
            return _django_issue(
                f"View '{context.node.name}' handles sensitive data but lacks @login_required decorator.",
                severity="MEDIUM",
                confidence="MEDIUM",
                cwe=issue.Cwe.IMPROPER_ACCESS_CONTROL,
            )
    return None


@test.checks("Call")
@test.with_id("D110")
def password_not_hashed(context):
    """Detect passwords being set without proper hashing."""
    if context.call_function_name_qual == "django.contrib.auth.models.User.set_password":
        return _django_issue(
            "Direct password assignment detected - ensure passwords are hashed properly.",
            severity="HIGH",
            confidence="MEDIUM",
            cwe=issue.Cwe.WEAK_CREDENTIALS,
        )
    return None
