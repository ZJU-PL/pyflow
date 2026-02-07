"""
Template Security Checks.

This module provides security tests for template rendering vulnerabilities,
particularly Jinja2 and other template engines.

**Test IDs:**
- B613: Jinja2 autoescape off
- B614: Jinja2 with mark_safe
- B615: Jinja2 template injection (SSTI)
"""

import ast

from ..core import issue
from ..core import test_properties as test


# Jinja2 template functions and methods
JINJA2_FUNCTIONS = [
    "Environment",
    "Template",
    "FileSystemLoader",
    "DictLoader",
    "PackageLoader",
    "FunctionLoader",
]

JINJA2_DANGEROUS_METHODS = [
    "render_template_string",
    "render_template",
    "from_string",
]


def _is_jinja2_import(node):
    """Check if node is an import from jinja2."""
    if isinstance(node, ast.ImportFrom):
        if node.module == "jinja2":
            for alias in node.names:
                if alias.name in JINJA2_FUNCTIONS:
                    return True
    return False


@test.checks("Call")
@test.with_id("B613")
def jinja2_autoescape_off(context):
    """
    Check for Jinja2 Environment with autoescape disabled.

    Disabling autoescape allows XSS attacks when rendering user input:
        env = Environment(autoescape=False)  # DANGEROUS!

    Safe patterns:
        env = Environment(autoescape=True)  # Default, safe
        env = Environment()  # Default, safe

    Args:
        context: Context object with call information

    Returns:
        Issue object if dangerous pattern detected, None otherwise
    """
    node = context.node

    # Check if this is a Jinja2 Environment call
    func_name = context.call_function_name_qual

    if func_name == "jinja2.Environment":
        # Check for autoescape=False in keywords
        for kw in node.keywords:
            if kw.arg == "autoescape":
                # Get the value
                if isinstance(kw.value, ast.Constant):
                    autoescape_value = kw.value.value
                elif isinstance(kw.value, ast.Name):
                    autoescape_value = kw.value.id == "False"
                else:
                    continue

                if autoescape_value is False:
                    return issue.Issue(
                        severity="MEDIUM",
                        confidence="HIGH",
                        cwe=issue.Cwe.XSS,
                        text="Jinja2 Environment created with autoescape=False. "
                             "This disables automatic escaping of HTML content and "
                             "can lead to Cross-Site Scripting (XSS) vulnerabilities. "
                             "Only disable autoescape if you are certain that all "
                             "rendered content is already safe (e.g., using a sanitizer).",
                    )

    return None


@test.checks("Call")
@test.with_id("B614")
def jinja2_mark_safe(context):
    """
    Check for Jinja2 mark_safe usage.

    Using mark_safe() bypasses Jinja2's autoescape and can introduce XSS
    if the marked content is not actually safe.

    Examples:
        # DANGEROUS if user_input is not sanitized
        mark_safe(user_input)

        # Also dangerous
        Markup("<b>User: </b>") + user_input

    Args:
        context: Context object with call information

    Returns:
        Issue object if dangerous pattern detected, None otherwise
    """
    node = context.node

    func_name = context.call_function_name_qual

    if func_name in ["jinja2.Markup.__add__", "jinja2.utils.Markup.__add__"]:
        # Check if one operand is user-controlled
        # Markup(...) + user_input
        if len(node.args) > 1 and isinstance(node.args[1], ast.Name):
            return issue.Issue(
                severity="LOW",
                confidence="MEDIUM",
                cwe=issue.Cwe.XSS,
                text="Jinja2 Markup concatenation with potentially user-controlled data. "
                     "Using Markup() + user_input can introduce XSS if the user input "
                     "contains malicious HTML/JavaScript.",
            )

    if func_name == "jinja2.Markup" or func_name == "jinja2.utils.Markup":
        # Markup(user_input) - likely dangerous
        if len(node.args) > 0:
            first_arg = node.args[0]
            # If the argument is a function call or variable, likely user input
            if isinstance(first_arg, (ast.Call, ast.Name, ast.Subscript)):
                return issue.Issue(
                    severity="LOW",
                    confidence="MEDIUM",
                    cwe=issue.Cwe.XSS,
                    text="Jinja2 Markup() used with potentially user-controlled data. "
                         "mark_safe() bypasses XSS protection. Ensure the content "
                         "has been properly sanitized with a library like bleach.",
                )

    return None


@test.checks("Call")
@test.with_id("B615")
def jinja2_template_injection(context):
    """
    Check for Jinja2 template injection (SSTI).

    Template injection occurs when user input is directly included in
    template source code, allowing arbitrary code execution.

    Examples:
        # DANGEROUS: User input in template source
        template = Template(f"Hello {user_input}")

        # DANGEROUS: Template from user string
        template = Environment().from_string(user_input)

    Args:
        context: Context object with call information

    Returns:
        Issue object if dangerous pattern detected, None otherwise
    """
    node = context.node

    func_name = context.call_function_name_qual

    # Check for render_template_string with f-string or format
    if func_name in JINJA2_DANGEROUS_METHODS:
        # Check first argument for dangerous patterns
        if len(node.args) > 0:
            first_arg = node.args[0]

            # f-string: f"..."
            if isinstance(first_arg, ast.JoinedStr):
                return issue.Issue(
                    severity="HIGH",
                    confidence="HIGH",
                    cwe=issue.Cwe.CODE_INJECTION,
                    text="Jinja2 template created using f-string. "
                         "This pattern can lead to Server-Side Template Injection (SSTI) "
                         "if the string contains user input. Use render_template() "
                         "with separate template files instead.",
                )

            # .format() call on string
            if isinstance(first_arg, ast.Call):
                if isinstance(first_arg.func, ast.Attribute):
                    if first_arg.func.attr == "format":
                        # Check if format string contains user input markers
                        return issue.Issue(
                            severity="MEDIUM",
                            confidence="MEDIUM",
                            cwe=issue.Cwe.CODE_INJECTION,
                            text="Jinja2 template with .format() call. "
                                 "If the format string contains user input, this can "
                                 "lead to Server-Side Template Injection (SSTI).",
                        )

    # Check for Template() with f-string
    if func_name == "jinja2.Template":
        if len(node.args) > 0:
            first_arg = node.args[0]
            if isinstance(first_arg, ast.JoinedStr):
                return issue.Issue(
                    severity="HIGH",
                    confidence="HIGH",
                    cwe=issue.Cwe.CODE_INJECTION,
                    text="Jinja2 Template created from f-string. "
                         "This is a Server-Side Template Injection (SSTI) vulnerability. "
                         "Never include user input directly in template source code.",
                )

    # Check for from_string with dangerous argument
    if func_name == "jinja2.Environment.from_string":
        if len(node.args) > 0:
            first_arg = node.args[0]
            if isinstance(first_arg, ast.JoinedStr):
                return issue.Issue(
                    severity="HIGH",
                    confidence="HIGH",
                    cwe=issue.Cwe.CODE_INJECTION,
                    text="Jinja2 from_string() with f-string template. "
                         "This is a Server-Side Template Injection (SSTI) vulnerability.",
                )

    return None


@test.checks("Call")
@test.with_id("B616")
def jinja2_unsafe_loader(context):
    """
    Check for unsafe Jinja2 template loaders.

    Some template loaders can load templates from untrusted sources.

    Args:
        context: Context object with call information

    Returns:
        Issue object if dangerous pattern detected, None otherwise
    """
    node = context.node

    func_name = context.call_function_name_qual

    if func_name == "jinja2.FileSystemLoader":
        # Check if path is user-controlled (simplified check)
        if len(node.args) > 0:
            first_arg = node.args[0]
            if isinstance(first_arg, ast.Name):
                return issue.Issue(
                    severity="LOW",
                    confidence="LOW",
                    cwe=issue.Cwe.PATH_TRAVERSAL,
                    text="Jinja2 FileSystemLoader with variable path. "
                         "Ensure the path cannot be manipulated to load "
                         "templates from unintended directories.",
                )

    return None


@test.checks("Call")
@test.with_id("B617")
def django_mark_safe(context):
    """
    Check for Django's mark_safe usage.

    Django's mark_safe() similar to Jinja2's Markup - it bypasses
    HTML escaping and can introduce XSS.

    Args:
        context: Context object with call information

    Returns:
        Issue object if dangerous pattern detected, None otherwise
    """
    node = context.node

    func_name = context.call_function_name_qual

    if func_name == "django.utils.safestring.mark_safe":
        if len(node.args) > 0:
            first_arg = node.args[0]
            # If argument is a variable or function call, likely user input
            if isinstance(first_arg, (ast.Call, ast.Name, ast.Subscript)):
                return issue.Issue(
                    severity="LOW",
                    confidence="MEDIUM",
                    cwe=issue.Cwe.XSS,
                    text="Django's mark_safe() used with potentially user-controlled data. "
                         "Ensure the content has been properly sanitized. "
                         "Consider using bleach.clean() for HTML content.",
                )

    return None
