"""
FastAPI Security Checks.

Detects FastAPI-specific security misconfigurations and vulnerabilities.

Test IDs:
- A101: JWT without expiration
- A102: OAuth2PasswordBearer with weak secret
- A103: get_current_user without proper validation
- A104: Sensitive data in URL params
- A105: Missing rate limiting
- A106: CORS origin wildcard
- A107: Debug mode enabled
- A108: Sensitive fields in response_model
- A109: Password not hashed
- A110: No transaction safety in Depends
"""

import ast

from ..core import issue
from ..core import test_properties as test


SENSITIVE_FIELDS = (
    "password",
    "secret",
    "token",
    "key",
    "credential",
    "ssn",
    "credit_card",
)
SENSITIVE_PATH_PARAMS = ("user_id", "account_id", "admin_id", "token", "secret")


def _fastapi_issue(text, severity="MEDIUM", confidence="MEDIUM", cwe=None):
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
        markers = (
            "user",
            "input",
            "request",
            "form",
            "body",
            "data",
            "payload",
            "param",
            "query",
            "item",
        )
        return any(marker in name for marker in markers)
    if isinstance(node, ast.Attribute):
        return _is_user_input(node.value)
    if isinstance(node, ast.Subscript):
        return _is_user_input(node.value) or _is_user_input(node.slice)
    if isinstance(node, ast.Call):
        return any(_is_user_input(arg) for arg in node.args)
    return False


def _get_func_name(node):
    """Get function name from AST node."""
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return node.attr
    return ""


@test.checks("Call")
@test.with_id("A101")
def jwt_without_expiration(context):
    """Detect JWT token creation without expiration."""
    if context.call_function_name in ("encode", "decode"):
        qual = context.call_function_name_qual or ""
        if "jwt" in qual.lower() or "pyjwt" in qual.lower():
            has_expiration = False
            for kw in context.node.keywords:
                if kw.arg == "exp" or kw.arg == "expires_delta":
                    has_expiration = True
                    break
            if not has_expiration:
                return _fastapi_issue(
                    "JWT token without expiration allows indefinite session usage.",
                    severity="MEDIUM",
                    confidence="MEDIUM",
                    cwe=issue.Cwe.IMPROPER_ACCESS_CONTROL,
                )
    return None


@test.checks("Call")
@test.with_id("A102")
def oauth2_password_bearer_weak_secret(context):
    """Detect OAuth2PasswordBearer with weak secret key."""
    if context.call_function_name == "OAuth2PasswordBearer":
        for kw in context.node.keywords:
            if kw.arg == "secret_key":
                return _fastapi_issue(
                    "Ensure OAuth2PasswordBearer uses a strong, randomly generated secret key.",
                    severity="MEDIUM",
                    confidence="MEDIUM",
                    cwe=issue.Cwe.WEAK_CREDENTIALS,
                )
    return None


@test.checks("FunctionDef")
@test.with_id("A103")
def get_current_user_validation(context):
    """Detect get_current_user without proper token validation."""
    func_name = context.node.name.lower()
    if "current_user" in func_name or "get_user" in func_name:
        has_jwt_verify = False
        has_db_lookup = False
        for node in ast.walk(context.node):
            if isinstance(node, ast.Call):
                func = _get_func_name(node.func)
                if "decode" in func.lower() or "verify" in func.lower():
                    has_jwt_verify = True
                if "query" in func.lower() or "get_user" in func.lower():
                    has_db_lookup = True
        if not has_jwt_verify:
            return _fastapi_issue(
                f"Function '{context.node.name}' may lack proper token validation.",
                severity="MEDIUM",
                confidence="MEDIUM",
                cwe=issue.Cwe.IMPROPER_ACCESS_CONTROL,
            )
    return None


@test.checks("FunctionDef")
@test.with_id("A104")
def sensitive_data_in_url(context):
    """Detect sensitive data being passed in URL parameters."""
    for param in context.node.args.args:
        param_name = param.arg.lower()
        if any(sensitive in param_name for sensitive in SENSITIVE_PATH_PARAMS):
            return _fastapi_issue(
                f"Path parameter '{param.arg}' may contain sensitive data - consider using headers or body.",
                severity="MEDIUM",
                confidence="MEDIUM",
                cwe=issue.Cwe.IMPROPER_ACCESS_CONTROL,
            )
    return None


@test.checks("FunctionDef")
@test.with_id("A105")
def rate_limiting_missing(context):
    """Detect endpoints without rate limiting."""
    has_rate_limit = False
    for node in ast.walk(context.node):
        if isinstance(node, ast.Call):
            qual = context.call_function_name_qual or ""
            if "rate_limit" in qual.lower() or "limiter" in qual.lower():
                has_rate_limit = True
                break
    if not has_rate_limit:
        return _fastapi_issue(
            f"Endpoint '{context.node.name}' lacks explicit rate limiting.",
            severity="LOW",
            confidence="LOW",
            cwe=issue.Cwe.UNCONTROLLED_RESOURCE_CONSUMPTION,
        )
    return None


@test.checks("Call")
@test.with_id("A106")
def cors_origin_wildcard(context):
    """Detect CORS middleware with wildcard origin."""
    if context.call_function_name in ("add_middleware", "middleware"):
        for kw in context.node.keywords:
            if kw.arg == "allow_origins":
                if isinstance(kw.value, ast.List):
                    for elt in kw.value.elts:
                        if isinstance(elt, ast.Constant) and elt.value == "*":
                            return _fastapi_issue(
                                "CORS wildcard origin (*) allows cross-origin requests from any domain.",
                                severity="MEDIUM",
                                confidence="HIGH",
                                cwe=issue.Cwe.IMPROPER_ACCESS_CONTROL,
                            )
    return None


@test.checks("Call")
@test.with_id("A107")
def debug_mode_enabled(context):
    """Detect debug mode being enabled."""
    if context.call_function_name == "DebugMiddleware":
        return _fastapi_issue(
            "Debug mode in production may expose sensitive application details.",
            severity="MEDIUM",
            confidence="HIGH",
            cwe=issue.Cwe.IMPROPER_ERROR_HANDLING,
        )
    return None


@test.checks("FunctionDef")
@test.with_id("A108")
def sensitive_fields_in_response_model(context):
    """Detect response_model containing sensitive fields."""
    for kw in context.node.decorator_list:
        if isinstance(kw, ast.Call):
            for arg_kw in kw.keywords:
                if arg_kw.arg == "response_model":
                    model_name = ""
                    if isinstance(arg_kw.value, ast.Name):
                        model_name = arg_kw.value.id
                    elif isinstance(arg_kw.value, ast.Attribute):
                        model_name = arg_kw.value.attr
                    if any(
                        sensitive in model_name.lower()
                        for sensitive in SENSITIVE_FIELDS
                    ):
                        return _fastapi_issue(
                            f"response_model '{model_name}' may include sensitive fields - consider excluding them.",
                            severity="MEDIUM",
                            confidence="MEDIUM",
                            cwe=issue.Cwe.IMPROPER_ACCESS_CONTROL,
                        )
    return None


@test.checks("Call")
@test.with_id("A109")
def password_not_hashed(context):
    """Detect password operations without proper hashing."""
    if context.call_function_name == "PasswordProperty":
        return _fastapi_issue(
            "Ensure passwords are hashed using bcrypt, scrypt, or argon2 before storage.",
            severity="HIGH",
            confidence="HIGH",
            cwe=issue.Cwe.WEAK_CREDENTIALS,
        )
    if context.call_function_name == "verify_password":
        return _fastapi_issue(
            "Consider using a constant-time comparison for password verification.",
            severity="LOW",
            confidence="MEDIUM",
        )
    return None


@test.checks("FunctionDef")
@test.with_id("A110")
def transaction_safety_in_depends(context):
    """Detect database operations in Depends without transaction safety."""
    func_name = context.node.name.lower()
    has_db_operation = False
    has_commit = False
    has_rollback = False

    for node in ast.walk(context.node):
        if isinstance(node, ast.Call):
            qual = context.call_function_name_qual or ""
            if any(
                db in qual.lower() for db in ("session", "query", "commit", "rollback")
            ):
                has_db_operation = True
            if "commit" in qual.lower():
                has_commit = True
            if "rollback" in qual.lower():
                has_rollback = True

    if has_db_operation and not (has_commit or has_rollback):
        return _fastapi_issue(
            f"Function '{context.node.name}' performs database operations without explicit commit/rollback handling.",
            severity="LOW",
            confidence="LOW",
            cwe=issue.Cwe.IMPROPER_ERROR_HANDLING,
        )
    return None
