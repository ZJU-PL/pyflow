"""
Hardcoded Secret Detection.

Detects common hardcoded secret patterns in assignments and function calls.

Test IDs:
- B501: AWS Access Key
- B502: GitHub Token
- B503: Google API Key
- B504: Slack Token
- B505: Private Key
- B506: Database password in string
- B507: Generic password assignment
- B508: API token detection
- B509: JWT secret
- B510: Encryption key
"""

import ast
import re

from ..core import issue
from ..core import test_properties as test


AWS_ACCESS_KEY_RE = re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b")
GITHUB_TOKEN_RE = re.compile(r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{20,255}\b")
GOOGLE_API_KEY_RE = re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b")
SLACK_TOKEN_RE = re.compile(r"\bxox(?:b|p)-[A-Za-z0-9-]{10,255}\b")
PRIVATE_KEY_RE = re.compile(
    r"-----BEGIN (?:RSA |DSA |EC |OPENSSH |PGP )?PRIVATE KEY-----"
)
DATABASE_PASSWORD_RE = re.compile(
    r"(?:"
    r"(?:postgres(?:ql)?|mysql|mariadb|mongodb(?:\+srv)?|redis|amqp|mssql|oracle|sqlite)"
    r"://[^\s:@/]+:[^\s@/]+@"
    r"|(?:password|pwd|pass)=([^\s;&]+)"
    r")",
    re.IGNORECASE,
)
GENERIC_API_TOKEN_RE = re.compile(
    r"(?:"
    r"\b(?:api[_-]?key|access[_-]?token|auth[_-]?token|secret[_-]?token)\b"
    r"\s*[:=]\s*['\"][^'\"]{8,}['\"]"
    r"|\bBearer\s+[A-Za-z0-9._\-]{16,}\b"
    r")",
    re.IGNORECASE,
)

PASSWORD_NAME_RE = re.compile(r"(?:password|passwd|pwd|passphrase)", re.IGNORECASE)
TOKEN_NAME_RE = re.compile(
    r"(?:token|api[_-]?key|access[_-]?key|client[_-]?secret|secret)", re.IGNORECASE
)
JWT_NAME_RE = re.compile(r"(?:jwt|json[_-]?web[_-]?token).*(?:secret|key)", re.IGNORECASE)
ENCRYPTION_KEY_NAME_RE = re.compile(
    r"(?:encrypt(?:ion)?|crypto|cipher|aes|des|rsa).*(?:key|secret)|"
    r"(?:key|secret).*(?:encrypt(?:ion)?|crypto|cipher|aes|des|rsa)",
    re.IGNORECASE,
)

PLACEHOLDER_RE = re.compile(
    r"^(?:"
    r"<[^>]+>|"
    r"YOUR_[A-Z0-9_]+|"
    r"REPLACE_[A-Z0-9_]+|"
    r"CHANGE(?:_|)ME|"
    r"example|sample|default|test\d*|"
    r"\*+|x+"
    r")$",
    re.IGNORECASE,
)


def _get_string(node):
    """Extract string literal value from AST nodes."""
    if isinstance(node, ast.Str):
        return node.s
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    return None


def _collect_strings(node):
    """Collect all string literals from a node subtree."""
    strings = []
    for child in ast.walk(node):
        value = _get_string(child)
        if value is not None:
            strings.append(value)
    return strings


def _target_names(target):
    """Extract candidate identifier names from assignment targets."""
    names = []

    if isinstance(target, ast.Name):
        names.append(target.id)
    elif isinstance(target, ast.Attribute):
        names.append(target.attr)
    elif isinstance(target, (ast.Tuple, ast.List)):
        for elt in target.elts:
            names.extend(_target_names(elt))
    elif isinstance(target, ast.Subscript):
        key = target.slice
        if isinstance(key, ast.Index):  # pragma: no cover - py<3.9 compat
            key = key.value
        key_str = _get_string(key)
        if key_str:
            names.append(key_str)

    return names


def _is_placeholder(value):
    """Heuristic guard to reduce obvious placeholder false positives."""
    if not value:
        return True
    if PLACEHOLDER_RE.match(value.strip()):
        return True
    return False


def _new_issue(text):
    return issue.Issue(
        severity="HIGH",
        confidence="MEDIUM",
        cwe=issue.Cwe.HARDCODED_SECRET,
        text=text,
    )


def _find_match(pattern, values):
    for value in values:
        m = pattern.search(value)
        if m:
            return m.group(0)
    return None


@test.checks("Assign")
@test.with_id("B501")
def hardcoded_aws_access_key(context):
    """Detect hardcoded AWS access keys (AKIA..., ASIA...)."""
    match = _find_match(AWS_ACCESS_KEY_RE, _collect_strings(context.node.value))
    if match:
        return _new_issue(f"Possible hardcoded AWS access key detected: '{match}'")


@test.checks("Assign")
@test.with_id("B502")
def hardcoded_github_token(context):
    """Detect hardcoded GitHub tokens (ghp_, gho_, ghu_, ghs_, ghr_)."""
    match = _find_match(GITHUB_TOKEN_RE, _collect_strings(context.node.value))
    if match:
        return _new_issue(f"Possible hardcoded GitHub token detected: '{match}'")


@test.checks("Assign")
@test.with_id("B503")
def hardcoded_google_api_key(context):
    """Detect hardcoded Google API keys (AIza...)."""
    match = _find_match(GOOGLE_API_KEY_RE, _collect_strings(context.node.value))
    if match:
        return _new_issue(f"Possible hardcoded Google API key detected: '{match}'")


@test.checks("Assign")
@test.with_id("B504")
def hardcoded_slack_token(context):
    """Detect hardcoded Slack tokens (xoxb-, xoxp-)."""
    match = _find_match(SLACK_TOKEN_RE, _collect_strings(context.node.value))
    if match:
        return _new_issue(f"Possible hardcoded Slack token detected: '{match}'")


@test.checks("Assign")
@test.with_id("B505")
def hardcoded_private_key(context):
    """Detect embedded private key blocks."""
    match = _find_match(PRIVATE_KEY_RE, _collect_strings(context.node.value))
    if match:
        return _new_issue("Possible hardcoded private key material detected")


@test.checks("Assign")
@test.with_id("B506")
def hardcoded_database_password(context):
    """Detect database connection strings with inline passwords."""
    match = _find_match(DATABASE_PASSWORD_RE, _collect_strings(context.node.value))
    if match:
        return _new_issue("Possible database connection string with hardcoded password detected")


@test.checks("Assign")
@test.with_id("B507")
def hardcoded_generic_password_assignment(context):
    """Detect generic password-like variable assignments to string literals."""
    target_names = []
    for target in context.node.targets:
        target_names.extend(_target_names(target))

    value = _get_string(context.node.value)
    if value is None or _is_placeholder(value):
        return None

    if any(PASSWORD_NAME_RE.search(name or "") for name in target_names):
        return _new_issue(f"Possible hardcoded password assignment detected: '{value}'")


@test.checks("Call")
@test.with_id("B508")
def hardcoded_api_token_in_call(context):
    """Detect API token-like secrets in function call arguments."""
    for kw in context.node.keywords:
        if kw.arg is None:
            continue
        value = _get_string(kw.value)
        if value is None or _is_placeholder(value):
            continue

        if TOKEN_NAME_RE.search(kw.arg) and len(value) >= 8:
            return _new_issue(
                f"Possible hardcoded API token in call argument '{kw.arg}': '{value}'"
            )

        if GENERIC_API_TOKEN_RE.search(value):
            return _new_issue("Possible hardcoded API token detected in function call")

    for arg in context.node.args:
        value = _get_string(arg)
        if value is None or _is_placeholder(value):
            continue
        if GENERIC_API_TOKEN_RE.search(value):
            return _new_issue("Possible hardcoded API token detected in function call")


@test.checks("Assign")
@test.with_id("B509")
def hardcoded_jwt_secret(context):
    """Detect hardcoded JWT secrets."""
    target_names = []
    for target in context.node.targets:
        target_names.extend(_target_names(target))

    value = _get_string(context.node.value)
    if value is None or _is_placeholder(value):
        return None

    if any(JWT_NAME_RE.search(name or "") for name in target_names):
        return _new_issue(f"Possible hardcoded JWT secret detected: '{value}'")


@test.checks("Assign")
@test.with_id("B510")
def hardcoded_encryption_key(context):
    """Detect hardcoded encryption keys in variable assignments."""
    target_names = []
    for target in context.node.targets:
        target_names.extend(_target_names(target))

    value = _get_string(context.node.value)
    if value is None or _is_placeholder(value):
        return None

    looks_like_key_material = bool(
        re.match(r"^[A-Fa-f0-9]{16,}$", value)
        or re.match(r"^[A-Za-z0-9+/]{24,}={0,2}$", value)
        or len(value) >= 16
    )

    if looks_like_key_material and any(
        ENCRYPTION_KEY_NAME_RE.search(name or "") for name in target_names
    ):
        return _new_issue(f"Possible hardcoded encryption key detected: '{value}'")
