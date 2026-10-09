"""
Server-Side Request Forgery (SSRF) Detection.

This module provides security tests for SSRF vulnerabilities where
attacker can make the server make requests to arbitrary locations.

**Test IDs:**
- B701: requests.get with user URL
- B702: urllib.request with user URL
- B703: HTTP request to internal metadata
- B704: Socket connections to internal services
- B705: DNS rebinding possible
"""

import ast

from ...common import issue
from ..core import test_properties as test

# HTTP request functions
REQUESTS_FUNCTIONS = [
    "requests.get",
    "requests.post",
    "requests.put",
    "requests.delete",
    "requests.patch",
    "requests.head",
    "requests.options",
    "requests.request",
    "requests.Session.get",
    "requests.Session.post",
]

URLLIB_FUNCTIONS = [
    "urllib.request.urlopen",
    "urllib.request.urlretrieve",
    "urllib.request.Request",
    "urllib.request.urlparse",
]

HTTPLIB_FUNCTIONS = [
    "http.client.HTTPConnection.request",
    "http.client.HTTPSConnection.request",
]

# Internal network ranges
INTERNAL_IPS = [
    "127.0.0.1",
    "::1",
    "0.0.0.0",
]

# Cloud metadata endpoints
CLOUD_METADATA = [
    "169.254.169.254",  # AWS
    "metadata.google.internal",  # GCP
    "169.254.169.254",  # Azure
    "localhost",
    "169.254.0.0/16",  # Link-local
]


def _is_url_argument(node):
    """Check if a node looks like a URL."""
    if isinstance(node, ast.Constant):
        if isinstance(node.value, str):
            url_patterns = ["http://", "https://", "ftp://", "file://"]
            return any(node.value.lower().startswith(p) for p in url_patterns)
    return False


def _is_variable(node):
    """Check if a node is a variable (potential user input)."""
    return isinstance(node, ast.Name) and not isinstance(node.ctx, ast.Store)


def _url_argument(node, func_name):
    """Inspect the URL port, excluding method, payload, and header arguments."""
    for keyword in node.keywords:
        if keyword.arg == "url":
            return keyword.value
    position = 1 if func_name == "requests.request" else 0
    return node.args[position] if len(node.args) > position else None


@test.checks("Call")
@test.with_id("B701")
def requests_user_url(context):
    """
    Check for requests library with user-controlled URL.

    This pattern can lead to SSRF attacks where attacker can:
    - Access internal services
    - Scan internal network
    - Read cloud metadata
    - Bypass firewalls

    Examples:
        requests.get(user_provided_url)  # DANGEROUS!
        requests.get(f"https://api.example.com/{user_input}")  # DANGEROUS!

    Args:
        context: Context object with call information

    Returns:
        Issue object if dangerous pattern detected, None otherwise
    """
    node = context.node

    func_name = context.call_function_name_qual

    if not func_name:
        return None

    # Check if this is a requests call
    is_requests = func_name in REQUESTS_FUNCTIONS

    if not is_requests:
        return None

    if _is_variable(_url_argument(node, func_name)):
        return issue.Issue(
            severity="MEDIUM",
            confidence="LOW",
            cwe=issue.Cwe.SERVER_SIDE_REQUEST_FORGERY,
            text="Review requests call with a variable URL for possible SSRF. "
            "Pattern matching does not establish that the URL is user-controlled; "
            "use a dataflow engine to check its source. Allowlist destinations "
            "when URLs come from untrusted input.",
        )

    return None


@test.checks("Call")
@test.with_id("B702")
def urllib_user_url(context):
    """
    Check for urllib with user-controlled URL.

    urllib.request.urlopen() can be exploited for SSRF.

    Args:
        context: Context object with call information

    Returns:
        Issue object if dangerous pattern detected, None otherwise
    """
    node = context.node

    func_name = context.call_function_name_qual

    if not func_name:
        return None

    # Check if this is a urllib call
    is_urllib = func_name in URLLIB_FUNCTIONS

    if not is_urllib:
        return None

    # Check first argument
    if (first_arg := _url_argument(node, func_name)) is not None:
        if _is_variable(first_arg):
            return issue.Issue(
                severity="MEDIUM",
                confidence="LOW",
                cwe=issue.Cwe.SERVER_SIDE_REQUEST_FORGERY,
                text="Review urllib call with a variable URL for possible SSRF. "
                "Pattern matching does not establish that the URL is user-controlled; "
                "use a dataflow engine to check its source.",
            )

    return None


@test.checks("Call")
@test.with_id("B703")
def internal_metadata_access(context):
    """
    Check for requests to cloud internal metadata endpoints.

    Cloud providers expose metadata endpoints that can leak:
    - Temporary credentials
    - IAM roles
    - Instance information
    - Secret keys

    Examples:
        requests.get("http://169.254.169.254/latest/meta-data/")  # AWS
        requests.get("http://metadata.google.internal/computeMetadata/v1/")  # GCP

    Args:
        context: Context object with call information

    Returns:
        Issue object if dangerous pattern detected, None otherwise
    """
    node = context.node

    func_name = context.call_function_name_qual

    if not func_name:
        return None

    # Check if this is a requests or urllib call
    is_requests = func_name in REQUESTS_FUNCTIONS
    is_urllib = func_name in URLLIB_FUNCTIONS

    if not (is_requests or is_urllib):
        return None

    # Check first argument for internal metadata URLs
    if (first_arg := _url_argument(node, func_name)) is not None:
        if isinstance(first_arg, ast.Constant):
            if isinstance(first_arg.value, str):
                url_lower = first_arg.value.lower()
                metadata_patterns = [
                    "169.254.169.254",
                    "metadata.google.internal",
                    "metadata.google.internal",
                    "169.254.0.0/16",
                    "localhost",
                ]

                for pattern in metadata_patterns:
                    if pattern in url_lower:
                        return issue.Issue(
                            severity="HIGH",
                            confidence="HIGH",
                            cwe=issue.Cwe.SERVER_SIDE_REQUEST_FORGERY,
                            text=f"Request to cloud metadata endpoint ({pattern}). "
                            "This can leak sensitive credentials or allow privilege escalation. "
                            "Never make requests to metadata endpoints from untrusted code.",
                        )

    return None


@test.checks("Call")
@test.with_id("B704")
def socket_internal_connection(context):
    """
    Check for socket connections to internal services.

    Direct socket connections can be used for SSRF to:
    - Connect to internal databases
    - Connect to Redis/Memcached
    - Connect to message queues
    - Port scan internal network

    Args:
        context: Context object with call information

    Returns:
        Issue object if dangerous pattern detected, None otherwise
    """
    node = context.node

    func_name = context.call_function_name_qual

    if not func_name:
        return None

    if func_name == "socket.socket.connect":
        if len(node.args) > 0:
            connect_arg = node.args[0]
            if isinstance(connect_arg, ast.Tuple):
                if len(connect_arg.elts) > 0:
                    host_arg = connect_arg.elts[0]
                    if isinstance(host_arg, ast.Constant):
                        host = host_arg.value
                        if (
                            host in ["localhost", "127.0.0.1"]
                            or host.startswith("192.168.")
                            or host.startswith("10.")
                        ):
                            return issue.Issue(
                                severity="LOW",
                                confidence="LOW",
                                cwe=issue.Cwe.SERVER_SIDE_REQUEST_FORGERY,
                                text=f"Socket connection to internal host ({host}). "
                                "This could be part of an SSRF attack to access internal services.",
                            )

    return None


@test.checks("Call")
@test.with_id("B705")
def no_url_validation(context):
    """
    Check for HTTP requests without URL validation.

    When URLs come from user input, they should be validated to:
    - Use only HTTP/HTTPS schemes
    - Not contain null bytes
    - Not be IP addresses (especially private)
    - Not be localhost

    Args:
        context: Context object with call information

    Returns:
        Issue object if dangerous pattern detected, None otherwise
    """
    node = context.node

    func_name = context.call_function_name_qual

    if not func_name:
        return None

    # Check if this is a requests or urllib call
    is_requests = func_name in REQUESTS_FUNCTIONS
    is_urllib = func_name in URLLIB_FUNCTIONS

    if not (is_requests or is_urllib):
        return None

    # Check for missing allowlist/validation
    parent = getattr(node, "_bandit_parent", None)
    parent_name = ""

    if isinstance(parent, ast.FunctionDef):
        parent_name = parent.name.lower()

    validation_keywords = [
        "validate",
        "allowlist",
        "whitelist",
        "check",
        "sanitize",
        "filter",
    ]

    # If function name doesn't suggest validation, flag it
    if not any(kw in parent_name for kw in validation_keywords):
        if (first_arg := _url_argument(node, func_name)) is not None:
            if _is_variable(first_arg):
                return issue.Issue(
                    severity="LOW",
                    confidence="LOW",
                    cwe=issue.Cwe.SERVER_SIDE_REQUEST_FORGERY,
                    text="HTTP request without obvious URL validation. "
                    "Consider implementing URL validation to prevent SSRF attacks. "
                    "Validate: scheme (http/https), hostname (no private IPs), "
                    "and reject file:// or other dangerous schemes.",
                )

    return None


@test.checks("Call")
@test.with_id("B706")
def dangerous_url_scheme(context):
    """
    Check for dangerous URL schemes in requests.

    Some URL schemes can lead to security issues:
    - file:// - Read local files
    - gopher:// - Talk to other services (Redis, MySQL)
    - dict:// - Dictionary protocol
    - ldap:// - LDAP queries

    Args:
        context: Context object with call information

    Returns:
        Issue object if dangerous pattern detected, None otherwise
    """
    node = context.node

    func_name = context.call_function_name_qual

    if not func_name:
        return None

    # Check if this is a requests or urllib call
    is_requests = func_name in REQUESTS_FUNCTIONS
    is_urllib = func_name in URLLIB_FUNCTIONS

    if not (is_requests or is_urllib):
        return None

    dangerous_schemes = [
        "file://",
        "gopher://",
        "dict://",
        "ldap://",
        "sftp://",
        "smb://",
    ]

    if (first_arg := _url_argument(node, func_name)) is not None:
        if isinstance(first_arg, ast.Constant):
            if isinstance(first_arg.value, str):
                url_lower = first_arg.value.lower()
                for scheme in dangerous_schemes:
                    if url_lower.startswith(scheme):
                        return issue.Issue(
                            severity="HIGH",
                            confidence="HIGH",
                            cwe=issue.Cwe.SERVER_SIDE_REQUEST_FORGERY,
                            text=f"Dangerous URL scheme '{scheme}' detected. "
                            f"This scheme can be exploited for SSRF attacks. "
                            f"Allow only http:// and https:// schemes.",
                        )

    return None
