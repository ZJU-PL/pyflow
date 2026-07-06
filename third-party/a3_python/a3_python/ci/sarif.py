"""
SARIF 2.1.0 serializer for A³ results.

Converts the internal results dict (from _analyze_project) to the
SARIF JSON format consumed by GitHub Code Scanning, VS Code SARIF Viewer,
and other SARIF-compatible tools.

Spec: https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from a3_python import __version__
from a3_python.unsafe.registry import SECURITY_BUG_TYPES

# ── Bug-type metadata ────────────────────────────────────────────────────────

_BUG_RULES: dict[str, dict[str, str]] = {
    # ══════════════════ Core Error Bug Types (20) ══════════════════
    "DIV_ZERO": {
        "id": "PFS001",
        "name": "DivisionByZero",
        "shortDescription": "Potential division by zero",
        "fullDescription": (
            "An arithmetic division or modulo operation may receive a zero "
            "divisor, causing a ZeroDivisionError at runtime."
        ),
        "level": "error",
        "precision": "high",
        "cwe": "CWE-369",
    },
    "NULL_PTR": {
        "id": "PFS002",
        "name": "NoneReference",
        "shortDescription": "Potential NoneType dereference",
        "fullDescription": (
            "An attribute access, subscript, or call may be performed on a "
            "value that could be None, causing an AttributeError or TypeError."
        ),
        "level": "error",
        "precision": "high",
        "cwe": "CWE-476",
    },
    "INDEX_OOB": {
        "id": "PFS003",
        "name": "IndexOutOfBounds",
        "shortDescription": "Potential index out of bounds",
        "fullDescription": (
            "A list/tuple subscript may use an index that is outside the "
            "valid range, causing an IndexError."
        ),
        "level": "error",
        "precision": "high",
        "cwe": "CWE-129",
    },
    # Alias: registry uses BOUNDS, SARIF maps both
    "BOUNDS": {
        "id": "PFS003",
        "name": "IndexOutOfBounds",
        "shortDescription": "Potential index out of bounds",
        "fullDescription": (
            "A list/tuple subscript may use an index that is outside the "
            "valid range, causing an IndexError."
        ),
        "level": "error",
        "precision": "high",
        "cwe": "CWE-129",
    },
    "KEY_ERROR": {
        "id": "PFS004",
        "name": "KeyError",
        "shortDescription": "Potential missing dictionary key",
        "fullDescription": (
            "A dictionary subscript may use a key that does not exist, "
            "causing a KeyError."
        ),
        "level": "warning",
        "precision": "medium",
        "cwe": "CWE-754",
    },
    "TYPE_ERROR": {
        "id": "PFS005",
        "name": "TypeError",
        "shortDescription": "Potential type error in operation",
        "fullDescription": (
            "An operation may receive operands of incompatible types, "
            "causing a TypeError at runtime."
        ),
        "level": "error",
        "precision": "medium",
        "cwe": "CWE-843",
    },
    "TYPE_CONFUSION": {
        "id": "PFS005",
        "name": "TypeConfusion",
        "shortDescription": "Potential type confusion",
        "fullDescription": (
            "A value may be used as an incompatible type, "
            "causing a TypeError at runtime."
        ),
        "level": "error",
        "precision": "medium",
        "cwe": "CWE-843",
    },
    "OVERFLOW": {
        "id": "PFS006",
        "name": "IntegerOverflow",
        "shortDescription": "Potential integer overflow",
        "fullDescription": (
            "An arithmetic operation may overflow the expected integer range. "
            "While Python ints have arbitrary precision, this may cause "
            "performance issues or logic errors."
        ),
        "level": "warning",
        "precision": "low",
        "cwe": "CWE-190",
    },
    "INTEGER_OVERFLOW": {
        "id": "PFS006",
        "name": "IntegerOverflow",
        "shortDescription": "Potential integer overflow",
        "fullDescription": (
            "An arithmetic operation may overflow the expected integer range. "
            "While Python ints have arbitrary precision, this may cause "
            "performance issues or logic errors."
        ),
        "level": "warning",
        "precision": "low",
        "cwe": "CWE-190",
    },
    "ASSERT_FAIL": {
        "id": "PFS007",
        "name": "AssertionFailure",
        "shortDescription": "Potential assertion failure",
        "fullDescription": (
            "An assert statement may fail at runtime, indicating a violated "
            "invariant or precondition."
        ),
        "level": "warning",
        "precision": "medium",
        "cwe": "CWE-617",
    },
    "UNBOUND_VAR": {
        "id": "PFS008",
        "name": "UnboundVariable",
        "shortDescription": "Potential unbound local variable",
        "fullDescription": (
            "A local variable may be referenced before assignment on some "
            "execution paths, causing an UnboundLocalError."
        ),
        "level": "error",
        "precision": "high",
        "cwe": "CWE-457",
    },
    "FP_DOMAIN": {
        "id": "PFS014",
        "name": "FloatingPointDomain",
        "shortDescription": "Potential floating-point domain error",
        "fullDescription": (
            "A math function may receive an argument outside its domain "
            "(e.g. sqrt of negative, log of zero), causing a ValueError."
        ),
        "level": "error",
        "precision": "medium",
        "cwe": "CWE-682",
    },
    "STACK_OVERFLOW": {
        "id": "PFS015",
        "name": "StackOverflow",
        "shortDescription": "Potential stack overflow via unbounded recursion",
        "fullDescription": (
            "A recursive call chain may exceed the maximum recursion depth, "
            "causing a RecursionError."
        ),
        "level": "error",
        "precision": "medium",
        "cwe": "CWE-674",
    },
    "MEMORY_LEAK": {
        "id": "PFS016",
        "name": "MemoryLeak",
        "shortDescription": "Potential resource or memory leak",
        "fullDescription": (
            "A resource (file handle, connection, etc.) may not be properly "
            "released on all execution paths."
        ),
        "level": "warning",
        "precision": "medium",
        "cwe": "CWE-401",
    },
    "NON_TERMINATION": {
        "id": "PFS017",
        "name": "NonTermination",
        "shortDescription": "Potential infinite loop",
        "fullDescription": (
            "A loop may never terminate because its exit condition "
            "cannot be satisfied."
        ),
        "level": "warning",
        "precision": "low",
        "cwe": "CWE-835",
    },
    "ITERATOR_INVALID": {
        "id": "PFS018",
        "name": "InvalidIterator",
        "shortDescription": "Potential invalid iterator use",
        "fullDescription": (
            "An iterator or generator may be used after exhaustion "
            "or invalidated by concurrent modification."
        ),
        "level": "warning",
        "precision": "medium",
        "cwe": "CWE-825",
    },
    "USE_AFTER_FREE": {
        "id": "PFS019",
        "name": "UseAfterFree",
        "shortDescription": "Potential use-after-free",
        "fullDescription": (
            "A resource may be accessed after it has been released or closed."
        ),
        "level": "error",
        "precision": "medium",
        "cwe": "CWE-416",
    },
    "DOUBLE_FREE": {
        "id": "PFS020",
        "name": "DoubleFree",
        "shortDescription": "Potential double-free or double-close",
        "fullDescription": (
            "A resource may be released or closed more than once."
        ),
        "level": "error",
        "precision": "medium",
        "cwe": "CWE-415",
    },
    "UNINIT_MEMORY": {
        "id": "PFS021",
        "name": "UninitializedMemory",
        "shortDescription": "Potential use of uninitialized data",
        "fullDescription": (
            "A variable or buffer may be read before being initialized."
        ),
        "level": "error",
        "precision": "medium",
        "cwe": "CWE-908",
    },
    "DATA_RACE": {
        "id": "PFS022",
        "name": "DataRace",
        "shortDescription": "Potential data race",
        "fullDescription": (
            "A shared variable may be accessed concurrently by multiple "
            "threads without proper synchronization."
        ),
        "level": "error",
        "precision": "low",
        "cwe": "CWE-362",
    },
    "DEADLOCK": {
        "id": "PFS023",
        "name": "Deadlock",
        "shortDescription": "Potential deadlock",
        "fullDescription": (
            "Two or more threads may wait for each other's locks, "
            "causing a deadlock."
        ),
        "level": "error",
        "precision": "low",
        "cwe": "CWE-833",
    },
    "SEND_SYNC": {
        "id": "PFS024",
        "name": "UnsafeSendSync",
        "shortDescription": "Potential unsafe cross-thread data sharing",
        "fullDescription": (
            "Data that is not thread-safe may be shared across threads."
        ),
        "level": "warning",
        "precision": "low",
        "cwe": "CWE-362",
    },
    "INFO_LEAK": {
        "id": "PFS025",
        "name": "InformationLeak",
        "shortDescription": "Potential information disclosure",
        "fullDescription": (
            "Sensitive information may be leaked to an unauthorized actor."
        ),
        "level": "warning",
        "precision": "medium",
        "cwe": "CWE-200",
    },
    "TIMING_CHANNEL": {
        "id": "PFS026",
        "name": "TimingChannel",
        "shortDescription": "Potential timing side-channel",
        "fullDescription": (
            "A comparison of security-sensitive data (e.g. password, token) "
            "may be vulnerable to timing attacks."
        ),
        "level": "warning",
        "precision": "medium",
        "cwe": "CWE-208",
    },
    "PANIC": {
        "id": "PFS027",
        "name": "UnhandledException",
        "shortDescription": "Potential unhandled exception",
        "fullDescription": (
            "An exception may be raised and not caught, causing the program "
            "to terminate abnormally."
        ),
        "level": "warning",
        "precision": "low",
        "cwe": "CWE-755",
    },

    # ══════════════════ Security Bug Types (47) ══════════════════
    "SSRF": {
        "id": "PFS100",
        "name": "ServerSideRequestForgery",
        "shortDescription": "Potential SSRF vulnerability",
        "fullDescription": (
            "User-controlled input may flow to a URL in an HTTP request, "
            "allowing server-side request forgery."
        ),
        "level": "error",
        "precision": "medium",
        "cwe": "CWE-918",
    },
    "SQL_INJECTION": {
        "id": "PFS101",
        "name": "SQLInjection",
        "shortDescription": "Potential SQL injection",
        "fullDescription": (
            "User-controlled input may be interpolated into a SQL query "
            "without proper sanitisation."
        ),
        "level": "error",
        "precision": "medium",
        "cwe": "CWE-89",
    },
    "COMMAND_INJECTION": {
        "id": "PFS102",
        "name": "CommandInjection",
        "shortDescription": "Potential command injection",
        "fullDescription": (
            "User-controlled input may flow to a shell command, allowing "
            "arbitrary command execution."
        ),
        "level": "error",
        "precision": "medium",
        "cwe": "CWE-78",
    },
    # Alias: old SARIF used CMD_INJECTION
    "CMD_INJECTION": {
        "id": "PFS102",
        "name": "CommandInjection",
        "shortDescription": "Potential command injection",
        "fullDescription": (
            "User-controlled input may flow to a shell command, allowing "
            "arbitrary command execution."
        ),
        "level": "error",
        "precision": "medium",
        "cwe": "CWE-78",
    },
    "CODE_INJECTION": {
        "id": "PFS103",
        "name": "CodeInjection",
        "shortDescription": "Potential code injection",
        "fullDescription": (
            "User-controlled input may flow to eval(), exec(), or similar, "
            "allowing arbitrary code execution."
        ),
        "level": "error",
        "precision": "high",
        "cwe": "CWE-94",
    },
    "PATH_INJECTION": {
        "id": "PFS104",
        "name": "PathInjection",
        "shortDescription": "Potential path injection / traversal",
        "fullDescription": (
            "User-controlled input may be used in a file path without "
            "proper sanitisation, allowing access to unintended files."
        ),
        "level": "error",
        "precision": "medium",
        "cwe": "CWE-22",
    },
    # Alias: old SARIF used PATH_TRAVERSAL
    "PATH_TRAVERSAL": {
        "id": "PFS104",
        "name": "PathTraversal",
        "shortDescription": "Potential path traversal",
        "fullDescription": (
            "User-controlled input may be used in a file path without "
            "proper sanitisation, allowing access to unintended files."
        ),
        "level": "error",
        "precision": "medium",
        "cwe": "CWE-22",
    },
    "REFLECTED_XSS": {
        "id": "PFS105",
        "name": "ReflectedXSS",
        "shortDescription": "Potential reflected cross-site scripting",
        "fullDescription": (
            "User-controlled input may be reflected in HTTP responses "
            "without proper escaping, enabling XSS attacks."
        ),
        "level": "error",
        "precision": "medium",
        "cwe": "CWE-79",
    },
    "UNSAFE_DESERIALIZATION": {
        "id": "PFS106",
        "name": "UnsafeDeserialization",
        "shortDescription": "Potential unsafe deserialization",
        "fullDescription": (
            "Untrusted data may be deserialized using pickle, yaml.load, "
            "or similar, allowing arbitrary code execution."
        ),
        "level": "error",
        "precision": "high",
        "cwe": "CWE-502",
    },
    "XXE": {
        "id": "PFS107",
        "name": "XMLExternalEntity",
        "shortDescription": "Potential XML external entity injection",
        "fullDescription": (
            "An XML parser may process external entities from untrusted input, "
            "allowing file disclosure or SSRF."
        ),
        "level": "error",
        "precision": "medium",
        "cwe": "CWE-611",
    },
    "CLEARTEXT_LOGGING": {
        "id": "PFS108",
        "name": "CleartextLogging",
        "shortDescription": "Potential cleartext logging of sensitive data",
        "fullDescription": (
            "Sensitive data (passwords, tokens) may be written to log files "
            "in cleartext."
        ),
        "level": "warning",
        "precision": "medium",
        "cwe": "CWE-532",
    },
    "CLEARTEXT_STORAGE": {
        "id": "PFS109",
        "name": "CleartextStorage",
        "shortDescription": "Potential cleartext storage of sensitive data",
        "fullDescription": (
            "Sensitive data (passwords, tokens) may be stored in cleartext."
        ),
        "level": "warning",
        "precision": "medium",
        "cwe": "CWE-312",
    },
    "LDAP_INJECTION": {
        "id": "PFS110",
        "name": "LDAPInjection",
        "shortDescription": "Potential LDAP injection",
        "fullDescription": (
            "User-controlled input may be interpolated into an LDAP query "
            "without proper sanitisation."
        ),
        "level": "error",
        "precision": "medium",
        "cwe": "CWE-90",
    },
    "XPATH_INJECTION": {
        "id": "PFS111",
        "name": "XPathInjection",
        "shortDescription": "Potential XPath injection",
        "fullDescription": (
            "User-controlled input may be interpolated into an XPath query "
            "without proper sanitisation."
        ),
        "level": "error",
        "precision": "medium",
        "cwe": "CWE-643",
    },
    "NOSQL_INJECTION": {
        "id": "PFS112",
        "name": "NoSQLInjection",
        "shortDescription": "Potential NoSQL injection",
        "fullDescription": (
            "User-controlled input may be interpolated into a NoSQL query "
            "without proper sanitisation."
        ),
        "level": "error",
        "precision": "medium",
        "cwe": "CWE-943",
    },
    "REGEX_INJECTION": {
        "id": "PFS113",
        "name": "RegexInjection",
        "shortDescription": "Potential regex injection",
        "fullDescription": (
            "User-controlled input may be used in a regular expression "
            "without proper escaping, enabling ReDoS or logic bypass."
        ),
        "level": "warning",
        "precision": "medium",
        "cwe": "CWE-1333",
    },
    "URL_REDIRECT": {
        "id": "PFS114",
        "name": "URLRedirect",
        "shortDescription": "Potential open redirect",
        "fullDescription": (
            "User-controlled input may be used as a redirect target URL, "
            "enabling phishing attacks."
        ),
        "level": "warning",
        "precision": "medium",
        "cwe": "CWE-601",
    },
    "HEADER_INJECTION": {
        "id": "PFS115",
        "name": "HeaderInjection",
        "shortDescription": "Potential HTTP header injection",
        "fullDescription": (
            "User-controlled input may be used in HTTP response headers, "
            "enabling header injection or response splitting."
        ),
        "level": "error",
        "precision": "medium",
        "cwe": "CWE-113",
    },
    "COOKIE_INJECTION": {
        "id": "PFS116",
        "name": "CookieInjection",
        "shortDescription": "Potential cookie injection",
        "fullDescription": (
            "User-controlled input may be used in a cookie value without "
            "proper sanitisation."
        ),
        "level": "warning",
        "precision": "medium",
        "cwe": "CWE-20",
    },
    "FLASK_DEBUG": {
        "id": "PFS117",
        "name": "FlaskDebugMode",
        "shortDescription": "Flask app running in debug mode",
        "fullDescription": (
            "A Flask application may be running with debug=True in production, "
            "exposing the interactive debugger."
        ),
        "level": "error",
        "precision": "high",
        "cwe": "CWE-215",
    },
    "INSECURE_COOKIE": {
        "id": "PFS118",
        "name": "InsecureCookie",
        "shortDescription": "Cookie set without security flags",
        "fullDescription": (
            "A cookie may be set without HttpOnly, Secure, or SameSite "
            "flags, making it vulnerable to theft or misuse."
        ),
        "level": "warning",
        "precision": "high",
        "cwe": "CWE-614",
    },
    "WEAK_CRYPTO": {
        "id": "PFS119",
        "name": "WeakCryptography",
        "shortDescription": "Use of weak cryptographic algorithm",
        "fullDescription": (
            "A cryptographic operation uses a weak or deprecated algorithm "
            "(e.g. MD5, SHA1 for security purposes)."
        ),
        "level": "warning",
        "precision": "high",
        "cwe": "CWE-327",
    },
    "HARDCODED_CREDENTIALS": {
        "id": "PFS120",
        "name": "HardcodedCredentials",
        "shortDescription": "Potential hardcoded credentials",
        "fullDescription": (
            "A password, secret key, or API token may be hardcoded in source code."
        ),
        "level": "error",
        "precision": "medium",
        "cwe": "CWE-798",
    },
    "INSECURE_PROTOCOL": {
        "id": "PFS121",
        "name": "InsecureProtocol",
        "shortDescription": "Use of insecure protocol",
        "fullDescription": (
            "An insecure protocol (HTTP, FTP, Telnet) may be used where "
            "a secure alternative (HTTPS, SFTP, SSH) is available."
        ),
        "level": "warning",
        "precision": "high",
        "cwe": "CWE-319",
    },
    "CERT_VALIDATION_DISABLED": {
        "id": "PFS122",
        "name": "CertValidationDisabled",
        "shortDescription": "TLS certificate validation disabled",
        "fullDescription": (
            "SSL/TLS certificate verification may be disabled (verify=False), "
            "enabling man-in-the-middle attacks."
        ),
        "level": "error",
        "precision": "high",
        "cwe": "CWE-295",
    },
    "XML_BOMB": {
        "id": "PFS123",
        "name": "XMLBomb",
        "shortDescription": "Potential XML bomb (billion laughs)",
        "fullDescription": (
            "An XML parser may be vulnerable to exponential entity expansion "
            "(XML bomb / billion laughs attack)."
        ),
        "level": "error",
        "precision": "medium",
        "cwe": "CWE-776",
    },
    "TAR_SLIP": {
        "id": "PFS124",
        "name": "TarSlip",
        "shortDescription": "Potential tar slip / zip slip",
        "fullDescription": (
            "Archive extraction may allow files to be written outside the "
            "intended directory via path traversal in archive entries."
        ),
        "level": "error",
        "precision": "medium",
        "cwe": "CWE-22",
    },
    "JINJA2_AUTOESCAPE_FALSE": {
        "id": "PFS125",
        "name": "Jinja2AutoescapeDisabled",
        "shortDescription": "Jinja2 autoescape disabled",
        "fullDescription": (
            "A Jinja2 environment may be created with autoescape=False, "
            "enabling template injection or XSS."
        ),
        "level": "warning",
        "precision": "high",
        "cwe": "CWE-79",
    },
    "REDOS": {
        "id": "PFS126",
        "name": "ReDoS",
        "shortDescription": "Potential regular expression denial of service",
        "fullDescription": (
            "A regular expression may exhibit exponential backtracking on "
            "crafted input, causing denial of service."
        ),
        "level": "warning",
        "precision": "medium",
        "cwe": "CWE-1333",
    },
    "POLYNOMIAL_REDOS": {
        "id": "PFS127",
        "name": "PolynomialReDoS",
        "shortDescription": "Potential polynomial ReDoS",
        "fullDescription": (
            "A regular expression may exhibit polynomial-time matching on "
            "crafted input."
        ),
        "level": "warning",
        "precision": "medium",
        "cwe": "CWE-1333",
    },
    "BAD_TAG_FILTER": {
        "id": "PFS128",
        "name": "BadTagFilter",
        "shortDescription": "Incomplete HTML tag filter",
        "fullDescription": (
            "An HTML tag sanitisation regex may be bypassable, allowing "
            "script injection."
        ),
        "level": "warning",
        "precision": "medium",
        "cwe": "CWE-79",
    },
    "INCOMPLETE_HOSTNAME_REGEXP": {
        "id": "PFS129",
        "name": "IncompleteHostnameRegexp",
        "shortDescription": "Incomplete hostname validation regex",
        "fullDescription": (
            "A hostname validation regex may not be anchored, allowing "
            "subdomain bypass attacks."
        ),
        "level": "warning",
        "precision": "medium",
        "cwe": "CWE-20",
    },
    "OVERLY_LARGE_RANGE": {
        "id": "PFS130",
        "name": "OverlyLargeRange",
        "shortDescription": "Overly large character class range in regex",
        "fullDescription": (
            "A regex character class range like [a-Z] may match unintended "
            "characters."
        ),
        "level": "warning",
        "precision": "medium",
        "cwe": "CWE-185",
    },
    "INCOMPLETE_URL_SUBSTRING_SANITIZATION": {
        "id": "PFS131",
        "name": "IncompleteURLSubstringSanitization",
        "shortDescription": "Incomplete URL substring sanitization",
        "fullDescription": (
            "A URL validation check may use substring matching (e.g. 'startswith') "
            "that can be bypassed."
        ),
        "level": "warning",
        "precision": "medium",
        "cwe": "CWE-20",
    },
    "INSECURE_TEMPORARY_FILE": {
        "id": "PFS132",
        "name": "InsecureTemporaryFile",
        "shortDescription": "Insecure temporary file creation",
        "fullDescription": (
            "A temporary file may be created with predictable name or "
            "insecure permissions (e.g. mktemp instead of mkstemp)."
        ),
        "level": "warning",
        "precision": "high",
        "cwe": "CWE-377",
    },
    "WEAK_FILE_PERMISSIONS": {
        "id": "PFS133",
        "name": "WeakFilePermissions",
        "shortDescription": "Weak file permissions",
        "fullDescription": (
            "A file may be created with overly permissive permissions "
            "(e.g. 0o777 or world-writable)."
        ),
        "level": "warning",
        "precision": "high",
        "cwe": "CWE-732",
    },
    "PARTIAL_SSRF": {
        "id": "PFS134",
        "name": "PartialSSRF",
        "shortDescription": "Potential partial SSRF",
        "fullDescription": (
            "User-controlled input may partially control a URL in an HTTP "
            "request (e.g. host or path component)."
        ),
        "level": "warning",
        "precision": "medium",
        "cwe": "CWE-918",
    },
    "BIND_TO_ALL_INTERFACES": {
        "id": "PFS135",
        "name": "BindToAllInterfaces",
        "shortDescription": "Server binding to all network interfaces",
        "fullDescription": (
            "A server socket may bind to 0.0.0.0, exposing the service "
            "on all network interfaces."
        ),
        "level": "warning",
        "precision": "high",
        "cwe": "CWE-200",
    },
    "MISSING_HOST_KEY_VALIDATION": {
        "id": "PFS136",
        "name": "MissingHostKeyValidation",
        "shortDescription": "Missing SSH host key validation",
        "fullDescription": (
            "An SSH connection may accept any host key without validation, "
            "enabling man-in-the-middle attacks."
        ),
        "level": "error",
        "precision": "high",
        "cwe": "CWE-295",
    },
    "CSRF_PROTECTION_DISABLED": {
        "id": "PFS137",
        "name": "CSRFProtectionDisabled",
        "shortDescription": "CSRF protection disabled",
        "fullDescription": (
            "Cross-site request forgery protection may be disabled for "
            "a web application or endpoint."
        ),
        "level": "warning",
        "precision": "high",
        "cwe": "CWE-352",
    },
    "STACK_TRACE_EXPOSURE": {
        "id": "PFS138",
        "name": "StackTraceExposure",
        "shortDescription": "Stack trace exposed to users",
        "fullDescription": (
            "Detailed exception stack traces may be returned in HTTP "
            "responses, revealing internal implementation details."
        ),
        "level": "warning",
        "precision": "medium",
        "cwe": "CWE-209",
    },
    "LOG_INJECTION": {
        "id": "PFS139",
        "name": "LogInjection",
        "shortDescription": "Potential log injection",
        "fullDescription": (
            "User-controlled input may be written to log files without "
            "sanitisation, enabling log forging."
        ),
        "level": "warning",
        "precision": "medium",
        "cwe": "CWE-117",
    },
    "UNSAFE_SHELL_COMMAND_CONSTRUCTION": {
        "id": "PFS140",
        "name": "UnsafeShellCommandConstruction",
        "shortDescription": "Unsafe shell command construction",
        "fullDescription": (
            "A shell command may be constructed by string concatenation "
            "or formatting with user input, rather than using a safe API."
        ),
        "level": "error",
        "precision": "medium",
        "cwe": "CWE-78",
    },
    "PAM_AUTHORIZATION_BYPASS": {
        "id": "PFS141",
        "name": "PAMAuthorizationBypass",
        "shortDescription": "Potential PAM authorization bypass",
        "fullDescription": (
            "A PAM authentication check may be bypassable, granting "
            "unauthorized access."
        ),
        "level": "error",
        "precision": "low",
        "cwe": "CWE-862",
    },
    "UNTRUSTED_DATA_TO_EXTERNAL_API": {
        "id": "PFS142",
        "name": "UntrustedDataToExternalAPI",
        "shortDescription": "Untrusted data sent to external API",
        "fullDescription": (
            "User-controlled input may be sent to an external API without "
            "proper validation."
        ),
        "level": "warning",
        "precision": "low",
        "cwe": "CWE-20",
    },
    "WEAK_CRYPTO_KEY": {
        "id": "PFS143",
        "name": "WeakCryptoKey",
        "shortDescription": "Weak cryptographic key size",
        "fullDescription": (
            "A cryptographic key may be generated with insufficient length "
            "(e.g. RSA < 2048 bits)."
        ),
        "level": "warning",
        "precision": "high",
        "cwe": "CWE-326",
    },
    "BROKEN_CRYPTO_ALGORITHM": {
        "id": "PFS144",
        "name": "BrokenCryptoAlgorithm",
        "shortDescription": "Use of broken cryptographic algorithm",
        "fullDescription": (
            "A cryptographic operation uses a broken algorithm (e.g. DES, "
            "RC4, MD4) with known vulnerabilities."
        ),
        "level": "error",
        "precision": "high",
        "cwe": "CWE-327",
    },
    "WEAK_SENSITIVE_DATA_HASHING": {
        "id": "PFS145",
        "name": "WeakSensitiveDataHashing",
        "shortDescription": "Weak hashing of sensitive data",
        "fullDescription": (
            "Sensitive data (passwords, etc.) may be hashed with a weak "
            "algorithm (MD5, SHA1) instead of a proper KDF (bcrypt, scrypt)."
        ),
        "level": "warning",
        "precision": "high",
        "cwe": "CWE-916",
    },
    "INSECURE_DEFAULT_PROTOCOL": {
        "id": "PFS146",
        "name": "InsecureDefaultProtocol",
        "shortDescription": "Use of insecure default TLS protocol version",
        "fullDescription": (
            "A TLS context may default to an insecure protocol version "
            "(SSLv2, SSLv3, TLSv1.0)."
        ),
        "level": "warning",
        "precision": "high",
        "cwe": "CWE-327",
    },

    # ══════════════════ Exception Bug Types ══════════════════
    "VALUE_ERROR": {
        "id": "PFS200",
        "name": "ValueError",
        "shortDescription": "Potential ValueError",
        "fullDescription": (
            "A function may receive an argument of the correct type but "
            "inappropriate value."
        ),
        "level": "warning",
        "precision": "medium",
        "cwe": "CWE-20",
    },
    "RUNTIME_ERROR": {
        "id": "PFS201",
        "name": "RuntimeError",
        "shortDescription": "Potential RuntimeError",
        "fullDescription": (
            "A runtime error may occur that doesn't fit other categories."
        ),
        "level": "warning",
        "precision": "low",
        "cwe": "CWE-755",
    },
    "FILE_NOT_FOUND": {
        "id": "PFS202",
        "name": "FileNotFoundError",
        "shortDescription": "Potential FileNotFoundError",
        "fullDescription": (
            "A file operation may fail because the target file does not exist."
        ),
        "level": "warning",
        "precision": "medium",
        "cwe": "CWE-755",
    },
    "PERMISSION_ERROR": {
        "id": "PFS203",
        "name": "PermissionError",
        "shortDescription": "Potential PermissionError",
        "fullDescription": (
            "A file or resource operation may fail due to insufficient permissions."
        ),
        "level": "warning",
        "precision": "medium",
        "cwe": "CWE-755",
    },
    "OS_ERROR": {
        "id": "PFS204",
        "name": "OSError",
        "shortDescription": "Potential OSError",
        "fullDescription": (
            "An operating system call may fail."
        ),
        "level": "warning",
        "precision": "low",
        "cwe": "CWE-755",
    },
    "IO_ERROR": {
        "id": "PFS205",
        "name": "IOError",
        "shortDescription": "Potential IOError",
        "fullDescription": (
            "An I/O operation (read, write, etc.) may fail."
        ),
        "level": "warning",
        "precision": "low",
        "cwe": "CWE-755",
    },
    "IMPORT_ERROR": {
        "id": "PFS206",
        "name": "ImportError",
        "shortDescription": "Potential ImportError",
        "fullDescription": (
            "A module import may fail because the module is not installed "
            "or not found."
        ),
        "level": "warning",
        "precision": "medium",
        "cwe": "CWE-755",
    },
    "NAME_ERROR": {
        "id": "PFS207",
        "name": "NameError",
        "shortDescription": "Potential NameError",
        "fullDescription": (
            "A name may not be defined in the current scope."
        ),
        "level": "error",
        "precision": "high",
        "cwe": "CWE-457",
    },
    "UNBOUND_LOCAL": {
        "id": "PFS208",
        "name": "UnboundLocalError",
        "shortDescription": "Potential UnboundLocalError",
        "fullDescription": (
            "A local variable may be referenced before assignment."
        ),
        "level": "error",
        "precision": "high",
        "cwe": "CWE-457",
    },
    "TIMEOUT_ERROR": {
        "id": "PFS209",
        "name": "TimeoutError",
        "shortDescription": "Potential TimeoutError",
        "fullDescription": (
            "An operation may time out, and the timeout is not properly handled."
        ),
        "level": "warning",
        "precision": "low",
        "cwe": "CWE-755",
    },
    "CONNECTION_ERROR": {
        "id": "PFS210",
        "name": "ConnectionError",
        "shortDescription": "Potential ConnectionError",
        "fullDescription": (
            "A network connection may fail, and the failure is not properly handled."
        ),
        "level": "warning",
        "precision": "low",
        "cwe": "CWE-755",
    },
    "UNICODE_ERROR": {
        "id": "PFS211",
        "name": "UnicodeError",
        "shortDescription": "Potential UnicodeError",
        "fullDescription": (
            "A string encoding or decoding operation may fail due to "
            "invalid Unicode data."
        ),
        "level": "warning",
        "precision": "medium",
        "cwe": "CWE-838",
    },
}

# Fallback for unknown bug types
_DEFAULT_RULE = {
    "id": "PFS999",
    "name": "UnclassifiedBug",
    "shortDescription": "Potential runtime error",
    "fullDescription": "A potential runtime error was detected by static analysis.",
    "level": "warning",
    "precision": "medium",
    "cwe": "CWE-710",
}


def _rule_for(bug_type: str) -> dict[str, str]:
    """Get the SARIF rule descriptor for a bug type."""
    return _BUG_RULES.get(bug_type, {**_DEFAULT_RULE, "name": bug_type})


def _make_rule_id(bug_type: str) -> str:
    rule = _rule_for(bug_type)
    return rule["id"]


# ── Public API ────────────────────────────────────────────────────────────────


def results_to_sarif(
    results: dict[str, Any],
    repo_root: Path | str,
) -> dict[str, Any]:
    """
    Convert a a3 results dict to SARIF 2.1.0 JSON.

    Parameters
    ----------
    results : dict
        The results dict produced by ``_analyze_project`` and saved via
        ``--save-results``.  Expected keys: ``prod_bugs``, ``dse_reachable``,
        ``project``, ``total_functions``, ``total_bugs``, ``grand_fp``.
        May also include ``_call_graph`` and ``_summaries`` for rich location data.
    repo_root : Path
        Absolute path to the repository root.  File paths in the SARIF output
        will be made relative to this.

    Returns
    -------
    dict
        A SARIF 2.1.0 JSON-serialisable dict.
    """
    repo_root = Path(repo_root).resolve()

    # Extract rich data if available (in-memory only, not serialised)
    call_graph = results.get("_call_graph")
    summaries = results.get("_summaries", {})
    dse_full = results.get("dse_reachable_full", {})

    # Build a lookup: func_name -> FunctionInfo (file_path, line_number)
    func_info_map: dict[str, Any] = {}
    if call_graph:
        for fname, finfo in call_graph.functions.items():
            func_info_map[fname] = finfo

    # Build a lookup: func_name -> bug line numbers from crash summaries
    # crash_summaries store BytecodeLocation with line_number per bug
    bug_lines_map: dict[str, dict[str, int | None]] = {}
    if summaries:
        for fname, summary in summaries.items():
            analyzer_crash_locs = getattr(summary, "_crash_locations", None)
            # crash_locations aren't on the summary; instead look at bytecode_instructions
            # to find the bug line from the code object
            if fname not in bug_lines_map:
                bug_lines_map[fname] = {}

    # Collect all unique bug types to build the rules array
    all_bug_types: set[str] = set()
    for _, bug_type in results.get("prod_bugs", []):
        all_bug_types.add(bug_type)
    for func_name, (status, bug_type) in results.get("dse_reachable", {}).items():
        all_bug_types.add(bug_type)

    # Build rules array (one per unique bug type)
    rules = []
    rule_index_map: dict[str, int] = {}
    for i, bug_type in enumerate(sorted(all_bug_types)):
        meta = _rule_for(bug_type)
        rule_index_map[bug_type] = i
        rules.append({
            "id": meta["id"],
            "name": meta["name"],
            "shortDescription": {"text": meta["shortDescription"]},
            "fullDescription": {"text": meta["fullDescription"]},
            "defaultConfiguration": {"level": meta["level"]},
            "properties": {
                "precision": meta["precision"],
                "tags": ["security" if bug_type in SECURITY_BUG_TYPES else "correctness"],
            },
            "helpUri": f"https://cwe.mitre.org/data/definitions/{meta['cwe'].split('-')[1]}.html",
        })

    # Build results array
    sarif_results = []

    # DSE-confirmed reachable bugs (highest confidence)
    dse_confirmed: set[str] = set()
    for func_name, (status, bug_type) in results.get("dse_reachable", {}).items():
        dse_confirmed.add(func_name)
        cex = dse_full.get(func_name, (None, None, None))[2] if dse_full else None
        sarif_results.append(
            _make_result(
                func_name, bug_type, rule_index_map, repo_root,
                dse_confirmed=True,
                func_info_map=func_info_map,
                counterexample=cex,
            )
        )

    # Production candidates not already covered by DSE
    for func_name, bug_type in results.get("prod_bugs", []):
        if func_name not in dse_confirmed:
            sarif_results.append(
                _make_result(
                    func_name, bug_type, rule_index_map, repo_root,
                    dse_confirmed=False,
                    func_info_map=func_info_map,
                )
            )

    # Assemble SARIF envelope
    sarif: dict[str, Any] = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "a3",
                        "semanticVersion": __version__,
                        "informationUri": "https://github.com/thehalleyyoung/A³",
                        "rules": rules,
                    }
                },
                "results": sarif_results,
                "invocations": [
                    {
                        "executionSuccessful": True,
                        "toolExecutionNotifications": [],
                    }
                ],
                "properties": {
                    "metrics": {
                        "totalFunctions": results.get("total_functions", 0),
                        "totalBugs": results.get("total_bugs", 0),
                        "provenFP": results.get("grand_fp", 0),
                        "remainingCandidates": results.get("remaining_count", 0),
                    }
                },
            }
        ],
    }
    return sarif


def write_sarif(sarif: dict[str, Any], output_path: Path | str) -> None:
    """Write a SARIF dict to a JSON file."""
    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "w") as f:
        json.dump(sarif, f, indent=2)


def load_sarif(path: Path | str) -> dict[str, Any]:
    """Load a SARIF JSON file."""
    path = Path(path)
    if not path.exists():
        print(f"Error: SARIF file not found: {path}", file=__import__('sys').stderr)
        raise SystemExit(3)
    try:
        with open(path) as f:
            return json.load(f)
    except json.JSONDecodeError as e:
        print(f"Error: invalid JSON in SARIF file {path}: {e}", file=__import__('sys').stderr)
        raise SystemExit(3)


# ── Internal helpers ─────────────────────────────────────────────────────────


def _parse_func_location(
    func_name: str,
    repo_root: Path,
    func_info_map: dict[str, Any] | None = None,
) -> tuple[str, int]:
    """
    Extract (relative_file_path, line_number) from a qualified function name.

    Uses the call graph's FunctionInfo when available for precise locations.
    Falls back to dotted-module → path heuristic otherwise.
    """
    # Try call-graph FunctionInfo first (has real file_path + line_number)
    if func_info_map:
        info = func_info_map.get(func_name)
        if info is not None:
            abs_path = Path(getattr(info, "file_path", ""))
            line = getattr(info, "line_number", 1) or 1
            try:
                rel = abs_path.resolve().relative_to(repo_root)
                return str(rel), line
            except ValueError:
                # file_path is already relative or not under repo_root
                return str(abs_path), line

    # Fallback: dotted module → file path
    parts = func_name.split(".")

    for depth in range(len(parts), 0, -1):
        candidate = Path(*parts[:depth]).with_suffix(".py")
        full = repo_root / candidate
        if full.exists():
            return str(candidate), 1

    module_parts = parts[:-1] if len(parts) > 1 else parts
    rel = Path(*module_parts).with_suffix(".py") if module_parts else Path(func_name + ".py")
    return str(rel), 1


def _read_source_snippet(
    rel_path: str,
    line: int,
    repo_root: Path,
    context_lines: int = 3,
) -> tuple[str | None, int, int]:
    """
    Read source code lines around the bug location.

    Returns (snippet_text, start_line, end_line) or (None, line, line).
    """
    abs_path = repo_root / rel_path
    if not abs_path.is_file():
        return None, line, line

    try:
        text = abs_path.read_text(encoding="utf-8", errors="replace")
        lines = text.splitlines()
        total = len(lines)
        start = max(0, line - 1 - context_lines)
        end = min(total, line + context_lines)
        snippet = "\n".join(lines[start:end])
        return snippet, start + 1, end
    except Exception:
        return None, line, line


def _make_result(
    func_name: str,
    bug_type: str,
    rule_index_map: dict[str, int],
    repo_root: Path,
    *,
    dse_confirmed: bool = False,
    func_info_map: dict[str, Any] | None = None,
    counterexample: Any = None,
) -> dict[str, Any]:
    """Build a single SARIF result object with rich location and code context."""
    meta = _rule_for(bug_type)
    rel_path, line = _parse_func_location(func_name, repo_root, func_info_map)

    # Extract the last component as the function display name
    display_name = func_name.rsplit(".", 1)[-1] if "." in func_name else func_name

    # Read source code snippet
    snippet_text, snippet_start, snippet_end = _read_source_snippet(
        rel_path, line, repo_root
    )

    # Build message with more context
    msg_parts = [f"{meta['shortDescription']} in `{display_name}()`"]
    if dse_confirmed:
        msg_parts.append("(DSE-confirmed reachable)")
    message_text = " ".join(msg_parts)

    # Build region with real line number
    region: dict[str, Any] = {
        "startLine": line,
    }
    if snippet_text:
        region["snippet"] = {"text": snippet_text}

    # Build physical location
    phys_loc: dict[str, Any] = {
        "artifactLocation": {
            "uri": rel_path,
            "uriBaseId": "%SRCROOT%",
        },
        "region": region,
    }

    # Build the result
    result: dict[str, Any] = {
        "ruleId": meta["id"],
        "ruleIndex": rule_index_map.get(bug_type, 0),
        "level": meta["level"],
        "message": {"text": message_text},
        "locations": [
            {
                "physicalLocation": phys_loc,
                "logicalLocations": [
                    {
                        "fullyQualifiedName": func_name,
                        "kind": "function",
                    }
                ],
            }
        ],
        "properties": {
            "dseConfirmed": dse_confirmed,
            "bugType": bug_type,
            "qualifiedName": func_name,
        },
    }

    # Add counterexample from DSE if available
    if counterexample and isinstance(counterexample, dict):
        cex_lines = []
        for param, value in counterexample.items():
            cex_lines.append(f"  {param} = {value!r}")
        if cex_lines:
            result["message"]["text"] += (
                "\n\nCounterexample (inputs that trigger the bug):\n"
                + "\n".join(cex_lines)
            )
            result["properties"]["counterexample"] = counterexample

    return result
