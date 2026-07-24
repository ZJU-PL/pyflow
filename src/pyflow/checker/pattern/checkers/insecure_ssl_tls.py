"""
B501/B502/B503: Test for insecure SSL/TLS configuration.

Using weak SSL/TLS protocol versions or ciphers exposes
connections to downgrade and decryption attacks.
"""
from ..core import issue
from ..core import test_properties as test

WEAK_SSL_METHODS = {
    "PROTOCOL_SSLv2", "PROTOCOL_SSLv3",
    "PROTOCOL_TLSv1", "PROTOCOL_TLSv1_1",
}


@test.checks("Call")
@test.with_id("B501")
def weak_ssl_method(context):
    qualname = context.call_function_name_qual
    if not qualname.startswith("ssl."):
        return None
    method = qualname.split(".")[-1]
    if method in WEAK_SSL_METHODS:
        return issue.Issue(
            severity="HIGH",
            confidence="HIGH",
            cwe=issue.Cwe.INADEQUATE_ENCRYPTION_STRENGTH,
            text=f"Use of weak SSL/TLS method {method}. "
            f"{method} is deprecated and vulnerable to "
            "downgrade attacks. Use ssl.PROTOCOL_TLSv1_2 or higher.",
        )
    return None


@test.checks("Call")
@test.with_id("B502")
def weak_ssl_context(context):
    qualname = context.call_function_name_qual
    if qualname not in {
        "ssl.create_default_context",
        "ssl.SSLContext",
    }:
        return None
    for kw in context.node.keywords:
        if kw.arg == "protocol" and hasattr(kw.value, "value"):
            proto = str(kw.value.value)
            if "SSLv2" in proto or "SSLv3" in proto:
                return issue.Issue(
                    severity="HIGH",
                    confidence="HIGH",
                    cwe=issue.Cwe.INADEQUATE_ENCRYPTION_STRENGTH,
                    text="SSL context created with insecure protocol. "
                    "Use ssl.PROTOCOL_TLSv1_2 or higher.",
                )
    return None


@test.checks("Call")
@test.with_id("B503")
def weak_cert_verification(context):
    qualname = context.call_function_name_qual
    if qualname in {"ssl.match_hostname", "ssl.SSLContext.check_hostname"}:
        return issue.Issue(
            severity="MEDIUM",
            confidence="HIGH",
            cwe=issue.Cwe.IMPROPER_CERT_VALIDATION,
            text="Hostname verification may be insufficient. "
            "Ensure SSL certificates are properly validated.",
        )
    return None
