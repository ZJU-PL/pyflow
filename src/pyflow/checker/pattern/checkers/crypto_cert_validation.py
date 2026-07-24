"""
B508: Test for disabling certificate verification.

Disabling SSL/TLS certificate verification makes connections
vulnerable to man-in-the-middle attacks.
"""
from ..core import issue
from ..core import test_properties as test


@test.checks("Call")
@test.with_id("B508")
def request_no_cert_validation(context):
    qualname = context.call_function_name_qual
    if qualname not in {
        "requests.get", "requests.post", "requests.put",
        "requests.delete", "requests.patch", "requests.head",
        "requests.options", "requests.request",
    }:
        return None
    for kw in context.node.keywords:
        if kw.arg == "verify" and (
            (hasattr(kw.value, "value") and kw.value.value is False)
            or (hasattr(kw.value, "id") and kw.value.id == "False")
        ):
            return issue.Issue(
                severity="MEDIUM",
                confidence="HIGH",
                cwe=issue.Cwe.IMPROPER_CERT_VALIDATION,
                text="Requests call with verify=False disabling SSL/TLS "
                "certificate verification. This exposes the connection "
                "to man-in-the-middle attacks.",
            )
    return None


@test.checks("Call")
@test.with_id("B509")
def ssl_with_no_cert(context):
    qualname = context.call_function_name_qual
    if qualname not in {
        "ssl.wrap_socket",
        "ssl.SSLContext.wrap_socket",
    }:
        return None
    for kw in context.node.keywords:
        if kw.arg == "cert_reqs" and (
            (hasattr(kw.value, "value") and kw.value.value == "CERT_NONE")
            or (hasattr(kw.value, "id") and kw.value.id == "CERT_NONE")
        ):
            return issue.Issue(
                severity="HIGH",
                confidence="HIGH",
                cwe=issue.Cwe.IMPROPER_CERT_VALIDATION,
                text="SSL connection with cert_reqs=CERT_NONE. "
                "This disables certificate verification entirely.",
            )
    return None
