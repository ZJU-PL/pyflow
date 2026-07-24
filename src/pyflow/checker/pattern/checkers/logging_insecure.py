"""
B107: Test for insecure logging configuration.

Logging to network sockets or configuring log servers on
insecure interfaces may leak sensitive information.
"""
from ..core import issue
from ..core import test_properties as test


@test.checks("Call")
@test.with_id("B107")
def logging_insecure_listen(context):
    qualname = context.call_function_name_qual
    if qualname not in {
        "logging.handlers.SysLogHandler",
        "logging.handlers.SocketHandler",
        "logging.handlers.DatagramHandler",
        "logging.handlers.HTTPHandler",
    }:
        return None
    for arg in context.node.args:
        if hasattr(arg, "value") and isinstance(arg.value, str):
            if arg.value == "0.0.0.0":
                return issue.Issue(
                    severity="MEDIUM",
                    confidence="MEDIUM",
                    cwe=issue.Cwe.IMPROPER_ACCESS_CONTROL,
                    text="Logging handler configured to listen on all "
                    "interfaces (0.0.0.0). This may expose log data "
                    "to unintended network segments.",
                )
    return None


@test.checks("Call")
@test.with_id("B108")
def logging_no_encryption(context):
    qualname = context.call_function_name_qual
    if qualname not in {
        "logging.handlers.SysLogHandler",
        "logging.handlers.SocketHandler",
        "logging.handlers.DatagramHandler",
    }:
        return None
    return issue.Issue(
        severity="LOW",
        confidence="MEDIUM",
        cwe=issue.Cwe.CLEARTEXT_TRANSMISSION,
        text="Logging handler sends data over the network without "
        "encryption. Consider using a secure transport or "
        "ensure the network is trusted.",
    )
