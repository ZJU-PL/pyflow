"""
B107: Test for insecure logging configuration.

Logging to network sockets or configuring log servers on
insecure interfaces may leak sensitive information.

B612: Test for insecure use of logging.config.listen.
The logging.config.listen function opens a socket server that
passes received config through eval(). Use with a 'verify'
argument to authenticate the source.
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


@test.checks("Call")
@test.with_id("B612")
def logging_config_listen(context):
    qualname = context.call_function_name_qual
    if qualname != "logging.config.listen":
        return None
    if "verify" not in context.call_keywords:
        return issue.Issue(
            severity="MEDIUM",
            confidence="HIGH",
            cwe=issue.Cwe.CODE_INJECTION,
            text="Use of insecure logging.config.listen() detected. "
            "The listener accepts configuration data over a socket and "
            "passes it through eval(). Use the 'verify' argument with "
            "a callable that authenticates the configuration source.",
        )
    return None
