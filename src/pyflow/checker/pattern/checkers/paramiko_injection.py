"""
B507: Test for unsafe Paramiko usage.

Paramiko SSH commands executed via shell=True or without input
validation can lead to command injection.
"""
from ..core import issue
from ..core import test_properties as test


@test.checks("Call")
@test.with_id("B507")
def paramiko_command_injection(context):
    qualname = context.call_function_name_qual
    if qualname not in {
        "paramiko.SSHClient.exec_command",
        "paramiko.SSHClient.invoke_shell",
    }:
        return None
    for arg in context.node.args:
        if hasattr(arg, "s"):
            return issue.Issue(
                severity="MEDIUM",
                confidence="MEDIUM",
                cwe=issue.Cwe.OS_COMMAND_INJECTION,
                text="Paramiko SSH command execution with string argument. "
                "If the command string contains user input, it may be "
                "vulnerable to command injection. Use shlex.quote() "
                "or pass arguments separately.",
            )
    return None


@test.checks("Call")
@test.with_id("B509")
def paramiko_missing_host_key(context):
    qualname = context.call_function_name_qual
    if qualname not in {
        "paramiko.SSHClient.set_missing_host_key_policy",
        "paramiko.AutoAddPolicy",
        "paramiko.WarningPolicy",
    }:
        return None
    if qualname == "paramiko.SSHClient.set_missing_host_key_policy":
        for arg in context.node.args:
            if hasattr(arg, "id") and arg.id in ("AutoAddPolicy", "WarningPolicy"):
                return issue.Issue(
                    severity="HIGH",
                    confidence="HIGH",
                    cwe=issue.Cwe.IMPROPER_CERT_VALIDATION,
                    text="Paramiko SSH client configured to automatically "
                    "accept unknown host keys. This makes the connection "
                    "vulnerable to man-in-the-middle attacks. "
                    "Use paramiko.RejectPolicy or verify the host key.",
                )
            if hasattr(arg, "attr") and arg.attr in ("AutoAddPolicy", "WarningPolicy"):
                return issue.Issue(
                    severity="HIGH",
                    confidence="HIGH",
                    cwe=issue.Cwe.IMPROPER_CERT_VALIDATION,
                    text="Paramiko SSH client configured to automatically "
                    "accept unknown host keys.",
                )
    return None
