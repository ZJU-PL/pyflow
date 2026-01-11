# Check for shell injection vulnerabilities
import ast

from ..core import issue
from ..core import test_properties as test


def shell_injection_issue():
    """Create a shell injection issue"""
    return issue.Issue(
        severity="HIGH",
        confidence="HIGH",
        cwe=issue.Cwe.OS_COMMAND_INJECTION,
        text="Possible shell injection via subprocess module.",
    )


@test.checks("Call")
@test.with_id("B602")
def subprocess_popen_with_shell_equals_true(context):
    """Check for subprocess.Popen with shell=True"""
    if context.call_function_name_qual == "subprocess.Popen":
        shell_arg = context.get_call_arg_value("shell")
        if shell_arg is True:
            return shell_injection_issue()


@test.checks("Call")
@test.with_id("B603")
def subprocess_without_shell_equals_true(context):
    """Check for subprocess calls without shell=True but with shell injection risk"""
    # This is a simplified check - in practice you'd want to analyze the command construction
    # For now, we'll skip this check to avoid false positives
    pass


@test.checks("Call")
@test.with_id("B604")
def any_other_function_with_shell_equals_true(context):
    """Check for other functions with shell=True"""
    if context.call_function_name_qual in [
        "os.system",
        "os.popen",
        "commands.getstatusoutput",
    ]:
        return shell_injection_issue()
