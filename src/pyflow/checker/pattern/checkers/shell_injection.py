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
    SUBPROCESS_FUNCS = {
        "subprocess.Popen",
        "subprocess.call",
        "subprocess.check_call",
        "subprocess.check_output",
        "subprocess.run",
    }
    if context.call_function_name_qual not in SUBPROCESS_FUNCS:
        return None
    shell_arg = context.get_call_arg_value("shell")
    if shell_arg is True or shell_arg == "True":
        return None
    return issue.Issue(
        severity="LOW",
        confidence="HIGH",
        cwe=issue.Cwe.OS_COMMAND_INJECTION,
        text="subprocess call - check for execution of untrusted input. "
        "Even without shell=True, ensure all arguments are properly "
        "validated and not constructed from user input.",
    )


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
