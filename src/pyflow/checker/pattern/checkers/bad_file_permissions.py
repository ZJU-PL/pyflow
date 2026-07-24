"""
B102/B103: Test for bad file permissions.

Setting world-writable or overly permissive file permissions can
expose sensitive data or allow unauthorized modification.
"""
import ast
import stat

from ..core import issue
from ..core import test_properties as test


@test.checks("Call")
@test.with_id("B102")
def set_world_writable(context):
    qualname = context.call_function_name_qual
    if qualname not in {"os.chmod", "os.chown"}:
        return None
    for arg in context.node.args:
        if isinstance(arg, ast.Constant) and isinstance(arg.value, int):
            if arg.value & stat.S_IWOTH:
                return issue.Issue(
                    severity="HIGH",
                    confidence="HIGH",
                    cwe=issue.Cwe.INCORRECT_PERMISSION_ASSIGNMENT,
                    text="World-writable file permission detected. "
                    "Using os.chmod with 0o777 or similar world-writable "
                    "permissions is dangerous. Use more restrictive permissions.",
                )
    return None


@test.checks("Call")
@test.with_id("B103")
def set_allow_world_readable(context):
    qualname = context.call_function_name_qual
    if qualname not in {"os.chmod", "os.chown"}:
        return None
    for arg in context.node.args:
        if isinstance(arg, ast.Constant) and isinstance(arg.value, int):
            if arg.value & stat.S_IROTH:
                return issue.Issue(
                    severity="MEDIUM",
                    confidence="MEDIUM",
                    cwe=issue.Cwe.INCORRECT_PERMISSION_ASSIGNMENT,
                    text="World-readable file permission detected. "
                    "Using os.chmod with overly permissive flags "
                    "may expose sensitive data.",
                )
    return None
