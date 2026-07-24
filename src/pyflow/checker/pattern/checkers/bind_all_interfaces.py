"""
B104: Test for binding to all interfaces.

Binding to all network interfaces (0.0.0.0) may expose internal
services to unintended network segments.
"""
import ast

from ..core import issue
from ..core import test_properties as test


@test.checks("Call")
@test.with_id("B104")
def hardcoded_bind_all_interfaces(context):
    qualname = context.call_function_name_qual
    if qualname not in {"socket.bind", "socket.setsockopt"}:
        return None
    for arg in context.node.args:
        if isinstance(arg, ast.Constant) and arg.value == "0.0.0.0":
            return issue.Issue(
                severity="MEDIUM",
                confidence="MEDIUM",
                cwe=issue.Cwe.BINDING_TO_ALL_NETWORK_INTERFACES,
                text="Possible binding to all interfaces. "
                "Use a specific IP address instead of 0.0.0.0.",
            )
        if isinstance(arg, ast.Tuple):
            for elt in arg.elts:
                if isinstance(elt, ast.Constant) and elt.value == "0.0.0.0":
                    return issue.Issue(
                        severity="MEDIUM",
                        confidence="MEDIUM",
                        cwe=issue.Cwe.BINDING_TO_ALL_NETWORK_INTERFACES,
                        text="Possible binding to all interfaces. "
                        "Use a specific IP address instead of 0.0.0.0.",
                    )
    return None
