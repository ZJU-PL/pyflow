"""
B105: Test for shell wildcard injection.

Using user input in shell wildcard operations can lead to
argument injection or unexpected file matching.
"""
from ..core import issue
from ..core import test_properties as test


@test.checks("Call")
@test.with_id("B105")
def wildcard_injection(context):
    qualname = context.call_function_name_qual
    if qualname not in {
        "glob.glob", "glob.iglob",
        "fnmatch.fnmatch", "fnmatch.filter",
        "pathlib.Path.glob", "pathlib.Path.rglob",
    }:
        return None
    for arg in context.node.args:
        if hasattr(arg, "value") and isinstance(arg.value, str):
            if "*" in arg.value or "?" in arg.value or "[" in arg.value:
                return issue.Issue(
                    severity="LOW",
                    confidence="MEDIUM",
                    cwe=issue.Cwe.IMPROPER_INPUT_VALIDATION,
                    text="Wildcard injection possible. User-controlled "
                    "data in wildcard patterns may lead to unexpected "
                    "file matching or denial of service.",
                )
    return None
