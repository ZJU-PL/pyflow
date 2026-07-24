"""
B201: Test for application debug mode enabled.

Running applications in debug mode may expose sensitive
information through detailed error messages and stack traces.
"""
from ..core import issue
from ..core import test_properties as test

DEBUG_FLAGS = {
    "True", "true", "1", "yes",
}


@test.checks("Assign")
@test.with_id("B201")
def flask_debug_true(context):
    node = context.node
    if not node.targets or not hasattr(node.targets[0], "id"):
        return None
    if node.targets[0].id not in {"DEBUG", "debug"}:
        return None
    if hasattr(node.value, "value"):
        val = str(node.value.value)
        if val in DEBUG_FLAGS:
            return issue.Issue(
                severity="MEDIUM",
                confidence="MEDIUM",
                cwe=issue.Cwe.IMPROPER_ERROR_HANDLING,
                text="Application debug mode enabled. Debug mode "
                "displays detailed error messages that may expose "
                "sensitive application internals to users. "
                "Disable debug in production.",
            )
    return None


@test.checks("Call")
@test.with_id("B202")
def app_run_debug(context):
    qualname = context.call_function_name_qual
    if qualname not in {"flask.Flask.run", "app.run", "application.run"}:
        return None
    for kw in context.node.keywords:
        if kw.arg == "debug" and hasattr(kw.value, "value"):
            if str(kw.value.value) in DEBUG_FLAGS:
                return issue.Issue(
                    severity="MEDIUM",
                    confidence="HIGH",
                    cwe=issue.Cwe.IMPROPER_ERROR_HANDLING,
                    text="Application started with debug=True. "
                    "Debug mode exposes sensitive internal state.",
                )
    return None
