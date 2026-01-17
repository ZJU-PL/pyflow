# Check for use of exec
from ..core import issue
from ..core import test_properties as test


@test.checks("Call")
@test.with_id("B102")
def exec_used(context):
    """Check for use of exec function"""
    if context.call_function_name_qual == "exec":
        return issue.Issue(
            severity="MEDIUM",
            confidence="HIGH",
            cwe=issue.Cwe.OS_COMMAND_INJECTION,
            text="Use of exec detected.",
        )
