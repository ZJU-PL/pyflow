"""
B609: Test for MarkupSafe XSS.

Using Markup/MarkupSafe without proper escaping can introduce
cross-site scripting vulnerabilities.
"""
from ..core import issue
from ..core import test_properties as test


@test.checks("Call")
@test.with_id("B609")
def markupsafe_xss(context):
    qualname = context.call_function_name_qual
    if qualname not in {
        "markupsafe.Markup", "markupsafe.escape",
    }:
        return None
    for arg in context.node.args:
        if hasattr(arg, "id"):
            return issue.Issue(
                severity="LOW",
                confidence="MEDIUM",
                cwe=issue.Cwe.XSS,
                text="MarkupSafe usage with variable input. "
                "Ensure the content is properly sanitized "
                "before marking it as safe HTML.",
            )
    return None


@test.checks("Call")
@test.with_id("B610")
def markupsafe_unescape(context):
    qualname = context.call_function_name_qual
    if qualname in {"markupsafe.Markup.unescape", "markupsafe.Markup.striptags"}:
        return issue.Issue(
            severity="LOW",
            confidence="LOW",
            cwe=issue.Cwe.XSS,
            text="MarkupSafe unescape/striptags used. "
            "Reversing escaped content may expose "
            "the application to XSS if the output is "
            "subsequently rendered without re-escaping.",
        )
    return None
