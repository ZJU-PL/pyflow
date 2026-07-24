"""
B113: Test for requests calls without timeout.

HTTP requests without a timeout may hang indefinitely,
leading to resource exhaustion or denial of service.
"""
from ..core import issue
from ..core import test_properties as test


@test.checks("Call")
@test.with_id("B113")
def request_without_timeout(context):
    qualname = context.call_function_name_qual
    if qualname not in {
        "requests.get", "requests.post", "requests.put",
        "requests.delete", "requests.patch", "requests.head",
        "requests.options", "requests.request",
    }:
        return None
    has_timeout = False
    for kw in context.node.keywords:
        if kw.arg == "timeout":
            has_timeout = True
            break
    if not has_timeout:
        return issue.Issue(
            severity="LOW",
            confidence="HIGH",
            cwe=issue.Cwe.UNCONTROLLED_RESOURCE_CONSUMPTION,
            text="requests call missing timeout parameter. "
            "Without a timeout, the request may hang indefinitely "
            "and potentially cause resource exhaustion.",
        )
    return None
