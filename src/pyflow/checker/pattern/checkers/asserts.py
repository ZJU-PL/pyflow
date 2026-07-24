"""
B101: Test for use of assert.

The assert statement is removed when compiling to optimised byte code
(Python -O). Projects that use assert to enforce interface constraints
will lose those protections when optimized.
"""
import fnmatch

from ..core import issue
from ..core import test_properties as test


def gen_config(name):
    if name == "assert_used":
        return {"skips": []}


@test.takes_config
@test.checks("Assert")
@test.with_id("B101")
def assert_used(context, config):
    for skip in config.get("skips", []):
        if fnmatch.fnmatch(context.filename, skip):
            return None
    return issue.Issue(
        severity="LOW",
        confidence="HIGH",
        cwe=issue.Cwe.IMPROPER_CHECK_OF_EXCEPT_COND,
        text="Use of assert detected. The enclosed code "
        "will be removed when compiling to optimised byte code.",
    )
