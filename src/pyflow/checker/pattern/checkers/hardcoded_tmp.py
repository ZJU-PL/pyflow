"""
B108: Test for hardcoded /tmp directory usage.

Using hardcoded /tmp is insecure as it can be exploited via symlink attacks
to overwrite or access files. Use tempfile.mkstemp() or tempfile.mkdtemp().
"""
from ..core import issue
from ..core import test_properties as test


@test.checks("Str")
@test.with_id("B108")
def hardcoded_tmp_directory(context):
    s = context.string
    if not isinstance(s, str):
        return None
    if "/tmp" in s or "/var/tmp" in s:
        return issue.Issue(
            severity="MEDIUM",
            confidence="MEDIUM",
            cwe=issue.Cwe.INSECURE_TEMP_FILE,
            text="Use of hardcoded /tmp directory detected. "
            "Use tempfile.mkstemp() or tempfile.mkdtemp() "
            "to create temporary files securely.",
        )
    return None
