"""
B112: Test for unsafe tarfile extraction.

Extracting tar archives without validating member paths can lead to
path traversal attacks (zip/tar slip). Always use the 'data' filter
or validate member names.
"""
from ..core import issue
from ..core import test_properties as test


@test.checks("Call")
@test.with_id("B112")
def tarfile_unsafe_extraction(context):
    qualname = context.call_function_name_qual
    if qualname not in {
        "tarfile.TarFile.extractall",
        "tarfile.TarFile.extract",
        "tarfile.open",
    }:
        return None
    if qualname == "tarfile.open":
        for kw in context.node.keywords:
            if kw.arg in ("mode",) and hasattr(kw.value, "value"):
                val = str(kw.value.value)
                if "r" in val and ":" not in val:
                    return issue.Issue(
                        severity="MEDIUM",
                        confidence="HIGH",
                        cwe=issue.Cwe.PATH_TRAVERSAL,
                        text="tarfile.open() without safe extraction filter. "
                        "Extracting archives can overwrite files via path "
                        "traversal. Use extractall(filter='data') or "
                        "validate member paths manually.",
                    )
    else:
        return issue.Issue(
            severity="MEDIUM",
            confidence="HIGH",
            cwe=issue.Cwe.PATH_TRAVERSAL,
            text="tarfile extraction without input validation. "
            "Malicious tar archives can overwrite arbitrary files "
            "via path traversal (tar slip). Ensure member paths "
            "are validated before extraction.",
        )
    return None
