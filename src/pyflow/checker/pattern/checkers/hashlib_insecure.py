"""
B324: Test for use of insecure hash functions.

MD4, MD5, SHA-0, and SHA-1 are broken hash functions that are
vulnerable to collision attacks. Use SHA-256 or stronger.
"""
from ..core import issue
from ..core import test_properties as test

WEAK_HASHES = {
    "md5", "MD5", "md4", "MD4", "sha", "SHA",
    "sha0", "SHA0", "sha1", "SHA1",
}


@test.checks("Call")
@test.with_id("B324")
def hashlib_insecure_functions(context):
    qualname = context.call_function_name_qual
    if not qualname.startswith("hashlib."):
        return None
    name = qualname.split(".")[-1]
    if name.lower() in {w.lower() for w in WEAK_HASHES}:
        return issue.Issue(
            severity="MEDIUM",
            confidence="HIGH",
            cwe=issue.Cwe.BROKEN_CRYPTO,
            text=f"Use of insecure hash function {name}. "
            f"{name} is vulnerable to collision attacks. "
            "Use hashlib.sha256 or stronger.",
        )
    if name == "new":
        for arg in context.node.args:
            if hasattr(arg, "value") and isinstance(arg.value, str):
                if arg.value.lower() in {w.lower() for w in WEAK_HASHES}:
                    return issue.Issue(
                        severity="MEDIUM",
                        confidence="HIGH",
                        cwe=issue.Cwe.BROKEN_CRYPTO,
                        text=f"Use of insecure hash function {arg.value} "
                        "via hashlib.new(). Use hashlib.sha256 or stronger.",
                    )
    return None
