"""
B814: Test for Trojan Source attacks.

Detects Unicode bidirectional (Bidi) override characters that can
be used to inject invisible code (CVE-2021-42574).
"""
from ..core import issue
from ..core import test_properties as test

BIDI_CHARS = {
    "\u202a", "\u202b", "\u202c", "\u202d", "\u202e",
    "\u2066", "\u2067", "\u2068", "\u2069",
    "\u200f", "\u200e",
}


@test.checks("Str")
@test.with_id("B814")
def trojan_source_bidi(context):
    s = context.string
    if not isinstance(s, str):
        return None
    for char in s:
        if char in BIDI_CHARS:
            return issue.Issue(
                severity="HIGH",
                confidence="HIGH",
                cwe=issue.Cwe.CODE_INJECTION,
                text="Source code contains Unicode bidirectional (Bidi) "
                "override characters. This may be a Trojan Source attack "
                "(CVE-2021-42574) attempting to hide malicious code.",
            )
    return None
