from __future__ import annotations

from pyflow.checker import Cwe


def test_hashlib_md5_is_flagged(scan):
    res = scan("import hashlib\nhashlib.md5(b'abc')\n")
    issues = res.issues

    assert [i.test_id for i in issues] == ["B304"]
    issue = issues[0]
    assert issue.cwe.id == Cwe.BROKEN_CRYPTO
    assert issue.severity == "MEDIUM"
    assert issue.confidence == "HIGH"
    assert issue.lineno == 2


def test_aes_new_weak_key_size_is_flagged(scan):
    # No import needed; the checker is purely AST-based.
    res = scan("AES.new(key_size=64)\n")
    issues = res.issues

    assert [i.test_id for i in issues] == ["B303"]
    issue = issues[0]
    assert issue.cwe.id == Cwe.BROKEN_CRYPTO
    assert issue.severity == "MEDIUM"
    assert issue.confidence == "HIGH"
    assert issue.lineno == 1
