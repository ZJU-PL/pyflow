from __future__ import annotations


def _by_test_id(issues, test_id: str):
    return [i for i in issues if i.test_id == test_id]


def test_blacklisted_import_telnetlib(scan):
    res = scan("import telnetlib\n")
    issues = res.issues

    hits = _by_test_id(issues, "B401")
    assert len(hits) == 1
    assert hits[0].severity == "HIGH"
    assert hits[0].confidence == "HIGH"
    assert hits[0].lineno == 1


def test_blacklisted_call_pickle_loads(scan):
    # The blacklist check is purely AST-based; importing isn't required and would
    # also trigger an import blacklist finding.
    res = scan("pickle.loads(b'xyz')\n")
    issues = res.issues

    hits = _by_test_id(issues, "B301")
    assert len(hits) == 1
    assert hits[0].severity == "MEDIUM"
    assert hits[0].confidence == "HIGH"
    assert hits[0].lineno == 1
