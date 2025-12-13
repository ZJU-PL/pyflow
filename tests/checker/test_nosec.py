from __future__ import annotations


def test_nosec_suppresses_issue_without_id(scan):
    res = scan("exec('1+1')  # nosec\n")
    assert res.issues == []


def test_nosec_suppresses_issue_with_matching_id(scan):
    res = scan("exec('1+1')  # nosec: B102\n")
    assert res.issues == []


def test_ignore_nosec_keeps_issues(scan):
    res = scan("exec('1+1')  # nosec\n", ignore_nosec=True)
    assert res.ids() == ["B102"]
