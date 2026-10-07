from __future__ import annotations

from pyflow.checker import Cwe


def test_hardcoded_password_assignment_is_flagged(scan):
    res = scan("password = 'secret'\n")
    issues = res.issues

    b105_issues = [i for i in issues if i.test_id == "B105"]
    assert len(b105_issues) == 1, f"Expected exactly one B105 issue, got {[i.test_id for i in issues]}"
    issue = b105_issues[0]
    assert issue.cwe.id == Cwe.HARD_CODED_PASSWORD
    assert issue.severity == "LOW"
    assert issue.confidence == "MEDIUM"
    assert issue.lineno == 1


def test_hardcoded_password_keyword_argument_is_flagged(scan):
    res = scan("login(password='secret')\n")
    issues = res.issues

    assert [i.test_id for i in issues] == ["B106"]
    issue = issues[0]
    assert issue.cwe.id == Cwe.HARD_CODED_PASSWORD
    assert issue.lineno == 1


def test_hardcoded_password_default_argument_is_flagged(scan):
    res = scan(
        """
        def f(password='secret'):
            return password
        """
    )
    issues = res.issues

    b107_issues = [i for i in issues if i.test_id == "B107"]
    assert len(b107_issues) == 1, f"Expected exactly one B107 issue, got {[i.test_id for i in issues]}"
    issue = b107_issues[0]
    assert issue.cwe.id == Cwe.HARD_CODED_PASSWORD
    assert issue.lineno == 1


def test_hardcoded_password_compare_is_flagged(scan):
    res = scan(
        """
        if password == 'secret':
            pass
        """
    )
    issues = res.issues

    assert [i.test_id for i in issues] == ["B105"]
    issue = issues[0]
    assert issue.cwe.id == Cwe.HARD_CODED_PASSWORD
    assert issue.lineno == 1
