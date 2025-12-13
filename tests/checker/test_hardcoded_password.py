from __future__ import annotations

from pyflow.checker import Cwe


def test_hardcoded_password_assignment_is_flagged(scan):
    res = scan("password = 'secret'\n")
    issues = res.issues

    assert [i.test_id for i in issues] == ["B105"]
    issue = issues[0]
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

    assert [i.test_id for i in issues] == ["B107"]
    issue = issues[0]
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
