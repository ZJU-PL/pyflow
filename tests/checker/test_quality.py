from __future__ import annotations

import pytest

from pyflow.checker import Cwe, Issue
from pyflow.checker.pattern.core import constants
from pyflow.checker.quality import (
    BareSuppressionWarning,
    BaselineStore,
    apply_guard_aware_demotion,
    apply_taint_aware_demotion,
    find_security_guards,
    is_guarded,
    is_suppressed,
    parse_suppressions,
    score_confidence,
)


def _issue(
    *,
    test_id: str = "B102",
    lineno: int = 1,
    severity: str = constants.HIGH,
    confidence: str = constants.HIGH,
    cwe: int = Cwe.CODE_INJECTION,
) -> Issue:
    issue = Issue(
        severity=severity,
        confidence=confidence,
        cwe=cwe,
        text="dynamic code execution",
        test_id=test_id,
        lineno=lineno,
    )
    issue.fname = "example.py"
    issue.test = "exec_used"
    return issue


def test_parse_scoped_suppression_matches_issue():
    suppressions = parse_suppressions(
        "exec(code)  # pyflow: ignore B102 -- accepted test fixture\n",
        warn_bare=False,
    )
    assert is_suppressed(_issue(test_id="B102"), suppressions)
    assert not is_suppressed(_issue(test_id="B999"), suppressions)


def test_parse_bare_suppression_warns_and_suppresses_all():
    with pytest.warns(BareSuppressionWarning):
        suppressions = parse_suppressions("exec(code)  # pyflow: ignore\n")
    assert is_suppressed(_issue(test_id="B999"), suppressions)


def test_baseline_store_filters_existing_issue(tmp_path):
    issue = _issue()
    baseline = BaselineStore.generate([issue])
    path = tmp_path / "baseline.json"
    baseline.save(path)

    loaded = BaselineStore.load(path)

    assert len(loaded) == 1
    assert loaded.contains(issue)
    assert loaded.filter_new([issue]) == []


def test_confidence_scoring_rewards_taint_trace():
    issue = _issue(confidence=constants.MEDIUM)

    assert score_confidence(issue, has_taint_trace=True) > score_confidence(
        issue,
        has_taint_trace=False,
    )


def test_taint_aware_demotion_caps_high_injection_without_trace():
    issue = _issue(severity=constants.HIGH, confidence=constants.HIGH)

    apply_taint_aware_demotion(issue, has_taint_trace=False, structural=False)

    assert issue.severity == constants.MEDIUM
    assert issue.confidence in {constants.MEDIUM, constants.HIGH}


def test_find_security_guards_marks_protected_auth_body():
    source = """
def view(request):
    if request.user.is_authenticated:
        eval(request.GET["expr"])
"""
    guards = find_security_guards(source)

    assert any(guard.kind == "auth_check" for guard in guards)
    assert is_guarded(_issue(lineno=4), guards, guard_kinds={"auth_check"})


def test_guard_aware_demotion_lowers_guarded_issue():
    source = """
def view(request):
    if value.isdigit():
        eval(value)
"""
    issue = _issue(lineno=4, severity=constants.HIGH, confidence=constants.HIGH)

    apply_guard_aware_demotion(
        issue,
        find_security_guards(source),
        guard_kinds={"input_validation"},
    )

    assert issue.severity == constants.MEDIUM
    assert issue.confidence == constants.LOW
