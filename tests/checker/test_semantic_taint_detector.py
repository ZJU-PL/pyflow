from __future__ import annotations

from types import SimpleNamespace

from pyflow.checker.semantic.detectors.semantic_taint import SemanticTaintDetector


class _DummyQueries:
    def get_ipa_analysis(self):
        raise RuntimeError("IPA unavailable in unit test")


def _make_session(sources_by_name, func_to_file=None):
    return SimpleNamespace(
        sources_by_name=sources_by_name,
        func_to_file=func_to_file or {},
        queries=_DummyQueries(),
    )


def test_semantic_taint_detector_reports_direct_eval_flow():
    session = _make_session(
        {
            "vuln": """
def vuln():
    data = input()
    eval(data)
"""
        },
        {"vuln": "sample.py"},
    )

    issues = SemanticTaintDetector().run(session)

    assert len(issues) == 1
    issue = issues[0]
    assert issue.test == "semantic_taint"
    assert issue.fname == "sample.py"
    assert issue.cwe.id == 94
    assert issue.test_id == "S005"
    assert "eval" in issue.text


def test_semantic_taint_detector_propagates_interprocedural_taint():
    session = _make_session(
        {
            "source": """
def source():
    return input()
""",
            "sink": """
def sink(arg):
    eval(arg)
""",
            "main": """
def main():
    value = source()
    sink(value)
""",
        },
        {
            "source": "sample.py",
            "sink": "sample.py",
            "main": "sample.py",
        },
    )

    issues = SemanticTaintDetector().run(session)

    assert len(issues) == 1
    issue = issues[0]
    assert issue.fname == "sample.py"
    assert issue.ident == "eval"
    assert issue.cwe.id == 94
