from __future__ import annotations

from types import SimpleNamespace

from pyflow.checker.semantic.detectors.semantic_taint import SemanticTaintDetector
from pyflow.analysis.ifds.modeling.calls import CallModel, CallModelRegistry
from pyflow.analysis.taint import TaintPolicy, TaintRule


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
    assert issue.cwe.id == 95
    assert issue.test_id == "PYFLOW-STDLIB-RCE"
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
    assert issue.cwe.id == 95


def _typed_policy(*models):
    return TaintPolicy.from_call_models(
        CallModelRegistry(models),
        [
            TaintRule(
                "TEST-TYPED-FLOW",
                "Typed test flow",
                frozenset({"user_input"}),
                frozenset({"dangerous"}),
                severity="high",
                cwe="CWE-999",
            )
        ],
    )


def test_semantic_taint_detector_respects_sink_parameter_ports():
    policy = _typed_policy(
        CallModel("input", source_kinds=frozenset({"user_input"})),
        CallModel(
            "target_sink",
            sink_kinds=frozenset({"dangerous"}),
            sink_arg_positions=frozenset({1}),
            cwe="CWE-999",
        ),
    )
    safe = _make_session(
        {"main": "def main():\n    value = input()\n    target_sink(value, 'safe')\n"}
    )
    unsafe = _make_session(
        {"main": "def main():\n    value = input()\n    target_sink('safe', value)\n"}
    )

    assert SemanticTaintDetector(policy=policy).run(safe) == []
    issues = SemanticTaintDetector(policy=policy).run(unsafe)
    assert len(issues) == 1
    assert issues[0].test_id == "TEST-TYPED-FLOW"


def test_semantic_taint_detector_applies_universal_sanitizer():
    policy = _typed_policy(
        CallModel("input", source_kinds=frozenset({"user_input"})),
        CallModel("target_sink", sink_kinds=frozenset({"dangerous"})),
        CallModel("clean", sanitizer_kinds=frozenset({"*"})),
    )
    session = _make_session(
        {
            "main": (
                "def main():\n"
                "    value = input()\n"
                "    target_sink(clean(value))\n"
            )
        }
    )

    assert SemanticTaintDetector(policy=policy).run(session) == []
