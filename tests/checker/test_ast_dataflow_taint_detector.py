from __future__ import annotations

from types import SimpleNamespace

from pyflow.checker.ast_dataflow.detectors.taint import ASTDataflowTaintDetector
from pyflow.checker.ast_dataflow.core.context import AnalysisSession
from pyflow.analysis.ifds.modeling.calls import CallModel, CallModelRegistry
from pyflow.analysis.taint import TaintPolicy, TaintRule
from pyflow.application.program import Program


class _DummyQueries:
    def get_ipa_function_summaries(self):
        raise RuntimeError("IPA unavailable in unit test")


def _make_session(sources_by_name, func_to_file=None):
    return SimpleNamespace(
        sources_by_name=sources_by_name,
        func_to_file=func_to_file or {},
        queries=_DummyQueries(),
    )


def test_source_collection_normalizes_indented_method_with_multiline_string():
    source = '''
class App:
    def index(self):
        return """first
column-zero
        last"""
'''

    sources, filenames, _imports = AnalysisSession._collect_sources_and_imports(
        Program(), {"sample.py": source}
    )

    assert "App.index" in sources
    assert "index" not in sources
    compile(sources["App.index"], "sample.py", "exec")
    assert filenames["App.index"] == "sample.py"


def test_source_collection_preserves_nested_qualified_function_names():
    source = """
class Handler:
    def post(self, payload):
        def execute(value):
            eval(value)
        execute(payload)
"""

    sources, filenames, _imports = AnalysisSession._collect_sources_and_imports(
        Program(), {"sample.py": source}
    )

    assert set(sources) == {"Handler.post", "Handler.post.execute"}
    assert filenames == {
        "Handler.post": "sample.py",
        "Handler.post.execute": "sample.py",
    }


def test_ast_dataflow_taint_detector_reports_direct_eval_flow():
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

    issues = ASTDataflowTaintDetector().run(session)

    assert len(issues) == 1
    issue = issues[0]
    assert issue.test == "ast_dataflow_taint"
    assert issue.fname == "sample.py"
    assert issue.cwe.id == 95
    assert issue.test_id == "PYFLOW-STDLIB-RCE"
    assert "eval" in issue.text


def test_formal_detector_treats_external_entry_parameter_as_untrusted():
    session = _make_session(
        {"handler": "def handler(payload):\n    eval(payload)\n"},
        {"handler": "sample.py"},
    )

    result = ASTDataflowTaintDetector().analyze(session)

    assert len(result.findings) == 1
    assert result.findings[0].function == "handler"


def test_formal_detector_does_not_report_sanitized_entry_parameter():
    session = _make_session(
        {
            "handler": (
                "def handler(payload):\n"
                "    cleaned = sanitize(payload)\n"
                "    eval(cleaned)\n"
            )
        },
        {"handler": "sample.py"},
    )

    result = ASTDataflowTaintDetector(sanitizers={"sanitize"}).analyze(session)

    assert result.findings == ()


def test_formal_detector_infers_syntactic_root_when_declared_entry_is_incomplete():
    session = _make_session(
        {
            "declared": "def declared():\n    return 1\n",
            "handler": "def handler(payload):\n    eval(payload)\n",
        },
        {"declared": "sample.py", "handler": "sample.py"},
    )
    session.program = SimpleNamespace(entryPoints=())

    result = ASTDataflowTaintDetector().analyze(session)

    assert any(finding.function == "handler" for finding in result.findings)


def test_ast_dataflow_taint_detector_returns_typed_result_with_sink_line():
    session = _make_session(
        {"vuln": "def vuln():\n    data = input()\n    eval(data)\n"},
        {"vuln": "sample.py"},
    )

    result = ASTDataflowTaintDetector().analyze(session)

    assert result.status == "complete"
    assert result.statistics["findings"] == 1
    assert result.findings[0].sink_line == 3
    assert result.findings[0].source_kinds == frozenset({"user_input"})
    assert [step.operation for step in result.findings[0].trace] == [
        "source",
        "assign",
        "sink",
    ]


def test_ast_dataflow_taint_detector_propagates_interprocedural_taint():
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

    issues = ASTDataflowTaintDetector().run(session)

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


def test_ast_dataflow_taint_detector_respects_sink_parameter_ports():
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

    assert ASTDataflowTaintDetector(policy=policy).run(safe) == []
    issues = ASTDataflowTaintDetector(policy=policy).run(unsafe)
    assert len(issues) == 1
    assert issues[0].test_id == "TEST-TYPED-FLOW"


def test_ast_dataflow_taint_detector_applies_universal_sanitizer():
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

    assert ASTDataflowTaintDetector(policy=policy).run(session) == []


def test_ast_dataflow_taint_detector_applies_kind_scoped_sanitizer():
    policy = TaintPolicy.from_call_models(
        CallModelRegistry(
            [
                CallModel("input", source_kinds=frozenset({"html", "shell"})),
                CallModel("target_sink", sink_kinds=frozenset({"dangerous"})),
                CallModel("clean_html", sanitizer_kinds=frozenset({"html"})),
            ]
        ),
        [
            TaintRule(
                "HTML-FLOW",
                "HTML flow",
                frozenset({"html"}),
                frozenset({"dangerous"}),
            ),
            TaintRule(
                "SHELL-FLOW",
                "Shell flow",
                frozenset({"shell"}),
                frozenset({"dangerous"}),
            ),
        ],
    )
    session = _make_session(
        {
            "main": (
                "def main():\n"
                "    value = input()\n"
                "    target_sink(clean_html(value))\n"
            )
        }
    )

    result = ASTDataflowTaintDetector(policy=policy).analyze(session)

    assert [finding.rule_id for finding in result.findings] == ["SHELL-FLOW"]
    assert result.findings[0].source_kinds == frozenset({"shell"})


def test_formal_detector_merges_manual_models_with_explicit_policy():
    policy = _typed_policy()
    session = _make_session(
        {"main": "def main():\n    value = custom_source()\n    custom_sink(value)\n"}
    )

    result = ASTDataflowTaintDetector(
        policy=policy,
        sources={"custom_source"},
        sinks={"custom_sink"},
    ).analyze(session)

    assert len(result.findings) == 1
    assert result.findings[0].rule_id == "PYFLOW-SEMANTIC-MANUAL"
