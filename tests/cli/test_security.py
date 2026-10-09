from __future__ import annotations

from pyflow.checker.common.diagnostics import CheckerDiagnostic

import io
import json
from types import SimpleNamespace

import pytest

import pyflow.cli.security.command as security_cli
from pyflow.checker.ast_dataflow.detectors._taint_models import (
    ASTDataflowTaintFinding,
    ASTDataflowTaintResult,
    ASTDataflowTraceStep,
)
from pyflow.checker.formatters import json as json_formatter
from pyflow.checker.formatters import text as text_formatter
from pyflow.checker.common import constants as b_constants
from pyflow.checker.common.issue import Issue
from pyflow.checker.formatters.security import (
    ast_dataflow_report,
    security_json,
    security_sarif,
    security_text,
)
from pyflow.cli.security.command import _security_exit_code


def _totals() -> dict[str, int]:
    totals = {
        "loc": 0,
        "nosec": 0,
        "skipped_tests": 0,
    }
    for criteria, _ in b_constants.CRITERIA:
        for rank in b_constants.RANKING:
            totals[f"{criteria}.{rank}"] = 0
    return totals


def test_ast_scanner_json_includes_primary_and_ancestor_cwes():
    issue = Issue("HIGH", cwe=78, confidence="HIGH", text="shell injection")
    issue.fname = "sample.py"
    issue.lineno = 7
    manager = SimpleNamespace(get_issue_list=lambda *_args: [issue])

    finding = security_json("ast-scanner", manager)["results"][0]

    assert finding["cwe"] == "CWE-78"
    assert finding["cwes"] == ["CWE-78", "CWE-77"]
    assert finding["cwe_ancestors"] == ["CWE-77"]
    assert finding["issue_cwe"]["id"] == 78


class _FormatterManager:
    quiet = False
    verbose = False
    files_list: list[str] = []
    scores: list[object] = []
    excluded_files: list[str] = []
    metrics = SimpleNamespace(data={"_totals": _totals()})

    def results_count(self, *_args, **_kwargs):
        return 0

    def get_issue_list(self, *_args, **_kwargs):
        return []

    def get_skipped(self):
        return []


@pytest.mark.parametrize(
    "formatter",
    [text_formatter.report, json_formatter.report],
)
def test_formatters_keep_caller_owned_stream_open(formatter):
    buffer = io.StringIO()

    formatter(_FormatterManager(), buffer, b_constants.LOW, b_constants.LOW)

    buffer.write("still-open")
    assert "still-open" in buffer.getvalue()


def test_json_formatter_reports_partial_when_files_are_skipped():
    class PartialManager(_FormatterManager):
        def get_skipped(self):
            return [("broken.py", "syntax error")]

    buffer = io.StringIO()
    json_formatter.report(PartialManager(), buffer, b_constants.LOW, b_constants.LOW)

    payload = json.loads(buffer.getvalue())
    assert payload["status"] == "partial"
    assert payload["errors"] == [{"filename": "broken.py", "reason": "syntax error"}]


def test_security_cli_threads_pattern_excludes_into_discover_files(
    monkeypatch,
    tmp_path,
):
    captured = {}
    sample = tmp_path / "sample.py"
    sample.write_text("pass\n")

    class FakePatternManager:
        def __init__(self, *args, **kwargs):
            pass

        verbose = False
        quiet = False
        files_list = []
        scores = []
        excluded_files = []

        class _Metrics:
            data = {
                "_totals": {
                    "loc": 0,
                    "nosec": 0,
                    "skipped_tests": 0,
                    "SEVERITY.UNDEFINED": 0,
                    "SEVERITY.LOW": 0,
                    "SEVERITY.MEDIUM": 0,
                    "SEVERITY.HIGH": 0,
                    "CONFIDENCE.UNDEFINED": 0,
                    "CONFIDENCE.LOW": 0,
                    "CONFIDENCE.MEDIUM": 0,
                    "CONFIDENCE.HIGH": 0,
                }
            }

        metrics = _Metrics()

        def results_count(self, sev_level, conf_level):
            return 0

        def get_skipped(self):
            return []

        def discover_files(self, targets, recursive=False, excluded_paths=""):
            captured["targets"] = list(targets)
            captured["recursive"] = recursive
            captured["excluded_paths"] = excluded_paths

        def run_tests(self):
            captured["run_tests"] = True

        def get_issue_list(self, *_args, **_kwargs):
            return []

    monkeypatch.setattr(security_cli, "SecurityManager", FakePatternManager)

    args = SimpleNamespace(
        recursive=True,
        verbose=False,
        debug=False,
        exclude=" foo.py , bar.py ",
        engine="ast-scanner",
        micro_bench=None,
        format="text",
        output=None,
        targets=[str(sample)],
    )

    exit_code = security_cli.run_security(args)

    assert exit_code == 0
    assert captured["targets"] == [str(sample)]
    assert captured["recursive"] is True
    assert captured["excluded_paths"] == "foo.py,bar.py"
    assert captured["run_tests"] is True


def test_security_cli_threads_ast_dataflow_excludes_into_config(monkeypatch):
    captured = {}

    class FakeASTDataflowManager:
        def __init__(self, config, debug=False, verbose=False, quiet=False):
            captured["exclude"] = config.exclude
            captured["sources"] = config.sources
            captured["sinks"] = config.sinks
            self.verbose = verbose
            self.quiet = quiet

        files_list = []
        scores = []
        excluded_files = []

        class _Metrics:
            data = {
                "_totals": {
                    "loc": 0,
                    "nosec": 0,
                    "skipped_tests": 0,
                    "SEVERITY.UNDEFINED": 0,
                    "SEVERITY.LOW": 0,
                    "SEVERITY.MEDIUM": 0,
                    "SEVERITY.HIGH": 0,
                    "CONFIDENCE.UNDEFINED": 0,
                    "CONFIDENCE.LOW": 0,
                    "CONFIDENCE.MEDIUM": 0,
                    "CONFIDENCE.HIGH": 0,
                }
            }

        metrics = _Metrics()

        def results_count(self, sev_level, conf_level):
            return 0

        def get_skipped(self):
            return []

        def analyze(self, targets):
            captured["targets"] = list(targets)

        def get_issue_list(self, *_args, **_kwargs):
            return []

    monkeypatch.setattr(security_cli, "ASTDataflowManager", FakeASTDataflowManager)

    args = SimpleNamespace(
        recursive=False,
        verbose=False,
        debug=False,
        exclude=" foo.py , bar.py ",
        engine="ast-dataflow",
        sources=["input"],
        sinks=["eval"],
        micro_bench=None,
        format="text",
        output=None,
        targets=["sample.py"],
    )

    exit_code = security_cli.run_security(args)

    assert exit_code == 0
    assert captured["targets"] == ["sample.py"]
    assert captured["exclude"][:2] == ("foo.py", "bar.py")
    assert {"tests", ".*"} <= set(captured["exclude"])
    assert captured["sources"] == ("input",)
    assert captured["sinks"] == ("eval",)


def test_security_cli_ast_dataflow_completes_on_taint_file(tmp_path, capsys):
    sample = tmp_path / "ast_dataflow_taint.py"
    sample.write_text(
        """
import os


def command_from_input():
    cmd = input("cmd> ")
    os.system(cmd)


def eval_from_input():
    expr = input("expr> ")
    return eval(expr)
""",
        encoding="utf-8",
    )

    args = SimpleNamespace(
        recursive=False,
        verbose=False,
        debug=False,
        exclude="",
        engine="ast-dataflow",
        format="text",
        output=None,
        targets=[str(sample)],
    )

    exit_code = security_cli.run_security(args)

    out = capsys.readouterr().out
    assert exit_code == 0
    assert "os.system" in out
    assert "eval" in out
    assert "Traceback" not in out


def test_security_cli_ast_dataflow_handles_conditional_expression(tmp_path, capsys):
    sample = tmp_path / "conditional_expression.py"
    sample.write_text(
        """
def choose(training, configured_dropout):
    dropout = configured_dropout if training else 0
    consume(dropout_p=dropout)


def consume(**kwargs):
    return kwargs
""",
        encoding="utf-8",
    )

    args = SimpleNamespace(
        recursive=False,
        verbose=False,
        debug=False,
        exclude="",
        engine="ast-dataflow",
        format="text",
        output=None,
        targets=[str(sample)],
    )

    exit_code = security_cli.run_security(args)

    captured = capsys.readouterr()
    assert exit_code == 0
    assert "Traceback" not in captured.out
    assert "Traceback" not in captured.err


def test_ast_dataflow_json_and_sarif_preserve_trace_and_diagnostics():
    finding = ASTDataflowTaintFinding(
        function="run",
        filename="sample.py",
        sink_name="eval",
        sink_line=9,
        source_kinds=frozenset({"code"}),
        rule_id="PYFLOW-CODE",
        rule_title="Code injection",
        severity="high",
        cwe="CWE-95",
        trace=(
            ASTDataflowTraceStep("source", "run.payload", "sample.py", 3, "input"),
            ASTDataflowTraceStep("sink", "eval", "sample.py", 9, "eval"),
        ),
    )
    diagnostic = CheckerDiagnostic(
        "Unknown library effect",
        "unknown-call-effect",
        True,
        "run",
        "unsupported",
        "sample.py",
        7,
        "library.call",
    )
    manager = SimpleNamespace(
        analysis_result=ASTDataflowTaintResult(
            (finding,), status="partial", diagnostics=(diagnostic,)
        )
    )

    payload = ast_dataflow_report(manager)
    sarif = security_sarif("ast-dataflow", manager)

    assert payload["findings"][0]["trace"][0]["operation"] == "source"
    assert payload["findings"][0]["cwes"] == ["CWE-95", "CWE-94"]
    assert payload["findings"][0]["cwe_ancestors"] == ["CWE-94"]
    assert payload["diagnostics"][0]["operation"] == "library.call"
    thread_locations = sarif["runs"][0]["results"][0]["codeFlows"][0]["threadFlows"][0]["locations"]
    assert [
        item["location"]["physicalLocation"]["region"]["startLine"] for item in thread_locations
    ] == [
        3,
        9,
    ]


def test_security_cli_cpg_reports_nested_source_to_sink_flow(tmp_path):
    sample = tmp_path / "cpg_flow.py"
    sample.write_text(
        """
import os


class Box:
    def __init__(self):
        self.value = None


def source():
    return input("cmd> ")


def passthrough(value):
    return value


def run_from_field():
    box = Box()
    box.value = passthrough(source())
    os.system(box.value)


def run_from_dict():
    payload = {"cmd": source()}
    cmd = f"{payload['cmd']}"
    eval(cmd)
""",
        encoding="utf-8",
    )

    args = SimpleNamespace(
        recursive=False,
        sources=["source", "input"],
        sinks=["os.system", "eval"],
        sanitizers=[],
        framework=[],
    )

    report = security_cli._run_cpg([str(sample)], args)
    assert report["statistics"], "Shared reporting must retain engine statistics"
    findings = report["findings"]

    sink_labels = {finding["sink_label"] for finding in findings}
    assert "os.system" in sink_labels
    assert "eval" in sink_labels


def test_security_cli_cpg_reports_flask_framework_flow(tmp_path):
    sample = tmp_path / "cpg_flask.py"
    sample.write_text(
        """
import os
from flask import request


def route_handler():
    cmd = request.args.get("cmd")
    os.system(cmd)
""",
        encoding="utf-8",
    )

    args = SimpleNamespace(
        recursive=False,
        sources=[],
        sinks=[],
        sanitizers=[],
        framework=["flask"],
    )

    findings = security_cli._run_cpg([str(sample)], args)["findings"]

    assert any(finding["sink_label"] == "os.system" for finding in findings)


def test_security_report_exit_policy_separates_process_and_analysis_status():
    args = SimpleNamespace(exit_code_policy="report")

    assert _security_exit_code(args, status="partial", has_findings=True) == 0
    assert _security_exit_code(args, status="failed", has_findings=False) == 4
    assert _security_exit_code(args, status="invalid", has_findings=False) == 2


@pytest.mark.parametrize("policy,expected", [("report", 0), ("findings", 1)])
def test_security_exit_policy_for_findings(policy, expected):
    assert (
        _security_exit_code(
            SimpleNamespace(exit_code_policy=policy), status="complete", has_findings=True
        )
        == expected
    )


def test_security_parser_defaults_to_reporting():
    import argparse
    from pyflow.cli.security.parser import add_security_parser

    parser = argparse.ArgumentParser()
    add_security_parser(parser.add_subparsers())
    assert parser.parse_args(["security", "sample.py"]).exit_code_policy == "report"


def test_security_missing_target_still_fails_in_report_mode(tmp_path, capsys):
    import argparse
    from pyflow.cli.security.parser import add_security_parser

    parser = argparse.ArgumentParser()
    add_security_parser(parser.add_subparsers())
    args = parser.parse_args(["security", str(tmp_path / "missing.py"), "--format", "json"])
    assert security_cli.run_security(args) == 2
    assert json.loads(capsys.readouterr().out)["errors"]


@pytest.mark.parametrize("kind", ["taint", "nullness", "lock_leak"])
def test_ifds_text_renders_normalized_finding_metadata(kind):
    report = {
        "status": "complete",
        "findings": [
            {
                "kind": kind,
                "rule_id": "TEST-RULE",
                "severity": "high",
                "message": "Review this flow",
                "procedure": "app.run",
                "primary_location": {"uri": "app.py", "start_line": 17},
            }
        ],
    }
    text = security_text("ifds", report)
    assert "[TEST-RULE]" in text
    assert "Severity: high" in text
    assert "Location: app.py:17" in text
    assert "Review this flow" in text
    assert "?" not in text


def test_ifds_text_explicitly_reports_unavailable_source():
    text = security_text("ifds", {"findings": [{"rule_id": "TEST", "primary_location": None}]})
    assert "<source location unavailable>" in text


def test_cpg_text_does_not_display_unknown_locations_as_line_zero():
    text = security_text("cpg", {"findings": [{"source_line": 0, "sink_line": 0}]})
    assert text.count("<source location unavailable>") == 2
    assert "line 0" not in text


def test_session_diagnostics_preserve_serialized_fields_and_partial_status():
    from pyflow.cli.security.command import _apply_session_diagnostics

    diagnostic = {
        "code": "partial-graph",
        "message": "Graph incomplete",
        "affects_completeness": True,
    }
    report = {"status": "complete", "diagnostics": [diagnostic]}
    result = _apply_session_diagnostics(report, SimpleNamespace(diagnostics=()))
    assert result["status"] == "partial"
    assert result["diagnostics"] == [diagnostic]
