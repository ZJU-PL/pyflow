"""Tests for the IFDS analysis API and CLI entrypoints."""

from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

from pyflow.analysis.ifds.api import run_taint_analysis
from pyflow.cli.dataflow import run_dataflow_analysis


PROGRAM = """
def source():
    return 1

def sanitize(x):
    return x

def sink(x):
    return x

def helper(x):
    return x

def main():
    a = source()
    b = helper(a)
    c = sanitize(b)
    sink(b)
    sink(c)
    return c
"""


def test_run_taint_analysis_api_on_source_file(tmp_path):
    target = tmp_path / "sample.py"
    target.write_text(PROGRAM)

    session, result = run_taint_analysis(
        [target],
        function="main",
        source_names=["source"],
        sink_names=["sink"],
        sanitizer_names=["sanitize"],
    )

    assert {code.codeName() for code in session.program.liveCode} >= {
        "main",
        "helper",
        "sanitize",
        "sink",
        "source",
    }
    assert len(result.findings) == 1
    assert result.findings[0].sink_name == "sink"
    assert [local.name for local in result.findings[0].tainted_arguments] == ["b"]


def test_run_taint_analysis_api_on_repo_backed_multi_file_snippet():
    snippet_dir = Path(__file__).parent / "snippets" / "multi_file_taint"
    python_files = sorted(snippet_dir.glob("*.py"))

    session, result = run_taint_analysis(
        python_files,
        function="main",
        source_names=["source"],
        sink_names=["sink"],
        sanitizer_names=["sanitize"],
        search_paths=[str(snippet_dir)],
    )

    assert {code.codeName() for code in session.program.liveCode} >= {
        "main",
        "helper",
        "sanitize",
        "sink",
        "source",
    }
    assert len(result.findings) == 1
    assert result.findings[0].sink_name == "sink"
    assert [local.name for local in result.findings[0].tainted_arguments] == ["b"]


def test_run_taint_analysis_handles_nested_and_computed_sink_expressions(tmp_path):
    target = tmp_path / "nested.py"
    target.write_text(
        """
def source():
    return 1

def sink(x):
    return x

def helper(x):
    return x

def main():
    sink(source())
    a = source()
    sink(a + 1)
    b = helper(source())
    sink(b)
"""
    )

    _session, result = run_taint_analysis(
        [target],
        function="main",
        source_names=["source"],
        sink_names=["sink"],
    )

    findings = sorted(
        ([local.name for local in finding.tainted_arguments], finding.tainted_argument_labels)
        for finding in result.findings
    )
    assert findings == [
        ([], ("source()",)),
        (["a"], ()),
        (["b"], ()),
    ]


def test_run_taint_analysis_ignores_sanitized_nested_sink_expressions(tmp_path):
    target = tmp_path / "sanitized.py"
    target.write_text(
        """
def source():
    return 1

def sanitize(x):
    return x

def sink(x):
    return x

def main():
    a = source()
    sink(sanitize(a))
    sink(sanitize(source()))
"""
    )

    _session, result = run_taint_analysis(
        [target],
        function="main",
        source_names=["source"],
        sink_names=["sink"],
        sanitizer_names=["sanitize"],
    )

    assert result.findings == ()


def test_run_taint_analysis_tracks_nested_call_results(tmp_path):
    target = tmp_path / "nested_results.py"
    target.write_text(
        """
def source():
    return 1

def wrap(x):
    return x

def wrapper():
    return wrap(source())

def sink(x):
    return x

def main():
    sink(wrapper())
"""
    )

    _session, result = run_taint_analysis(
        [target],
        function="main",
        source_names=["source"],
        sink_names=["sink"],
    )

    assert len(result.findings) == 1
    assert result.findings[0].tainted_arguments == ()
    assert result.findings[0].tainted_argument_labels == ("wrapper()",)


def test_run_taint_analysis_ignores_try_except_sink_flow_in_normal_flow_only_mode(tmp_path):
    target = tmp_path / "try_except.py"
    target.write_text(
        """
def source():
    return 1

def sink(x):
    return x

def main():
    try:
        x = source()
        raise ValueError()
    except ValueError:
        sink(x)
"""
    )

    _session, result = run_taint_analysis(
        [target],
        function="main",
        source_names=["source"],
        sink_names=["sink"],
    )

    assert result.findings == ()


def test_run_taint_analysis_does_not_report_unreachable_except_calls(tmp_path):
    target = tmp_path / "unreachable_except.py"
    target.write_text(
        """
def source():
    return 1

def sink(x):
    return x

def main():
    try:
        x = 0
    except Exception:
        sink(source())
"""
    )

    _session, result = run_taint_analysis(
        [target],
        function="main",
        source_names=["source"],
        sink_names=["sink"],
    )

    assert result.findings == ()


def test_run_taint_analysis_scopes_findings_to_reachable_entry(tmp_path):
    target = tmp_path / "reachability.py"
    target.write_text(
        """
def source():
    return 1

def sink(x):
    return x

def dead():
    sink(source())

def main():
    return 0
"""
    )

    _session, result = run_taint_analysis(
        [target],
        function="main",
        source_names=["source"],
        sink_names=["sink"],
    )

    assert result.findings == ()


def test_dataflow_cli_emits_json_report(tmp_path, capsys):
    target = tmp_path / "sample.py"
    target.write_text(PROGRAM)

    args = SimpleNamespace(
        function="main",
        analysis="taint",
        sources=["source"],
        sinks=["sink"],
        sanitizers=["sanitize"],
        format="json",
        recursive=False,
        dependency_strategy="auto",
        verbose=False,
    )

    exit_code = run_dataflow_analysis(target, args)
    payload = json.loads(capsys.readouterr().out)

    assert exit_code == 1
    assert payload["function"] == "main"
    assert len(payload["findings"]) == 1
    assert payload["findings"][0]["tainted_arguments"] == ["b"]


def test_dataflow_cli_reports_expression_only_taint_findings(tmp_path, capsys):
    target = tmp_path / "nested.py"
    target.write_text(
        """
def source():
    return 1

def sink(x):
    return x

def main():
    sink(source())
"""
    )

    args = SimpleNamespace(
        function="main",
        analysis="taint",
        sources=["source"],
        sinks=["sink"],
        sanitizers=[],
        format="json",
        recursive=False,
        dependency_strategy="auto",
        verbose=False,
    )

    exit_code = run_dataflow_analysis(target, args)
    payload = json.loads(capsys.readouterr().out)

    assert exit_code == 1
    assert payload["findings"][0]["tainted_arguments"] == ["source()"]
