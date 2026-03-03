"""Tests for the IFDS analysis API and CLI entrypoints."""

from __future__ import annotations

import json
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

    assert session.program.liveCode
    assert len(result.findings) == 1
    assert result.findings[0].sink_name == "sink"
    assert [local.name for local in result.findings[0].tainted_arguments] == ["b"]


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
    captured = capsys.readouterr()
    payload = json.loads(captured.out)

    assert exit_code == 1
    assert payload["function"] == "main"
    assert len(payload["findings"]) == 1
    assert payload["findings"][0]["tainted_arguments"] == ["b"]
