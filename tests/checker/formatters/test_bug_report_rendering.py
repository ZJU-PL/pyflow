"""Tests for user-friendly bug report rendering across IFDS, AST-dataflow, and CPG."""

from __future__ import annotations

import argparse
import json
from types import SimpleNamespace

import pytest

from pyflow.analysis.ifds.core.solver import SolverOptions
from pyflow.analysis.ifds.modeling.calls import CallModel, CallModelRegistry
from pyflow.analysis.ifds.reporting import (
    normalized_nullness_findings,
    normalized_typestate_findings,
)
from pyflow.analysis.taint_policy import TaintRule
from pyflow.api.ifds import run_nullness_analysis, run_typestate_analysis
from pyflow.checker.cpg.taint.model import TaintFinding
from pyflow.checker.formatters.cpg import finding_to_sarif
from pyflow.checker.formatters.report_render import render_bug_report_html
from pyflow.checker.formatters.security import (
    security_html,
    security_markdown,
    security_sarif,
    security_text,
)
from pyflow.checker.ifds.api import run_taint_analysis
from pyflow.checker.ifds.reporting import (
    nullness_result_to_dict,
    taint_result_to_dict,
    typestate_result_to_dict,
)
from pyflow.cli.security.parser import add_security_parser
from pyflow.cli.security.command import run_security


def _security_args(*tokens):
    parser = argparse.ArgumentParser()
    add_security_parser(parser.add_subparsers())
    return parser.parse_args(["security", *[str(t) for t in tokens]])


def test_ifds_taint_bug_reports_include_snippets_traces_nesting_and_suggestions(tmp_path):
    target = tmp_path / "taint_flow.py"
    target.write_text(
        """
def get_input():
    return "untrusted"

def run_cmd(cmd):
    exec_cmd(cmd)

def exec_cmd(x):
    return x

def main():
    user = get_input()
    run_cmd(user)
""".lstrip(),
        encoding="utf-8",
    )

    models = CallModelRegistry(
        [
            CallModel("get_input", source_kinds=frozenset({"user.input"})),
            CallModel(
                "exec_cmd",
                sink_kinds=frozenset({"cmd.exec"}),
                cwe="CWE-78",
                suggestion="Pass argument lists to subprocess.run(..., shell=False).",
            ),
        ]
    )
    rules = (
        TaintRule(
            "CMD-INJ",
            "Command Injection",
            frozenset({"user.input"}),
            frozenset({"cmd.exec"}),
            severity="high",
            cwe="CWE-78",
            suggestion="Validate and escape command inputs.",
        ),
    )

    _session, result, _ = run_taint_analysis(
        [target],
        function="main",
        call_models=models,
        rules=rules,
        solver_options=SolverOptions(trace_mode="all"),
    )
    report = taint_result_to_dict(str(target), result)
    assert len(report["findings"]) == 1
    finding = report["findings"][0]
    assert finding["code_flow"], "Expected IFDS taint code_flow steps"
    # Step messages are humanized (no raw CFGNode reprs) and track real nesting depth
    assert all("CFGNode(" not in step["message"] for step in finding["code_flow"])
    assert any(step.get("nesting_level", 0) >= 1 for step in finding["code_flow"])

    # Plain text hides noisy solver statistics by default and displays snippet, flow, suggestion
    text = security_text("ifds", report)
    assert "[CMD-INJ]" in text
    assert "CWE-78" in text
    assert "exec_cmd(cmd)" in text
    assert "Flow:" in text
    assert "Suggestion:" in text
    assert "Statistics:" not in text

    # Verbose text shows solver statistics
    verbose_text = security_text("ifds", report, verbose=True)
    assert "Statistics:" in verbose_text

    # Colored screen output emits ANSI escapes
    colored = security_text("ifds", report, color=True)
    assert "\033[" in colored

    # Markdown output renders summary table, code fence, trace table, and CWE link
    md = security_markdown("ifds", report)
    assert "# PyFlow Security Report (`ifds`)" in md
    assert "https://cwe.mitre.org/data/definitions/78.html" in md
    assert "```python" in md
    assert "| # | Step | Location | Detail | Code |" in md
    assert "> **Suggestion:**" in md

    # HTML output is standalone with highlight and trace
    html_out = security_html("ifds", report)
    assert "<!DOCTYPE html>" in html_out
    assert "code-line highlight" in html_out
    assert "Dataflow Trace" in html_out
    assert "CWE-78" in html_out

    # SARIF uses real call-stack nestingLevel rather than monotonic index - 1
    sarif = security_sarif("ifds", report)
    tf_locs = sarif["runs"][0]["results"][0]["codeFlows"][0]["threadFlows"][0]["locations"]
    nesting_levels = [loc["nestingLevel"] for loc in tf_locs]
    assert max(nesting_levels) < len(tf_locs) - 1 or len(tf_locs) <= 2


def test_ifds_nullness_and_typestate_produce_traces_cwes_and_suggestions(tmp_path):
    null_file = tmp_path / "null_case.py"
    null_file.write_text(
        """
import re

def parse(text: str):
    match = re.search(r"\\d+", text)
    return match.group(0)
""".lstrip(),
        encoding="utf-8",
    )
    _session, null_res = run_nullness_analysis(
        [null_file],
        function="parse",
        solver_options=SolverOptions(trace_mode="all"),
    )
    norm_null = normalized_nullness_findings(null_res)
    assert norm_null
    assert norm_null[0].cwe == "CWE-476"
    assert norm_null[0].suggestion
    assert norm_null[0].code_flow, "Expected nullness explain_path witness"
    null_dict = nullness_result_to_dict(str(null_file), null_res)
    null_text = security_text("ifds", null_dict)
    assert "CWE-476" in null_text
    assert "Flow:" in null_text
    assert "Suggestion:" in null_text
    assert "match.group(0)" in null_text

    ts_file = tmp_path / "resource_case.py"
    ts_file.write_text(
        """
def bad_io():
    handle = open("data.txt")
    handle.close()
    return handle.read()
""".lstrip(),
        encoding="utf-8",
    )
    _session2, ts_res = run_typestate_analysis(
        [ts_file],
        function="bad_io",
        solver_options=SolverOptions(trace_mode="all"),
    )
    norm_ts = normalized_typestate_findings(ts_res)
    assert norm_ts
    assert norm_ts[0].cwe is not None
    assert norm_ts[0].suggestion
    assert norm_ts[0].code_flow, "Expected typestate explain_path witness"
    ts_dict = typestate_result_to_dict(str(ts_file), ts_res)
    ts_md = security_markdown("ifds", ts_dict)
    assert "Dataflow Trace" in ts_md
    assert "> **Suggestion:**" in ts_md


@pytest.mark.parametrize("engine", ["ast-dataflow", "cpg", "ifds"])
@pytest.mark.parametrize("fmt", ["text", "screen", "markdown", "html", "sarif"])
def test_cli_security_renders_all_user_friendly_formats_for_all_dataflow_engines(
    tmp_path, capsys, engine, fmt
):
    app = tmp_path / "vuln_app.py"
    app.write_text(
        """
import os

def handle():
    user = input()
    os.system(user)

handle()
""".lstrip(),
        encoding="utf-8",
    )

    code = run_security(_security_args(app, "--engine", engine, "--format", fmt))
    captured = capsys.readouterr()
    assert code == 0, captured.err
    out = captured.out
    assert out.strip()

    if fmt == "text":
        assert "Status:" in out
        assert "os.system(user)" in out
    elif fmt == "screen":
        assert "Status:" in out
        assert "\033[" in out
    elif fmt == "markdown":
        assert f"# PyFlow Security Report (`{engine}`)" in out
        assert "```python" in out
    elif fmt == "html":
        assert "<!DOCTYPE html>" in out
        assert f"PyFlow Security Report ({engine})" in out
        assert "code-line highlight" in out
    elif fmt == "sarif":
        doc = json.loads(out)
        assert doc["version"] == "2.1.0"
        assert doc["runs"][0]["results"], f"Expected SARIF result for {engine}"
        for res in doc["runs"][0]["results"]:
            assert "partialFingerprints" in res
            assert res["partialFingerprints"].get("pyflow/v1")


def test_cpg_sarif_adapters_agree_on_sink_primary_location_and_fingerprints(tmp_path):
    src_file = tmp_path / "cpg_sample.py"
    src_file.write_text("x = input()\neval(x)\n", encoding="utf-8")

    src_node = SimpleNamespace(
        ast_node=SimpleNamespace(
            lineno=1, col_offset=4, end_col_offset=11, _pyflow_filename=str(src_file)
        ),
        kind="call",
        label="input()",
    )
    snk_node = SimpleNamespace(
        ast_node=SimpleNamespace(
            lineno=2, col_offset=0, end_col_offset=7, _pyflow_filename=str(src_file)
        ),
        kind="call",
        label="eval(x)",
    )
    finding = TaintFinding(
        cwe="CWE-95",
        severity="high",
        source_label="input()",
        sink_label="eval(x)",
        source_node=src_node,
        sink_node=snk_node,
        path_nodes=[src_node, snk_node],
        rule_id="CPG-EVAL",
        rule_title="Code Injection via eval",
        suggestion="Avoid eval() on untrusted input; use ast.literal_eval() instead.",
    )

    direct_sarif = finding_to_sarif(finding, artifact_uri=str(src_file))
    shared_sarif = security_sarif(
        "cpg",
        {"status": "complete", "findings": [finding.to_dict()]},
        artifact_uri=str(src_file),
    )["runs"][0]["results"][0]

    # Both CPG SARIF adapters point primary location to sink line (2) and emit fingerprints
    assert direct_sarif["locations"][0]["physicalLocation"]["region"]["startLine"] == 2
    assert shared_sarif["locations"][0]["physicalLocation"]["region"]["startLine"] == 2
    assert direct_sarif["partialFingerprints"]["pyflow/v1"]
    assert shared_sarif["partialFingerprints"]["pyflow/v1"]

    # Rich CPG text displays snippet, flow, rule title, and suggestion
    text = security_text("cpg", {"status": "complete", "findings": [finding.to_dict()]})
    assert "Code Injection via eval" in text
    assert "eval(x)" in text
    assert "Flow:" in text
    assert "Suggestion:" in text


def test_unified_json_schema_preserves_suggestion_and_normalized_code_flow(tmp_path, capsys):
    app = tmp_path / "unified_app.py"
    app.write_text(
        """
import os

def main():
    cmd = input()
    os.system(cmd)
""".lstrip(),
        encoding="utf-8",
    )

    code = run_security(
        _security_args(
            app,
            "--engine",
            "ast-dataflow",
            "--format",
            "json",
            "--json-schema",
            "unified",
        )
    )
    assert code == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["schema_version"] == 1
    assert payload["findings"]
    first = payload["findings"][0]
    assert "suggestion" in first
    assert "code_flow" in first
    assert isinstance(first["code_flow"], list)


def test_html_report_escapes_untrusted_text_against_xss():
    malicious = {
        "status": "complete",
        "findings": [
            {
                "rule_id": "<script>evil()</script>",
                "severity": "high",
                "message": '<img src=x onerror="alert(1)">',
                "procedure": "<b>proc</b>",
                "primary_location": {"uri": "<svg/onload=1>.py", "start_line": 1},
                "suggestion": "<script>steal()</script>",
            }
        ],
    }
    rendered = render_bug_report_html("ifds", malicious)
    assert "<script>evil()" not in rendered
    assert "<script>steal()" not in rendered
    assert 'onerror="alert(1)"' not in rendered
    assert "&lt;script&gt;evil()&lt;/script&gt;" in rendered
    assert "&lt;script&gt;steal()&lt;/script&gt;" in rendered
