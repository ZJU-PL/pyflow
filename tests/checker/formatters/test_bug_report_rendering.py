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


@pytest.mark.parametrize("engine", ["ast-dataflow", "ifds", "cpg"])
def test_interprocedural_reports_are_clean_relative_and_free_of_internal_noise(
    tmp_path, capsys, engine
):
    """Verify all three dataflow engines produce clean, developer-friendly bug reports."""
    (tmp_path / "helpers.py").write_text(
        """
import os
import sqlite3

def build_query(user_id):
    return "SELECT * FROM users WHERE id = " + user_id

def run_sql(db_path, query):
    conn = sqlite3.connect(db_path)
    cur = conn.cursor()
    return cur.execute(query)

def run_cmd(arg):
    cmd = f"echo {arg}"
    os.system(cmd)
""".lstrip(),
        encoding="utf-8",
    )
    (tmp_path / "app.py").write_text(
        """
from helpers import build_query, run_sql, run_cmd

def handle_request():
    uid = input("user: ")
    q = build_query(uid)
    run_sql("app.db", q)
    run_cmd(uid)

if __name__ == "__main__":
    handle_request()
""".lstrip(),
        encoding="utf-8",
    )

    extra = (
        ["--entry", "app.py", "--sources", "input", "--sinks", "os.system,execute"]
        if engine == "ifds"
        else ["--recursive"]
    )
    code = run_security(_security_args(tmp_path, "--engine", engine, "--format", "text", *extra))
    captured = capsys.readouterr()
    assert code == 0, captured.err
    out = captured.out

    # No noisy extraction banner on stdout/stderr in default mode
    assert "begin [ extraction ]" not in captured.out
    assert "begin [ extraction ]" not in captured.err

    # Both vulnerabilities reported with numbered headers, CWEs, relative paths, and remediation
    assert "[1]" in out and "[2]" in out
    assert "CWE-89" in out and "CWE-78" in out
    assert "Function: run_sql" in out and "Function: run_cmd" in out
    assert "helpers.py:10" in out and "helpers.py:14" in out
    assert str(tmp_path) not in out
    assert out.count("Suggestion:") >= 2

    # Clean traces: no internal compiler intrinsics, raw PDG labels, or internal source prefixes
    assert "interpreter_format" not in out
    assert "interpreter_join_str" not in out
    assert "from:cpg:" not in out
    assert "[STMT] Discard" not in out
    assert "[ENTRY] Entry\n" not in out
    assert "local-binding" not in out
    assert "[SOURCE]" in out
    assert "[ENTER]" in out
    assert "[SINK]" in out

    if engine == "ifds":
        # Leading <module> bootstrap and unrelated sqlite3.connect/cursor lines are trimmed
        assert "Analysis entry in app.<module>" not in out
        assert "sqlite3.connect" not in out
    if engine == "cpg":
        # Unrelated conn.cursor() unknown-call-effect in run_sql must not downgrade run_cmd
        assert "90%" in out and "(HIGH)" in out
        # Caret highlights cur.execute(query) rather than 'return'
        assert (
            "       > 10 |     return cur.execute(query)\n            |            ^~~~~~~" in out
        )
    if engine == "ast-dataflow":
        # Cross-procedure trace includes call site, callee entry, and callee assignment
        assert "Calls run_cmd()" in out
        assert "Enters run_cmd()" in out
        assert "Assigns tainted value to 'cmd'" in out


def test_taint_rule_titles_do_not_duplicate_sink_suffix():
    from pathlib import Path

    config_dir = Path("src/pyflow/config/taint")
    for path in sorted(config_dir.glob("*.json")):
        payload = json.loads(path.read_text(encoding="utf-8"))
        for rule in payload.get("rules", ()):
            title = str(rule.get("title") or "")
            assert (
                "sink sink" not in title.lower()
            ), f"Duplicate 'sink sink' in {path.name}: {title}"


def test_rule_pack_folding_merges_cwe_less_duplicates_and_ranks_stdlib_and_sink_packs():
    from pyflow.cli.security.filters import _fold_taint_findings
    from pyflow.util.cwe import default_cwe_for_rule_id

    assert default_cwe_for_rule_id("PYFLOW-NETWORK-XSS") == "CWE-79"
    assert default_cwe_for_rule_id("PYFLOW-NETWORK-SSRF") == "CWE-918"
    assert default_cwe_for_rule_id("PYFLOW-STDLIB-LOGGING") == "CWE-117"
    assert default_cwe_for_rule_id("PYFLOW-CLI-DANGEROUS") is None

    # Same sink line reported by both PYFLOW-FLASK-XSS (CWE-79) and PYFLOW-NETWORK-XSS (no cwe)
    folded_xss = _fold_taint_findings(
        [
            {
                "rule_id": "PYFLOW-NETWORK-XSS",
                "rule_title": "Untrusted data reaches xss sink",
                "severity": "high",
                "sink_name": "flask.make_response",
                "primary_location": {"uri": "app/main.py", "start_line": 50},
            },
            {
                "rule_id": "PYFLOW-FLASK-XSS",
                "rule_title": "Untrusted data reaches xss sink",
                "severity": "high",
                "cwe": "CWE-79",
                "sink_name": "flask.make_response",
                "primary_location": {"uri": "app/main.py", "start_line": 50},
            },
        ]
    )
    assert len(folded_xss) == 1
    assert folded_xss[0]["rule_id"] == "PYFLOW-FLASK-XSS"

    # Generic PYFLOW-NETWORK-SSRF (no cwe) folds with PYFLOW-FASTAPI-SSRF (CWE-918) and wins
    folded_ssrf = _fold_taint_findings(
        [
            {
                "rule_id": "PYFLOW-FASTAPI-SSRF",
                "rule_title": "Untrusted data reaches ssrf sink",
                "severity": "high",
                "cwe": "CWE-918",
                "sink_name": "urllib.request.urlopen",
                "primary_location": {"uri": "net.py", "start_line": 12},
            },
            {
                "rule_id": "PYFLOW-NETWORK-SSRF",
                "rule_title": "Untrusted data reaches ssrf sink",
                "severity": "high",
                "sink_name": "urllib.request.urlopen",
                "primary_location": {"uri": "net.py", "start_line": 12},
            },
        ]
    )
    assert len(folded_ssrf) == 1
    assert folded_ssrf[0]["rule_id"] == "PYFLOW-NETWORK-SSRF"
    rendered = security_text("ifds", {"status": "complete", "findings": folded_ssrf})
    assert "(CWE-918)" in rendered
    assert "Suggestion:" in rendered

    # PYFLOW-STDLIB-DANGEROUS beats PYFLOW-NETWORK-DANGEROUS on generic sinks
    folded_generic = _fold_taint_findings(
        [
            {
                "rule_id": "PYFLOW-NETWORK-DANGEROUS",
                "rule_title": "Untrusted data reaches dangerous sink",
                "severity": "high",
                "sink_name": "logger.info",
                "primary_location": {"uri": "app.py", "start_line": 8},
            },
            {
                "rule_id": "PYFLOW-STDLIB-DANGEROUS",
                "rule_title": "Untrusted data reaches dangerous sink",
                "severity": "high",
                "sink_name": "logger.info",
                "primary_location": {"uri": "app.py", "start_line": 8},
            },
        ]
    )
    assert len(folded_generic) == 1
    assert folded_generic[0]["rule_id"] == "PYFLOW-STDLIB-DANGEROUS"


def test_cpg_trace_filters_synthetic_blocks_temps_intrinsics_and_preserves_terminal_sink(
    tmp_path, capsys
):
    from pyflow.checker.cpg.taint.formal import FormalCPGTaintAnalysis, TaintOrigin

    assert (
        FormalCPGTaintAnalysis._format_source_label(
            TaintOrigin("user_input", "loader.py", 1, symbol="entry-parameter:mod.main:user_path")
        )
        == "parameter 'user_path' of main()"
    )
    assert (
        FormalCPGTaintAnalysis._format_source_label(
            TaintOrigin("user_input", "loader.py", 1, symbol="module-initializer:CONFIG")
        )
        == "module global 'CONFIG'"
    )

    app = tmp_path / "loader.py"
    app.write_text(
        '''
def load_file(user_path):
    """Docstring should not appear as a trace step."""
    info = {}
    info["path"] = user_path
    if user_path:
        with open(user_path, "r") as handle:
            return handle.read()

p = input()
load_file(p)
'''.lstrip(),
        encoding="utf-8",
    )

    code = run_security(_security_args(app, "--engine", "cpg", "--format", "text"))
    captured = capsys.readouterr()
    assert code == 0, captured.err
    out = captured.out

    assert "CWE-22" in out
    assert "entry-parameter:" not in out
    assert "[BLOCK]" not in out
    assert "[STMT] InputBlock" not in out
    assert "__pyflow_tmp" not in out
    assert "interpreter_setitem" not in out
    assert "Updates container item" in out
    assert '"""Docstring' not in out
    assert "[SOURCE]" in out and "[SINK]" in out
    # Caret narrows from 'with open(...)' to 'open(user_path, "r")'
    assert 'with open(user_path, "r") as handle:' in out
    assert "|              ^~~~~~~~~~~~~~~~~~~~" in out

    # Long (>25-step) CPG witness path preserves both [SOURCE] and terminal [SINK]
    long_steps = tuple(
        {
            "kind": "source" if i == 0 else ("sink" if i == 34 else "assign"),
            "line": i + 1,
            "column": 0,
            "filename": str(app),
            "procedure": "load_file",
            "nesting_level": 0,
            "label": f"Step {i}",
        }
        for i in range(35)
    )
    dummy = SimpleNamespace(
        ast_node=SimpleNamespace(
            lineno=1, col_offset=0, end_col_offset=5, _pyflow_filename=str(app)
        ),
        kind="call",
        label="open",
    )
    long_finding = TaintFinding(
        cwe="CWE-22",
        severity="high",
        source_label="parameter 'user_path' of load_file()",
        sink_label="open",
        source_node=dummy,
        sink_node=dummy,
        path_nodes=[dummy],
        path_steps=long_steps,
    )
    preview = long_finding.to_dict()["path_preview"]
    assert len(preview) == 25
    assert preview[0]["kind"] == "source"
    assert preview[-1]["kind"] == "sink"
    assert any(step["kind"] == "ellipsis" for step in preview)


def test_diagnostics_summarization_relativization_and_comment_only_init_skip(tmp_path):
    from pyflow.cli.security.command import _resolve_ifds_entry_files

    pkg = tmp_path / "pkg"
    pkg.mkdir()
    (pkg / "__init__.py").write_text("# comment only\n", encoding="utf-8")
    (pkg / "doc_init").mkdir()
    (pkg / "doc_init" / "__init__.py").write_text(
        '"""Package docstring only."""\n', encoding="utf-8"
    )
    (pkg / "main.py").write_text("x = 1\n", encoding="utf-8")

    entries = _resolve_ifds_entry_files([str(tmp_path)], None, recursive=True)
    assert entries == ((pkg / "main.py").resolve(),)

    diags = [
        {
            "code": "cpg-unknown-call-effect",
            "message": f"Unknown call effects for helper_{i}",
            "filename": str(pkg / "main.py"),
            "line": i + 1,
        }
        for i in range(8)
    ] + [
        {
            "code": "cpg-loop-convergence-threshold",
            "message": "Loop required more fixed-point updates",
        },
        {
            "code": "cpg-no-functions",
            "message": f"No analyzable functions found in {tmp_path}/empty.py",
        },
    ]
    compact = security_text(
        "cpg",
        {"status": "partial", "findings": [], "diagnostics": diags},
        base_dir=tmp_path,
    )
    assert "8 unmodeled calls" in compact
    assert "1 loops exceeded convergence-reporting threshold" in compact
    assert "Re-run with --verbose" in compact
    assert str(tmp_path) not in compact
    assert "empty.py" in compact

    verbose = security_text(
        "cpg",
        {"status": "partial", "findings": [], "diagnostics": diags},
        verbose=True,
        base_dir=tmp_path,
    )
    assert "helper_7" in verbose
    assert "Re-run with --verbose" not in verbose

    from pyflow.checker.formatters.report_render import _caret_span
    from pyflow.checker.ifds.reporting import _humanize_argument_label

    assert _humanize_argument_label("interpreter_getitem()") == "subscript expression"
    assert _humanize_argument_label("interpreter_format()") == "formatted string"
    # Multiline assignment where end_column belongs to a later line still underlines the sink call
    assert _caret_span("        response = super().open(", 8, 9, "open") == (27, 4)


@pytest.mark.parametrize("engine", ["ast-dataflow", "ifds", "cpg"])
def test_sarif_and_json_exports_include_ide_tips_snippets_and_step_importance(
    tmp_path, capsys, engine
):
    app = tmp_path / "ide_export.py"
    app.write_text(
        """
import os

def run_cmd(cmd):
    os.system(cmd)

def main():
    user = input("cmd: ")
    run_cmd(user)

main()
""".lstrip(),
        encoding="utf-8",
    )

    # 1. SARIF export for VS Code SARIF Viewer / GitHub Code Scanning
    code = run_security(_security_args(app, "--engine", engine, "--format", "sarif"))
    assert code == 0
    sarif_doc = json.loads(capsys.readouterr().out)
    run = sarif_doc["runs"][0]
    assert run["results"], f"Expected SARIF result for {engine}"
    rule = run["tool"]["driver"]["rules"][0]
    res = run["results"][0]

    # Rule-level tips: plain text + rich Markdown + MITRE CWE helpUri + external/cwe tag
    assert rule["help"]["text"]
    assert "**Remediation:**" in rule["help"]["markdown"]
    assert rule["helpUri"].startswith("https://cwe.mitre.org/data/definitions/")
    assert any(t.startswith("external/cwe/cwe-") for t in rule["properties"]["tags"])

    # Result-level IDE fields: snippet, logicalLocations, per-result suggestion, CWE & URL
    primary = res["locations"][0]
    assert "os.system(cmd)" in primary["physicalLocation"]["region"]["snippet"]["text"]
    assert primary["logicalLocations"][0]["name"] == "run_cmd"
    assert res["properties"]["suggestion"]
    assert res["properties"]["cwe"] == "CWE-78"
    assert res["properties"]["cweUrl"] == "https://cwe.mitre.org/data/definitions/78.html"

    # CodeFlow steps: nestingLevel + SARIF importance + inline snippet
    tf_locs = res["codeFlows"][0]["threadFlows"][0]["locations"]
    assert tf_locs
    assert all(loc["importance"] in {"essential", "important", "unimportant"} for loc in tf_locs)
    assert any(loc["importance"] == "essential" for loc in tf_locs)
    assert any(
        loc["location"]["physicalLocation"]["region"].get("snippet", {}).get("text")
        for loc in tf_locs
    )

    # 2. Unified JSON export for custom bug dashboards / IDE plugins
    code = run_security(
        _security_args(app, "--engine", engine, "--format", "json", "--json-schema", "unified")
    )
    assert code == 0
    unified = json.loads(capsys.readouterr().out)
    item = unified["findings"][0]
    assert item["cwe"] == "CWE-78"
    assert item["cwe_url"] == "https://cwe.mitre.org/data/definitions/78.html"
    assert item["suggestion"]
    assert item["procedure"] == "run_cmd"
    assert "os.system(cmd)" in item["code_snippet"]
    assert item["code_flow"]
    assert any(step.get("code_snippet") for step in item["code_flow"])

    # 3. Legacy JSON export also carries suggestion and CWE metadata
    code = run_security(_security_args(app, "--engine", engine, "--format", "json"))
    assert code == 0
    legacy = json.loads(capsys.readouterr().out)
    legacy_finding = legacy["findings"][0]
    assert legacy_finding["suggestion"]
    assert legacy_finding["cwe"] == "CWE-78"
