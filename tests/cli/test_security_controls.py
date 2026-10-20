"""CLI output contracts and report controls across security engines."""

import argparse
import json

import pytest

from pyflow.cli.security.parser import add_security_parser
from pyflow.cli.security.command import run_security


def _args(*argv):
    parser = argparse.ArgumentParser()
    add_security_parser(parser.add_subparsers())
    return parser.parse_args(["security", *map(str, argv)])


@pytest.mark.parametrize("engine", ["ast-scanner", "ast-dataflow", "ifds", "cpg"])
def test_every_engine_has_clean_stdout_and_common_unified_finding_fields(engine, tmp_path, capsys):
    path = tmp_path / "app.py"
    path.write_text("def run():\n    value = input()\n    eval(value)\nrun()\n")
    code = run_security(
        _args(path, "--engine", engine, "--format", "json", "--json-schema", "unified")
    )
    captured = capsys.readouterr()
    report = json.loads(captured.out)
    assert code == 0
    assert report["engine"] == engine
    assert report["schema_version"] == 1
    assert set(report) == {
        "schema_version",
        "engine",
        "status",
        "findings",
        "errors",
        "diagnostics",
        "statistics",
    }
    assert report["findings"]
    for item in report["findings"]:
        assert item["rule_id"]
        assert item["severity"] in {"low", "medium", "high", "critical"}
        assert item["confidence"] in {"low", "medium", "high"}
        assert item["location"]["filename"]
        assert item["location"]["line"] > 0


@pytest.mark.parametrize("engine", ["ast-scanner", "ast-dataflow", "ifds", "cpg"])
def test_baseline_suppression_precedes_findings_gate(engine, tmp_path, capsys):
    path = tmp_path / "app.py"
    path.write_text("def run():\n    value = input()\n    eval(value)\nrun()\n")
    baseline = tmp_path / "baseline.json"
    args = _args(
        path,
        "--engine",
        engine,
        "--format",
        "json",
        "--json-schema",
        "unified",
        "--fail-on",
        "low",
        "-o",
        baseline,
    )
    assert run_security(args) == 1
    assert json.loads(baseline.read_text())["findings"]
    args.output = None
    args.baseline = baseline
    assert run_security(args) == 0
    assert json.loads(capsys.readouterr().out)["findings"] == []


def test_severity_confidence_skip_and_gate_controls(tmp_path, capsys):
    path = tmp_path / "app.py"
    path.write_text("assert True\n")
    assert run_security(_args(path, "--format", "json", "--fail-on", "high")) == 0
    assert json.loads(capsys.readouterr().out)["results"]
    assert run_security(_args(path, "--format", "json", "--fail-on", "low")) == 1
    capsys.readouterr()
    for options in (("--severity", "high"), ("--severity", "critical"), ("--skip-rule", "B101")):
        assert run_security(_args(path, "--format", "json", "--fail-on", "low", *options)) == 0
        assert json.loads(capsys.readouterr().out)["results"] == []


@pytest.mark.parametrize("engine", ["ast-scanner", "ast-dataflow", "cpg"])
def test_default_exclusions_can_be_overridden(engine, tmp_path, capsys):
    source = "def run():\n    value = input()\n    eval(value)\nrun()\n"
    for folder in ("src", "tests", ".git", ".venv/lib"):
        path = tmp_path / folder / "sample.py"
        path.parent.mkdir(parents=True)
        path.write_text(source)
    args = _args(tmp_path, "-r", "--engine", engine, "--format", "json", "--json-schema", "unified")
    assert run_security(args) == 0
    report = json.loads(capsys.readouterr().out)
    assert {item["location"]["filename"] for item in report["findings"]} == {
        str(tmp_path / "src/sample.py")
    }
    args.no_default_excludes = True
    assert run_security(args) == 0
    report = json.loads(capsys.readouterr().out)
    assert any("tests/sample.py" in item["location"]["filename"] for item in report["findings"])


@pytest.mark.parametrize("excluded", ["tests", "./tests", "tests/", "tests/,src", "absolute"])
def test_exclusion_spellings_are_consistent(excluded, tmp_path, capsys):
    for folder in ("tests", "src"):
        path = tmp_path / folder / "app.py"
        path.parent.mkdir()
        path.write_text("assert True\n")
    if excluded == "absolute":
        excluded = str(tmp_path / "tests")
    args = _args(tmp_path, "-r", "--no-default-excludes", "--exclude", excluded, "--format", "json")
    assert run_security(args) == 0
    report = json.loads(capsys.readouterr().out)
    assert all("tests/app.py" not in item["filename"] for item in report["results"])
    if excluded != "tests/,src":
        assert report["results"]


def test_ast_entry_parameters_keep_user_input_kind_without_fabricating_file_or_environment_sources(
    tmp_path, capsys
):
    path = tmp_path / "app.py"
    path.write_text("def handler(value):\n    eval(value)\n")
    args = _args(path, "--engine", "ast-dataflow", "--format", "json")
    assert run_security(args) == 0
    findings = json.loads(capsys.readouterr().out)["findings"]
    assert findings
    assert all(item["source_kinds"] == ["user_input"] for item in findings)


def test_unknown_ast_calls_preserve_real_input_kinds_and_disclose_assumptions(tmp_path, capsys):
    path = tmp_path / "app.py"
    path.write_text("def handler():\n    value = input()\n    eval(vendor.wrap(value))\n")
    assert run_security(_args(path, "--engine", "ast-dataflow", "--format", "json")) == 0
    report = json.loads(capsys.readouterr().out)
    assert report["status"] == "partial"
    assert all(item["source_kinds"] == ["user_input"] for item in report["findings"])
    assert any(item["code"] == "unknown-call-effect" for item in report["diagnostics"])


def test_critical_custom_taint_rule_survives_filtering_and_gates_successful_scan(tmp_path, capsys):
    path = tmp_path / "app.py"
    path.write_text("def run():\n    vendor_sink(input())\nrun()\n")
    pack = tmp_path / "custom.json"
    pack.write_text(
        json.dumps(
            {
                "schema_version": 2,
                "framework": "custom",
                "version": "1.0",
                "type": "taint",
                "models": [
                    {
                        "call": "vendor_sink",
                        "sinks": [{"kind": "custom_sink", "port": {"parameter": 0}}],
                    }
                ],
                "rules": [
                    {
                        "id": "CUSTOM-CRITICAL",
                        "title": "Critical test policy",
                        "sources": ["user_input"],
                        "sinks": ["custom_sink"],
                        "severity": "critical",
                    }
                ],
            }
        )
    )
    args = _args(
        path,
        "--engine",
        "ast-dataflow",
        "--registry-path",
        pack,
        "--severity",
        "critical",
        "--fail-on",
        "critical",
        "--format",
        "json",
        "--json-schema",
        "unified",
    )
    assert run_security(args) == 1
    findings = json.loads(capsys.readouterr().out)["findings"]
    assert [item["rule_id"] for item in findings] == ["CUSTOM-CRITICAL"]
    assert findings[0]["severity"] == "critical"


@pytest.mark.parametrize("directory", [False, True])
def test_ifds_loads_relative_entry_once(tmp_path, monkeypatch, capsys, directory):
    (tmp_path / "app.py").write_text("def run():\n    eval(input())\nrun()\n")
    monkeypatch.chdir(tmp_path)
    target = "." if directory else "app.py"
    extra = ["--entry", "app.py"] if directory else []
    assert run_security(_args(target, "--engine", "ifds", "--format", "json", *extra)) == 0
    report = json.loads(capsys.readouterr().out)
    findings = report["findings"]
    assert len(findings) == 1
    assert findings[0]["primary_location"]["start_line"] == 2


def test_ifds_default_time_budget_and_config_override(tmp_path):
    from pyflow.cli.security.command import _apply_ifds_config, _ifds_solver_options

    args = _args(tmp_path, "--engine", "ifds")
    assert _ifds_solver_options(args).max_seconds == 30.0
    (tmp_path / "pyflow.json").write_text('{"solver_options": {"max_seconds": 12}}')
    _apply_ifds_config(args)
    assert _ifds_solver_options(args).max_seconds == 12
    args = _args(tmp_path, "--engine", "ifds", "--ifds-max-seconds", "7")
    _apply_ifds_config(args)
    assert _ifds_solver_options(args).max_seconds == 7


def test_cpg_total_budget_stops_before_remaining_targets(tmp_path, monkeypatch):
    from pyflow.cli.security import command

    ticks = iter([0.0, 2.0])
    monkeypatch.setattr(command, "monotonic", lambda: next(ticks))
    args = _args(tmp_path, "--engine", "cpg", "--cpg-total-max-seconds", "1")
    report = command._run_cpg([str(tmp_path)], args)
    assert report["status"] == "partial"
    assert report["diagnostics"][0]["code"] == "cpg-total-time-budget"


def test_ast_dataflow_text_groups_repeated_unknown_call_diagnostics(tmp_path, capsys):
    sample = tmp_path / "app.py"
    sample.write_text("def f():\n    unknown()\n    unknown()\n")
    assert run_security(_args(sample, "--engine", "ast-dataflow")) == 0
    output = capsys.readouterr().out
    assert output.count("[unknown-call-effect]") == 1
    assert "(2 occurrences)" in output


def test_ast_time_budget_reports_partial_in_json(tmp_path, monkeypatch, capsys):
    from pyflow.cli.security import command
    from pyflow.cli.analysis_budget import AnalysisBudgetExceeded

    sample = tmp_path / "sample.py"
    sample.write_text("def f(): pass\n")

    def expire(self, paths):
        raise AnalysisBudgetExceeded("Analysis exceeded 30 seconds")

    monkeypatch.setattr(command.ASTDataflowManager, "analyze", expire)
    args = _args(
        sample, "--engine", "ast-dataflow", "--format", "json", "--exit-code-policy", "findings"
    )
    assert command.run_security(args) == 3
    report = json.loads(capsys.readouterr().out)
    assert report["status"] == "partial"
    assert report["diagnostics"][0]["code"] == "ast-time-budget"


def test_ifds_total_budget_retains_completed_entry_findings(tmp_path, monkeypatch):
    from pyflow.cli.security import command
    from pyflow.cli.analysis_budget import AnalysisBudgetExceeded

    first, second = tmp_path / "first.py", tmp_path / "second.py"
    monkeypatch.setattr(command, "_resolve_ifds_entry_files", lambda *_: (first, second))

    def run_entry(targets, args):
        if args.entry == second:
            raise AnalysisBudgetExceeded("Analysis exceeded 60 seconds")
        return {"entry": "first.py", "findings": [{"rule_id": "TEST"}], "status": "complete"}

    monkeypatch.setattr(command, "_run_ifds_entry", run_entry)
    report = command._run_ifds([str(tmp_path)], _args(tmp_path, "--engine", "ifds"))
    assert report["status"] == "partial"
    assert report["findings"] == [{"rule_id": "TEST"}]
    assert report["diagnostics"][0]["code"] == "ifds-total-time-budget"


def test_security_total_budgets_have_finite_defaults():
    args = _args()
    assert args.ast_max_seconds == 30
    assert args.ifds_total_max_seconds == 60
    assert args.cpg_total_max_seconds == 60
