"""CLI budgets terminate work visibly without emitting corrupt JSON."""

from argparse import ArgumentParser
import json
import signal
import time

import pytest

from pyflow.cli import alias, capabilities
from pyflow.cli.analysis_budget import AnalysisBudgetExceeded, analysis_time_budget
from pyflow.cli.security.parser import add_security_parser


@pytest.mark.skipif(not hasattr(signal, "setitimer"), reason="Unix timer required")
def test_timer_interrupts_work_even_inside_generic_exception_handlers():
    previous_handler = signal.getsignal(signal.SIGALRM)
    with pytest.raises(AnalysisBudgetExceeded):
        with analysis_time_budget(0.01):
            try:
                time.sleep(0.05)
            except Exception:
                pytest.fail("An internal error handler must not swallow a CLI budget")
    assert signal.getsignal(signal.SIGALRM) == previous_handler
    assert signal.getitimer(signal.ITIMER_REAL) == (0.0, 0.0)


@pytest.mark.skipif(not hasattr(signal, "setitimer"), reason="Unix timer required")
def test_preexisting_timer_and_handler_are_restored():
    original = signal.getsignal(signal.SIGALRM)
    handler = lambda *_: None
    try:
        signal.signal(signal.SIGALRM, handler)
        signal.setitimer(signal.ITIMER_REAL, 10)
        with analysis_time_budget(1):
            pass
        assert signal.getsignal(signal.SIGALRM) is handler
        assert 9 < signal.getitimer(signal.ITIMER_REAL)[0] <= 10
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, original)


def test_alias_timeout_preserves_finished_files_and_reports_partial(monkeypatch, tmp_path, capsys):
    for name in ("a.py", "b.py"):
        (tmp_path / name).write_text("value = 1\n")
    parser = ArgumentParser()
    alias.add_alias_parser(parser.add_subparsers())
    args = parser.parse_args(["alias", str(tmp_path), "--json"])

    def analyze(path):
        if path.name == "b.py":
            raise AnalysisBudgetExceeded("Analysis exceeded test budget")
        print("frontend progress")
        return {"file": str(path), "functions": {}}

    monkeypatch.setattr(alias, "_analyze_file_flow_sensitive_json", analyze)
    assert alias.run_alias_analysis(str(tmp_path), args) == 0
    captured = capsys.readouterr()
    reports = json.loads(captured.out)
    assert reports[0]["file"].endswith("a.py")
    assert reports[1]["status"] == "partial"
    assert reports[1]["diagnostics"][0]["code"] == "analysis-time-budget"
    assert "frontend progress" in captured.err


def test_capabilities_timeout_is_partial_json_report(monkeypatch, tmp_path, capsys):
    source = tmp_path / "main.py"
    source.write_text("print('hello')\n")
    parser = ArgumentParser()
    capabilities.add_capabilities_parser(parser.add_subparsers())
    args = parser.parse_args(["capabilities", str(source), "--format", "json"])

    def analyze(*_, **__):
        raise AnalysisBudgetExceeded("Analysis exceeded test budget")

    monkeypatch.setattr(capabilities.DefensiveCapabilityAnalysis, "analyze_project", analyze)
    assert capabilities.run_capabilities(args) == 0
    report = json.loads(capsys.readouterr().out)
    assert report["status"] == "partial"
    assert report["diagnostics"][0]["kind"] == "budget"
    args.exit_code_policy = "findings"
    assert capabilities.run_capabilities(args) == 1


def test_capabilities_iteration_budget_reaches_pointer_solver(tmp_path, capsys):
    source = tmp_path / "main.py"
    source.write_text("import subprocess\nsubprocess.run(['id'])\n")
    parser = ArgumentParser()
    capabilities.add_capabilities_parser(parser.add_subparsers())
    args = parser.parse_args(
        ["capabilities", str(source), "--format", "json", "--max-iterations", "1"]
    )
    assert capabilities.run_capabilities(args) == 0
    report = json.loads(capsys.readouterr().out)
    assert report["status"] == "partial"
    assert any(item["kind"] == "budget" for item in report["diagnostics"])


def test_cpg_cli_has_finite_defaults():
    parser = ArgumentParser()
    add_security_parser(parser.add_subparsers())
    args = parser.parse_args(["security", "project", "--engine", "cpg"])
    assert args.cpg_max_states == 50000
    assert args.cpg_max_seconds == 30
