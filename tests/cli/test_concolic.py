from __future__ import annotations

import argparse
import json

from pyflow.cli import concolic


class _Args:
    entry = "main"
    inputs = "[0]"
    max_iterations = 10
    max_loop_iterations = 20
    json = True


def test_concolic_parser_exposes_coverage_search_controls():
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command")
    concolic.add_concolic_parser(subparsers)

    args = parser.parse_args(
        [
            "concolic",
            "target.py",
            "--search-strategy",
            "fifo",
            "--max-uninteresting-iterations",
            "7",
            "--total-timeout",
            "10",
            "--per-run-timeout",
            "2",
            "--solver-timeout",
            "1",
            "--solver-rlimit",
            "1000",
            "--max-solver-calls",
            "20",
            "--max-pending-states",
            "30",
            "--max-symbolic-container-size",
            "4",
            "--refine-opaque-calls",
            "--max-opaque-refinements",
            "40",
            "--emit-pytest",
            "generated_test.py",
        ]
    )

    assert args.search_strategy == "fifo"
    assert args.max_uninteresting_iterations == 7
    assert args.total_timeout == 10
    assert args.per_run_timeout == 2
    assert args.solver_timeout == 1
    assert args.solver_rlimit == 1000
    assert args.max_solver_calls == 20
    assert args.max_pending_states == 30
    assert args.max_symbolic_container_size == 4
    assert args.refine_opaque_calls
    assert args.max_opaque_refinements == 40
    assert args.emit_pytest == "generated_test.py"


def test_concolic_parser_exposes_project_scan_controls():
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command")
    concolic.add_concolic_parser(subparsers)

    args = parser.parse_args(
        [
            "concolic",
            "project",
            "--scan-project",
            "--max-functions",
            "12",
            "--input-complexity",
            "3",
            "--function-timeout",
            "4",
            "--json-output",
            "report.json",
        ]
    )

    assert args.scan_project
    assert args.max_functions == 12
    assert args.input_complexity == 3
    assert args.function_timeout == 4
    assert args.json_output == "report.json"


def test_concolic_cli_emits_generated_inputs(tmp_path, capsys):
    target = tmp_path / "target.py"
    target.write_text(
        "def main(value):\n" "    if value == 3:\n" "        return 1\n" "    return 0\n",
        encoding="utf-8",
    )
    args = _Args()
    args.input_path = str(target)

    assert concolic.run_concolic(args) == 0
    output = json.loads(capsys.readouterr().out)
    assert [3] in output["generated_inputs"]
    assert output["coverage"]["node_count"] > 0
    assert output["coverage"]["branch_count"] == 2
    assert output["statistics"]["solver"]["calls"] >= 1
    assert output["statistics"]["solver"]["seconds"] >= 0
    assert output["statistics"]["timing"]["total_seconds"] >= 0
    assert output["statistics"]["search"]["stop_reason"] == "exhausted"
    assert all("outcome" in run and "coverage" in run for run in output["runs"])


def test_concolic_cli_rejects_non_array_inputs(tmp_path, capsys):
    target = tmp_path / "target.py"
    target.write_text("def main():\n    return 0\n", encoding="utf-8")
    args = _Args()
    args.input_path = str(target)
    args.inputs = "0"

    assert concolic.run_concolic(args) == 2
    assert "JSON array" in capsys.readouterr().err


def test_concolic_cli_reports_contract_counterexamples(tmp_path, capsys):
    target = tmp_path / "target.py"
    target.write_text(
        "def main(value):\n" '    """post: __return__ > 0"""\n' "    return value\n",
        encoding="utf-8",
    )
    args = _Args()
    args.input_path = str(target)
    args.check_contracts = True

    assert concolic.run_concolic(args) == 0
    output = json.loads(capsys.readouterr().out)
    assert output["counterexamples"][0]["clause"] == "__return__ > 0"


def test_concolic_cli_emits_replay_validated_pytest(tmp_path, capsys):
    target = tmp_path / "target.py"
    target.write_text(
        "def main(value):\n"
        "    if value == 1:\n"
        "        raise ValueError('bad')\n"
        "    return value * 2\n",
        encoding="utf-8",
    )
    output_path = tmp_path / "generated_test.py"
    args = _Args()
    args.input_path = str(target)
    args.emit_pytest = str(output_path)

    assert concolic.run_concolic(args) == 0
    output = json.loads(capsys.readouterr().out)
    assert output["pytest_generation"]["emitted_tests"] == 2
    assert output_path.exists()
    assert "def test_main_001" in output_path.read_text(encoding="utf-8")


def test_concolic_cli_refuses_to_overwrite_the_target(tmp_path, capsys):
    target = tmp_path / "target.py"
    source = "def main(value):\n    return value\n"
    target.write_text(source, encoding="utf-8")
    args = _Args()
    args.input_path = str(target)
    args.emit_pytest = str(target)

    assert concolic.run_concolic(args) == 2
    assert target.read_text(encoding="utf-8") == source
    assert "cannot overwrite" in capsys.readouterr().err


def test_concolic_cli_scans_project_and_writes_json(tmp_path, capsys):
    target = tmp_path / "target.py"
    target.write_text(
        "def classify(value: int):\n" "    return value > 0\n",
        encoding="utf-8",
    )
    report = tmp_path / "report.json"
    args = _Args()
    args.input_path = str(tmp_path)
    args.scan_project = True
    args.input_complexity = 0
    args.function_timeout = 10
    args.json_output = str(report)

    assert concolic.run_concolic(args) == 0
    output = json.loads(capsys.readouterr().out)
    assert output["summary"]["statuses"] == {"supported": 1}
    assert (
        json.loads(report.read_text(encoding="utf-8"))["functions"][0]["target"]["qualname"]
        == "classify"
    )
