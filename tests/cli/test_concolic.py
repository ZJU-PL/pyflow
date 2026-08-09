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
            "--max-solver-calls",
            "20",
            "--max-pending-states",
            "30",
        ]
    )

    assert args.search_strategy == "fifo"
    assert args.max_uninteresting_iterations == 7
    assert args.total_timeout == 10
    assert args.per_run_timeout == 2
    assert args.solver_timeout == 1
    assert args.max_solver_calls == 20
    assert args.max_pending_states == 30


def test_concolic_cli_emits_generated_inputs(tmp_path, capsys):
    target = tmp_path / "target.py"
    target.write_text(
        "def main(value):\n"
        "    if value == 3:\n"
        "        return 1\n"
        "    return 0\n",
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
        "def main(value):\n"
        '    """post: __return__ > 0"""\n'
        "    return value\n",
        encoding="utf-8",
    )
    args = _Args()
    args.input_path = str(target)
    args.check_contracts = True

    assert concolic.run_concolic(args) == 0
    output = json.loads(capsys.readouterr().out)
    assert output["counterexamples"][0]["clause"] == "__return__ > 0"
