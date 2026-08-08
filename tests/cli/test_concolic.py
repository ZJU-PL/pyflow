from __future__ import annotations

import json

from pyflow.cli import concolic


class _Args:
    entry = "main"
    inputs = "[0]"
    max_iterations = 10
    max_loop_iterations = 20
    json = True


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
