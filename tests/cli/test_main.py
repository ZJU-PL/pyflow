from __future__ import annotations

import importlib
from pathlib import Path
import subprocess
import sys

cli_main = importlib.import_module("pyflow.cli.main")


def test_console_entrypoint_freezes_heap_after_main(monkeypatch):
    calls = []
    monkeypatch.setattr(cli_main, "main", lambda: 7)
    monkeypatch.setattr(cli_main.gc, "freeze", lambda: calls.append("freeze"))

    assert cli_main.entrypoint() == 7
    assert calls == ["freeze"]


def test_main_lists_opt_passes_without_input(monkeypatch):
    called = []

    monkeypatch.setattr(cli_main, "list_optimization_passes", lambda: called.append(True))
    monkeypatch.setattr(cli_main.sys, "argv", ["pyflow", "optimize", "--list-opt-passes"])

    assert cli_main.main() == 0
    assert called == [True]


def test_main_dispatches_optimize(monkeypatch, tmp_path):
    sample = tmp_path / "sample.py"
    sample.write_text("def f():\n    return 1\n", encoding="utf-8")
    seen = {}

    def fake_run_analysis(input_path, args):
        seen["path"] = input_path
        seen["command"] = args.command

    monkeypatch.setattr(cli_main, "run_analysis", fake_run_analysis)
    monkeypatch.setattr(cli_main.sys, "argv", ["pyflow", "optimize", str(sample)])

    assert cli_main.main() == 0
    assert seen["path"] == Path(sample)
    assert seen["command"] == "optimize"


def test_main_dispatches_callgraph(monkeypatch, tmp_path):
    sample = tmp_path / "sample.py"
    sample.write_text("def f():\n    return 1\n", encoding="utf-8")
    seen = {}

    def fake_run_callgraph(input_path, args):
        seen["path"] = input_path
        seen["algorithm"] = args.algorithm
        return 7

    monkeypatch.setattr(cli_main.callgraph, "run_callgraph", fake_run_callgraph)
    monkeypatch.setattr(
        cli_main.sys,
        "argv",
        ["pyflow", "callgraph", str(sample), "--algorithm", "simple"],
    )

    assert cli_main.main() == 7
    assert seen["path"] == Path(sample)
    assert seen["algorithm"] == "simple"


def test_main_dispatches_concolic(monkeypatch, tmp_path):
    sample = tmp_path / "sample.py"
    sample.write_text("def main(value):\n    return value\n", encoding="utf-8")
    seen = {}

    def fake_run_concolic(args):
        seen["command"] = args.command
        seen["input_path"] = args.input_path
        return 4

    monkeypatch.setattr(cli_main, "run_concolic", fake_run_concolic)
    monkeypatch.setattr(cli_main.sys, "argv", ["pyflow", "concolic", str(sample)])

    assert cli_main.main() == 4
    assert seen == {"command": "concolic", "input_path": str(sample)}


def test_main_dispatches_supply_chain(monkeypatch, tmp_path):
    seen = {}

    def fake_run_supply_chain(args):
        seen["command"] = args.command
        seen["supply_chain_command"] = args.supply_chain_command
        seen["targets"] = args.targets
        return 3

    monkeypatch.setattr(cli_main, "run_supply_chain", fake_run_supply_chain)
    monkeypatch.setattr(cli_main.sys, "argv", ["pyflow", "supply-chain", "sbom", str(tmp_path)])

    assert cli_main.main() == 3
    assert seen["command"] == "supply-chain"
    assert seen["supply_chain_command"] == "sbom"
    assert seen["targets"] == [str(tmp_path)]


def test_main_returns_error_for_missing_input(monkeypatch, capsys):
    missing = "/tmp/definitely-missing-pyflow-file.py"
    monkeypatch.setattr(cli_main.sys, "argv", ["pyflow", "optimize", missing])

    assert cli_main.main() == 1
    assert str(Path(missing)) in capsys.readouterr().err


def test_query_lookup_errors_are_concise(monkeypatch, tmp_path, capsys):
    source = tmp_path / "app.py"
    source.write_text("def run():\n    pass\n")

    def fail(_args):
        raise ValueError("Function 'missing' not found. Available candidates: app.run")

    monkeypatch.setattr(cli_main, "run_query", fail)
    monkeypatch.setattr(
        cli_main.sys, "argv", ["pyflow", "query", str(source), "--get-cfg", "missing"]
    )
    assert cli_main.main() == 2
    error = capsys.readouterr().err
    assert "app.run" in error
    assert "Traceback" not in error


def test_alias_json_handles_a_closed_output_pipe(tmp_path):
    source = tmp_path / "many.py"
    source.write_text("\n".join(f"value_{index} = []" for index in range(300)))
    process = subprocess.Popen(
        [sys.executable, "-m", "pyflow.cli.main", "alias", str(source), "--json"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    try:
        assert process.stdout.read(32)
        process.stdout.close()
        error = process.stderr.read().decode()
        assert process.wait(timeout=30) == 0, error
        assert "BrokenPipeError" not in error
        assert "Traceback" not in error
    finally:
        process.stdout.close()
        process.stderr.close()
        if process.poll() is None:
            process.kill()
            process.wait()


def test_entrypoint_handles_shutdown_flush_broken_pipe(monkeypatch):
    from types import SimpleNamespace

    calls = []

    def flush():
        raise BrokenPipeError()

    monkeypatch.setattr(cli_main, "main", lambda: 0)
    monkeypatch.setattr(cli_main.sys, "stdout", SimpleNamespace(flush=flush, fileno=lambda: 1))
    monkeypatch.setattr(cli_main.os, "open", lambda *_: 23)
    monkeypatch.setattr(cli_main.os, "dup2", lambda source, target: calls.append((source, target)))
    monkeypatch.setattr(cli_main.os, "close", lambda descriptor: calls.append(descriptor))
    monkeypatch.setattr(cli_main.gc, "freeze", lambda: None)
    assert cli_main.entrypoint() == 0
    assert calls == [(23, 1), 23]
