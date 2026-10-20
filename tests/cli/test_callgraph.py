from __future__ import annotations

import argparse
from pathlib import Path
from types import SimpleNamespace

import pyflow.cli.callgraph as callgraph_cli


def parse_callgraph_args(*arguments):
    parser = argparse.ArgumentParser()
    callgraph_cli.add_callgraph_parser(parser.add_subparsers())
    return parser.parse_args(["callgraph", *map(str, arguments)])


def test_callgraph_rejects_constraint_only_flags_for_simple_algorithm(
    monkeypatch, tmp_path, capsys
):
    sample = tmp_path / "sample.py"
    sample.write_text("def f():\n    return 1\n", encoding="utf-8")

    monkeypatch.setattr(
        callgraph_cli,
        "analyze_file_ast",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            AssertionError("simple analyzer should not run")
        ),
    )

    args = SimpleNamespace(
        algorithm="simple",
        verbose=False,
        context_sensitive=True,
        context_depth=3,
        fixpoint_max_iterations=5,
        no_fixpoint_warning=True,
        allocation_site_sensitive_instances=True,
        as_graph_output=tmp_path / "graph.json",
        output=None,
    )

    exit_code = callgraph_cli.run_callgraph(Path(sample), args)

    assert exit_code == 1
    assert "only supported with --algorithm constraint" in capsys.readouterr().err


def test_callgraph_reports_ambiguous_detected_entries(tmp_path, capsys):
    package = tmp_path / "src" / "demo"
    package.mkdir(parents=True)
    for name in ("client", "server"):
        (package / f"{name}.py").write_text("def main(): pass\n", encoding="utf-8")
    (tmp_path / "pyproject.toml").write_text(
        """[project]
name = "demo"

[project.scripts]
client = "demo.client:main"
server = "demo.server:main"
""",
        encoding="utf-8",
    )
    args = SimpleNamespace(entry=None, verbose=False, dry_run=True)

    exit_code = callgraph_cli.run_callgraph(tmp_path, args)

    error = capsys.readouterr().err
    assert exit_code == 1
    assert "Multiple entry points detected" in error
    assert "src/demo/client.py [project.scripts] (command: client)" in error
    assert "src/demo/server.py [project.scripts] (command: server)" in error
    assert "Use --entry to select one" in error


def test_constraint_project_entry_defaults_to_reachable_scopes(monkeypatch, tmp_path, capsys):
    sample = tmp_path / "main.py"
    sample.write_text("def main():\n    return 1\n", encoding="utf-8")
    captured = []

    def fake_analyze(_path, **kwargs):
        captured.append(kwargs)
        return "graph"

    monkeypatch.setattr(callgraph_cli, "analyze_file_constraint", fake_analyze)
    args = SimpleNamespace(
        algorithm="constraint",
        verbose=False,
        context_sensitive=False,
        context_depth=1,
        fixpoint_max_iterations=None,
        no_fixpoint_warning=False,
        allocation_site_sensitive_instances=False,
        all_scopes=False,
        skip_stdlib=True,
        as_graph_output=None,
        output=None,
    )

    assert callgraph_cli._analyze_file(sample, args, project_entry=True) == 0
    assert captured[-1]["analyze_reachable_only"] is True
    assert captured[-1]["seed_entry_file_scopes"] is True
    capsys.readouterr()

    args.all_scopes = True
    assert callgraph_cli._analyze_file(sample, args, project_entry=True) == 0
    assert captured[-1]["analyze_reachable_only"] is False
    assert captured[-1]["seed_entry_file_scopes"] is False


def test_native_pycg_mir_cli_resolves_callback_without_external_pycg(tmp_path, monkeypatch, capsys):
    sample = tmp_path / "sample.py"
    sample.write_text(
        "def chosen():\n    pass\n" "def use(callback):\n    callback()\n" "use(chosen)\n",
        encoding="utf-8",
    )

    original = callgraph_cli.run_isolated_callgraph
    def native_worker(request, **kwargs):
        assert request["algorithm"] == "pycg-mir"
        return original(request, **kwargs)

    monkeypatch.setattr(callgraph_cli, "run_isolated_callgraph", native_worker)
    args = parse_callgraph_args(sample, "--algorithm", "pycg-mir")

    assert callgraph_cli.run_callgraph(sample, args) == 0
    output = capsys.readouterr().out
    assert "sample.use -> sample.chosen" in output


def test_native_pycg_mir_cli_passes_project_root(tmp_path, monkeypatch, capsys):
    entry = tmp_path / "src" / "app.py"
    entry.parent.mkdir()
    entry.write_text("def run(): pass\nrun()\n", encoding="utf-8")
    captured = {}

    def analyze(request, *, timeout):
        captured.update(filepath=request["filepath"], verbose=request["verbose"], project_root=request["project_root"])
        assert timeout == 30
        return "native graph"

    monkeypatch.setattr(callgraph_cli, "run_isolated_callgraph", analyze)
    args = parse_callgraph_args(tmp_path, "--entry", "src/app.py", "--algorithm", "pycg-mir")
    assert callgraph_cli.run_callgraph(tmp_path, args) == 0
    assert captured == {
        "filepath": str(entry),
        "verbose": False,
        "project_root": str(tmp_path),
    }
    assert "native graph" in capsys.readouterr().out


def test_native_pycg_mir_cli_reports_invalid_source(tmp_path, capsys):
    sample = tmp_path / "broken.py"
    sample.write_text("def broken(: pass\n", encoding="utf-8")
    output = tmp_path / "graph.txt"
    args = parse_callgraph_args(sample, "--algorithm", "pycg-mir", "-o", output)

    assert callgraph_cli.run_callgraph(sample, args) == 1
    assert "Error:" in capsys.readouterr().err
    assert not output.exists()


def test_native_pycg_mir_cli_rejects_context_sensitive_flag(tmp_path, capsys):
    sample = tmp_path / "sample.py"
    sample.write_text("pass\n", encoding="utf-8")
    args = parse_callgraph_args(sample, "--algorithm", "pycg-mir", "--context-sensitive")

    assert callgraph_cli.run_callgraph(sample, args) == 1
    assert "--context-sensitive" in capsys.readouterr().err


def test_native_pycg_mir_handles_unmodeled_stdlib_with_partial_diagnostic(tmp_path, capsys):
    sample = tmp_path / "sample.py"
    sample.write_text("import math\ndef f(): return math.sqrt(4)\nf()\n")
    args = parse_callgraph_args(sample, "--algorithm", "pycg-mir", "--format", "json")
    assert callgraph_cli.run_callgraph(sample, args) == 0
    captured = capsys.readouterr()
    import json

    assert "sample.f" in json.loads(captured.out)["sample"]
    assert "MIR call graph is partial" in captured.err
    args = parse_callgraph_args(sample, "--algorithm", "pycg-mir", "--mir-import-policy", "strict")
    assert callgraph_cli.run_callgraph(sample, args) == 1


def test_mir_import_policy_rejects_other_algorithms(tmp_path, capsys):
    sample = tmp_path / "sample.py"
    sample.write_text("pass\n")
    args = parse_callgraph_args(
        sample, "--algorithm", "constraint", "--mir-import-policy", "strict"
    )
    assert callgraph_cli.run_callgraph(sample, args) == 1
    assert "only supported with --algorithm pycg-mir" in capsys.readouterr().err
