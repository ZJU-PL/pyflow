from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import pyflow.cli.callgraph as callgraph_cli


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
