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
