"""
Integration test: Analyzer attaches a hybrid concolic+symbolic replay witness.

This ensures that when the analyzer finds a BUG and DSE produces a concrete repro,
we also run a selective concolic trace and replay it symbolically with an oracle.
"""

from __future__ import annotations

from pathlib import Path

from a3_python.analyzer import Analyzer


def test_analyzer_attaches_hybrid_witness_on_realized_bug(tmp_path: Path):
    prog = tmp_path / "prog.py"
    prog.write_text("x = 1 / 0\n")

    analyzer = Analyzer(verbose=False, max_paths=50, max_depth=200)
    result = analyzer.analyze_file(prog)

    assert result.verdict == "BUG"
    assert result.counterexample is not None
    assert "hybrid_witness" in result.counterexample

    hybrid = result.counterexample["hybrid_witness"]
    assert hybrid["concolic_exception_type"] == "ZeroDivisionError"
    assert hybrid["replay_paths"] >= 1

