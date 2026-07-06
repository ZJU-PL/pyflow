from __future__ import annotations

import textwrap
from pathlib import Path

from a3_python.analyzer import Analyzer


def test_no_concolic_skips_dse_and_lockstep(tmp_path: Path):
    prog = tmp_path / "prog.py"
    prog.write_text("x = 1 / 0\n")

    analyzer = Analyzer(max_paths=50, max_depth=50, enable_concolic=False, enable_lockstep_concolic=True)
    result = analyzer.analyze_file(prog)

    assert result.verdict == "BUG"
    assert result.counterexample is not None
    assert "dse_validated" not in result.counterexample
    assert "hybrid_witness" not in result.counterexample
    assert result.lockstep is None

