"""Tests for the optional mypy stubtest integration."""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest

from pyflow.cli import stubtest


def test_stubtest_requires_mypy(monkeypatch, capsys) -> None:
    monkeypatch.setattr(stubtest, "_stubtest_executable", lambda: None)

    assert stubtest.run_stubtest(["module"]) == 2
    assert "pyflow-analysis[stubs]" in capsys.readouterr().err


def test_stubtest_checks_a_matching_stub(tmp_path: Path) -> None:
    if stubtest._stubtest_executable() is None:
        pytest.skip("mypy stubtest is not installed")
    (tmp_path / "mod.py").write_text("def add(a: int, b: int) -> int:\n    return a + b\n")
    (tmp_path / "mod.pyi").write_text("def add(a: int, b: int) -> int: ...\n")
    env = dict(os.environ)
    env["PYTHONPATH"] = str(tmp_path)

    completed = subprocess.run(
        [sys.executable, "-m", "pyflow.cli.main", "stubtest", "mod"],
        cwd=tmp_path,
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )

    assert completed.returncode == 0, completed.stdout + completed.stderr
