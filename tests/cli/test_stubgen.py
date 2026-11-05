"""Tests for the optional mypy stubgen integration."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

from pyflow.cli import stubgen


def test_stubgen_requires_mypy(monkeypatch, capsys) -> None:
    monkeypatch.setattr(stubgen, "_stubgen_executable", lambda: None)

    assert stubgen.run_stubgen(["module.py"]) == 2
    assert "pyflow-analysis[stubs]" in capsys.readouterr().err


def test_stubgen_generates_pyi(tmp_path: Path) -> None:
    if stubgen._stubgen_executable() is None:
        pytest.skip("mypy stubgen is not installed")
    module = tmp_path / "mod.py"
    module.write_text("def add(a: int, b: int) -> int:\n    return a + b\n")
    output = tmp_path / "out"

    completed = subprocess.run(
        [
            sys.executable,
            "-m",
            "pyflow.cli.main",
            "stubgen",
            "-o",
            str(output),
            str(module),
        ],
        capture_output=True,
        text=True,
        check=False,
    )

    assert completed.returncode == 0, completed.stderr
    stub = output / "mod.pyi"
    assert stub.is_file()
    assert "def add(a: int, b: int) -> int" in stub.read_text()
