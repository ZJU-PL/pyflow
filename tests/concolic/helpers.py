"""Shared fixtures for concolic executor tests."""

from pathlib import Path


def target_file(tmp_path: Path, source: str) -> Path:
    target = tmp_path / "target.py"
    target.write_text(source, encoding="utf-8")
    return target
