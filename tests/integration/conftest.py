"""Shared fixtures for integration tests."""

from __future__ import annotations

import textwrap
from pathlib import Path

import pytest


@pytest.fixture
def sample_file_with_issue(tmp_path: Path) -> Path:
    """A temporary Python file that triggers a known security finding (B105)."""
    path = tmp_path / "sample.py"
    path.write_text(
        textwrap.dedent("""
            password = "secret"
        """).lstrip(),
        encoding="utf-8",
    )
    return path


@pytest.fixture
def sample_file_clean(tmp_path: Path) -> Path:
    """A temporary Python file with no security issues."""
    path = tmp_path / "clean.py"
    path.write_text(
        textwrap.dedent("""
            x = 1
            print(x)
        """).lstrip(),
        encoding="utf-8",
    )
    return path
