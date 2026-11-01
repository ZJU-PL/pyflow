"""Type diagnostics respect source-level ``# type: ignore`` comments."""

from __future__ import annotations

from pathlib import Path

from pyflow.lsp.document_analysis import document_diagnostics
from pyflow.lsp.workspace import SourceIndex


def _diagnostics(tmp_path: Path, source: str) -> list[dict]:
    path = tmp_path / "app.py"
    index = SourceIndex({str(path): source}, (tmp_path,))
    return document_diagnostics(index, path.as_uri())


def test_type_ignore_suppresses_annotation_mismatch(tmp_path: Path) -> None:
    source = "def f() -> str:\n    return 1  # type: ignore\n"
    assert not [
        item for item in _diagnostics(tmp_path, source) if item["code"] == "annotation-mismatch"
    ]


def test_annotation_mismatch_still_reported_without_ignore(tmp_path: Path) -> None:
    source = "def f() -> str:\n    return 1\n"
    assert any(item["code"] == "annotation-mismatch" for item in _diagnostics(tmp_path, source))
