"""Read Python source using its declared encoding, including a UTF-8 BOM."""

from __future__ import annotations

from pathlib import Path
import tokenize


def read_python_source(path: str | Path) -> str:
    with tokenize.open(path) as stream:
        return stream.read()
