"""Consistent path exclusions for CLI source discovery."""

from __future__ import annotations

import fnmatch
from pathlib import Path
from typing import Iterable

SECURITY_DEFAULT_EXCLUDES = (
    ".*",
    "__pycache__",
    "venv",
    "env",
    "node_modules",
    "build",
    "dist",
    "test",
    "tests",
)


def exclusion_patterns(values: str | Iterable[str] | None) -> tuple[str, ...]:
    if isinstance(values, str):
        values = (values,)
    return tuple(
        part.strip().rstrip("/")
        for value in values or ()
        for part in value.split(",")
        if part.strip().rstrip("/")
    )


def path_is_excluded(path: str | Path, patterns: Iterable[str], root: str | Path) -> bool:
    """Match basenames, directory components, globs, and rooted paths."""
    absolute = Path(path).absolute()
    try:
        relative = absolute.relative_to(Path(root).absolute()).as_posix()
    except ValueError:
        relative = Path(path).as_posix()
    for pattern in patterns:
        normalized = pattern.removeprefix("./").rstrip("/")
        if Path(normalized).is_absolute():
            target = Path(normalized).as_posix()
            if fnmatch.fnmatch(absolute.as_posix(), target) or absolute.as_posix().startswith(
                target + "/"
            ):
                return True
        elif "/" not in normalized:
            if any(fnmatch.fnmatch(part, normalized) for part in Path(relative).parts):
                return True
        elif fnmatch.fnmatch(relative, normalized) or relative.startswith(normalized + "/"):
            return True
    return False


def discover_python_files(
    root: Path, *, recursive: bool, exclude: Iterable[str] = ()
) -> list[Path]:
    import os

    files = []
    for current, directories, names in os.walk(root):
        directories[:] = (
            sorted(
                name
                for name in directories
                if not path_is_excluded(Path(current, name), exclude, root)
            )
            if recursive
            else []
        )
        files.extend(
            Path(current, name)
            for name in sorted(names)
            if name.endswith(".py") and not path_is_excluded(Path(current, name), exclude, root)
        )
    return files
