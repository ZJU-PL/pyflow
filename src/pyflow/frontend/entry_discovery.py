"""Shared application entry-file discovery for project-oriented analyses."""

from __future__ import annotations

import ast
import importlib
from dataclasses import dataclass
from pathlib import Path
from typing import Any, cast


KNOWN_ENTRY_NAMES = ("main.py", "app.py", "manage.py", "cli.py", "run.py", "launch.py")
IGNORED_PACKAGE_ROOTS = {
    "test",
    "tests",
    "example",
    "examples",
    "benchmark",
    "benchmarks",
}


@dataclass(frozen=True)
class EntryCandidate:
    """An executable entry file together with the evidence that identified it."""

    path: Path
    source: str
    command: str | None = None


def _read_pyproject(project_root: Path) -> dict[str, Any]:
    pyproject = project_root / "pyproject.toml"
    if not pyproject.is_file():
        return {}

    try:
        toml_reader = importlib.import_module("tomllib")
    except ImportError:  # pragma: no cover - Python 3.10 compatibility
        try:
            toml_reader = importlib.import_module("tomli")
        except ImportError:
            return {}

    try:
        with pyproject.open("rb") as handle:
            return cast(dict[str, Any], toml_reader.load(handle))
    except (OSError, ValueError):
        return {}


def _is_application_package_root(relative: Path) -> bool:
    return not any(part.lower() in IGNORED_PACKAGE_ROOTS for part in relative.parts)


def _module_search_bases(project_root: Path, data: dict[str, Any]) -> list[Path]:
    relative_bases = [Path(), Path("src"), Path("lib")]
    setuptools = data.get("tool", {}).get("setuptools", {})

    package_dir = setuptools.get("package-dir", {})
    if isinstance(package_dir, dict):
        for value in package_dir.values():
            if isinstance(value, str):
                relative_bases.append(Path(value))

    find_where = setuptools.get("packages", {}).get("find", {}).get("where", [])
    if isinstance(find_where, str):
        find_where = [find_where]
    if isinstance(find_where, list):
        relative_bases.extend(
            Path(value) for value in find_where if isinstance(value, str)
        )

    bases: list[Path] = []
    for relative in relative_bases:
        if not _is_application_package_root(relative):
            continue
        base = project_root / relative
        if base.is_dir() and base not in bases:
            bases.append(base)
    return bases


def _module_to_path(module: str, project_root: Path, bases: list[Path]) -> Path | None:
    parts = module.split(".")
    relative_module = Path(*parts)
    for base in bases:
        module_file = base / relative_module.with_suffix(".py")
        if module_file.is_file():
            return module_file.relative_to(project_root)
        package_init = base / relative_module / "__init__.py"
        if package_init.is_file():
            return package_init.relative_to(project_root)
    return None


def _entries_from_pyproject(
    project_root: Path, data: dict[str, Any], bases: list[Path]
) -> list[EntryCandidate]:
    script_groups = [
        ("project.scripts", data.get("project", {}).get("scripts", {})),
        ("project.gui-scripts", data.get("project", {}).get("gui-scripts", {})),
    ]
    poetry_scripts = data.get("tool", {}).get("poetry", {}).get("scripts", {})
    if poetry_scripts:
        script_groups.append(("tool.poetry.scripts", poetry_scripts))

    candidates: list[EntryCandidate] = []
    for source, scripts in script_groups:
        if not isinstance(scripts, dict):
            continue
        for command, reference in scripts.items():
            if isinstance(reference, dict):
                reference = reference.get("callable")
            if not isinstance(command, str) or not isinstance(reference, str):
                continue
            module = reference.split(":", 1)[0].strip()
            entry = _module_to_path(module, project_root, bases)
            if entry is not None:
                candidates.append(EntryCandidate(entry, source, command))
    return candidates


def _entries_from_setup_py(
    project_root: Path, bases: list[Path]
) -> list[EntryCandidate]:
    setup_py = project_root / "setup.py"
    if not setup_py.is_file():
        return []

    try:
        tree = ast.parse(setup_py.read_text(encoding="utf-8", errors="replace"))
    except (OSError, SyntaxError):
        return []

    candidates: list[EntryCandidate] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        is_setup_call = (
            isinstance(node.func, ast.Name) and node.func.id == "setup"
        ) or (
            isinstance(node.func, ast.Attribute) and node.func.attr == "setup"
        )
        if not is_setup_call:
            continue
        for keyword in node.keywords:
            if keyword.arg != "entry_points" or not isinstance(keyword.value, ast.Dict):
                continue
            for key, value in zip(keyword.value.keys, keyword.value.values):
                if not (
                    isinstance(key, ast.Constant)
                    and key.value == "console_scripts"
                    and isinstance(value, (ast.List, ast.Tuple))
                ):
                    continue
                for element in value.elts:
                    if not (
                        isinstance(element, ast.Constant)
                        and isinstance(element.value, str)
                    ):
                        continue
                    declaration = element.value
                    command, separator, reference = declaration.partition("=")
                    if not separator:
                        continue
                    module = reference.split(":", 1)[0].strip()
                    entry = _module_to_path(module, project_root, bases)
                    if entry is not None:
                        candidates.append(
                            EntryCandidate(
                                entry, "setup.py console_scripts", command.strip()
                            )
                        )
    return candidates


def _deduplicate(candidates: list[EntryCandidate]) -> list[EntryCandidate]:
    unique: list[EntryCandidate] = []
    seen: set[tuple[Path, str | None]] = set()
    for candidate in candidates:
        key = (candidate.path, candidate.command)
        if key not in seen:
            seen.add(key)
            unique.append(candidate)
    return unique


def discover_entry_files(project_root: str | Path) -> list[EntryCandidate]:
    """Return candidates from the strongest evidence tier that is present."""
    root = Path(project_root)
    data = _read_pyproject(root)
    bases = _module_search_bases(root, data)

    metadata = _entries_from_pyproject(root, data, bases)
    metadata.extend(_entries_from_setup_py(root, bases))
    metadata = _deduplicate(metadata)
    if metadata:
        return metadata

    package_mains: list[EntryCandidate] = []
    for base in bases:
        for child in sorted(base.iterdir()):
            if (
                child.is_dir()
                and not child.name.startswith(".")
                and child.name.lower() not in IGNORED_PACKAGE_ROOTS
            ):
                main_py = child / "__main__.py"
                if main_py.is_file():
                    package_mains.append(
                        EntryCandidate(main_py.relative_to(root), "package __main__.py")
                    )

    package_mains = _deduplicate(package_mains)
    if package_mains:
        return package_mains

    return [
        EntryCandidate(Path(name), "root filename convention")
        for name in KNOWN_ENTRY_NAMES
        if (root / name).is_file()
    ]


def _unique_path(candidates: list[EntryCandidate]) -> Path | None:
    paths = list(dict.fromkeys(candidate.path for candidate in candidates))
    return paths[0] if len(paths) == 1 else None


def detect_entry_file(project_root: str | Path) -> Path | None:
    """Select an entry only when the strongest candidate tier is unambiguous."""
    return _unique_path(discover_entry_files(project_root))


def resolve_entry_file(
    project_root: str | Path,
    entry: str | Path | None = None,
) -> Path | None:
    """Resolve an explicit or detected entry to an absolute Python file path."""
    root = Path(project_root).resolve()
    selected = Path(entry) if entry is not None else detect_entry_file(root)
    if selected is None:
        return None
    resolved = (
        selected.resolve() if selected.is_absolute() else (root / selected).resolve()
    )
    try:
        resolved.relative_to(root)
    except ValueError as error:
        raise ValueError(
            f"Entry point '{selected}' is outside project root '{root}'."
        ) from error
    if not resolved.is_file():
        raise ValueError(f"Entry point '{selected}' not found in '{root}'.")
    if resolved.suffix != ".py":
        raise ValueError(f"Entry point '{selected}' is not a Python file.")
    return resolved


__all__ = [
    "EntryCandidate",
    "KNOWN_ENTRY_NAMES",
    "detect_entry_file",
    "discover_entry_files",
    "resolve_entry_file",
]
