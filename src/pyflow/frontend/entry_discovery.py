"""Shared application entry-file discovery for project-oriented analyses."""

from __future__ import annotations

import ast
from pathlib import Path


KNOWN_ENTRY_NAMES = ("main.py", "app.py", "cli.py", "run.py", "launch.py")


def _module_to_path(module: str, project_root: Path) -> Path | None:
    parts = module.split(".")
    relative_module = Path(*parts)
    for base in (project_root, project_root / "src"):
        module_file = base / relative_module.with_suffix(".py")
        if module_file.is_file():
            return module_file.relative_to(project_root)
        package_init = base / relative_module / "__init__.py"
        if package_init.is_file():
            return package_init.relative_to(project_root)
    return None


def _entry_from_pyproject(project_root: Path) -> Path | None:
    pyproject = project_root / "pyproject.toml"
    if not pyproject.is_file():
        return None

    try:
        import tomllib
    except ImportError:  # pragma: no cover - Python 3.10 compatibility
        try:
            import tomli as tomllib  # type: ignore[no-redef]
        except ImportError:
            return None

    try:
        with pyproject.open("rb") as handle:
            data = tomllib.load(handle)
    except (OSError, ValueError):
        return None

    scripts = data.get("project", {}).get("scripts", {})
    if not scripts:
        scripts = data.get("tool", {}).get("poetry", {}).get("scripts", {})

    for reference in scripts.values():
        if not isinstance(reference, str):
            continue
        module = reference.split(":", 1)[0].strip()
        entry = _module_to_path(module, project_root)
        if entry is not None:
            return entry
    return None


def _entry_from_setup_py(project_root: Path) -> Path | None:
    setup_py = project_root / "setup.py"
    if not setup_py.is_file():
        return None

    try:
        tree = ast.parse(setup_py.read_text(encoding="utf-8"))
    except (OSError, SyntaxError):
        return None

    for node in ast.walk(tree):
        if not isinstance(node, ast.Call) or getattr(node.func, "id", None) != "setup":
            continue
        for keyword in node.keywords:
            if keyword.arg != "entry_points" or not isinstance(keyword.value, ast.Dict):
                continue
            for key, value in zip(keyword.value.keys, keyword.value.values):
                if not (
                    isinstance(key, ast.Constant)
                    and key.value == "console_scripts"
                    and isinstance(value, ast.List)
                ):
                    continue
                for element in value.elts:
                    if not (
                        isinstance(element, ast.Constant)
                        and isinstance(element.value, str)
                    ):
                        continue
                    module = element.value.split(":", 1)[0]
                    module = module.split("=", 1)[-1].strip()
                    entry = _module_to_path(module, project_root)
                    if entry is not None:
                        return entry
    return None


def detect_entry_file(project_root: str | Path) -> Path | None:
    """Return a likely entry file relative to *project_root*, if one is found."""
    root = Path(project_root)

    for detector in (_entry_from_pyproject, _entry_from_setup_py):
        entry = detector(root)
        if entry is not None:
            return entry

    for child in sorted(root.iterdir()):
        if not child.is_dir() or child.name.startswith(".") or child.name == "tests":
            continue
        main_py = child / "__main__.py"
        if main_py.is_file():
            return main_py.relative_to(root)

    for name in KNOWN_ENTRY_NAMES:
        entry = root / name
        if entry.is_file():
            return Path(name)

    return None


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


__all__ = ["KNOWN_ENTRY_NAMES", "detect_entry_file", "resolve_entry_file"]
