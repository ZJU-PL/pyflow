"""Project-level configuration for static type inference.

Reads ``[typeinfo]`` from ``pyflow.toml`` or ``[tool.pyflow.typeinfo]`` from
``pyproject.toml`` in the analysed project root.  The settings mirror the
corresponding :class:`InferenceOptions` fields so a repository can pin the
diagnostic policy the same way ``mypy.ini`` pins mypy's error codes.
"""

from __future__ import annotations

import importlib
from dataclasses import replace
from pathlib import Path

from pyflow.analysis.typeinfo.inference.engine import InferenceOptions

_SETTING_KEYS = frozenset(
    {
        "strict_annotations",
        "check_member_access",
        "check_overrides",
        "disabled_diagnostics",
        "diagnostic_severity",
        "max_iterations",
        "max_loop_iterations",
        "max_union_size",
        "max_specializations_per_function",
    }
)


def _toml_reader():
    for name in ("tomllib", "tomli"):
        try:
            return importlib.import_module(name)
        except ImportError:
            continue
    return None


def _read_table(path: Path, *keys: str) -> dict | None:
    reader = _toml_reader()
    if reader is None or not path.is_file():
        return None
    try:
        with path.open("rb") as handle:
            data = reader.load(handle)
    except (OSError, ValueError):
        return None
    current = data
    for key in keys:
        if not isinstance(current, dict):
            return None
        current = current.get(key)
    return current if isinstance(current, dict) else None


def _coerce(name: str, value: object) -> object | None:
    if name in {"strict_annotations", "check_member_access", "check_overrides"}:
        return bool(value) if isinstance(value, bool) else None
    if name in {
        "max_iterations",
        "max_loop_iterations",
        "max_union_size",
        "max_specializations_per_function",
    }:
        return int(value) if isinstance(value, int) and value > 0 else None
    if name == "disabled_diagnostics":
        if isinstance(value, list) and all(isinstance(item, str) for item in value):
            return frozenset(value)
        return None
    if name == "diagnostic_severity":
        if isinstance(value, dict) and all(
            isinstance(key, str) and isinstance(item, str) for key, item in value.items()
        ):
            return dict(value)
        return None
    return None


def load_project_settings(project_root: str | Path | None) -> dict[str, object]:
    """Return the raw validated ``[typeinfo]`` settings for a project root."""
    if project_root is None:
        return {}
    root = Path(project_root)
    table = _read_table(root / "pyflow.toml", "typeinfo")
    if table is None:
        table = _read_table(root / "pyproject.toml", "tool", "pyflow", "typeinfo")
    if table is None:
        return {}
    settings: dict[str, object] = {}
    for name, value in table.items():
        if name not in _SETTING_KEYS:
            continue
        coerced = _coerce(name, value)
        if coerced is not None:
            settings[name] = coerced
    return settings


def load_inference_options(
    project_root: str | Path | None,
    base: InferenceOptions | None = None,
) -> InferenceOptions:
    """Apply project settings on top of *base* (or the defaults)."""
    options = base or InferenceOptions()
    settings = load_project_settings(project_root)
    if not settings:
        return options
    return replace(options, **settings)
