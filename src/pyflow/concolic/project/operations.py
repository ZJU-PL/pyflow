"""Static operation corpus for prioritizing concolic model coverage."""

from __future__ import annotations

import ast
from collections import Counter, defaultdict
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Any, Iterable

from ..core.modules import _SUMMARY_MODULES


class OperationSupport(str, Enum):
    """How an operation discovered in source is expected to be handled."""

    BUILTIN = "builtin"
    MODELLED = "modelled"
    LOCAL = "local"
    UNKNOWN = "unknown"


@dataclass(frozen=True)
class OperationUse:
    """One aggregated call operation in a source or stub corpus."""

    name: str
    support: OperationSupport
    count: int
    locations: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "support": self.support.value,
            "count": self.count,
            "locations": list(self.locations),
        }


@dataclass(frozen=True)
class OperationCatalog:
    """Frequency-ranked calls that can drive model implementation work."""

    root: Path
    operations: tuple[OperationUse, ...]

    @property
    def unknown(self) -> tuple[OperationUse, ...]:
        return tuple(
            operation
            for operation in self.operations
            if operation.support is OperationSupport.UNKNOWN
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "root": str(self.root),
            "summary": {
                "operations": len(self.operations),
                "calls": sum(operation.count for operation in self.operations),
                "unknown": len(self.unknown),
            },
            "operations": [operation.to_dict() for operation in self.operations],
        }


_BUILTINS = {
    "abs",
    "all",
    "any",
    "bool",
    "bytes",
    "dict",
    "enumerate",
    "float",
    "frozenset",
    "id",
    "int",
    "len",
    "list",
    "max",
    "min",
    "range",
    "reversed",
    "round",
    "set",
    "sorted",
    "str",
    "sum",
    "tuple",
    "zip",
}


def discover_operations(root: str | Path) -> OperationCatalog:
    """Build a call corpus without importing the analyzed project.

    Both ``.py`` and ``.pyi`` files are accepted, which lets a typeshed or
    third-party stub tree serve as a model-prioritization corpus.
    """

    corpus_root = Path(root).resolve()
    files = (corpus_root,) if corpus_root.is_file() else tuple(_source_files(corpus_root))
    counts: Counter[tuple[str, OperationSupport]] = Counter()
    locations: dict[tuple[str, OperationSupport], set[str]] = defaultdict(set)
    for path in files:
        try:
            tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        except (OSError, SyntaxError, UnicodeError):
            continue
        aliases = _import_aliases(tree)
        local_names = {
            statement.name
            for statement in tree.body
            if isinstance(statement, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))
        }
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            name = _resolved_name(node.func, aliases)
            if name is None:
                continue
            support = _support_for(name, local_names)
            key = (name, support)
            counts[key] += 1
            locations[key].add(f"{path}:{node.lineno}")
    operations = tuple(
        OperationUse(name, support, count, tuple(sorted(locations[(name, support)])))
        for (name, support), count in sorted(
            counts.items(), key=lambda item: (-item[1], item[0][0])
        )
    )
    return OperationCatalog(corpus_root, operations)


def _source_files(root: Path) -> Iterable[Path]:
    for suffix in ("*.py", "*.pyi"):
        for path in root.rglob(suffix):
            if not any(part in {".git", ".venv", "venv", "__pycache__"} for part in path.parts):
                yield path


def _import_aliases(tree: ast.Module) -> dict[str, str]:
    aliases: dict[str, str] = {}
    for statement in tree.body:
        if isinstance(statement, ast.Import):
            for alias in statement.names:
                aliases[alias.asname or alias.name.split(".")[0]] = alias.name
        elif isinstance(statement, ast.ImportFrom) and statement.module:
            for alias in statement.names:
                aliases[alias.asname or alias.name] = f"{statement.module}.{alias.name}"
    return aliases


def _resolved_name(node: ast.expr, aliases: dict[str, str]) -> str | None:
    if isinstance(node, ast.Name):
        return aliases.get(node.id, node.id)
    if isinstance(node, ast.Attribute):
        prefix = _resolved_name(node.value, aliases)
        return f"{prefix}.{node.attr}" if prefix else node.attr
    return None


def _support_for(name: str, local_names: set[str]) -> OperationSupport:
    if name in _BUILTINS:
        return OperationSupport.BUILTIN
    if name in local_names:
        return OperationSupport.LOCAL
    if any(name == module or name.startswith(f"{module}.") for module in _SUMMARY_MODULES):
        return OperationSupport.MODELLED
    return OperationSupport.UNKNOWN
