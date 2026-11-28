"""Pure helpers for Python module and import discovery.

This module deliberately owns no resolver state.  Keeping these operations
pure prevents the program extractor, dependency resolver, and project context
from growing subtly different interpretations of Python import syntax.
"""

from __future__ import annotations

import ast
import os
from collections.abc import Callable, Iterable, Iterator, Mapping
from typing import Optional


def infer_analysis_root(paths: Iterable[str]) -> Optional[str]:
    """Infer the common import root for a collection of source paths."""

    resolved_roots: list[str] = []
    for path in paths:
        if not path or path.startswith("<"):
            continue

        absolute = os.path.realpath(path)
        current = absolute if os.path.isdir(absolute) else os.path.dirname(absolute)
        if not current:
            continue

        while os.path.isfile(os.path.join(current, "__init__.py")):
            parent = os.path.dirname(current)
            if not parent or parent == current:
                break
            current = parent
        resolved_roots.append(current)

    if not resolved_roots:
        return None
    try:
        return os.path.commonpath(resolved_roots)
    except ValueError:
        return None


def base_name_from_expr(node: ast.AST) -> Optional[str]:
    """Return a dotted base/decorator name from a simple AST expression."""

    if isinstance(node, ast.Subscript):
        return base_name_from_expr(node.value)
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        parts: list[str] = []
        current: ast.AST = node
        while isinstance(current, ast.Attribute):
            parts.append(current.attr)
            current = current.value
        if isinstance(current, ast.Name):
            parts.append(current.id)
            return ".".join(reversed(parts))
    return None


def iter_import_nodes_in_scope(
    nodes: Iterable[ast.AST],
    *,
    environment=None,
) -> Iterator[ast.AST]:
    """Yield imports executed in a scope without entering nested definitions.

    Uses :class:`AnalysisEnvironment` with ``type_checking=False`` by default
    so runtime-only imports (and ``if not TYPE_CHECKING:`` branches) are
    followed while ``if TYPE_CHECKING:`` blocks are excluded.
    """
    from pyflow.language.environment import AnalysisEnvironment, iter_active_imports

    env = (
        environment if environment is not None else AnalysisEnvironment.current(type_checking=False)
    )
    yield from iter_active_imports(nodes, env, include_nested=False)


def literal_string_list(node: ast.AST) -> Optional[list[str]]:
    """Read a statically declared list, tuple, or set of strings."""

    if not isinstance(node, (ast.List, ast.Tuple, ast.Set)):
        return None
    values: list[str] = []
    for element in node.elts:
        if not isinstance(element, ast.Constant) or not isinstance(element.value, str):
            return None
        values.append(element.value)
    return values


def discover_module_exports(source: str, *, module_name: str = "") -> list[str]:
    """Approximate the names exported by ``from module import *``."""
    from pyflow.language.modules.module_graph import extract_module_export_table
    from pyflow.language.modules.workspace import parse_source_cached

    try:
        tree = parse_source_cached(source, filename=f"<{module_name or 'module'}>")
    except SyntaxError:
        return []

    table = extract_module_export_table(module_name, tree)
    if table.explicit_all is not None:
        return list(table.explicit_all)
    return sorted(table.public_names())


def build_module_source_map(
    source_files: Mapping[str, str],
    module_name_from_path: Callable[[str], str],
) -> dict[str, str]:
    """Build a module-name to source mapping for in-memory files."""

    mapping: dict[str, str] = {}
    for filename, source in source_files.items():
        module = module_name_from_path(filename)
        mapping[module] = source
        if module.endswith(".__init__"):
            mapping[module[: -len(".__init__")]] = source
    return mapping


__all__ = [
    "base_name_from_expr",
    "build_module_source_map",
    "discover_module_exports",
    "infer_analysis_root",
    "iter_import_nodes_in_scope",
    "literal_string_list",
]
