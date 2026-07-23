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


def iter_import_nodes_in_scope(nodes: Iterable[ast.AST]) -> Iterator[ast.AST]:
    """Yield imports executed in a scope without entering nested definitions."""

    for node in nodes:
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            yield node
            continue
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            continue
        if isinstance(
            node, (ast.If, ast.For, ast.AsyncFor, ast.While, ast.With, ast.AsyncWith)
        ):
            yield from iter_import_nodes_in_scope(getattr(node, "body", ()) or ())
            yield from iter_import_nodes_in_scope(getattr(node, "orelse", ()) or ())
            continue
        if isinstance(node, (ast.Try, getattr(ast, "TryStar", ast.Try))):
            yield from iter_import_nodes_in_scope(getattr(node, "body", ()) or ())
            for handler in getattr(node, "handlers", ()) or ():
                yield from iter_import_nodes_in_scope(
                    getattr(handler, "body", ()) or ()
                )
            yield from iter_import_nodes_in_scope(getattr(node, "orelse", ()) or ())
            yield from iter_import_nodes_in_scope(getattr(node, "finalbody", ()) or ())
            continue
        if hasattr(ast, "Match") and isinstance(node, ast.Match):
            for case in getattr(node, "cases", ()) or ():
                yield from iter_import_nodes_in_scope(getattr(case, "body", ()) or ())


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


def discover_module_exports(source: str) -> list[str]:
    """Approximate the names exported by ``from module import *``."""

    try:
        tree = ast.parse(source)
    except SyntaxError:
        return []

    explicit_all: Optional[list[str]] = None
    discovered: set[str] = set()
    for node in getattr(tree, "body", ()) or ():
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            if not node.name.startswith("_"):
                discovered.add(node.name)
            continue
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if not isinstance(target, ast.Name):
                    continue
                if target.id == "__all__":
                    explicit_all = literal_string_list(node.value)
                elif not target.id.startswith("_"):
                    discovered.add(target.id)
            continue
        if isinstance(node, ast.Import):
            for alias in node.names:
                local = alias.asname or alias.name.split(".")[-1]
                if not local.startswith("_"):
                    discovered.add(local)
            continue
        if isinstance(node, ast.ImportFrom):
            for alias in node.names:
                if alias.name == "*":
                    continue
                local = alias.asname or alias.name
                if not local.startswith("_"):
                    discovered.add(local)

    return explicit_all if explicit_all is not None else sorted(discovered)


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
