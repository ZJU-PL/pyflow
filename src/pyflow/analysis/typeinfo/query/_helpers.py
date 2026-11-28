"""Stateless AST, annotation, and stdlib helpers shared by TypeInfoService mixins."""

from __future__ import annotations

import ast
import importlib
import sys
import sysconfig
from functools import lru_cache
from pathlib import Path
from typing import Iterator

from pyflow.analysis.typeinfo.core.typesystem import Variance

_UNSET = object()

_SELF_ANNOTATIONS = frozenset({"Self", "typing.Self", "typing_extensions.Self"})

_TYPE_CHECKING_NAMES = frozenset(
    {"TYPE_CHECKING", "typing.TYPE_CHECKING", "typing_extensions.TYPE_CHECKING"}
)


@lru_cache(maxsize=1)
def _stdlib_root() -> Path | None:
    try:
        stdlib = sysconfig.get_paths().get("stdlib")
        return Path(stdlib).resolve() if stdlib else None
    except (KeyError, OSError, ValueError):
        return None


def _module_statements(tree: ast.Module | list[ast.stmt]) -> list[ast.stmt]:
    """Flatten ``if TYPE_CHECKING:`` blocks, which mypy always analyses."""
    from pyflow.language.environment import (
        AnalysisEnvironment,
        _collect_import_aliases,
        evaluate_static_condition,
    )

    statements = tree.body if isinstance(tree, ast.Module) else list(tree)
    aliases = _collect_import_aliases(statements)
    tc_env = AnalysisEnvironment.current(type_checking=True)
    rt_env = AnalysisEnvironment.current(type_checking=False)

    def _flatten(stmts: list[ast.stmt]) -> list[ast.stmt]:
        result: list[ast.stmt] = []
        for statement in stmts:
            result.append(statement)
            if isinstance(statement, ast.If):
                is_tc_true = (
                    evaluate_static_condition(statement.test, tc_env, aliases=aliases) is True
                    and evaluate_static_condition(statement.test, rt_env, aliases=aliases) is False
                )
                is_tc_false = (
                    evaluate_static_condition(statement.test, tc_env, aliases=aliases) is False
                    and evaluate_static_condition(statement.test, rt_env, aliases=aliases) is True
                )
                if is_tc_true:
                    result.extend(_flatten(statement.body))
                elif is_tc_false and statement.orelse:
                    result.extend(_flatten(statement.orelse))
        return result

    return _flatten(statements)


def _stub_variance(declaration) -> Variance:
    if declaration.covariant:
        return Variance.COVARIANT
    if declaration.contravariant:
        return Variance.CONTRAVARIANT
    return Variance.INVARIANT


def _top_level_package_dir(path: Path) -> Path | None:
    """Return the top-level package directory of an installed module."""
    try:
        parts = path.resolve().parts
    except OSError:
        return None
    for index, part in enumerate(parts):
        if part in {"site-packages", "dist-packages"}:
            if index + 1 < len(parts):
                return Path(*parts[: index + 2])
            return None
    return None


def _iter_arguments(args: ast.arguments) -> Iterator[ast.arg]:
    yield from args.posonlyargs
    yield from args.args
    yield from args.kwonlyargs


def _annotation_to_str(node: ast.expr) -> str:
    return ast.unparse(node)


def _expr_name(node: ast.expr) -> str | None:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        base = _expr_name(node.value)
        return f"{base}.{node.attr}" if base else node.attr
    return None


def _split_annotation_arguments(annotation: str) -> list[str]:
    """Split top-level comma-separated annotation arguments."""
    parts: list[str] = []
    depth = 0
    start = 0
    for index, character in enumerate(annotation):
        if character in "[(":
            depth += 1
        elif character in "])":
            depth = max(0, depth - 1)
        elif character == "," and depth == 0:
            parts.append(annotation[start:index])
            start = index + 1
    tail = annotation[start:].strip()
    if tail:
        parts.append(tail)
    return parts


def _strip_annotation_wrapper(annotation: str, wrapper: str) -> str | None:
    """Return ``T`` from ``Wrapper[T]`` or ``None`` when unwrapped is absent."""
    head, _, rest = annotation.partition("[")
    if head.rsplit(".", 1)[-1] != wrapper or not rest:
        return None
    return rest[:-1].strip() or None


def _runtime_stdlib_class(full_name: str) -> type | None:
    """Return the real stdlib class named by *full_name*, when safely available.

    Typeshed describes runtime classes.  Using the actual class object keeps
    stub-derived instances interchangeable with PyFlow's builtin/stdlib models.
    Third-party modules are left synthetic so analysis never imports arbitrary
    project code.
    """
    module_name, _, class_name = full_name.rpartition(".")
    if not module_name or not class_name:
        return None
    if module_name.split(".", 1)[0] not in sys.stdlib_module_names:
        return None
    try:
        module = importlib.import_module(module_name)
    except Exception:
        return None
    candidate = vars(module).get(class_name)
    if not isinstance(candidate, type):
        return None
    runtime_aliases = {
        "TracebackType": "traceback",
        "ModuleType": "module",
    }
    expected_name = runtime_aliases.get(class_name, class_name)
    if candidate.__name__ != expected_name or candidate.__qualname__ != expected_name:
        return None
    return candidate
