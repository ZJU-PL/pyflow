"""Target analysis environment and static conditional branch evaluation.

Provides a shared, IR-independent model of the target Python runtime
(``python_version``, ``platform``, and ``TYPE_CHECKING`` mode) together with a
conservative 3-valued static condition evaluator.  When a condition cannot be
proven statically true or false, the evaluator returns ``None`` so callers
conservatively analyze both branches without sacrificing recall.
"""

from __future__ import annotations

import ast
import hashlib
import operator
import sys
from collections.abc import Iterable, Iterator, Mapping
from dataclasses import dataclass, replace
from typing import Any

_TYPE_CHECKING_QUALIFIED = frozenset(
    {
        "TYPE_CHECKING",
        "typing.TYPE_CHECKING",
        "typing_extensions.TYPE_CHECKING",
    }
)

_COMPARISON_OPS = {
    ast.Eq: operator.eq,
    ast.NotEq: operator.ne,
    ast.Lt: operator.lt,
    ast.LtE: operator.le,
    ast.Gt: operator.gt,
    ast.GtE: operator.ge,
}


@dataclass(frozen=True)
class AnalysisEnvironment:
    """Target Python environment parameters shared across static analyses."""

    python_version: tuple[int, int] = (sys.version_info.major, sys.version_info.minor)
    platform: str = sys.platform
    type_checking: bool | None = None

    @classmethod
    def current(cls, *, type_checking: bool | None = None) -> "AnalysisEnvironment":
        return cls(
            python_version=(sys.version_info.major, sys.version_info.minor),
            platform=sys.platform,
            type_checking=type_checking,
        )

    def for_type_checking(self) -> "AnalysisEnvironment":
        """Return a view where ``typing.TYPE_CHECKING`` evaluates to ``True``."""
        return replace(self, type_checking=True)

    def for_runtime(self) -> "AnalysisEnvironment":
        """Return a view where ``typing.TYPE_CHECKING`` evaluates to ``False``."""
        return replace(self, type_checking=False)

    def with_version(self, major: int, minor: int) -> "AnalysisEnvironment":
        return replace(self, python_version=(major, minor))

    def with_platform(self, platform: str) -> "AnalysisEnvironment":
        return replace(self, platform=platform)

    @property
    def os_name(self) -> str:
        """Return the Python ``os.name`` corresponding to :attr:`platform`."""
        if self.platform in {"win32", "cygwin", "msys"}:
            return "nt"
        return "posix"

    def fingerprint(self) -> str:
        """Stable content hash of this environment for incremental caching."""
        raw = (
            f"py={self.python_version[0]}.{self.python_version[1]}"
            f"|plat={self.platform}|tc={self.type_checking}"
        )
        return hashlib.blake2b(raw.encode("utf-8"), digest_size=16).hexdigest()


def _dotted_name(node: ast.AST) -> str | None:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        base = _dotted_name(node.value)
        if base:
            return f"{base}.{node.attr}"
    return None


def _resolve_dotted(node: ast.AST, aliases: Mapping[str, str] | None) -> str | None:
    name = _dotted_name(node)
    if not name:
        return None
    if not aliases:
        return name
    head, sep, tail = name.partition(".")
    mapped = aliases.get(head)
    if not mapped:
        return name
    return f"{mapped}{sep}{tail}" if sep else mapped


def _eval_static_value(
    node: ast.AST,
    env: AnalysisEnvironment,
    aliases: Mapping[str, str] | None,
) -> tuple[bool, Any]:
    """Evaluate a small set of pure environment/literal expressions.

    Returns ``(True, value)`` when statically known, or ``(False, None)``
    when the expression is dynamic or unsupported.
    """
    if isinstance(node, ast.Constant):
        if isinstance(node.value, (bool, int, str, bytes, type(None))):
            return True, node.value
        return False, None

    if isinstance(node, (ast.Tuple, ast.List, ast.Set)):
        items: list[Any] = []
        for elt in node.elts:
            ok, value = _eval_static_value(elt, env, aliases)
            if not ok:
                return False, None
            items.append(value)
        if isinstance(node, ast.Tuple):
            return True, tuple(items)
        if isinstance(node, ast.Set):
            try:
                return True, frozenset(items)
            except TypeError:
                return False, None
        return True, tuple(items)

    # sys.version_info[:2], sys.version_info[0], etc.
    if isinstance(node, ast.Subscript):
        ok, base = _eval_static_value(node.value, env, aliases)
        if not ok or not isinstance(base, tuple):
            return False, None
        if isinstance(node.slice, ast.Slice):
            step = None
            if node.slice.step is not None:
                ok_s, step = _eval_static_value(node.slice.step, env, aliases)
                if not ok_s or not isinstance(step, int) or step == 0:
                    return False, None
            lower = None
            if node.slice.lower is not None:
                ok_l, lower = _eval_static_value(node.slice.lower, env, aliases)
                if not ok_l or not isinstance(lower, int):
                    return False, None
            upper = None
            if node.slice.upper is not None:
                ok_u, upper = _eval_static_value(node.slice.upper, env, aliases)
                if not ok_u or not isinstance(upper, int):
                    return False, None
            return True, base[slice(lower, upper, step)]
        ok_idx, idx = _eval_static_value(node.slice, env, aliases)
        if ok_idx and isinstance(idx, int) and -len(base) <= idx < len(base):
            return True, base[idx]
        return False, None

    # sys.platform.startswith("linux") / sys.platform.startswith(("linux", "darwin"))
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and not node.keywords:
        if node.func.attr == "startswith" and len(node.args) == 1:
            ok_recv, recv = _eval_static_value(node.func.value, env, aliases)
            ok_arg, arg = _eval_static_value(node.args[0], env, aliases)
            if ok_recv and ok_arg and isinstance(recv, str):
                if isinstance(arg, str):
                    return True, recv.startswith(arg)
                if isinstance(arg, tuple) and all(isinstance(item, str) for item in arg):
                    return True, recv.startswith(arg)
        return False, None

    resolved = _resolve_dotted(node, aliases)
    if not resolved:
        return False, None

    if resolved in _TYPE_CHECKING_QUALIFIED:
        if env.type_checking is None:
            return False, None
        return True, env.type_checking
    if resolved == "sys.version_info":
        return True, (env.python_version[0], env.python_version[1], 0)
    if resolved == "sys.version_info.major":
        return True, env.python_version[0]
    if resolved == "sys.version_info.minor":
        return True, env.python_version[1]
    if resolved == "sys.version_info.micro":
        return True, 0
    if resolved == "sys.platform":
        return True, env.platform
    if resolved == "os.name":
        return True, env.os_name

    return False, None


def _compare_pair(op: ast.cmpop, left: Any, right: Any) -> tuple[bool, bool]:
    if isinstance(op, ast.In):
        if isinstance(right, (tuple, frozenset, str, bytes)):
            try:
                return True, left in right
            except TypeError:
                return False, False
        return False, False
    if isinstance(op, ast.NotIn):
        if isinstance(right, (tuple, frozenset, str, bytes)):
            try:
                return True, left not in right
            except TypeError:
                return False, False
        return False, False
    if isinstance(op, ast.Is):
        return True, left is right
    if isinstance(op, ast.IsNot):
        return True, left is not right
    comparator = _COMPARISON_OPS.get(type(op))
    if comparator is None:
        return False, False
    # Align version_info tuples like (3, 12, 0) vs (3, 12) so comparisons
    # behave identically to Python's version_info comparison semantics.
    if (
        isinstance(left, tuple)
        and isinstance(right, tuple)
        and all(isinstance(x, int) for x in left)
        and all(isinstance(x, int) for x in right)
    ):
        max_len = max(len(left), len(right))
        left = left + (0,) * (max_len - len(left))
        right = right + (0,) * (max_len - len(right))
    try:
        return True, bool(comparator(left, right))
    except TypeError:
        return False, False


def evaluate_static_condition(
    test: ast.AST,
    env: AnalysisEnvironment,
    *,
    aliases: Mapping[str, str] | None = None,
) -> bool | None:
    """Evaluate *test* statically under *env* using Kleene 3-valued logic.

    Returns ``True`` if statically guaranteed true, ``False`` if statically
    guaranteed false, or ``None`` if unknown/dynamic.
    """
    if isinstance(test, ast.UnaryOp) and isinstance(test.op, ast.Not):
        inner = evaluate_static_condition(test.operand, env, aliases=aliases)
        return None if inner is None else (not inner)

    if isinstance(test, ast.BoolOp):
        if isinstance(test.op, ast.And):
            unknown_seen = False
            for operand in test.values:
                val = evaluate_static_condition(operand, env, aliases=aliases)
                if val is False:
                    return False
                if val is None:
                    unknown_seen = True
            return None if unknown_seen else True
        if isinstance(test.op, ast.Or):
            unknown_seen = False
            for operand in test.values:
                val = evaluate_static_condition(operand, env, aliases=aliases)
                if val is True:
                    return True
                if val is None:
                    unknown_seen = True
            return None if unknown_seen else False

    if isinstance(test, ast.Compare):
        ok_left, current = _eval_static_value(test.left, env, aliases)
        if not ok_left:
            return None
        for op, comparator_node in zip(test.ops, test.comparators):
            ok_right, right = _eval_static_value(comparator_node, env, aliases)
            if not ok_right:
                return None
            ok_cmp, outcome = _compare_pair(op, current, right)
            if not ok_cmp:
                return None
            if not outcome:
                return False
            current = right
        return True

    ok, value = _eval_static_value(test, env, aliases)
    if ok:
        return bool(value)
    return None


def _collect_import_aliases(statements: Iterable[ast.stmt]) -> dict[str, str]:
    """Collect simple module-scope import aliases for static condition evaluation."""
    aliases: dict[str, str] = {}
    for stmt in statements:
        if isinstance(stmt, ast.Import):
            for alias in stmt.names:
                local = alias.asname or alias.name.split(".", 1)[0]
                aliases[local] = alias.name if alias.asname else alias.name.split(".", 1)[0]
        elif isinstance(stmt, ast.ImportFrom) and stmt.level == 0 and stmt.module:
            for alias in stmt.names:
                if alias.name == "*":
                    continue
                local = alias.asname or alias.name
                aliases[local] = f"{stmt.module}.{alias.name}"
    return aliases


def iter_active_statements(
    statements: Iterable[ast.stmt],
    env: AnalysisEnvironment,
    *,
    aliases: Mapping[str, str] | None = None,
    flatten_static_ifs: bool = True,
) -> Iterator[ast.stmt]:
    """Yield statements active under *env*, preserving order.

    For ``if`` statements whose condition evaluates statically to ``True`` or
    ``False``, yields only the active branch (recursively when
    ``flatten_static_ifs=True``).  Dynamic ``if`` statements are yielded intact
    so downstream analyses inspect both branches.
    """
    stmt_list = list(statements)
    effective_aliases = aliases if aliases is not None else _collect_import_aliases(stmt_list)
    for stmt in stmt_list:
        if isinstance(stmt, ast.If) and flatten_static_ifs:
            decision = evaluate_static_condition(stmt.test, env, aliases=effective_aliases)
            if decision is True:
                yield from iter_active_statements(
                    stmt.body, env, aliases=effective_aliases, flatten_static_ifs=True
                )
                continue
            if decision is False:
                yield from iter_active_statements(
                    stmt.orelse, env, aliases=effective_aliases, flatten_static_ifs=True
                )
                continue
        yield stmt


def iter_active_imports(
    statements: Iterable[ast.stmt],
    env: AnalysisEnvironment,
    *,
    include_nested: bool = False,
    aliases: Mapping[str, str] | None = None,
) -> Iterator[ast.Import | ast.ImportFrom]:
    """Yield import nodes reachable under *env* without walking expressions."""
    stmt_list = list(statements)
    effective_aliases = aliases if aliases is not None else _collect_import_aliases(stmt_list)
    for stmt in stmt_list:
        if isinstance(stmt, (ast.Import, ast.ImportFrom)):
            yield stmt
            continue
        if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            if include_nested:
                yield from iter_active_imports(
                    stmt.body,
                    env,
                    include_nested=True,
                    aliases=effective_aliases,
                )
            continue
        if isinstance(stmt, ast.If):
            decision = evaluate_static_condition(stmt.test, env, aliases=effective_aliases)
            if decision is True:
                yield from iter_active_imports(
                    stmt.body, env, include_nested=include_nested, aliases=effective_aliases
                )
            elif decision is False:
                yield from iter_active_imports(
                    stmt.orelse, env, include_nested=include_nested, aliases=effective_aliases
                )
            else:
                yield from iter_active_imports(
                    stmt.body, env, include_nested=include_nested, aliases=effective_aliases
                )
                yield from iter_active_imports(
                    stmt.orelse, env, include_nested=include_nested, aliases=effective_aliases
                )
            continue
        if isinstance(stmt, (ast.For, ast.AsyncFor, ast.While, ast.With, ast.AsyncWith)):
            yield from iter_active_imports(
                getattr(stmt, "body", ()) or (),
                env,
                include_nested=include_nested,
                aliases=effective_aliases,
            )
            yield from iter_active_imports(
                getattr(stmt, "orelse", ()) or (),
                env,
                include_nested=include_nested,
                aliases=effective_aliases,
            )
            continue
        if isinstance(stmt, (ast.Try, getattr(ast, "TryStar", ast.Try))):
            yield from iter_active_imports(
                getattr(stmt, "body", ()) or (),
                env,
                include_nested=include_nested,
                aliases=effective_aliases,
            )
            for handler in getattr(stmt, "handlers", ()) or ():
                yield from iter_active_imports(
                    getattr(handler, "body", ()) or (),
                    env,
                    include_nested=include_nested,
                    aliases=effective_aliases,
                )
            yield from iter_active_imports(
                getattr(stmt, "orelse", ()) or (),
                env,
                include_nested=include_nested,
                aliases=effective_aliases,
            )
            yield from iter_active_imports(
                getattr(stmt, "finalbody", ()) or (),
                env,
                include_nested=include_nested,
                aliases=effective_aliases,
            )
            continue
        if hasattr(ast, "Match") and isinstance(stmt, ast.Match):
            for case in getattr(stmt, "cases", ()) or ():
                yield from iter_active_imports(
                    getattr(case, "body", ()) or (),
                    env,
                    include_nested=include_nested,
                    aliases=effective_aliases,
                )


__all__ = [
    "AnalysisEnvironment",
    "evaluate_static_condition",
    "iter_active_imports",
    "iter_active_statements",
]
