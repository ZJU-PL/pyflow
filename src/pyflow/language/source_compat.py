"""Small, semantics-preserving source repairs shared by analysis frontends."""

from __future__ import annotations

import ast
import re
import warnings

_EXCEPT_CLAUSE = re.compile(
    r"^(?P<indent>\s*)except(?P<star>\*?)\s+(?P<rest>[^#\r\n]+?)\s*:(?P<tail>[ \t]*(?:#[^\r\n]*)?)$",
    re.MULTILINE,
)
_IDENT_RE = re.compile(r"^[A-Za-z_]\w*$")
_DOTTED_IDENT_RE = re.compile(r"^[A-Za-z_]\w*(?:\.[A-Za-z_]\w*)*$")
_EXCEPTION_SUFFIXES = ("Error", "Exception", "Warning", "Exit", "Interrupt")


def _split_top_level_commas(text: str) -> list[str]:
    """Split *text* on commas outside brackets/parentheses."""
    parts: list[str] = []
    depth = 0
    start = 0
    for idx, ch in enumerate(text):
        if ch in "([{":
            depth += 1
        elif ch in ")]}":
            depth = max(0, depth - 1)
        elif ch == "," and depth == 0:
            parts.append(text[start:idx].strip())
            start = idx + 1
    parts.append(text[start:].strip())
    return parts


def _looks_like_exception_type(expr: str) -> bool:
    """Distinguish PEP 758 exception types from Python 2 binding variables."""
    if not expr:
        return False
    if "." in expr:
        return bool(_DOTTED_IDENT_RE.match(expr))
    if not _IDENT_RE.match(expr):
        return False
    # Exception classes follow CapWords (PEP 8) or standard exception suffixes.
    stripped = expr.lstrip("_")
    if stripped and stripped[0].isupper():
        return True
    return expr.endswith(_EXCEPTION_SUFFIXES)


def _rewrite_except_clause(match: re.Match[str]) -> str:
    indent = match.group("indent")
    star = match.group("star")
    rest = match.group("rest").strip()
    tail = match.group("tail")
    if "," not in rest or re.search(r"\bas\b", rest):
        return match.group(0)

    parts = _split_top_level_commas(rest)
    if len(parts) < 2 or any(not part for part in parts):
        return match.group(0)

    # PEP 758: `except* A, B:` or 3+ unparenthesized items `except A, B, C:`
    # are always multi-exception tuples, never Python 2 binding syntax.
    if star or len(parts) >= 3:
        if all(_DOTTED_IDENT_RE.match(part) for part in parts):
            joined = ", ".join(parts)
            return f"{indent}except{star} ({joined}):{tail}"
        return match.group(0)

    first, second = parts
    # Already parenthesized first element: Python 2 `except (A, B), exc:`.
    if first.startswith("(") and first.endswith(")"):
        if _IDENT_RE.match(second):
            return f"{indent}except {first} as {second}:{tail}"
        return match.group(0)

    # Two unparenthesized items: `except E1, E2:` (PEP 758) vs `except E1, e:` (Py2).
    if _looks_like_exception_type(second):
        return f"{indent}except ({first}, {second}):{tail}"
    if _IDENT_RE.match(second):
        return f"{indent}except {first} as {second}:{tail}"
    return match.group(0)


def normalize_legacy_python_syntax(source: str) -> str:
    """Repair Python 2 ``except E, e:`` and Python 3.14 PEP 758 ``except E1, E2:``."""
    return _EXCEPT_CLAUSE.sub(_rewrite_except_clause, source)


def parse_python_source(source: str, filename: str = "<unknown>") -> ast.Module:
    """Parse Python source with syntax compatibility normalization and quiet warnings."""
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", SyntaxWarning)
        try:
            return ast.parse(source, filename)
        except SyntaxError:
            normalized = normalize_legacy_python_syntax(source)
            if normalized == source:
                raise
            return ast.parse(normalized, filename)


__all__ = ["normalize_legacy_python_syntax", "parse_python_source"]
