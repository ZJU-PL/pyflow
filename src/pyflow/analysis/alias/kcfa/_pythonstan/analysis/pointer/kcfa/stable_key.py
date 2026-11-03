"""Stable semantic tokens for synthesized analysis identities."""

from __future__ import annotations

import ast
import hashlib
from enum import Enum
from typing import Any


def _describe(value: Any) -> str:
    if value is None or isinstance(value, (str, int, float, bool)):
        return repr(value)
    if isinstance(value, Enum):
        return f"{type(value).__qualname__}:{value.value}"
    if isinstance(value, ast.AST):
        lineno = getattr(value, "lineno", None)
        col = getattr(value, "col_offset", None)
        if lineno is not None and col is not None:
            # Full ``ast.dump`` of a class definition is quadratic in the
            # class body size and dominated class-heavy analyses.  The source
            # span plus node type is stable and sufficient for synthesized
            # solver identities.
            return (
                f"{type(value).__qualname__}:{lineno}:{col}:"
                f"{getattr(value, 'end_lineno', lineno)}:"
                f"{getattr(value, 'end_col_offset', col)}"
            )
        return ast.dump(value, annotate_fields=True, include_attributes=True)
    if isinstance(value, (tuple, list)):
        return "[" + ",".join(_describe(item) for item in value) + "]"

    get_ast = getattr(value, "get_ast", None)
    if callable(get_ast):
        node = get_ast()
        get_qualname = getattr(value, "get_qualname", None)
        qualname = get_qualname() if callable(get_qualname) else None
        return (
            f"{type(value).__module__}.{type(value).__qualname__}:"
            f"{qualname!r}:{_describe(node)}"
        )
    if hasattr(value, "alloc_site") and hasattr(value, "context"):
        return (
            f"{type(value).__module__}.{type(value).__qualname__}:"
            f"{_describe(value.alloc_site)}:{_describe(value.context)}"
        )
    if hasattr(value, "stmt") and hasattr(value, "kind"):
        return (
            f"{type(value).__module__}.{type(value).__qualname__}:"
            f"{_describe(value.kind)}:{_describe(value.stmt)}"
        )
    if hasattr(value, "name") and hasattr(value, "kind"):
        return (
            f"{type(value).__module__}.{type(value).__qualname__}:"
            f"{_describe(value.kind)}:{value.name}"
        )
    if hasattr(value, "to_string") and callable(value.to_string):
        return f"{type(value).__qualname__}:{value.to_string()}"
    if hasattr(value, "statement") and hasattr(value, "scope_name") and hasattr(value, "index"):
        return (
            f"{type(value).__qualname__}:{value.scope_name}:"
            f"{value.index}:{_describe(value.statement)}"
        )
    return f"{type(value).__module__}.{type(value).__qualname__}:{str(value)}"


def stable_token(*parts: Any, length: int = 16) -> str:
    """Return a deterministic compact token for semantic identity parts."""
    payload = "\x1f".join(_describe(part) for part in parts).encode("utf-8")
    return hashlib.blake2b(payload, digest_size=16).hexdigest()[:length]
