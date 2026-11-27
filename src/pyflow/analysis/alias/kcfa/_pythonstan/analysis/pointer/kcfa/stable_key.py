"""Stable semantic tokens for synthesized analysis identities."""

from __future__ import annotations

import ast
import hashlib
from enum import Enum
from typing import Any

_MAX_DESCRIBE_CACHE = 32768
_DESCRIBE_CACHE: dict[Any, str] = {}
_FOLD_THRESHOLD = 96


def _fold_description(text: str) -> str:
    if len(text) <= _FOLD_THRESHOLD:
        return text
    return "#" + hashlib.blake2b(text.encode("utf-8"), digest_size=16).hexdigest()


def _describe_uncached(value: Any) -> str:
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
        return _fold_description(ast.dump(value, annotate_fields=True, include_attributes=True))
    if isinstance(value, (tuple, list)):
        return _fold_description("[" + ",".join(_describe(item) for item in value) + "]")

    get_ast = getattr(value, "get_ast", None)
    if callable(get_ast):
        node = get_ast()
        get_qualname = getattr(value, "get_qualname", None)
        qualname = get_qualname() if callable(get_qualname) else None
        return _fold_description(
            f"{type(value).__module__}.{type(value).__qualname__}:"
            f"{qualname!r}:{_describe(node)}"
        )
    if hasattr(value, "context") and hasattr(value, "scope") and hasattr(value, "content"):
        return _fold_description(
            f"{type(value).__module__}.{type(value).__qualname__}:"
            f"{_describe(value.content)}:{_describe(value.scope)}:{_describe(value.context)}"
        )
    if hasattr(value, "stmt") and hasattr(value, "obj") and hasattr(value, "context"):
        return _fold_description(
            f"{type(value).__module__}.{type(value).__qualname__}:"
            f"{_describe(value.stmt)}:{_describe(value.context)}:{_describe(value.obj)}"
        )
    if hasattr(value, "alloc_site") and hasattr(value, "context"):
        return _fold_description(
            f"{type(value).__module__}.{type(value).__qualname__}:"
            f"{_describe(value.alloc_site)}:{_describe(value.context)}"
        )
    if hasattr(value, "stmt") and hasattr(value, "kind"):
        return _fold_description(
            f"{type(value).__module__}.{type(value).__qualname__}:"
            f"{_describe(value.kind)}:{_describe(value.stmt)}"
        )
    if hasattr(value, "name") and hasattr(value, "kind"):
        return _fold_description(
            f"{type(value).__module__}.{type(value).__qualname__}:"
            f"{_describe(value.kind)}:{value.name}"
        )
    # Structural context description avoids exponential ``to_string()`` expansion
    # on nested ParamContext/ObjectContext/TypeContext trees.
    cls_name = type(value).__qualname__
    if hasattr(value, "to_string") and callable(value.to_string):
        if hasattr(value, "call_sites") and hasattr(value, "alloc_sites"):
            return _fold_description(
                f"{cls_name}:{value.call_k}:{value.obj_depth}:"
                f"{_describe(value.call_sites)}:{_describe(value.alloc_sites)}"
            )
        if hasattr(value, "call_sites") and hasattr(value, "k"):
            return _fold_description(f"{cls_name}:{value.k}:{_describe(value.call_sites)}")
        if hasattr(value, "alloc_sites") and hasattr(value, "depth"):
            return _fold_description(f"{cls_name}:{value.depth}:{_describe(value.alloc_sites)}")
        if hasattr(value, "types") and hasattr(value, "depth"):
            return _fold_description(f"{cls_name}:{value.depth}:{_describe(value.types)}")
        if hasattr(value, "receivers") and hasattr(value, "depth"):
            return _fold_description(f"{cls_name}:{value.depth}:{_describe(value.receivers)}")
        if hasattr(value, "params") and hasattr(value, "depth"):
            return _fold_description(f"{cls_name}:{value.depth}:{_describe(value.params)}")
        if hasattr(value, "inner"):
            return _fold_description(f"{cls_name}:{_describe(value.inner)}")
        return _fold_description(f"{cls_name}:{value.to_string()}")
    if hasattr(value, "statement") and hasattr(value, "scope_name") and hasattr(value, "index"):
        return _fold_description(
            f"{cls_name}:{value.scope_name}:{value.index}:{_describe(value.statement)}"
        )
    return _fold_description(f"{type(value).__module__}.{cls_name}:{str(value)}")


def _describe(value: Any) -> str:
    if value is None or isinstance(value, (str, int, float, bool)):
        return repr(value)
    cache_key = None
    if not isinstance(value, (list, dict, set)):
        try:
            cache_key = (type(value), value)
            cached = _DESCRIBE_CACHE.get(cache_key)
            if cached is not None:
                return cached
        except TypeError:
            cache_key = None
    result = _describe_uncached(value)
    if cache_key is not None:
        if len(_DESCRIBE_CACHE) >= _MAX_DESCRIBE_CACHE:
            _DESCRIBE_CACHE.clear()
        _DESCRIBE_CACHE[cache_key] = result
    return result


def stable_token(*parts: Any, length: int = 16) -> str:
    """Return a deterministic compact token for semantic identity parts."""
    payload = "\x1f".join(_describe(part) for part in parts).encode("utf-8")
    return hashlib.blake2b(payload, digest_size=16).hexdigest()[:length]
