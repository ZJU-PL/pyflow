"""
Helpers for locating function source code within a file.

The frontend often needs to convert a Python callable into PyFlow AST. When we only
have a mapping of filename -> full module source, passing the whole file to the
FunctionExtractor can mis-associate when there are multiple functions with the
same name (methods, nested functions, overload-like patterns).

This module provides a lightweight AST-based lookup that prefers:
1) filename + co_firstlineno (best signal)
2) __qualname__ (class/method and nesting aware)
3) fallback to name-only match
"""

from __future__ import annotations

import ast
import os
import sys
from dataclasses import dataclass
from typing import Dict, Iterable, List, Optional, Tuple


@dataclass(frozen=True)
class FunctionSpan:
    qualname: str
    name: str
    lineno: int
    end_lineno: int


# Each entry point lookup re-parses and re-walks a full file AST unless the
# spans are cached; a source map of N files x M callables is the frontend's
# dominant cost.  Keyed by the source *content* (strings hash by value), so a
# ``textwrap.dedent``-ed copy of a module shares the entry with the original
# instead of missing an ``id(source)``-keyed cache on every conversion.  The
# cap keeps long-running processes (LSP) from accumulating stale entries.
_SPAN_CACHE: "Dict[str, List[FunctionSpan]]" = {}
_MAX_SPAN_CACHE_ENTRIES = 8192


def _cached_spans(source: str) -> List[FunctionSpan]:
    cached = _SPAN_CACHE.get(source)
    if cached is not None:
        return cached
    tree = ast.parse(source)
    spans = list(_iter_function_spans(tree))
    if len(_SPAN_CACHE) >= _MAX_SPAN_CACHE_ENTRIES:
        _SPAN_CACHE.clear()
    _SPAN_CACHE[source] = spans
    return spans


def _normalize_qualname(qualname: Optional[str]) -> Optional[str]:
    if qualname is None:
        return None
    return qualname.replace(".<locals>", "")


def _iter_function_spans(tree: ast.AST) -> Iterable[FunctionSpan]:
    stack: List[str] = []

    # NodeVisitor doesn't support generators directly, so we manually drive a stack.
    # We implement a small custom traversal that yields spans.
    def walk(node: ast.AST) -> Iterable[FunctionSpan]:
        if isinstance(node, ast.ClassDef):
            stack.append(node.name)
            for child in node.body:
                yield from walk(child)
            stack.pop()
            return

        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            stack.append(node.name)
            qualname = ".".join(stack)

            lineno = getattr(node, "lineno", None)
            end_lineno = getattr(node, "end_lineno", None)
            if isinstance(lineno, int) and isinstance(end_lineno, int):
                yield FunctionSpan(
                    qualname=qualname,
                    name=node.name,
                    lineno=lineno,
                    end_lineno=end_lineno,
                )
            # Keep walking nested defs.
            for child in getattr(node, "body", []):
                yield from walk(child)
            stack.pop()
            return

        # Generic: walk children.
        for child in ast.iter_child_nodes(node):
            yield from walk(child)

    yield from walk(tree)


def _slice_lines(source: str, lineno: int, end_lineno: int) -> str:
    lines = source.splitlines()
    start = max(lineno - 1, 0)
    end = min(end_lineno, len(lines))
    return "\n".join(lines[start:end])


# ``best_source_for_callable`` runs for every callable the frontend converts.
# When a callable's ``co_filename`` is absent from the source map (external or
# unresolved functions) the fallback linearly scans every source file; memoize
# the result -- including the ``None`` miss -- per source set so a repeated
# lookup for the same callable scans at most once.  The source map is keyed by
# identity with a strong reference (mirroring ``_SPAN_CACHE``) so the id can
# never alias a recycled object and a rebuilt source set starts a fresh bucket.
_LookupKey = Tuple[Optional[str], Optional[int], Optional[str], Optional[str]]


@dataclass(frozen=True)
class _IndexedSpan:
    file_order: int
    source: str
    span: FunctionSpan


class _SourceIndex:
    """Reverse index for fallback lookups across a stable source mapping."""

    def __init__(self, sources_by_filename: Dict[str, str]) -> None:
        self.by_lineno: Dict[int, List[_IndexedSpan]] = {}
        self.by_name: Dict[str, List[_IndexedSpan]] = {}
        self.by_qualname: Dict[str, List[_IndexedSpan]] = {}
        for file_order, source in enumerate(sources_by_filename.values()):
            try:
                spans = _cached_spans(source)
            except SyntaxError:
                continue
            for span in spans:
                indexed = _IndexedSpan(file_order, source, span)
                self.by_lineno.setdefault(span.lineno, []).append(indexed)
                self.by_name.setdefault(span.name, []).append(indexed)
                normalized = _normalize_qualname(span.qualname)
                if normalized is not None:
                    self.by_qualname.setdefault(normalized, []).append(indexed)

    @staticmethod
    def _first_file(candidates: List[_IndexedSpan]) -> List[_IndexedSpan]:
        if not candidates:
            return []
        first_order = candidates[0].file_order
        return [item for item in candidates if item.file_order == first_order]

    @staticmethod
    def _slice(indexed: _IndexedSpan) -> str:
        return _slice_lines(
            indexed.source, indexed.span.lineno, indexed.span.end_lineno
        )

    def resolve(
        self,
        *,
        firstlineno: Optional[int],
        name: Optional[str],
        qualname: Optional[str],
    ) -> Optional[str]:
        """Resolve with the same precedence as ``find_function_source_segment``.

        Candidate lists retain source-map insertion order, preserving the old
        fallback's deterministic "first matching file" behavior without
        re-scanning every file for every callable.
        """
        normalized_qualname = _normalize_qualname(qualname)

        if isinstance(firstlineno, int):
            candidates = list(self.by_lineno.get(firstlineno, ()))
            if name:
                candidates = [item for item in candidates if item.span.name == name]
            candidates = self._first_file(candidates)
            if candidates:
                if normalized_qualname:
                    qual_matches = [
                        item
                        for item in candidates
                        if _normalize_qualname(item.span.qualname)
                        == normalized_qualname
                    ]
                    if qual_matches:
                        candidates = qual_matches
                best = min(
                    candidates,
                    key=lambda item: (
                        item.span.end_lineno - item.span.lineno,
                        item.span.qualname,
                    ),
                )
                return self._slice(best)

        if normalized_qualname:
            candidates = list(self.by_qualname.get(normalized_qualname, ()))
            if name:
                candidates = [item for item in candidates if item.span.name == name]
            candidates = self._first_file(candidates)
            if candidates:
                best = min(
                    candidates,
                    key=lambda item: (
                        item.span.end_lineno - item.span.lineno,
                        item.span.lineno,
                    ),
                )
                return self._slice(best)

        if name:
            candidates = self._first_file(list(self.by_name.get(name, ())))
            if candidates:
                best = min(
                    candidates,
                    key=lambda item: (
                        item.span.lineno,
                        item.span.end_lineno - item.span.lineno,
                    ),
                )
                return self._slice(best)
        return None


@dataclass
class _SourceLookupState:
    sources: Dict[str, str]
    results: Dict[_LookupKey, Optional[str]]
    normalized_sources: Optional[Dict[str, str]] = None
    index: Optional[_SourceIndex] = None


_SOURCE_LOOKUP_CACHE: "Dict[int, _SourceLookupState]" = {}
_MAX_SOURCE_LOOKUP_SETS = 4


def _source_lookup_state(sources_by_filename: Dict[str, str]) -> _SourceLookupState:
    key = id(sources_by_filename)
    entry = _SOURCE_LOOKUP_CACHE.get(key)
    if entry is not None and entry.sources is sources_by_filename:
        return entry
    if len(_SOURCE_LOOKUP_CACHE) >= _MAX_SOURCE_LOOKUP_SETS:
        _SOURCE_LOOKUP_CACHE.clear()
    state = _SourceLookupState(sources_by_filename, {})
    _SOURCE_LOOKUP_CACHE[key] = state
    return state


def _source_lookup_cache(
    sources_by_filename: Dict[str, str],
) -> Dict[_LookupKey, Optional[str]]:
    return _source_lookup_state(sources_by_filename).results


def _normalized_sources(sources_by_filename: Dict[str, str]) -> Dict[str, str]:
    state = _source_lookup_state(sources_by_filename)
    if state.normalized_sources is None:
        state.normalized_sources = {
            os.path.realpath(filename): source
            for filename, source in sources_by_filename.items()
            if filename and not filename.startswith("<")
        }
    return state.normalized_sources


def _source_index(sources_by_filename: Dict[str, str]) -> _SourceIndex:
    state = _source_lookup_state(sources_by_filename)
    if state.index is None:
        state.index = _SourceIndex(sources_by_filename)
    return state.index


_STDLIB_DIRS: Tuple[str, ...] = tuple(
    p
    for p in {
        os.path.realpath(os.path.dirname(os.__file__)),
        os.path.realpath(sys.base_prefix),
        os.path.realpath(sys.prefix),
    }
    if p
)


def _is_external_runtime_file(filename: Optional[str]) -> bool:
    if not filename:
        return False
    if filename.startswith("<frozen ") or filename.startswith("<built-in"):
        return True
    if not os.path.isabs(filename):
        return False
    real = os.path.realpath(filename)
    if any(real == p or real.startswith(p + os.sep) for p in _STDLIB_DIRS):
        return True
    path_parts = set(real.replace("\\", "/").split("/"))
    if path_parts.intersection({"site-packages", "dist-packages"}):
        return True
    return False


def _resolve_best_source(
    filename: Optional[str],
    firstlineno: Optional[int],
    name: Optional[str],
    qualname: Optional[str],
    sources_by_filename: Dict[str, str],
) -> Optional[str]:
    # Exact filename lookup first.
    if filename:
        if filename in sources_by_filename:
            src = sources_by_filename[filename]
            seg = find_function_source_segment(
                src, name=name, qualname=qualname, lineno=firstlineno
            )
            return seg or src
        real_fn = os.path.realpath(filename)
        normalized_sources = _normalized_sources(sources_by_filename)
        if real_fn in normalized_sources:
            src = normalized_sources[real_fn]
            seg = find_function_source_segment(
                src, name=name, qualname=qualname, lineno=firstlineno
            )
            return seg or src
        if _is_external_runtime_file(filename):
            return None

    # Build one reverse index lazily for unresolved local paths.  This changes
    # repeated fallback lookup from O(callables * files) to O(files + callables).
    return _source_index(sources_by_filename).resolve(
        firstlineno=firstlineno,
        name=name,
        qualname=qualname,
    )


def best_source_for_callable(
    func: object, sources_by_filename: Dict[str, str]
) -> Optional[str]:
    filename = getattr(getattr(func, "__code__", None), "co_filename", None)
    firstlineno = getattr(getattr(func, "__code__", None), "co_firstlineno", None)
    name = getattr(func, "__name__", None)
    qualname = getattr(func, "__qualname__", None)

    cache = _source_lookup_cache(sources_by_filename)
    cache_key = (filename, firstlineno, name, qualname)
    if cache_key in cache:
        return cache[cache_key]

    result = _resolve_best_source(
        filename, firstlineno, name, qualname, sources_by_filename
    )
    cache[cache_key] = result
    return result


def find_function_source_segment(
    source: str,
    *,
    name: Optional[str] = None,
    qualname: Optional[str] = None,
    lineno: Optional[int] = None,
) -> Optional[str]:
    try:
        spans = _cached_spans(source)
    except SyntaxError:
        return None
    if not spans:
        return None

    # Prefer exact lineno match (best signal from code object).
    if isinstance(lineno, int):
        candidates = [s for s in spans if s.lineno == lineno]
        if name:
            candidates = [s for s in candidates if s.name == name]
        if qualname:
            qual_matches = [
                s
                for s in candidates
                if _normalize_qualname(s.qualname) == _normalize_qualname(qualname)
            ]
            if qual_matches:
                candidates = qual_matches
        if candidates:
            best = min(candidates, key=lambda s: (s.end_lineno - s.lineno, s.qualname))
            return _slice_lines(source, best.lineno, best.end_lineno)

    # Next: exact qualname match (class/method aware).
    if qualname:
        normalized_qualname = _normalize_qualname(qualname)
        candidates = [
            s
            for s in spans
            if _normalize_qualname(s.qualname) == normalized_qualname
        ]
        if name:
            candidates = [s for s in candidates if s.name == name]
        if candidates:
            best = min(candidates, key=lambda s: (s.end_lineno - s.lineno, s.lineno))
            return _slice_lines(source, best.lineno, best.end_lineno)

    # Fallback: name-only match (pick earliest, smallest).
    if name:
        candidates = [s for s in spans if s.name == name]
        if candidates:
            best = min(candidates, key=lambda s: (s.lineno, s.end_lineno - s.lineno))
            return _slice_lines(source, best.lineno, best.end_lineno)

    return None
