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
from dataclasses import dataclass
from typing import Dict, Iterable, List, Optional


@dataclass(frozen=True)
class FunctionSpan:
    qualname: str
    name: str
    lineno: int
    end_lineno: int


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


def find_function_source_segment(
    source: str,
    *,
    name: Optional[str] = None,
    qualname: Optional[str] = None,
    lineno: Optional[int] = None,
) -> Optional[str]:
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return None

    spans = list(_iter_function_spans(tree))
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


def best_source_for_callable(
    func: object, sources_by_filename: Dict[str, str]
) -> Optional[str]:
    filename = getattr(getattr(func, "__code__", None), "co_filename", None)
    firstlineno = getattr(getattr(func, "__code__", None), "co_firstlineno", None)
    name = getattr(func, "__name__", None)
    qualname = getattr(func, "__qualname__", None)

    # Exact filename lookup first.
    if filename and filename in sources_by_filename:
        src = sources_by_filename[filename]
        seg = find_function_source_segment(
            src, name=name, qualname=qualname, lineno=firstlineno
        )
        return seg or src

    # Fallback: search all sources by qualname/name/lineno.
    for src in sources_by_filename.values():
        seg = find_function_source_segment(
            src, name=name, qualname=qualname, lineno=firstlineno
        )
        if seg:
            return seg

    return None
