"""Record legacy IR rewrites that may have a safe source-level equivalent.

The IR is richer than Python syntax, so recording a candidate is deliberately
not permission to emit it.  The source backend must locate the exact source
span and revalidate its own, stricter safety rules before it applies anything.
"""

from __future__ import annotations

from typing import Any


_CANDIDATE_STATS_KEY = "source_rewrite_candidates"


def _origin_payload(code: object, node: object) -> dict[str, Any] | None:
    catalog = getattr(code, "ir_catalog", None)
    if catalog is None:
        return None
    try:
        origin = catalog.source_of(node, code=code)
    except (KeyError, TypeError, ValueError):
        return None
    span = getattr(origin, "span", None)
    if span is None:
        return None
    return {
        "path": span.path,
        "start_line": span.start_line,
        "start_column": span.start_column,
        "end_line": span.end_line,
        "end_column": span.end_column,
    }


def record_source_candidate(
    compiler,
    code: object,
    node: object,
    kind: str,
    **payload: Any,
) -> None:
    """Append a source-addressable legacy rewrite candidate to compiler stats."""
    stats = getattr(compiler, "stats", None)
    if stats is None:
        return
    candidate = {"kind": kind, "origin": _origin_payload(code, node), **payload}
    candidates = stats.get(_CANDIDATE_STATS_KEY)
    if candidates is None:
        candidates = []
        stats[_CANDIDATE_STATS_KEY] = candidates
    candidates.append(candidate)


def source_candidates(compiler) -> tuple[dict[str, Any], ...]:
    """Return the legacy candidates recorded for the current compilation."""
    stats = getattr(compiler, "stats", None)
    if stats is None:
        return ()
    candidates = stats.get(_CANDIDATE_STATS_KEY, ())
    return tuple(candidate for candidate in candidates if isinstance(candidate, dict))


def source_candidate_coverage(candidates) -> dict[str, Any]:
    """Measure whether legacy candidates retain a complete IR source span.

    A complete span is necessary for source emission, but not sufficient: the
    source emitter separately verifies that it identifies one exact Python AST
    node before it applies a rewrite.
    """
    by_kind: dict[str, dict[str, int]] = {}
    for candidate in candidates:
        kind = str(candidate.get("kind", "unknown"))
        counts = by_kind.setdefault(
            kind,
            {
                "recorded": 0,
                "with_complete_span": 0,
                "without_complete_span": 0,
            },
        )
        counts["recorded"] += 1
        origin = candidate.get("origin")
        exact = isinstance(origin, dict) and all(
            origin.get(field) is not None
            for field in (
                "path",
                "start_line",
                "start_column",
                "end_line",
                "end_column",
            )
        )
        counts["with_complete_span" if exact else "without_complete_span"] += 1
    return by_kind


__all__ = [
    "record_source_candidate",
    "source_candidate_coverage",
    "source_candidates",
]
