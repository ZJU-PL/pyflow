"""Source locations and transformation provenance for stable IR entities."""

from __future__ import annotations

from dataclasses import dataclass
from functools import lru_cache

from .ids import NodeId, SymbolId


@dataclass(frozen=True, order=True)
class SourceSpan:
    path: str
    start_line: int
    start_column: int
    end_line: int | None = None
    end_column: int | None = None


@dataclass(frozen=True)
class SourceOrigin:
    span: SourceSpan
    name: str | None = None
    construct_kind: str | None = None


@dataclass(frozen=True)
class SyntheticOrigin:
    reason: str


@lru_cache(maxsize=262144)
def _source_origin(
    filename: str,
    line: int,
    column: int,
    end_line: int | None,
    end_column: int | None,
    name: str | None,
) -> SourceOrigin:
    return SourceOrigin(
        SourceSpan(filename, line, column, end_line, end_column),
        name,
    )


@lru_cache(maxsize=8192)
def _synthetic_origin(reason: str) -> SyntheticOrigin:
    return SyntheticOrigin(reason)


def normalize_origin(origin: object | None):
    if origin is None or isinstance(origin, (SourceOrigin, SyntheticOrigin)):
        return origin
    filename = getattr(origin, "filename", None)
    line = getattr(origin, "lineno", None)
    column = getattr(origin, "col", None)
    if filename is not None or line is not None or column is not None:
        return _source_origin(
            str(filename or ""),
            int(line or 0),
            int(column or 0),
            getattr(origin, "end_lineno", None),
            getattr(origin, "end_col", None),
            getattr(origin, "name", None),
        )
    return _synthetic_origin(str(origin))


@dataclass(frozen=True)
class TransformationFrame:
    kind: str
    inputs: tuple[NodeId, ...] = ()
    source: SourceOrigin | SyntheticOrigin | None = None
    detail: str = ""


@dataclass(frozen=True)
class RebuildProvenanceSeed:
    """Metadata transfer for a node created before a catalog rebuild."""

    node: object
    code: object
    origin: SourceOrigin | SyntheticOrigin | None
    inputs: tuple[NodeId, ...]
    transform: str
    detail: str = ""


class SourceMap:
    def __init__(self) -> None:
        self._node_origins: dict[NodeId, object] = {}
        self._symbol_origins: dict[SymbolId, object] = {}
        self._provenance: dict[NodeId, tuple[TransformationFrame, ...]] = {}
        self._normalization_cache: dict[int, tuple[object, object | None]] = {}

    def _normalize(self, origin: object | None):
        if origin is None or isinstance(origin, (SourceOrigin, SyntheticOrigin)):
            return origin
        key = id(origin)
        cached = self._normalization_cache.get(key)
        if cached is not None and cached[0] is origin:
            return cached[1]
        normalized = normalize_origin(origin)
        if len(self._normalization_cache) >= 8192:
            self._normalization_cache.clear()
        self._normalization_cache[key] = (origin, normalized)
        return normalized

    def set_origin(self, node: NodeId, origin: object | None) -> None:
        origin = self._normalize(origin)
        if origin is None:
            self._node_origins.pop(node, None)
        else:
            self._node_origins[node] = origin

    def origin(self, node: NodeId) -> object | None:
        return self._node_origins.get(node)

    def set_declaration(self, symbol: SymbolId, origin: object | None) -> None:
        origin = self._normalize(origin)
        if origin is None:
            self._symbol_origins.pop(symbol, None)
        else:
            self._symbol_origins[symbol] = origin

    def declaration(self, symbol: SymbolId) -> object | None:
        return self._symbol_origins.get(symbol)

    def set_provenance(
        self, node: NodeId, frames: tuple[TransformationFrame, ...]
    ) -> None:
        self._provenance[node] = tuple(frames)

    def append_provenance(self, node: NodeId, frame: TransformationFrame) -> None:
        self._provenance[node] = (*self._provenance.get(node, ()), frame)

    def provenance(self, node: NodeId) -> tuple[TransformationFrame, ...]:
        return self._provenance.get(node, ())


def source_filename(origin: object | None) -> str:
    normalized = normalize_origin(origin)
    if isinstance(normalized, SourceOrigin):
        return normalized.span.path
    return ""


def format_source(origin: object | None) -> str:
    normalized = normalize_origin(origin)
    if normalized is None:
        return "<unknown source>"
    if isinstance(normalized, SyntheticOrigin):
        return f"<synthetic: {normalized.reason}>"
    span = normalized.span
    position = f"{span.path}:{span.start_line}:{span.start_column}"
    return f"{normalized.name} ({position})" if normalized.name else position


__all__ = [
    "SourceMap",
    "SourceOrigin",
    "SourceSpan",
    "SyntheticOrigin",
    "TransformationFrame",
    "RebuildProvenanceSeed",
    "format_source",
    "normalize_origin",
    "source_filename",
]
