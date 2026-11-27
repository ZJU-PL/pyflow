"""Bounded provenance values used to explain taint propagation."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum

from .locations import TaintLocation


@dataclass(frozen=True, order=True)
class TaintOrigin:
    """Stable identity for one modeled source occurrence."""

    kind: str
    filename: str | None = None
    line: int | None = None
    column: int | None = None
    symbol: str | None = None
    _cached_hash: int | None = field(default=None, init=False, repr=False, compare=False)

    def __hash__(self) -> int:
        cached = self._cached_hash
        if cached is None:
            cached = hash((self.kind, self.filename, self.line, self.column, self.symbol))
            object.__setattr__(self, "_cached_hash", cached)
        return cached


class ProvenanceOperation(str, Enum):
    SOURCE = "source"
    ASSIGN = "assign"
    READ = "read"
    WRITE = "write"
    CALL = "call"
    RETURN = "return"
    YIELD = "yield"
    RAISE = "raise"
    SANITIZE = "sanitize"
    JOIN = "join"
    HAVOC = "havoc"


@dataclass(frozen=True, order=True)
class ProvenanceNode:
    location: TaintLocation
    kind: str
    origin: TaintOrigin
    _cached_hash: int | None = field(default=None, init=False, repr=False, compare=False)

    def __hash__(self) -> int:
        cached = self._cached_hash
        if cached is None:
            cached = hash((self.location, self.kind, self.origin))
            object.__setattr__(self, "_cached_hash", cached)
        return cached


@dataclass(frozen=True, order=True)
class ProvenanceEdge:
    """One bounded explanation edge between abstract facts."""

    source: ProvenanceNode
    target: ProvenanceNode
    operation: ProvenanceOperation
    filename: str | None = None
    line: int | None = None
    detail: str | None = None
    _cached_hash: int | None = field(default=None, init=False, repr=False, compare=False)

    def __hash__(self) -> int:
        cached = self._cached_hash
        if cached is None:
            cached = hash(
                (self.source, self.target, self.operation, self.filename, self.line, self.detail)
            )
            object.__setattr__(self, "_cached_hash", cached)
        return cached
