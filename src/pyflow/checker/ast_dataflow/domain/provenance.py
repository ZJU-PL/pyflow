"""Bounded provenance values used to explain taint propagation."""

from __future__ import annotations

from dataclasses import dataclass
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


@dataclass(frozen=True, order=True)
class ProvenanceEdge:
    """One bounded explanation edge between abstract facts."""

    source: ProvenanceNode
    target: ProvenanceNode
    operation: ProvenanceOperation
    filename: str | None = None
    line: int | None = None
    detail: str | None = None
