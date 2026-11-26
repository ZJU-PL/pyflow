"""Typed storage identities shared by semantic and data-flow analyses."""

from __future__ import annotations

from dataclasses import dataclass

from .ids import SymbolId, ValueId


class StorageLocation:
    """Marker base for immutable abstract storage identities."""

    __slots__ = ()


@dataclass(frozen=True, slots=True)
class LocalStorage(StorageLocation):
    symbol: SymbolId


@dataclass(frozen=True, slots=True)
class CellStorage(StorageLocation):
    symbol: SymbolId


@dataclass(frozen=True, slots=True)
class GlobalStorage(StorageLocation):
    module: str
    name: str


@dataclass(frozen=True, slots=True)
class AttributeStorage(StorageLocation):
    base: ValueId | StorageLocation | object
    field: object


@dataclass(frozen=True, slots=True)
class SubscriptStorage(StorageLocation):
    base: ValueId | StorageLocation | object
    key: object


@dataclass(frozen=True, slots=True)
class SummaryStorage(StorageLocation):
    base: ValueId | StorageLocation | object
    kind: str


@dataclass(frozen=True, slots=True)
class UnknownStorage(StorageLocation):
    kind: str = "unknown"
