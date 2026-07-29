"""Typed storage identities shared by semantic and data-flow analyses."""

from __future__ import annotations

from dataclasses import dataclass

from .ids import SymbolId, ValueId


class StorageLocation:
    """Marker base for immutable abstract storage identities."""


@dataclass(frozen=True)
class LocalStorage(StorageLocation):
    symbol: SymbolId


@dataclass(frozen=True)
class CellStorage(StorageLocation):
    symbol: SymbolId


@dataclass(frozen=True)
class GlobalStorage(StorageLocation):
    module: str
    name: str


@dataclass(frozen=True)
class AttributeStorage(StorageLocation):
    base: ValueId | StorageLocation | object
    field: object


@dataclass(frozen=True)
class SubscriptStorage(StorageLocation):
    base: ValueId | StorageLocation | object
    key: object


@dataclass(frozen=True)
class SummaryStorage(StorageLocation):
    base: ValueId | StorageLocation | object
    kind: str


@dataclass(frozen=True)
class UnknownStorage(StorageLocation):
    kind: str = "unknown"
