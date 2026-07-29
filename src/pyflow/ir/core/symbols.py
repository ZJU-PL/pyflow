"""Lexical symbols and SSA values."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Iterator

from .ids import NodeId, ScopeId, SymbolId, ValueId


class SymbolKind(str, Enum):
    PARAMETER = "parameter"
    LOCAL = "local"
    CELL = "cell"
    NONLOCAL = "nonlocal"
    GLOBAL = "global"
    RETURN = "return"
    TEMPORARY = "temporary"
    EXCEPTION = "exception"
    PATTERN = "pattern"


@dataclass(frozen=True)
class Symbol:
    id: SymbolId
    name: str
    kind: SymbolKind
    declaration_origin: object | None = None
    source_symbol: SymbolId | None = None

    @property
    def display_name(self) -> str:
        if self.kind is SymbolKind.TEMPORARY and not self.name.startswith("%"):
            return f"%{self.name}"
        return self.name


@dataclass(frozen=True)
class Value:
    id: ValueId
    definition: NodeId | None = None


class SymbolTable:
    """Own all lexical bindings for one IR catalog."""

    def __init__(self) -> None:
        self._symbols: dict[SymbolId, Symbol] = {}
        self._bindings: dict[tuple[ScopeId, str, SymbolKind], SymbolId] = {}
        self._next_ordinal: dict[ScopeId, int] = {}

    def intern(
        self,
        scope: ScopeId,
        name: str,
        kind: SymbolKind = SymbolKind.LOCAL,
        *,
        declaration_origin: object | None = None,
        source_symbol: SymbolId | None = None,
    ) -> Symbol:
        key = (scope, name, kind)
        existing = self._bindings.get(key)
        if existing is not None:
            symbol = self._symbols[existing]
            if (
                declaration_origin is not None
                and symbol.declaration_origin is None
            ):
                symbol = Symbol(
                    symbol.id,
                    symbol.name,
                    symbol.kind,
                    declaration_origin,
                    symbol.source_symbol,
                )
                self._symbols[symbol.id] = symbol
            return symbol
        return self.fresh(
            scope,
            name,
            kind,
            declaration_origin=declaration_origin,
            source_symbol=source_symbol,
            bind=True,
        )

    def fresh(
        self,
        scope: ScopeId,
        name: str,
        kind: SymbolKind = SymbolKind.TEMPORARY,
        *,
        declaration_origin: object | None = None,
        source_symbol: SymbolId | None = None,
        bind: bool = False,
    ) -> Symbol:
        ordinal = self._next_ordinal.get(scope, 0)
        self._next_ordinal[scope] = ordinal + 1
        symbol = Symbol(
            SymbolId(scope, ordinal),
            name,
            kind,
            declaration_origin,
            source_symbol,
        )
        self._symbols[symbol.id] = symbol
        if bind:
            self._bindings[(scope, name, kind)] = symbol.id
        return symbol

    def __getitem__(self, symbol_id: SymbolId) -> Symbol:
        return self._symbols[symbol_id]

    def get(self, symbol_id: SymbolId) -> Symbol | None:
        return self._symbols.get(symbol_id)

    def find(
        self,
        scope: ScopeId,
        name: str,
        kinds: tuple[SymbolKind, ...] | None = None,
    ) -> Symbol | None:
        allowed = kinds or tuple(SymbolKind)
        for kind in allowed:
            symbol_id = self._bindings.get((scope, name, kind))
            if symbol_id is not None:
                return self._symbols[symbol_id]
        return None

    def __iter__(self) -> Iterator[Symbol]:
        return iter(sorted(self._symbols.values(), key=lambda symbol: symbol.id))

    def __len__(self) -> int:
        return len(self._symbols)


class ValueTable:
    """Allocate deterministic SSA versions and record their definitions."""

    def __init__(self) -> None:
        self._next_version: dict[SymbolId, int] = {}
        self._values: dict[ValueId, Value] = {}

    def define(self, symbol: SymbolId, definition: NodeId | None = None) -> Value:
        version = self._next_version.get(symbol, 0)
        self._next_version[symbol] = version + 1
        value = Value(ValueId(symbol, version), definition)
        self._values[value.id] = value
        return value

    def __getitem__(self, value_id: ValueId) -> Value:
        return self._values[value_id]

    def get(self, value_id: ValueId) -> Value | None:
        return self._values.get(value_id)

    def __iter__(self) -> Iterator[Value]:
        return iter(sorted(self._values.values(), key=lambda value: value.id))

    def __len__(self) -> int:
        return len(self._values)
