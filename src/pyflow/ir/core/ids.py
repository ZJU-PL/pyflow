"""Deterministic, typed identifiers for IR entities."""

from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256


@dataclass(frozen=True, order=True)
class IRRevision:
    value: int = 0

    def next(self) -> "IRRevision":
        return IRRevision(self.value + 1)

    def __str__(self) -> str:
        return f"r{self.value}"


@dataclass(frozen=True, order=True)
class SourceAnchor:
    """Stable source anchor used to disambiguate definitions with equal names."""

    filename: str = ""
    line: int = 0
    column: int = 0

    def __str__(self) -> str:
        if not self.filename:
            return "<synthetic>"
        return f"{self.filename}:{self.line}:{self.column}"


@dataclass(frozen=True, order=True)
class CodeId:
    module: str
    qualname: str
    anchor: SourceAnchor = SourceAnchor()
    ordinal: int = 0

    def __str__(self) -> str:
        suffix = f"~{self.ordinal}" if self.ordinal else ""
        return f"{self.module}:{self.qualname}@{self.anchor}{suffix}"


@dataclass(frozen=True, order=True)
class ScopeId:
    code: CodeId
    ordinal: int = 0

    def __str__(self) -> str:
        return f"{self.code}/scope{self.ordinal}"


@dataclass(frozen=True, order=True)
class SymbolId:
    scope: ScopeId
    ordinal: int

    def __str__(self) -> str:
        return f"{self.scope}/s{self.ordinal}"


@dataclass(frozen=True, order=True)
class NodeId:
    code: CodeId
    ordinal: int

    def __str__(self) -> str:
        return f"{self.code}/n{self.ordinal}"


@dataclass(frozen=True, order=True)
class BlockId:
    code: CodeId
    ordinal: int

    def __str__(self) -> str:
        return f"{self.code}/bb{self.ordinal}"


@dataclass(frozen=True, order=True)
class EdgeId:
    source: BlockId
    label: str
    occurrence: int = 0

    def __str__(self) -> str:
        suffix = f".{self.occurrence}" if self.occurrence else ""
        return f"{self.source}/{self.label}{suffix}"


@dataclass(frozen=True, order=True)
class ValueId:
    symbol: SymbolId
    version: int

    def __str__(self) -> str:
        return f"{self.symbol}/v{self.version}"


@dataclass(frozen=True, order=True)
class CallSiteId:
    node: NodeId
    ordinal: int = 0

    def __str__(self) -> str:
        return f"{self.node}/call{self.ordinal}"


@dataclass(frozen=True, order=True)
class AllocationSiteId:
    node: NodeId
    ordinal: int = 0

    def __str__(self) -> str:
        return f"{self.node}/alloc{self.ordinal}"


@dataclass(frozen=True, order=True)
class ContextSignature:
    """Canonical, process-independent description of an analysis context."""

    value: str

    @property
    def digest(self) -> str:
        return sha256(self.value.encode("utf-8")).hexdigest()

    def __str__(self) -> str:
        return self.digest[:16]


@dataclass(frozen=True, order=True)
class ContextId:
    code: CodeId
    signature: ContextSignature

    def __str__(self) -> str:
        return f"{self.code}/ctx.{self.signature}"


@dataclass(frozen=True, order=True)
class InlineInstanceId:
    call_site: CallSiteId
    ordinal: int = 0

    def __str__(self) -> str:
        return f"{self.call_site}/inline{self.ordinal}"
