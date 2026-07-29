"""Explicit identity remaps produced by structural IR transformations."""

from __future__ import annotations

from dataclasses import dataclass, field
from types import MappingProxyType
from typing import Mapping, TypeVar

from .ids import (
    AllocationSiteId,
    BlockId,
    CallSiteId,
    EdgeId,
    IRRevision,
    NodeId,
    SymbolId,
    ValueId,
)


Identity = TypeVar("Identity")


def _freeze(mapping: Mapping[Identity, tuple[Identity, ...]]):
    return MappingProxyType(
        {identity: tuple(targets) for identity, targets in mapping.items()}
    )


@dataclass(frozen=True)
class IRRemap:
    """Complete, immutable mapping between two adjacent IR revisions.

    One source identity may map to zero, one, or several target identities.
    Empty target tuples represent removal; identities in ``created_*`` have no
    predecessor in the prior revision.
    """

    before: IRRevision
    after: IRRevision
    transform: str
    nodes: Mapping[NodeId, tuple[NodeId, ...]] = field(
        default_factory=lambda: MappingProxyType({})
    )
    blocks: Mapping[BlockId, tuple[BlockId, ...]] = field(
        default_factory=lambda: MappingProxyType({})
    )
    edges: Mapping[EdgeId, tuple[EdgeId, ...]] = field(
        default_factory=lambda: MappingProxyType({})
    )
    symbols: Mapping[SymbolId, tuple[SymbolId, ...]] = field(
        default_factory=lambda: MappingProxyType({})
    )
    values: Mapping[ValueId, tuple[ValueId, ...]] = field(
        default_factory=lambda: MappingProxyType({})
    )
    call_sites: Mapping[CallSiteId, tuple[CallSiteId, ...]] = field(
        default_factory=lambda: MappingProxyType({})
    )
    allocation_sites: Mapping[
        AllocationSiteId, tuple[AllocationSiteId, ...]
    ] = field(default_factory=lambda: MappingProxyType({}))
    created_nodes: frozenset[NodeId] = frozenset()
    created_blocks: frozenset[BlockId] = frozenset()
    created_edges: frozenset[EdgeId] = frozenset()
    created_symbols: frozenset[SymbolId] = frozenset()
    created_values: frozenset[ValueId] = frozenset()
    created_call_sites: frozenset[CallSiteId] = frozenset()
    created_allocation_sites: frozenset[AllocationSiteId] = frozenset()

    @classmethod
    def create(
        cls,
        *,
        before: IRRevision,
        after: IRRevision,
        transform: str,
        nodes: Mapping[NodeId, tuple[NodeId, ...]] | None = None,
        blocks: Mapping[BlockId, tuple[BlockId, ...]] | None = None,
        edges: Mapping[EdgeId, tuple[EdgeId, ...]] | None = None,
        symbols: Mapping[SymbolId, tuple[SymbolId, ...]] | None = None,
        values: Mapping[ValueId, tuple[ValueId, ...]] | None = None,
        call_sites: Mapping[CallSiteId, tuple[CallSiteId, ...]] | None = None,
        allocation_sites: Mapping[
            AllocationSiteId, tuple[AllocationSiteId, ...]
        ]
        | None = None,
        created_nodes: frozenset[NodeId] = frozenset(),
        created_blocks: frozenset[BlockId] = frozenset(),
        created_edges: frozenset[EdgeId] = frozenset(),
        created_symbols: frozenset[SymbolId] = frozenset(),
        created_values: frozenset[ValueId] = frozenset(),
        created_call_sites: frozenset[CallSiteId] = frozenset(),
        created_allocation_sites: frozenset[AllocationSiteId] = frozenset(),
    ) -> "IRRemap":
        return cls(
            before,
            after,
            transform,
            _freeze(nodes or {}),
            _freeze(blocks or {}),
            _freeze(edges or {}),
            _freeze(symbols or {}),
            _freeze(values or {}),
            _freeze(call_sites or {}),
            _freeze(allocation_sites or {}),
            frozenset(created_nodes),
            frozenset(created_blocks),
            frozenset(created_edges),
            frozenset(created_symbols),
            frozenset(created_values),
            frozenset(created_call_sites),
            frozenset(created_allocation_sites),
        )

    @property
    def changed(self) -> bool:
        return bool(self.before != self.after)


__all__ = ["IRRemap"]
