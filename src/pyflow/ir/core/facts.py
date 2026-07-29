"""Revision-aware immutable analysis fact publication."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Generic, Hashable, Iterable, TypeVar

from .ids import IRRevision


T = TypeVar("T", bound=Hashable)


class Precision(str, Enum):
    EXACT = "exact"
    CONSERVATIVE = "conservative"
    UNKNOWN = "unknown"


@dataclass(frozen=True)
class FactResult(Generic[T]):
    values: frozenset[T]
    precision: Precision
    producer: str
    diagnostics: tuple[object, ...] = ()

    @classmethod
    def exact(cls, values: Iterable[T], producer: str) -> "FactResult[T]":
        return cls(frozenset(values), Precision.EXACT, producer)

    @classmethod
    def conservative(
        cls,
        values: Iterable[T],
        producer: str,
        diagnostics: Iterable[object] = (),
    ) -> "FactResult[T]":
        return cls(
            frozenset(values),
            Precision.CONSERVATIVE,
            producer,
            tuple(diagnostics),
        )

    @classmethod
    def unknown(
        cls, producer: str, diagnostics: Iterable[object] = ()
    ) -> "FactResult[T]":
        return cls(frozenset(), Precision.UNKNOWN, producer, tuple(diagnostics))


@dataclass(frozen=True)
class _Snapshot:
    revision: int
    ir_revision: IRRevision
    producer: str
    facts: dict[Hashable, FactResult]


class FactStore:
    """Publish complete capability snapshots atomically."""

    def __init__(self, ir_revision: IRRevision = IRRevision()) -> None:
        self._revision = 0
        self._ir_revision = ir_revision
        self._snapshots: dict[str, dict[str, _Snapshot]] = {}

    @property
    def ir_revision(self) -> IRRevision:
        return self._ir_revision

    @property
    def revision(self) -> int:
        return self._revision

    def publish(
        self,
        capability: str,
        producer: str,
        facts: dict[Hashable, FactResult],
    ) -> int:
        return self.publish_many(producer, {capability: facts})

    def publish_many(
        self,
        producer: str,
        capabilities: dict[str, dict[Hashable, FactResult]],
    ) -> int:
        """Atomically replace a related family of capability snapshots."""
        self._revision += 1
        revision = self._revision
        for capability, facts in capabilities.items():
            self._snapshots.setdefault(capability, {})[producer] = _Snapshot(
                revision, self._ir_revision, producer, dict(facts)
            )
        return revision

    def replace_many(
        self,
        producer: str,
        capabilities: dict[str, dict[Hashable, FactResult]],
    ) -> int:
        """Atomically replace every producer snapshot for each capability.

        This is reserved for IR-wide filtering/remapping passes whose output
        supersedes the complete joined capability, such as context culling.
        Ordinary analyses should use :meth:`publish_many` and retain producer
        ownership independently.
        """
        self._revision += 1
        revision = self._revision
        for capability, facts in capabilities.items():
            self._snapshots[capability] = {
                producer: _Snapshot(
                    revision,
                    self._ir_revision,
                    producer,
                    dict(facts),
                )
            }
        return revision

    def has(self, capability: str) -> bool:
        return capability in self._snapshots

    def capabilities(self) -> frozenset[str]:
        return frozenset(self._snapshots)

    def query(self, capability: str, key: Hashable) -> FactResult:
        snapshots = self._snapshots.get(capability)
        if not snapshots:
            return FactResult.unknown("fact-store", (f"missing {capability}",))
        stale = tuple(
            snapshot
            for snapshot in snapshots.values()
            if snapshot.ir_revision != self._ir_revision
        )
        if stale:
            return FactResult.unknown(
                "+".join(sorted(snapshot.producer for snapshot in stale)),
                (
                    f"stale {capability} snapshot; current IR is "
                    f"{self._ir_revision}",
                ),
            )
        results = [
            snapshot.facts[key]
            for snapshot in snapshots.values()
            if key in snapshot.facts
        ]
        if not results:
            producers = "+".join(sorted(snapshots))
            return FactResult.unknown(producers, (f"missing fact for {key}",))
        values = frozenset(value for result in results for value in result.values)
        precision = max(
            (result.precision for result in results),
            key=lambda item: {
                Precision.EXACT: 0,
                Precision.CONSERVATIVE: 1,
                Precision.UNKNOWN: 2,
            }[item],
        )
        return FactResult(
            values,
            precision,
            "+".join(sorted({result.producer for result in results})),
            tuple(
                diagnostic
                for result in results
                for diagnostic in result.diagnostics
            ),
        )

    def query_producer(
        self, capability: str, producer: str, key: Hashable
    ) -> FactResult:
        """Query one designated producer without manufacturing a joined view."""
        snapshot = self._snapshots.get(capability, {}).get(producer)
        if snapshot is None:
            return FactResult.unknown(
                producer, (f"missing {capability} producer {producer}",)
            )
        if snapshot.ir_revision != self._ir_revision:
            return FactResult.unknown(
                producer,
                (
                    f"stale {capability} snapshot at {snapshot.ir_revision}; "
                    f"current IR is {self._ir_revision}",
                ),
            )
        return snapshot.facts.get(
            key,
            FactResult.unknown(producer, (f"missing fact for {key}",)),
        )

    def has_producer(self, capability: str, producer: str) -> bool:
        return producer in self._snapshots.get(capability, {})

    def snapshot_revision(self, capability: str) -> int | None:
        snapshots = self._snapshots.get(capability)
        return (
            max(snapshot.revision for snapshot in snapshots.values())
            if snapshots
            else None
        )

    def snapshot_ir_revision(self, capability: str) -> IRRevision | None:
        snapshots = self._snapshots.get(capability)
        if not snapshots:
            return None
        revisions = {snapshot.ir_revision for snapshot in snapshots.values()}
        if len(revisions) != 1:
            raise RuntimeError(f"mixed IR revisions for {capability}: {revisions}")
        return next(iter(revisions))

    def advance_ir_revision(
        self,
        revision: IRRevision,
        *,
        preserved: Iterable[str] = (),
    ) -> None:
        preserved = frozenset(preserved)
        self._snapshots = {
            capability: {
                producer: _Snapshot(
                    snapshot.revision,
                    revision,
                    snapshot.producer,
                    snapshot.facts,
                )
                for producer, snapshot in snapshots.items()
            }
            for capability, snapshots in self._snapshots.items()
            if capability in preserved
        }
        self._ir_revision = revision
        self._revision += 1

    def items(self, capability: str):
        snapshots = self._snapshots.get(capability)
        if not snapshots:
            return ()
        keys: set[Hashable] = set()
        for snapshot in snapshots.values():
            keys.update(snapshot.facts)
        return tuple(
            (key, self.query(capability, key))
            for key in sorted(keys, key=lambda item: str(item))
        )

    def import_producer(
        self,
        other: "FactStore",
        producer: str,
        capabilities: Iterable[str],
    ) -> None:
        """Import identity-remapped snapshots from one matching IR catalog."""
        imported = False
        for capability in capabilities:
            snapshot = other._snapshots.get(capability, {}).get(producer)
            if snapshot is None:
                continue
            self._snapshots.setdefault(capability, {})[producer] = _Snapshot(
                snapshot.revision,
                self._ir_revision,
                snapshot.producer,
                dict(snapshot.facts),
            )
            imported = True
        if imported:
            self._revision += 1

    def invalidate(self, capabilities: Iterable[str]) -> None:
        changed = False
        for capability in capabilities:
            changed |= self._snapshots.pop(capability, None) is not None
        if changed:
            self._revision += 1

    def clear(self) -> None:
        if self._snapshots:
            self._snapshots.clear()
            self._revision += 1
