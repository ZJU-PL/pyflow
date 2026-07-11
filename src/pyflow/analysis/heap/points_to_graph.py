"""Read-only points-to graph extracted from :class:`HeapAbstraction`.

The points-to graph is a snapshot of the heap state — canonical locations,
alias equivalence classes, escape status, reference counts, and update
policies.  It is the primary query surface for heap facts consumed by
optimization passes, the semantic query API, and debugging tooling.

Typical usage::

    >>> graph = heap_abstraction.to_points_to_graph()
    >>> graph.never_escapes(location)
    True
    >>> graph.single_reference(location)
    False
    >>> graph.aliased(loc_a, loc_b)
    True
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .model import HeapLocation, UpdatePolicy


@dataclass(frozen=True)
class PointsToEntry:
    """One canonical heap location and its alias/escape metadata.

    Each entry corresponds to a root-level :class:`HeapLocation` within the
    heap abstraction.  Nested field/element locations do not receive their
    own entries; their update policy is derived from the root entry.
    """

    location: "HeapLocation"
    """The canonical heap location (root-only; no nested selectors)."""

    label: str
    """Human-readable label for display and debugging."""

    aliases: "frozenset[HeapLocation]"
    """All root locations in the same alias equivalence class, including self."""

    ref_count: int
    """Total reference count for the equivalence class (from ``_site_ref_counts``)."""

    is_escaped: bool
    """Whether the root has been marked as escaped."""

    is_singleton: bool
    """Whether the root is eligible for strong updates (fresh + local + not escaped)."""

    update_policy: "UpdatePolicy"
    """Default update policy for writes to this location."""

    @property
    def is_strong(self) -> bool:
        """Shorthand: can this location receive strong updates?"""
        from .model import UpdatePolicy

        return self.update_policy is UpdatePolicy.STRONG

    def to_dict(self) -> dict[str, object]:
        """Serialize for inspection / JSON output."""
        return {
            "location": self.location.to_dict(),
            "label": self.label,
            "alias_count": len(self.aliases),
            "aliases": sorted(loc.root.label for loc in self.aliases if loc.root.label),
            "ref_count": self.ref_count,
            "is_escaped": self.is_escaped,
            "is_singleton": self.is_singleton,
            "update_policy": self.update_policy.value,
        }


@dataclass
class PointsToGraph:
    """A read-only snapshot of the heap state extracted from :class:`HeapAbstraction`.

    The graph maps every canonical root :class:`HeapLocation` to a
    :class:`PointsToEntry` and provides convenience query methods for
    alias, escape, and reference-count checks.  It is produced once via
    :meth:`HeapAbstraction.to_points_to_graph` and then consumed by
    optimization passes and the query API without touching the mutable
    heap state.
    """

    entries: "dict[HeapLocation, PointsToEntry]" = field(default_factory=dict)
    """Root location → metadata mapping."""

    # ── query methods ──────────────────────────────────────────────────

    def get(self, location: "HeapLocation") -> "PointsToEntry | None":
        """Look up the metadata for a root location.

        If *location* is a nested field/element location, the entry for its
        root is returned.  Returns ``None`` when the location is unknown.
        """
        root = location.root_location()
        return self.entries.get(root)

    def points_to(
        self,
        location: "HeapLocation",
    ) -> "frozenset[HeapLocation]":
        """Return all locations aliased with *location* (equivalence class).

        For nested locations the equivalence class of the root is returned.
        """
        entry = self.get(location)
        if entry is None:
            return frozenset({location})
        return entry.aliases

    def never_escapes(self, location: "HeapLocation") -> bool:
        """Return ``True`` if *location*'s root has **not** been marked escaped.

        Returns ``True`` (i.e. "has never escaped") for unknown locations to
        avoid spurious conservative results — callers tracking escape should
        ensure the location exists in the graph first.
        """
        entry = self.get(location)
        if entry is None:
            return True  # unknown → assume local
        return not entry.is_escaped

    def is_escaped(self, location: "HeapLocation") -> bool:
        """Return ``True`` if *location*'s root has been marked escaped."""
        entry = self.get(location)
        if entry is None:
            return False
        return entry.is_escaped

    def single_reference(self, location: "HeapLocation") -> bool:
        """Return ``True`` if *location*'s equivalence class has ≤ 1 reference.

        This is the gate for strong updates: when exactly one reference
        exists, a write can safely overwrite prior facts.
        """
        entry = self.get(location)
        if entry is None:
            return True
        return entry.ref_count <= 1

    def reference_count(self, location: "HeapLocation") -> int:
        """Return the total reference count for *location*'s equivalence class."""
        entry = self.get(location)
        if entry is None:
            return 0
        return entry.ref_count

    def strong_update_possible(self, location: "HeapLocation") -> bool:
        """Return ``True`` if writes to *location* can use strong updates.

        Equivalent to ``is_singleton and not is_escaped`` for root
        locations and ``allow_strong_nested_fresh and single_reference``
        for nested locations (policy-dependent).
        """
        from .model import UpdatePolicy

        entry = self.get(location)
        if entry is None:
            return False
        return entry.update_policy is UpdatePolicy.STRONG

    def aliased(self, a: "HeapLocation", b: "HeapLocation") -> bool:
        """Return ``True`` if *a* and *b* belong to the same alias class.

        Two locations are aliased when their roots share an equivalence
        class (union-find canonical root is the same).  This is must-alias
        for known roots and conservative for unknown roots.
        """
        if a == b:
            return True
        entry_a = self.get(a)
        entry_b = self.get(b)
        if entry_a is None or entry_b is None:
            return a == b
        # Check if the equivalence classes overlap.
        # Since each location belongs to exactly one equivalence class
        # and aliases includes self, intersection means same class.
        return not entry_a.aliases.isdisjoint(entry_b.aliases)

    def may_alias(self, a: "HeapLocation", b: "HeapLocation") -> bool:
        """Return ``True`` if *a* and *b* **may** refer to the same storage.

        This is conservative: returns ``True`` unless both locations are
        known to be distinct (different, non-overlapping equivalence classes).
        """
        if self.aliased(a, b):
            return True
        entry_a = self.get(a)
        entry_b = self.get(b)
        if entry_a is None or entry_b is None:
            return True  # unknown → may alias
        return False  # distinct classes → must not alias

    def escaped_locations(self) -> "frozenset[HeapLocation]":
        """Return all root locations that have been marked escaped."""
        return frozenset(
            entry.location
            for entry in self.entries.values()
            if entry.is_escaped
        )

    def singleton_locations(self) -> "frozenset[HeapLocation]":
        """Return all root locations eligible for strong updates."""
        return frozenset(
            entry.location
            for entry in self.entries.values()
            if entry.is_singleton
        )

    # ── bulk queries ───────────────────────────────────────────────────

    def iter_entries(self):
        """Yield every :class:`PointsToEntry` in the graph."""
        yield from self.entries.values()

    def __len__(self) -> int:
        return len(self.entries)

    def __bool__(self) -> bool:
        return bool(self.entries)

    def to_dict(self) -> dict[str, object]:
        """Serialize the full graph for inspection / JSON output."""
        return {
            "entry_count": len(self.entries),
            "escaped_count": len(self.escaped_locations()),
            "singleton_count": len(self.singleton_locations()),
            "entries": [entry.to_dict() for entry in self.entries.values()],
        }
