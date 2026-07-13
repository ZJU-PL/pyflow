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

    allow_strong_nested_fresh: bool = False
    """Whether exact paths below singleton roots admit strong updates."""

    heap_values: "dict[HeapLocation, frozenset[HeapLocation]]" = field(
        default_factory=dict
    )
    heap_contaminants: "dict[HeapLocation, frozenset[HeapLocation]]" = field(
        default_factory=dict
    )
    program_point_values: "dict[int, tuple[dict[HeapLocation, frozenset[HeapLocation]], dict[HeapLocation, frozenset[HeapLocation]]]]" = field(
        default_factory=dict
    )
    program_point_contaminants: "dict[int, tuple[dict[HeapLocation, frozenset[HeapLocation]], dict[HeapLocation, frozenset[HeapLocation]]]]" = field(
        default_factory=dict
    )

    # ── query methods ──────────────────────────────────────────────────

    def __contains__(self, location: "HeapLocation") -> bool:
        return location.root_location() in self.entries

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

    def values_at(
        self,
        location: "HeapLocation",
        operation: object | None = None,
        *,
        before: bool = False,
    ) -> "frozenset[HeapLocation]":
        """Return possible values stored at *location*.

        When *operation* is supplied, query the state immediately before or
        after that IR node.  Wildcard contaminants overlapping the requested
        path are included.
        """
        values = self.heap_values
        contaminants = self.heap_contaminants
        if operation is not None:
            index = 0 if before else 1
            point_values = self.program_point_values.get(id(operation))
            point_contaminants = self.program_point_contaminants.get(id(operation))
            if point_values is not None:
                values = point_values[index]
            if point_contaminants is not None:
                contaminants = point_contaminants[index]
        result = list(values.get(location, ()))
        from .heap_state import HeapState

        for contaminant, stored in contaminants.items():
            if HeapState.locations_may_overlap(location, contaminant):
                result.extend(stored)
        return frozenset(result)

    def never_escapes(self, location: "HeapLocation") -> bool:
        """Return ``True`` if *location*'s root has **not** been marked escaped.

        Unknown locations cannot prove non-escape and therefore return False.
        """
        entry = self.get(location)
        if entry is None:
            return False
        return not entry.is_escaped

    def is_escaped(self, location: "HeapLocation") -> bool:
        """Return ``True`` if *location*'s root has been marked escaped."""
        entry = self.get(location)
        if entry is None:
            return True
        return entry.is_escaped

    def single_reference(self, location: "HeapLocation") -> bool:
        """Return ``True`` if *location*'s equivalence class has ≤ 1 reference.

        This is the gate for strong updates: when exactly one reference
        exists, a write can safely overwrite prior facts.
        """
        entry = self.get(location)
        if entry is None:
            return False
        return entry.ref_count <= 1

    def reference_count(self, location: "HeapLocation") -> int:
        """Return the total reference count for *location*'s equivalence class."""
        entry = self.get(location)
        if entry is None:
            return 2
        return entry.ref_count

    def strong_update_possible(self, location: "HeapLocation") -> bool:
        """Return ``True`` if writes to *location* can use strong updates.

        Nested locations use the graph's fixed heap policy and root
        cardinality; escape and the number of aliases do not change the fact
        that a precise write overwrites a field of one concrete object.
        """
        from .model import UpdatePolicy

        entry = self.get(location)
        if entry is None:
            return False
        if location.is_nested():
            return self.allow_strong_nested_fresh and entry.is_singleton
        return entry.update_policy is UpdatePolicy.STRONG

    def aliased(self, a: "HeapLocation", b: "HeapLocation") -> bool:
        """Return ``True`` if *a* and *b* belong to the same alias class.

        Two locations are aliased when their roots share an equivalence
        class (union-find canonical root is the same) and their selector
        paths are identical.  This is must-alias for known roots and
        conservative for unknown roots.
        """
        if a == b:
            return True
        entry_a = self.get(a)
        entry_b = self.get(b)
        if entry_a is None or entry_b is None:
            return a == b
        if entry_a.aliases.isdisjoint(entry_b.aliases):
            return False
        return a.selectors == b.selectors

    def may_alias(self, a: "HeapLocation", b: "HeapLocation") -> bool:
        """Return ``True`` if *a* and *b* **may** refer to the same storage.

        This is conservative: returns ``True`` for overlapping root
        equivalence classes when selector paths may overlap, including
        wildcard/summary selectors.
        """
        if self.aliased(a, b):
            return True
        entry_a = self.get(a)
        entry_b = self.get(b)
        if entry_a is None or entry_b is None:
            return True  # unknown → may alias
        if self._roots_may_overlap(a.root, b.root):
            return self._selectors_may_overlap(a.selectors, b.selectors)
        if entry_a.aliases.isdisjoint(entry_b.aliases):
            return False
        return self._selectors_may_overlap(a.selectors, b.selectors)

    @staticmethod
    def _roots_may_overlap(a: object, b: object) -> bool:
        from .model import HeapObjectKind

        kind_a = getattr(a, "kind", None)
        kind_b = getattr(b, "kind", None)
        if kind_a in {
            HeapObjectKind.SUMMARY,
            HeapObjectKind.UNKNOWN,
            HeapObjectKind.CALL_RESULT,
            HeapObjectKind.RETURN,
        }:
            return True
        if kind_b in {
            HeapObjectKind.SUMMARY,
            HeapObjectKind.UNKNOWN,
            HeapObjectKind.CALL_RESULT,
            HeapObjectKind.RETURN,
        }:
            return True
        value_kinds = {
            HeapObjectKind.LOCAL,
            HeapObjectKind.PARAMETER,
            HeapObjectKind.RETURN,
            HeapObjectKind.ALLOCATION,
            HeapObjectKind.CALL_RESULT,
            HeapObjectKind.EXTERNAL,
            HeapObjectKind.SUMMARY,
            HeapObjectKind.UNKNOWN,
            HeapObjectKind.STORAGE,
        }
        if kind_a is HeapObjectKind.PARAMETER:
            return kind_b in value_kinds
        if kind_b is HeapObjectKind.PARAMETER:
            return kind_a in value_kinds
        return False

    def may_alias_path(self, a: "HeapLocation", b: "HeapLocation") -> bool:
        """Return whether two full access paths may overlap."""
        return self.may_alias(a, b)

    def label_for(self, location: "HeapLocation") -> str:
        """Return a stable display label for a root or nested location."""
        entry = self.get(location)
        if entry is None:
            label = location.root.label
        else:
            label = entry.label
        for selector in location.selectors:
            kind = getattr(selector, "kind", None)
            value = getattr(selector, "value", None)
            precise = getattr(selector, "precise", True)
            if kind == "field":
                label = f"{label}.*" if not precise else f"{label}.{value}"
            elif kind in {"element", "index"}:
                label = f"{label}[*]" if not precise else f"{label}[{value}]"
            elif kind == "key":
                label = f"{label}[{value!r}]"
            elif kind == "slice":
                label = f"{label}[slice]"
            elif kind == "summary":
                label = f"{label}.*"
        return label

    def locations_by_label(self) -> dict[str, "frozenset[HeapLocation]"]:
        """Return root locations grouped by display and root labels."""
        grouped: dict[str, set[HeapLocation]] = {}
        for entry in self.entries.values():
            grouped.setdefault(entry.label, set()).add(entry.location)
            root_label = entry.location.root.label
            if root_label:
                grouped.setdefault(root_label, set()).add(entry.location)
        return {
            label: frozenset(locations)
            for label, locations in grouped.items()
        }

    def alias_evidence(
        self,
        a: "HeapLocation",
        b: "HeapLocation",
    ) -> dict[str, object]:
        """Explain the graph evidence behind an alias query."""
        entry_a = self.get(a)
        entry_b = self.get(b)
        same_alias_class = False
        selector_overlap = False
        if entry_a is not None and entry_b is not None:
            same_alias_class = not entry_a.aliases.isdisjoint(entry_b.aliases)
            selector_overlap = self._selectors_may_overlap(a.selectors, b.selectors)
        return {
            "a": self.label_for(a),
            "b": self.label_for(b),
            "known_a": entry_a is not None,
            "known_b": entry_b is not None,
            "same_alias_class": same_alias_class,
            "same_path": a.selectors == b.selectors,
            "selector_overlap": selector_overlap,
            "aliased": self.aliased(a, b),
            "may_alias": self.may_alias(a, b),
        }

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
            "heap_value_location_count": len(self.heap_values),
            "program_point_count": len(self.program_point_values),
            "entries": [entry.to_dict() for entry in self.entries.values()],
        }

    @staticmethod
    def _selectors_may_overlap(a: tuple[object, ...], b: tuple[object, ...]) -> bool:
        if a == b:
            return True
        min_len = min(len(a), len(b))
        for index in range(min_len):
            if not PointsToGraph._selector_may_overlap(a[index], b[index]):
                return False
        return True

    @staticmethod
    def _selector_may_overlap(a: object, b: object) -> bool:
        if a == b:
            return True
        precise_a = getattr(a, "precise", True)
        precise_b = getattr(b, "precise", True)
        if not precise_a or not precise_b:
            return True
        kind_a = getattr(a, "kind", None)
        kind_b = getattr(b, "kind", None)
        if kind_a == "summary" or kind_b == "summary":
            return True
        if kind_a == "slice" and kind_b in {"element", "index", "key", "slice"}:
            return True
        if kind_b == "slice" and kind_a in {"element", "index", "key", "slice"}:
            return True
        return False
