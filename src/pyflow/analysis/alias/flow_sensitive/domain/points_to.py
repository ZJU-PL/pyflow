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
    >>> graph.must_alias(loc_a, loc_b)
    True
"""

from __future__ import annotations

from collections.abc import Iterator
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from ..model import (
        HeapLocation,
        HeapObjectCardinality,
        HeapObjectIdentity,
        UpdatePolicy,
    )


@dataclass(frozen=True)
class PossibleValues:
    """Possible reference values stored at one heap location."""

    locations: "frozenset[HeapLocation]"
    includes_unknown: bool = False
    definitely_absent: bool = False
    includes_non_reference: bool = False


@dataclass(frozen=True)
class HeapValueSnapshot:
    """Heap value domain for one labeled program-point outcome."""

    values: "dict[HeapLocation, frozenset[HeapLocation]]"
    contaminants: "dict[HeapLocation, frozenset[HeapLocation]]"
    absent: "frozenset[HeapLocation]"
    complete_roots: "frozenset[object]"
    scalar_present: "frozenset[HeapLocation]" = frozenset()
    definitely_scalar_present: "frozenset[HeapLocation]" = frozenset()
    precise_shadows: "frozenset[HeapLocation]" = frozenset()
    locals: "dict[tuple[object, str], frozenset[HeapLocation]]" = field(
        default_factory=dict
    )
    locals_non_reference: "frozenset[tuple[object, str]]" = frozenset()
    locals_unbound: "frozenset[tuple[object, str]]" = frozenset()
    returns: "dict[object, tuple[frozenset[HeapLocation], ...]]" = field(
        default_factory=dict
    )
    yields: "dict[object, frozenset[HeapLocation]]" = field(default_factory=dict)
    raised: "dict[object, frozenset[HeapLocation]]" = field(default_factory=dict)


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
    """Whether the root has cardinality ONE and a local object identity."""

    update_policy: "UpdatePolicy"
    """Default update policy for writes to this location."""

    cardinality: "HeapObjectCardinality"
    """Concrete-object cardinality represented by this root."""

    identity: "HeapObjectIdentity"
    """Whether the abstract root denotes one stable symbolic identity."""

    @property
    def is_strong(self) -> bool:
        """Shorthand: can this location receive strong updates?"""
        from ..model import UpdatePolicy

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
            "cardinality": self.cardinality.value,
            "identity": self.identity.value,
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
    program_point_values: dict[
        object,
        tuple[
            dict[HeapLocation, frozenset[HeapLocation]],
            dict[HeapLocation, frozenset[HeapLocation]],
        ],
    ] = field(default_factory=dict)
    program_point_contaminants: dict[
        object,
        tuple[
            dict[HeapLocation, frozenset[HeapLocation]],
            dict[HeapLocation, frozenset[HeapLocation]],
        ],
    ] = field(default_factory=dict)
    heap_absent: "frozenset[HeapLocation]" = frozenset()
    heap_scalar_present: "frozenset[HeapLocation]" = frozenset()
    heap_definitely_scalar_present: "frozenset[HeapLocation]" = frozenset()
    heap_precise_shadows: "frozenset[HeapLocation]" = frozenset()
    complete_roots: "frozenset[object]" = frozenset()
    program_point_absent: (
        "dict[object, tuple[frozenset[HeapLocation], frozenset[HeapLocation]]]"
    ) = field(default_factory=dict)
    program_point_scalar_present: (
        "dict[object, tuple[frozenset[HeapLocation], frozenset[HeapLocation]]]"
    ) = field(default_factory=dict)
    program_point_definitely_scalar_present: (
        "dict[object, tuple[frozenset[HeapLocation], frozenset[HeapLocation]]]"
    ) = field(default_factory=dict)
    program_point_precise_shadows: (
        "dict[object, tuple[frozenset[HeapLocation], frozenset[HeapLocation]]]"
    ) = field(default_factory=dict)
    program_point_complete_roots: (
        "dict[object, tuple[frozenset[object], frozenset[object]]]"
    ) = field(default_factory=dict)
    program_point_outcomes: "dict[object, dict[str, HeapValueSnapshot]]" = field(
        default_factory=dict
    )
    program_point_locals: dict[
        object,
        tuple[
            dict[tuple[object, str], frozenset[HeapLocation]],
            dict[tuple[object, str], frozenset[HeapLocation]],
        ],
    ] = field(default_factory=dict)
    program_point_local_non_reference: (
        "dict[object, tuple[frozenset[tuple[object, str]], frozenset[tuple[object, str]]]]"
    ) = field(default_factory=dict)
    program_point_local_unbound: (
        "dict[object, tuple[frozenset[tuple[object, str]], frozenset[tuple[object, str]]]]"
    ) = field(default_factory=dict)
    precision_degradations: "dict[object, frozenset[str]]" = field(default_factory=dict)
    operation_identities: "dict[object, object]" = field(default_factory=dict)

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

    def possible_values_at(
        self,
        location: "HeapLocation",
        operation: object | None = None,
        *,
        before: bool = False,
        outcome: str | None = None,
    ) -> PossibleValues:
        """Return possible values stored at *location*.

        When *operation* is supplied, query the state immediately before or
        after that IR node.  Wildcard contaminants overlapping the requested
        path are included.
        """
        values = self.heap_values
        contaminants = self.heap_contaminants
        absent = self.heap_absent
        scalar_present = self.heap_scalar_present
        definitely_scalar_present = self.heap_definitely_scalar_present
        precise_shadows = self.heap_precise_shadows
        complete_roots = self.complete_roots
        if before and outcome is not None:
            raise ValueError("outcome is only valid for post-state queries")
        if operation is not None:
            if outcome is not None:
                snapshot = self.program_point_outcomes.get(self._operation_key(operation), {}).get(
                    outcome
                )
                if snapshot is None:
                    return PossibleValues(
                        frozenset(),
                        definitely_absent=True,
                    )
                values = snapshot.values
                contaminants = snapshot.contaminants
                absent = snapshot.absent
                scalar_present = snapshot.scalar_present
                definitely_scalar_present = snapshot.definitely_scalar_present
                precise_shadows = snapshot.precise_shadows
                complete_roots = snapshot.complete_roots
            else:
                index = 0 if before else 1
                operation_key = self._operation_key(operation)
                point_values = self.program_point_values.get(operation_key)
                point_contaminants = self.program_point_contaminants.get(operation_key)
                if point_values is not None:
                    values = point_values[index]
                if point_contaminants is not None:
                    contaminants = point_contaminants[index]
                point_absent = self.program_point_absent.get(operation_key)
                point_complete = self.program_point_complete_roots.get(operation_key)
                point_scalar = self.program_point_scalar_present.get(operation_key)
                point_definitely_scalar = (
                    self.program_point_definitely_scalar_present.get(operation_key)
                )
                point_shadows = self.program_point_precise_shadows.get(operation_key)
                if point_absent is not None:
                    absent = point_absent[index]
                if point_complete is not None:
                    complete_roots = point_complete[index]
                if point_scalar is not None:
                    scalar_present = point_scalar[index]
                if point_definitely_scalar is not None:
                    definitely_scalar_present = point_definitely_scalar[index]
                if point_shadows is not None:
                    precise_shadows = point_shadows[index]
        result = list(values.get(location, ()))
        from .state import HeapState

        for contaminant, stored in contaminants.items():
            if HeapState.locations_may_overlap(
                location, contaminant
            ) and not self._contaminant_shadowed(
                location,
                contaminant,
                precise_shadows,
            ):
                result.extend(stored)
        locations = frozenset(result)
        has_overlapping_contaminant = any(
            HeapState.locations_may_overlap(location, contaminant)
            and not self._contaminant_shadowed(
                location,
                contaminant,
                precise_shadows,
            )
            for contaminant in contaminants
        )
        definitely_absent = (
            location in absent
            or (
                location.root in complete_roots
                and not locations
                and location not in scalar_present
            )
        ) and not has_overlapping_contaminant
        includes_unknown = any(
            self._root_value_is_unknown(value.root.kind) for value in locations
        ) or (
            not locations
            and not definitely_absent
            and location not in definitely_scalar_present
            and location.root not in complete_roots
        )
        return PossibleValues(
            locations,
            includes_unknown=includes_unknown,
            definitely_absent=definitely_absent,
            includes_non_reference=location in scalar_present,
        )

    def possible_local_values_at(
        self,
        procedure: object,
        local: object,
        operation: object,
        *,
        before: bool = False,
        outcome: str | None = None,
    ) -> PossibleValues:
        """Return the local binding at one program point/outcome."""
        if before and outcome is not None:
            raise ValueError("outcome is only valid for post-state queries")
        name = getattr(local, "name", local)
        key = (self._procedure_key(procedure), str(name))
        if outcome is not None:
            snapshot = self.program_point_outcomes.get(
                self._operation_key(operation), {}
            ).get(outcome)
            if snapshot is None:
                return PossibleValues(frozenset(), definitely_absent=True)
            locations = snapshot.locals.get(key, frozenset())
            includes_non_reference = key in snapshot.locals_non_reference
            may_unbound = key in snapshot.locals_unbound
            known = (
                key in snapshot.locals
                or includes_non_reference
                or may_unbound
            )
        else:
            pair = self.program_point_locals.get(self._operation_key(operation))
            if pair is None:
                return PossibleValues(frozenset(), definitely_absent=True)
            locations = pair[0 if before else 1].get(key, frozenset())
            index = 0 if before else 1
            non_reference_pair = self.program_point_local_non_reference.get(
                self._operation_key(operation),
                (frozenset(), frozenset()),
            )
            unbound_pair = self.program_point_local_unbound.get(
                self._operation_key(operation),
                (frozenset(), frozenset()),
            )
            includes_non_reference = key in non_reference_pair[index]
            may_unbound = key in unbound_pair[index]
            known = (
                key in pair[index]
                or includes_non_reference
                or may_unbound
            )
        return PossibleValues(
            locations,
            includes_unknown=any(
                self._root_value_is_unknown(location.root.kind)
                for location in locations
            ),
            definitely_absent=(
                not known
                or (
                    may_unbound
                    and not locations
                    and not includes_non_reference
                )
            ),
            includes_non_reference=includes_non_reference,
        )

    @staticmethod
    def _root_value_is_unknown(kind: object) -> bool:
        from ..model import HeapObjectKind

        return kind in {
            HeapObjectKind.UNKNOWN,
            HeapObjectKind.SUMMARY,
            HeapObjectKind.CALL_RESULT,
            HeapObjectKind.RETURN,
        }

    @staticmethod
    def _contaminant_shadowed(
        location: "HeapLocation",
        contaminant: "HeapLocation",
        precise_shadows: "frozenset[HeapLocation]",
    ) -> bool:
        return (
            location.is_precise()
            and location in precise_shadows
            and not contaminant.is_precise()
        )

    def outcome_snapshot(
        self,
        operation: object,
        outcome: str,
    ) -> HeapValueSnapshot | None:
        return self.program_point_outcomes.get(self._operation_key(operation), {}).get(outcome)

    def returned_values_at(
        self,
        procedure: object,
        operation: object,
        *,
        outcome: str = "return",
    ) -> tuple[frozenset[HeapLocation], ...]:
        snapshot = self.outcome_snapshot(operation, outcome)
        return () if snapshot is None else snapshot.returns.get(self._procedure_key(procedure), ())

    def yielded_values_at(
        self,
        procedure: object,
        operation: object,
        *,
        outcome: str = "yield",
    ) -> frozenset[HeapLocation]:
        snapshot = self.outcome_snapshot(operation, outcome)
        return (
            frozenset()
            if snapshot is None
            else snapshot.yields.get(self._procedure_key(procedure), frozenset())
        )

    def raised_values_at(
        self,
        procedure: object,
        operation: object,
        *,
        outcome: str = "raise",
    ) -> frozenset[HeapLocation]:
        snapshot = self.outcome_snapshot(operation, outcome)
        return (
            frozenset()
            if snapshot is None
            else snapshot.raised.get(self._procedure_key(procedure), frozenset())
        )

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
        from ..model import UpdatePolicy

        entry = self.get(location)
        if entry is None:
            return False
        if location.is_nested():
            return (
                location.is_precise()
                and self.allow_strong_nested_fresh
                and entry.is_singleton
            )
        return entry.update_policy is UpdatePolicy.STRONG

    def receiver_cardinality(
        self,
        location: "HeapLocation",
    ) -> "HeapObjectCardinality":
        from ..model import HeapObjectCardinality

        entry = self.get(location)
        if entry is None:
            return HeapObjectCardinality.UNKNOWN
        return entry.cardinality

    def must_alias(self, a: "HeapLocation", b: "HeapLocation") -> bool:
        """Return ``True`` if *a* and *b* belong to the same alias class.

        Two locations must-alias when their roots share an equivalence
        class (union-find canonical root is the same) and their selector
        paths are identical.  This is must-alias for known roots and
        conservative for unknown roots.
        """
        entry_a = self.get(a)
        entry_b = self.get(b)
        if entry_a is None or entry_b is None:
            return a == b and a.root.has_stable_identity() and a.is_precise()
        if not a.root.has_stable_identity() or not b.root.has_stable_identity():
            return False
        if entry_a.aliases.isdisjoint(entry_b.aliases):
            return False
        return a.selectors == b.selectors and a.is_precise() and b.is_precise()

    def symbolically_related(
        self,
        a: "HeapLocation",
        b: "HeapLocation",
    ) -> bool:
        """Whether two values share one provenance/version relation.

        Unlike :meth:`must_alias`, this does not assert one concrete identity.
        It is suitable for repeated dynamic reads whose provenance is stable
        while the produced object may be fresh on each evaluation.
        """
        return (
            a.root == b.root
            and a.selectors == b.selectors
            and a.is_precise()
            and b.is_precise()
        )

    def may_alias(self, a: "HeapLocation", b: "HeapLocation") -> bool:
        """Return ``True`` if *a* and *b* **may** refer to the same storage.

        This is conservative: returns ``True`` for overlapping root
        equivalence classes when selector paths may overlap, including
        wildcard/summary selectors.
        """
        if self.must_alias(a, b):
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
        from ..model import HeapObjectKind

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
        return {label: frozenset(locations) for label, locations in grouped.items()}

    def alias_evidence(
        self,
        a: "HeapLocation",
        b: "HeapLocation",
        operation: object | None = None,
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
            "a_kind": getattr(a.root.kind, "value", str(a.root.kind)),
            "b_kind": getattr(b.root.kind, "value", str(b.root.kind)),
            "a_identity": getattr(a.root.identity, "value", str(a.root.identity)),
            "b_identity": getattr(b.root.identity, "value", str(b.root.identity)),
            "a_escaped": entry_a.is_escaped if entry_a is not None else None,
            "b_escaped": entry_b.is_escaped if entry_b is not None else None,
            "same_alias_class": same_alias_class,
            "same_path": a.selectors == b.selectors,
            "selector_overlap": selector_overlap,
            "must_alias": self.must_alias(a, b),
            "may_alias": self.may_alias(a, b),
            "precision_degradations": sorted(
                self.degradations_at(operation) if operation is not None else ()
            ),
        }

    def degradations_at(self, operation: object) -> "frozenset[str]":
        """Return reasons this program point was conservatively degraded."""
        return self.precision_degradations.get(
            self._operation_key(operation), frozenset()
        )

    def _operation_key(self, operation: object) -> object:
        return self.operation_identities.get(operation, operation)

    @staticmethod
    def _procedure_key(procedure: object) -> object:
        catalog = getattr(procedure, "ir_catalog", None)
        if catalog is not None:
            return catalog.procedure(procedure).code_id
        return procedure

    def has_precision_degradation(self, operation: object | None = None) -> bool:
        if operation is None:
            return bool(self.precision_degradations)
        return bool(self.degradations_at(operation))

    def analysis_metrics(self) -> dict[str, object]:
        """Return compact quality/scalability counters for bug-finding runs."""
        from ..model import HeapObjectKind

        reason_counts: dict[str, int] = {}
        for reasons in self.precision_degradations.values():
            for reason in reasons:
                reason_counts[reason] = reason_counts.get(reason, 0) + 1
        return {
            "root_count": len(self.entries),
            "unknown_root_count": sum(
                entry.location.root.kind is HeapObjectKind.UNKNOWN
                for entry in self.entries.values()
            ),
            "summary_root_count": sum(
                entry.location.root.kind is HeapObjectKind.SUMMARY
                for entry in self.entries.values()
            ),
            "escaped_root_count": len(self.escaped_locations()),
            "program_point_count": len(self.program_point_values),
            "degraded_program_point_count": len(self.precision_degradations),
            "degradation_reason_counts": dict(sorted(reason_counts.items())),
        }

    def escaped_locations(self) -> "frozenset[HeapLocation]":
        """Return all root locations that have been marked escaped."""
        return frozenset(
            entry.location for entry in self.entries.values() if entry.is_escaped
        )

    def singleton_locations(self) -> "frozenset[HeapLocation]":
        """Return all root locations eligible for strong updates."""
        return frozenset(
            entry.location for entry in self.entries.values() if entry.is_singleton
        )

    # ── bulk queries ───────────────────────────────────────────────────

    def iter_entries(self) -> Iterator[PointsToEntry]:
        """Yield every :class:`PointsToEntry` in the graph."""
        yield from self.entries.values()

    def __len__(self) -> int:
        return len(self.entries)

    def __bool__(self) -> bool:
        return bool(self.entries)

    def to_dict(self) -> dict[str, object]:
        """Serialize the full graph for inspection / JSON output."""
        return {
            "metrics": self.analysis_metrics(),
            "entry_count": len(self.entries),
            "escaped_count": len(self.escaped_locations()),
            "singleton_count": len(self.singleton_locations()),
            "heap_value_location_count": len(self.heap_values),
            "program_point_count": len(self.program_point_values),
            "program_point_outcome_count": sum(
                len(outcomes) for outcomes in self.program_point_outcomes.values()
            ),
            "precision_degradation_count": sum(
                len(reasons) for reasons in self.precision_degradations.values()
            ),
            "precision_degradations": {
                str(operation_id): sorted(reasons)
                for operation_id, reasons in self.precision_degradations.items()
            },
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
