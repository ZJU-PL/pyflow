"""Path-insensitive heap value state for the standalone transfer engine."""

from __future__ import annotations

from dataclasses import dataclass, field
from itertools import count

from ..model import HeapLocation, UpdatePolicy

_HEAP_VERSION_IDS = count(1)


@dataclass
class HeapState:
    """Flow-sensitive, path-insensitive heap value map.

    ``values`` stores precise field/subscript contents. ``contaminants`` stores
    imprecise wildcard writes, such as ``obj[k] = value`` where ``k`` is not a
    known literal. Reads from a precise overlapping path return both the exact
    value and any contaminating values.
    """

    values: dict[HeapLocation, tuple[HeapLocation, ...]] = field(default_factory=dict)
    contaminants: dict[HeapLocation, tuple[HeapLocation, ...]] = field(default_factory=dict)
    # Exact locations proven to contain no heap value.  Absence is a must
    # fact: it is retained across a join only when every incoming path proves
    # the same location absent.  This keeps "not modeled" distinct from
    # "definitely deleted/overwritten with a non-heap value".
    absent: set[HeapLocation] = field(default_factory=set)
    # MAY contain a non-reference value.
    scalar_present: set[HeapLocation] = field(default_factory=set)
    # MUST contain only a non-reference value on every represented path.
    definitely_scalar_present: set[HeapLocation] = field(default_factory=set)
    # Exact paths whose newer strong write/delete shadows older wildcard facts.
    precise_shadows: set[HeapLocation] = field(default_factory=set)
    complete_roots: set[object] = field(default_factory=set)
    versions: dict[HeapLocation, frozenset[int]] = field(default_factory=dict)
    escaped: set[HeapLocation] = field(default_factory=set)
    returns: dict[object, tuple[HeapLocation, ...]] = field(default_factory=dict)
    return_slots: dict[object, tuple[tuple[HeapLocation, ...], ...]] = field(default_factory=dict)
    yields: dict[object, tuple[HeapLocation, ...]] = field(default_factory=dict)
    # Possible suspension ordinal(s) reached on the current path. Branches
    # may reach the same syntactic yield at different resume depths, so this
    # is a set-valued flow fact rather than one engine-global counter.
    yield_depths: dict[object, frozenset[int]] = field(default_factory=dict)
    raised: dict[object, tuple[HeapLocation, ...]] = field(default_factory=dict)
    # The exception currently being handled.  This is deliberately separate
    # from ``raised`` so a bare ``raise`` can re-raise the caught object after
    # the handler entry has consumed the pending exceptional edge.
    active_exceptions: dict[object, tuple[HeapLocation, ...]] = field(default_factory=dict)

    def read(
        self,
        location: HeapLocation,
        *,
        fallback: tuple[HeapLocation, ...] = (),
    ) -> tuple[HeapLocation, ...]:
        result: list[HeapLocation] = []
        result.extend(self.values.get(location, ()))
        for contaminant, values in self.contaminants.items():
            if self.locations_may_overlap(location, contaminant) and not self._contaminant_shadowed(
                location, contaminant
            ):
                result.extend(values)
        if result:
            return tuple(dict.fromkeys(result))
        return fallback

    def __contains__(self, location: HeapLocation) -> bool:
        return location in self.values or location in self.contaminants

    def definitely_absent(self, location: HeapLocation) -> bool:
        """Return whether *location* is absent on every represented path."""
        if location not in self.absent:
            return False
        return not any(
            self.locations_may_overlap(location, contaminant)
            and not self._contaminant_shadowed(location, contaminant)
            for contaminant in self.contaminants
        )

    def _contaminant_shadowed(
        self,
        location: HeapLocation,
        contaminant: HeapLocation,
    ) -> bool:
        return (
            location.is_precise()
            and location in self.precise_shadows
            and not contaminant.is_precise()
        )

    def read_many(
        self,
        locations: tuple[HeapLocation, ...],
    ) -> tuple[HeapLocation, ...]:
        result: list[HeapLocation] = []
        for location in locations:
            result.extend(self.read(location))
        return tuple(dict.fromkeys(result))

    def read_contained(
        self,
        container: HeapLocation,
    ) -> tuple[HeapLocation, ...]:
        """Read all element values stored under a container root.

        Unlike :meth:`read`, which returns values for an exact location plus
        overlapping contaminants, this method also collects values from precise
        sub-element writes (e.g. ``container[0]`` when querying ``container[*]``).
        This is used for for-loop variable binding where we need all element
        values regardless of write precision.
        """
        result: list[HeapLocation] = []
        seen: set[HeapLocation] = set()
        root = container.root
        # Direct wildcard lookup
        for val in self.read(container, fallback=()):
            if val not in seen:
                seen.add(val)
                result.append(val)
        # Precise sub-element values under the same root
        for loc, values in self.values.items():
            if loc.root == root and loc.selectors:
                for val in values:
                    if val not in seen:
                        seen.add(val)
                        result.append(val)
        # Contaminant sub-element values under the same root
        for loc, values in self.contaminants.items():
            if loc.root == root and loc.selectors:
                for val in values:
                    if val not in seen:
                        seen.add(val)
                        result.append(val)
        return tuple(result)

    def write(
        self,
        location: HeapLocation,
        values: tuple[HeapLocation, ...],
        policy: UpdatePolicy,
        *,
        has_non_reference: bool = False,
    ) -> None:
        version = next(_HEAP_VERSION_IDS)
        previous_versions = self.version_for(location)
        self.versions[location] = (
            frozenset({version})
            if policy is UpdatePolicy.STRONG
            else frozenset((*previous_versions, version))
        )
        target = self.values if location.is_precise() else self.contaminants
        if not location.is_precise():
            self.precise_shadows = {
                shadow
                for shadow in self.precise_shadows
                if not self.locations_may_overlap(shadow, location)
            }
        if policy is UpdatePolicy.STRONG:
            if location.is_precise() and location.is_nested():
                self.precise_shadows.add(location)
            if values:
                target[location] = tuple(dict.fromkeys(values))
                self.absent.discard(location)
                if has_non_reference and location.is_precise():
                    self.scalar_present.add(location)
                else:
                    self.scalar_present.discard(location)
                self.definitely_scalar_present.discard(location)
            else:
                target.pop(location, None)
                if location.is_precise():
                    if has_non_reference:
                        self.scalar_present.add(location)
                        self.definitely_scalar_present.add(location)
                        self.absent.discard(location)
                    else:
                        self.absent.add(location)
                        self.scalar_present.discard(location)
                        self.definitely_scalar_present.discard(location)
            return
        if not values:
            if has_non_reference and location.is_precise():
                self.scalar_present.add(location)
                self.absent.discard(location)
            return  # Weak update with nothing to add is a no-op.
        target[location] = tuple(dict.fromkeys((*target.get(location, ()), *values)))
        if location.is_precise():
            self.absent.discard(location)
            self.definitely_scalar_present.discard(location)
            if has_non_reference:
                self.scalar_present.add(location)

    def delete(self, location: HeapLocation) -> None:
        self.versions[location] = frozenset({next(_HEAP_VERSION_IDS)})
        if location.is_precise():
            self.values.pop(location, None)
            self.contaminants.pop(location, None)
            self.absent.add(location)
            self.scalar_present.discard(location)
            self.definitely_scalar_present.discard(location)
            if location.is_nested():
                self.precise_shadows.add(location)
            return
        self.values = {
            stored: values
            for stored, values in self.values.items()
            if not self.locations_may_overlap(stored, location)
        }
        self.contaminants = {
            stored: values
            for stored, values in self.contaminants.items()
            if not self.locations_may_overlap(stored, location)
        }
        self.absent = {
            stored for stored in self.absent if not self.locations_may_overlap(stored, location)
        }
        self.scalar_present = {
            stored
            for stored in self.scalar_present
            if not self.locations_may_overlap(stored, location)
        }
        self.definitely_scalar_present = {
            stored
            for stored in self.definitely_scalar_present
            if not self.locations_may_overlap(stored, location)
        }
        self.precise_shadows = {
            stored
            for stored in self.precise_shadows
            if not self.locations_may_overlap(stored, location)
        }

    def mark_escaped(self, locations: tuple[HeapLocation, ...]) -> None:
        self.escaped.update(locations)

    def version_for(self, location: HeapLocation) -> frozenset[int]:
        versions: set[int] = set()
        for changed, tokens in self.versions.items():
            if self.locations_may_overlap(location, changed):
                versions.update(tokens)
        return frozenset(versions or {0})

    def set_returns(
        self,
        procedure: object,
        locations: tuple[HeapLocation, ...],
    ) -> None:
        self.returns[procedure] = tuple(
            dict.fromkeys((*self.returns.get(procedure, ()), *locations))
        )

    def set_raised(
        self,
        procedure: object,
        locations: tuple[HeapLocation, ...],
    ) -> None:
        self.raised[procedure] = tuple(dict.fromkeys((*self.raised.get(procedure, ()), *locations)))

    def set_active_exception(
        self,
        procedure: object,
        locations: tuple[HeapLocation, ...],
    ) -> None:
        self.active_exceptions[procedure] = tuple(dict.fromkeys(locations))

    def set_yields(
        self,
        procedure: object,
        locations: tuple[HeapLocation, ...],
    ) -> None:
        self.yields[procedure] = tuple(dict.fromkeys((*self.yields.get(procedure, ()), *locations)))

    def current_yield_depths(self, procedure: object) -> frozenset[int]:
        return self.yield_depths.get(procedure, frozenset({0}))

    def advance_yield_depths(self, procedure: object) -> None:
        self.yield_depths[procedure] = frozenset(
            depth + 1 for depth in self.current_yield_depths(procedure)
        )

    def set_return_slots(
        self,
        procedure: object,
        slots: tuple[tuple[HeapLocation, ...], ...],
    ) -> None:
        existing = self.return_slots.get(procedure, ())
        count = max(len(existing), len(slots))
        merged: list[tuple[HeapLocation, ...]] = []
        for index in range(count):
            old = existing[index] if index < len(existing) else ()
            new = slots[index] if index < len(slots) else ()
            merged.append(tuple(dict.fromkeys((*old, *new))))
        self.return_slots[procedure] = tuple(merged)

    def join(self, other: "HeapState") -> "HeapState":
        if self is other:
            return self.copy()

        def merge_tuple_map(left: dict, right: dict) -> dict:
            if not right:
                return dict(left)
            if not left:
                return dict(right)
            merged = dict(left)
            for key, values in right.items():
                existing = merged.get(key)
                if existing is None:
                    merged[key] = values
                elif existing != values:
                    merged[key] = tuple(dict.fromkeys((*existing, *values)))
            return merged

        def merge_frozenset_map(left: dict, right: dict) -> dict:
            if not right:
                return dict(left)
            if not left:
                return dict(right)
            merged = dict(left)
            for key, values in right.items():
                existing = merged.get(key)
                if existing is None:
                    merged[key] = values
                elif existing != values:
                    merged[key] = existing | values
            return merged

        joined = HeapState()
        joined.values = merge_tuple_map(self.values, other.values)
        joined.contaminants = merge_tuple_map(self.contaminants, other.contaminants)
        joined.versions = merge_frozenset_map(self.versions, other.versions)
        joined.escaped = self.escaped | other.escaped
        joined.scalar_present = self.scalar_present | other.scalar_present
        joined.returns = merge_tuple_map(self.returns, other.returns)
        joined.return_slots = dict(self.return_slots)
        for procedure, slots in other.return_slots.items():
            existing = joined.return_slots.get(procedure)
            if existing is None:
                joined.return_slots[procedure] = slots
            elif existing != slots:
                count = max(len(existing), len(slots))
                joined.return_slots[procedure] = tuple(
                    (
                        existing[index]
                        if index < len(existing)
                        and index < len(slots)
                        and existing[index] == slots[index]
                        else tuple(
                            dict.fromkeys(
                                (
                                    *(existing[index] if index < len(existing) else ()),
                                    *(slots[index] if index < len(slots) else ()),
                                )
                            )
                        )
                    )
                    for index in range(count)
                )
        joined.yields = merge_tuple_map(self.yields, other.yields)
        joined.yield_depths = merge_frozenset_map(self.yield_depths, other.yield_depths)
        joined.raised = merge_tuple_map(self.raised, other.raised)
        joined.active_exceptions = merge_tuple_map(self.active_exceptions, other.active_exceptions)
        joined.absent = self.absent & other.absent
        if joined.absent:
            joined.absent.difference_update(joined.values)
            joined.absent.difference_update(joined.scalar_present)
        joined.definitely_scalar_present = (
            self.definitely_scalar_present & other.definitely_scalar_present
        )
        joined.precise_shadows = self.precise_shadows & other.precise_shadows
        joined.complete_roots = self.complete_roots & other.complete_roots
        return joined

    def copy(self) -> "HeapState":
        copied = HeapState()
        copied.values = dict(self.values)
        copied.contaminants = dict(self.contaminants)
        copied.absent = set(self.absent)
        copied.scalar_present = set(self.scalar_present)
        copied.definitely_scalar_present = set(self.definitely_scalar_present)
        copied.precise_shadows = set(self.precise_shadows)
        copied.complete_roots = set(self.complete_roots)
        copied.versions = dict(self.versions)
        copied.escaped = set(self.escaped)
        copied.returns = dict(self.returns)
        copied.return_slots = dict(self.return_slots)
        copied.yields = dict(self.yields)
        copied.yield_depths = dict(self.yield_depths)
        copied.raised = dict(self.raised)
        copied.active_exceptions = dict(self.active_exceptions)
        return copied

    def equivalent(self, other: "HeapState") -> bool:
        if self is other:
            return True

        def set_map_equal(left, right):
            if left.keys() != right.keys():
                return False
            for key, lval in left.items():
                rval = right[key]
                if lval != rval and frozenset(lval) != frozenset(rval):
                    return False
            return True

        def slot_map_equal(left, right):
            if left.keys() != right.keys():
                return False
            for key, lslots in left.items():
                rslots = right[key]
                if lslots == rslots:
                    continue
                if len(lslots) != len(rslots):
                    return False
                for lslot, rslot in zip(lslots, rslots):
                    if lslot != rslot and frozenset(lslot) != frozenset(rslot):
                        return False
            return True

        return (
            set_map_equal(self.values, other.values)
            and set_map_equal(self.contaminants, other.contaminants)
            and self.absent == other.absent
            and self.scalar_present == other.scalar_present
            and self.definitely_scalar_present == other.definitely_scalar_present
            and self.precise_shadows == other.precise_shadows
            and self.complete_roots == other.complete_roots
            # Mutation versions are relational invalidation metadata, not a
            # component of the dataflow lattice.  A transfer function may
            # execute the same abstract write while solving a loop; assigning
            # it a fresh numeric epoch must not manufacture a new lattice
            # element and prevent convergence.
            and self.escaped == other.escaped
            and set_map_equal(self.returns, other.returns)
            and slot_map_equal(self.return_slots, other.return_slots)
            and set_map_equal(self.yields, other.yields)
            and self.yield_depths == other.yield_depths
            and set_map_equal(self.raised, other.raised)
            and set_map_equal(self.active_exceptions, other.active_exceptions)
        )

    @staticmethod
    def locations_may_overlap(a: HeapLocation, b: HeapLocation) -> bool:
        if a.root != b.root:
            return False
        from .points_to import PointsToGraph

        return PointsToGraph._selectors_may_overlap(a.selectors, b.selectors)
