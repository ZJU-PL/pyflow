"""Path-insensitive heap value state for the standalone transfer engine."""

from __future__ import annotations

from dataclasses import dataclass, field

from .model import HeapLocation, UpdatePolicy


@dataclass
class HeapState:
    """Flow-sensitive, path-insensitive heap value map.

    ``values`` stores precise field/subscript contents. ``contaminants`` stores
    imprecise wildcard writes, such as ``obj[k] = value`` where ``k`` is not a
    known literal. Reads from a precise overlapping path return both the exact
    value and any contaminating values.
    """

    values: dict[HeapLocation, tuple[HeapLocation, ...]] = field(default_factory=dict)
    contaminants: dict[HeapLocation, tuple[HeapLocation, ...]] = field(
        default_factory=dict
    )
    # Exact locations proven to contain no heap value.  Absence is a must
    # fact: it is retained across a join only when every incoming path proves
    # the same location absent.  This keeps "not modeled" distinct from
    # "definitely deleted/overwritten with a non-heap value".
    absent: set[HeapLocation] = field(default_factory=set)
    complete_roots: set[object] = field(default_factory=set)
    escaped: set[HeapLocation] = field(default_factory=set)
    returns: dict[object, tuple[HeapLocation, ...]] = field(default_factory=dict)
    return_slots: dict[
        object, tuple[tuple[HeapLocation, ...], ...]
    ] = field(default_factory=dict)
    yields: dict[object, tuple[HeapLocation, ...]] = field(default_factory=dict)
    raised: dict[object, tuple[HeapLocation, ...]] = field(default_factory=dict)
    # The exception currently being handled.  This is deliberately separate
    # from ``raised`` so a bare ``raise`` can re-raise the caught object after
    # the handler entry has consumed the pending exceptional edge.
    active_exceptions: dict[object, tuple[HeapLocation, ...]] = field(
        default_factory=dict
    )

    def read(
        self,
        location: HeapLocation,
        *,
        fallback: tuple[HeapLocation, ...] | None = None,
    ) -> tuple[HeapLocation, ...]:
        result: list[HeapLocation] = []
        result.extend(self.values.get(location, ()))
        for contaminant, values in self.contaminants.items():
            if self.locations_may_overlap(location, contaminant):
                result.extend(values)
        if result:
            return tuple(dict.fromkeys(result))
        return fallback if fallback is not None else (location,)

    def __contains__(self, location: HeapLocation) -> bool:
        return location in self.values or location in self.contaminants

    def definitely_absent(self, location: HeapLocation) -> bool:
        """Return whether *location* is absent on every represented path."""
        if location not in self.absent:
            return False
        return not any(
            self.locations_may_overlap(location, contaminant)
            for contaminant in self.contaminants
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
        root_id = id(container.root)
        # Direct wildcard lookup
        for val in self.read(container, fallback=()):
            if val not in seen:
                seen.add(val)
                result.append(val)
        # Precise sub-element values under the same root
        for loc, values in self.values.items():
            if id(loc.root) == root_id and loc.selectors:
                for val in values:
                    if val not in seen:
                        seen.add(val)
                        result.append(val)
        # Contaminant sub-element values under the same root
        for loc, values in self.contaminants.items():
            if id(loc.root) == root_id and loc.selectors:
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
    ) -> None:
        target = self.values if location.is_precise() else self.contaminants
        if policy is UpdatePolicy.STRONG:
            if values:
                target[location] = tuple(dict.fromkeys(values))
                self.absent.discard(location)
            else:
                # Strong write of a non-heap value (e.g., None, a constant,
                # an unmodeled expression) clears the location — the previous
                # binding at this exact path is no longer reachable.
                target.pop(location, None)
                if location.is_precise():
                    self.absent.add(location)
            return
        if not values:
            return  # Weak update with nothing to add is a no-op.
        target[location] = tuple(
            dict.fromkeys((*target.get(location, ()), *values))
        )
        if location.is_precise():
            self.absent.discard(location)

    def delete(self, location: HeapLocation) -> None:
        if location.is_precise():
            self.values.pop(location, None)
            self.contaminants.pop(location, None)
            self.absent.add(location)
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
            stored
            for stored in self.absent
            if not self.locations_may_overlap(stored, location)
        }

    def mark_escaped(self, locations: tuple[HeapLocation, ...]) -> None:
        self.escaped.update(locations)

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
        self.raised[procedure] = tuple(
            dict.fromkeys((*self.raised.get(procedure, ()), *locations))
        )

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
        self.yields[procedure] = tuple(
            dict.fromkeys((*self.yields.get(procedure, ()), *locations))
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
        joined = HeapState()
        for source in (self, other):
            for location, values in source.values.items():
                joined.values[location] = tuple(
                    dict.fromkeys((*joined.values.get(location, ()), *values))
                )
            for location, values in source.contaminants.items():
                joined.contaminants[location] = tuple(
                    dict.fromkeys((*joined.contaminants.get(location, ()), *values))
                )
            joined.escaped.update(source.escaped)
            for procedure, values in source.returns.items():
                joined.returns[procedure] = tuple(
                    dict.fromkeys((*joined.returns.get(procedure, ()), *values))
                )
            for procedure, slots in source.return_slots.items():
                existing = joined.return_slots.get(procedure, ())
                count = max(len(existing), len(slots))
                joined.return_slots[procedure] = tuple(
                    tuple(
                        dict.fromkeys(
                            (
                                *(existing[index] if index < len(existing) else ()),
                                *(slots[index] if index < len(slots) else ()),
                            )
                        )
                    )
                    for index in range(count)
                )
            for procedure, values in source.yields.items():
                joined.yields[procedure] = tuple(
                    dict.fromkeys((*joined.yields.get(procedure, ()), *values))
                )
            for procedure, values in source.raised.items():
                joined.raised[procedure] = tuple(
                    dict.fromkeys((*joined.raised.get(procedure, ()), *values))
                )
            for procedure, values in source.active_exceptions.items():
                joined.active_exceptions[procedure] = tuple(
                    dict.fromkeys(
                        (*joined.active_exceptions.get(procedure, ()), *values)
                    )
                )
        joined.absent = set(self.absent).intersection(other.absent)
        joined.absent.difference_update(joined.values)
        joined.complete_roots = set(self.complete_roots).intersection(
            other.complete_roots
        )
        return joined

    def copy(self) -> "HeapState":
        copied = HeapState()
        copied.values = dict(self.values)
        copied.contaminants = dict(self.contaminants)
        copied.absent = set(self.absent)
        copied.complete_roots = set(self.complete_roots)
        copied.escaped = set(self.escaped)
        copied.returns = dict(self.returns)
        copied.return_slots = dict(self.return_slots)
        copied.yields = dict(self.yields)
        copied.raised = dict(self.raised)
        copied.active_exceptions = dict(self.active_exceptions)
        return copied

    def equivalent(self, other: "HeapState") -> bool:
        return (
            self.values == other.values
            and self.contaminants == other.contaminants
            and self.absent == other.absent
            and self.complete_roots == other.complete_roots
            and self.escaped == other.escaped
            and self.returns == other.returns
            and self.return_slots == other.return_slots
            and self.yields == other.yields
            and self.raised == other.raised
            and self.active_exceptions == other.active_exceptions
        )

    @staticmethod
    def locations_may_overlap(a: HeapLocation, b: HeapLocation) -> bool:
        if a.root != b.root:
            return False
        from .points_to_graph import PointsToGraph

        return PointsToGraph._selectors_may_overlap(a.selectors, b.selectors)
