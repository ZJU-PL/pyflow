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
    escaped: set[HeapLocation] = field(default_factory=set)
    returns: dict[object, tuple[HeapLocation, ...]] = field(default_factory=dict)
    return_slots: dict[
        object, tuple[tuple[HeapLocation, ...], ...]
    ] = field(default_factory=dict)
    raised: dict[object, tuple[HeapLocation, ...]] = field(default_factory=dict)

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
            else:
                # Strong write of a non-heap value (e.g., None, a constant,
                # an unmodeled expression) clears the location — the previous
                # binding at this exact path is no longer reachable.
                target.pop(location, None)
            return
        if not values:
            return  # Weak update with nothing to add is a no-op.
        target[location] = tuple(
            dict.fromkeys((*target.get(location, ()), *values))
        )

    def delete(self, location: HeapLocation) -> None:
        if location.is_precise():
            self.values.pop(location, None)
            self.contaminants.pop(location, None)
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
            for procedure, values in source.raised.items():
                joined.raised[procedure] = tuple(
                    dict.fromkeys((*joined.raised.get(procedure, ()), *values))
                )
        return joined

    def copy(self) -> "HeapState":
        copied = HeapState()
        copied.values = dict(self.values)
        copied.contaminants = dict(self.contaminants)
        copied.escaped = set(self.escaped)
        copied.returns = dict(self.returns)
        copied.return_slots = dict(self.return_slots)
        copied.raised = dict(self.raised)
        return copied

    def equivalent(self, other: "HeapState") -> bool:
        return (
            self.values == other.values
            and self.contaminants == other.contaminants
            and self.escaped == other.escaped
            and self.returns == other.returns
            and self.return_slots == other.return_slots
            and self.raised == other.raised
        )

    @staticmethod
    def locations_may_overlap(a: HeapLocation, b: HeapLocation) -> bool:
        if a.root != b.root:
            return False
        from .points_to_graph import PointsToGraph

        return PointsToGraph._selectors_may_overlap(a.selectors, b.selectors)
