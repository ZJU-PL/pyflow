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

    def read_many(
        self,
        locations: tuple[HeapLocation, ...],
    ) -> tuple[HeapLocation, ...]:
        result: list[HeapLocation] = []
        for location in locations:
            result.extend(self.read(location))
        return tuple(dict.fromkeys(result))

    def write(
        self,
        location: HeapLocation,
        values: tuple[HeapLocation, ...],
        policy: UpdatePolicy,
    ) -> None:
        if not values:
            return
        target = self.values if location.is_precise() else self.contaminants
        if policy is UpdatePolicy.STRONG:
            target[location] = tuple(dict.fromkeys(values))
            return
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
        self.returns[procedure] = tuple(dict.fromkeys(locations))

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
        return joined

    def copy(self) -> "HeapState":
        copied = HeapState()
        copied.values = dict(self.values)
        copied.contaminants = dict(self.contaminants)
        copied.escaped = set(self.escaped)
        copied.returns = dict(self.returns)
        return copied

    def equivalent(self, other: "HeapState") -> bool:
        return (
            self.values == other.values
            and self.contaminants == other.contaminants
            and self.escaped == other.escaped
            and self.returns == other.returns
        )

    @staticmethod
    def locations_may_overlap(a: HeapLocation, b: HeapLocation) -> bool:
        if a.root != b.root:
            return False
        from .points_to_graph import PointsToGraph

        return PointsToGraph._selectors_may_overlap(a.selectors, b.selectors)
