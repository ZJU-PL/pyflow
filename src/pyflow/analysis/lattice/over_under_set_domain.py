"""Over/Under set domain — tracks both over- and under-approximation.

Mirrors ``AbstractOverUnderSetDomain`` from Pysa.  Each element has a
``{element, in_under}`` structure: the over-approximation tracks all
possible elements (may-analysis), while the under-approximation tracks
elements that are definitely present (must-analysis).

Join unions the over-approximations and intersects the under-approximations.
This is the standard construction for simultaneous may+must analysis.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import (
    Any,
    Callable,
    FrozenSet,
    Iterator,
    List,
    Mapping,
    Optional,
    Sequence,
    Set,
    Tuple,
    TypeVar,
)

from .base import (
    OP_ACC,
    OP_ADD,
    OP_BY,
    OP_BY_FILTER,
    OP_EXISTS,
    OP_EXPAND,
    OP_FILTER,
    OP_FILTER_MAP,
    OP_MAP,
    AbstractDomain,
    PartId,
    TransformOp,
    ReduceOp,
    PartitionOp,
)

T = TypeVar("T")
V = TypeVar("V")


@dataclass(frozen=True)
class Approximation:
    """A single element with an under-approximation flag."""

    element: Any
    in_under: bool = True


class OverUnderSetDomain(AbstractDomain):
    """Biset lattice: over = may-set (union), under = must-set (intersection).

    Bottom is a special ``Bottom`` sentinel (different from empty biset).
    """

    _over: Optional[FrozenSet[Any]]
    _under: FrozenSet[Any]

    def __init__(
        self,
        over: Optional[FrozenSet[Any]] = None,
        under: Optional[FrozenSet[Any]] = None,
    ) -> None:
        self._over = over  # None = bottom
        self._under = frozenset() if under is None else under

    @staticmethod
    def bottom() -> OverUnderSetDomain:
        return OverUnderSetDomain(None, frozenset())

    @staticmethod
    def empty() -> OverUnderSetDomain:
        return OverUnderSetDomain(frozenset(), frozenset())

    def is_bottom(self) -> bool:
        return self._over is None

    def is_empty(self) -> bool:
        return self._over is not None and len(self._over) == 0

    @staticmethod
    def inject(element: Any) -> OverUnderSetDomain:
        return OverUnderSetDomain(
            frozenset([element]),
            frozenset([element]),
        )

    @staticmethod
    def singleton(element: Any) -> OverUnderSetDomain:
        return OverUnderSetDomain(
            frozenset([element]),
            frozenset([element]),
        )

    @staticmethod
    def of(*elements: Any) -> OverUnderSetDomain:
        s = frozenset(elements)
        return OverUnderSetDomain(s, s)

    def join(self, other: Any) -> OverUnderSetDomain:
        if not isinstance(other, OverUnderSetDomain):
            return NotImplemented
        if self.is_bottom():
            return other
        if other.is_bottom():
            return self
        return OverUnderSetDomain(
            self._over | other._over,
            self._under & other._under,
        )

    def meet(self, other: Any) -> OverUnderSetDomain:
        if not isinstance(other, OverUnderSetDomain):
            return NotImplemented
        if self.is_bottom() or other.is_bottom():
            return self.bottom()
        return OverUnderSetDomain(
            self._over & other._over,
            self._under | other._under,
        )

    def leq(self, other: Any) -> bool:
        if not isinstance(other, OverUnderSetDomain):
            return NotImplemented
        if self.is_bottom():
            return True
        if other.is_bottom():
            return False
        return self._over <= other._over and other._under <= self._under

    def widen(self, other: Any, iteration: int = 0) -> OverUnderSetDomain:
        return self.join(other)

    def sequence_join(self, other: Any) -> OverUnderSetDomain:
        """Sequential composition: unions both over and under."""
        if not isinstance(other, OverUnderSetDomain):
            return NotImplemented
        if self.is_bottom():
            return other
        if other.is_bottom():
            return self
        return OverUnderSetDomain(
            self._over | other._over,
            self._under | other._under,
        )

    def subtract(self, other: Any) -> OverUnderSetDomain:
        if not isinstance(other, OverUnderSetDomain):
            return NotImplemented
        if self.is_bottom() or other.is_bottom():
            return self
        new_over = self._over - other._over
        if len(new_over) == 0:
            return self.bottom()
        return OverUnderSetDomain(new_over | self._under, self._under)

    def over_to_under(self) -> OverUnderSetDomain:
        if self.is_bottom():
            return self.bottom()
        return OverUnderSetDomain(self._over, self._over)

    def to_approximations(self) -> List[Approximation]:
        if self.is_bottom():
            return []
        result: List[Approximation] = []
        for e in self._over:  # type: ignore
            result.append(Approximation(element=e, in_under=e in self._under))
        return result

    @staticmethod
    def of_approximations(apprs: List[Approximation]) -> OverUnderSetDomain:
        over: Set[Any] = set()
        under: Set[Any] = set()
        for a in apprs:
            over.add(a.element)
            if a.in_under:
                under.add(a.element)
        return OverUnderSetDomain(frozenset(over), frozenset(under))

    @staticmethod
    def of_set(s: FrozenSet[Any]) -> OverUnderSetDomain:
        return OverUnderSetDomain(s, s)

    def add_set(self, other: OverUnderSetDomain) -> OverUnderSetDomain:
        return self.sequence_join(other)

    def __hash__(self) -> int:
        return hash(("OverUnderSetDomain", self._over, self._under))

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, OverUnderSetDomain):
            return NotImplemented
        return self._over == other._over and self._under == other._under

    def __repr__(self) -> str:
        if self.is_bottom():
            return "<bottom>"
        parts = []
        for a in self.to_approximations():
            s = str(a.element)
            if not a.in_under:
                s += "(-)"
            parts.append(s)
        return "{" + ", ".join(parts) + "}"

    def contains(self, element: Any) -> bool:
        if self.is_bottom():
            return False
        return element in self._over

    def parts(self) -> Sequence[PartId]:
        return ["Self", "Element", "ElementAndUnder"]

    def parts_and_under(self) -> Sequence[PartId]:
        return ["Self", "Element", "ElementAndUnder"]

    def transform(self, part: PartId, op: TransformOp, f: Any) -> OverUnderSetDomain:
        if part == "Self":
            return self._transform_self(op, f)
        if part == "Element":
            return self._transform_element(op, f)
        if part == "ElementAndUnder":
            return self._transform_element_under(op, f)
        raise ValueError(f"{type(self).__name__} has no part {part!r}")

    def _transform_element(self, op: TransformOp, f: Any) -> OverUnderSetDomain:
        if self.is_bottom():
            if op == OP_ADD:
                return self.singleton(f)
            return self
        if op == OP_MAP:
            apprs = self.to_approximations()
            mapped = [Approximation(element=f(a.element), in_under=a.in_under) for a in apprs]
            return self.of_approximations(mapped)
        elif op == OP_ADD:
            return OverUnderSetDomain(
                self._over | {f},
                self._under | {f},
            )
        elif op == OP_FILTER:
            new_over = frozenset(e for e in self._over if f(e))
            new_under = frozenset(e for e in self._under if f(e))
            return OverUnderSetDomain(new_over, new_under)
        elif op == OP_FILTER_MAP:
            apprs = self.to_approximations()
            result: list[Approximation] = []
            for a in apprs:
                mapped = f(a.element)
                if mapped is not None:
                    result.append(Approximation(element=mapped, in_under=a.in_under))
            return self.of_approximations(result)
        elif op == OP_EXPAND:
            apprs = self.to_approximations()
            result = []
            for a in apprs:
                for expanded in f(a.element):
                    result.append(Approximation(element=expanded, in_under=a.in_under))
            return self.of_approximations(result)
        else:
            return self._transform_self(op, f)

    def _transform_element_under(self, op: TransformOp, f: Any) -> OverUnderSetDomain:
        if self.is_bottom():
            return self
        apprs = self.to_approximations()
        if op == OP_MAP:
            mapped = [f(a) for a in apprs]
            return self.of_approximations(mapped)
        elif op == OP_ADD:
            return self._add_element(f)
        elif op == OP_FILTER:
            filtered = [a for a in apprs if f(a)]
            return self.of_approximations(filtered)
        elif op == OP_FILTER_MAP:
            result = []
            for a in apprs:
                mapped = f(a)
                if mapped is not None:
                    result.append(mapped)
            return self.of_approximations(result)
        elif op == OP_EXPAND:
            result = []
            for a in apprs:
                for expanded in f(a):
                    result.append(expanded)
            return self.of_approximations(result)
        else:
            return self._transform_self(op, f)

    def _add_element(self, apr: Approximation) -> OverUnderSetDomain:
        if self.is_bottom():
            over = frozenset([apr.element])
            under = frozenset([apr.element]) if apr.in_under else frozenset()
            return OverUnderSetDomain(over, under)
        new_over = self._over | {apr.element}
        new_under = self._under | ({apr.element} if apr.in_under else frozenset())
        return OverUnderSetDomain(new_over, new_under)

    def reduce(self, part: PartId, op: ReduceOp, f: Any, init: V) -> V:
        if part == "Self":
            return self._reduce_self(op, f, init)
        if part == "Element":
            if self.is_bottom():
                return init
            if op == OP_ACC:
                acc = init
                for e in self._over:  # type: ignore
                    acc = f(e, acc)
                return acc
            elif op == OP_EXISTS:
                if init:
                    return init
                for e in self._over:  # type: ignore
                    if f(e):
                        return True  # type: ignore
                return False  # type: ignore
        if part == "ElementAndUnder":
            if self.is_bottom():
                return init
            apprs = self.to_approximations()
            if op == OP_ACC:
                acc = init
                for a in apprs:
                    acc = f(a, acc)
                return acc
            elif op == OP_EXISTS:
                if init:
                    return init
                for a in apprs:
                    if f(a):
                        return True  # type: ignore
                return False  # type: ignore
        raise ValueError(f"{type(self).__name__} has no part {part!r}")

    def partition(
        self, part: PartId, op: PartitionOp, f: Any
    ) -> Mapping[Any, OverUnderSetDomain]:
        if part == "Self":
            return self._partition_self(op, f)
        if part in ("Element", "ElementAndUnder"):
            if self.is_bottom():
                return {}
            apprs = self.to_approximations()
            result: dict[Any, list[Approximation]] = {}
            items = apprs if part == "ElementAndUnder" else [Approximation(e) for e in self._over]
            for item in items:
                val = item.element if isinstance(item, Approximation) and part == "Element" else item
                if op == OP_BY:
                    key = f(val)
                    result.setdefault(key, []).append(item)
                elif op == OP_BY_FILTER:
                    key = f(val)
                    if key is not None:
                        result.setdefault(key, []).append(item)
            return {
                k: self.of_approximations(v) if isinstance(v[0], Approximation) else OverUnderSetDomain(frozenset(v), frozenset(v))
                for k, v in result.items()
            }
        raise ValueError(f"{type(self).__name__} has no part {part!r}")

    def __iter__(self) -> Iterator[Approximation]:
        return iter(self.to_approximations())
