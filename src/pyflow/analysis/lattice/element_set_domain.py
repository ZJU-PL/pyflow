"""Element set domain — a set of abstract elements with a partial order.

Mirrors ``AbstractElementSetDomain`` from Pysa.  Unlike the standard
``SetDomain`` where elements are unrelated, ``ElementSetDomain`` tracks
a ``less_or_equal`` relation between elements.  When a new element is
added, it subsumes (replaces) any existing element that is less than or
equal to it.  Conversely, an incoming element is dropped if it is already
subsumed by an existing one.

This is useful for domains like type intervals or access paths where
elements form a hierarchy and only the maximal elements need to be stored.
"""

from __future__ import annotations

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
    Element,
    PartId,
    TransformOp,
    ReduceOp,
    PartitionOp,
)

T = TypeVar("T")


class ElementSetDomain(AbstractDomain):
    """A set of partially-ordered elements.  Join is closure under
    subsumption: only maximal elements are retained.

    Elements must implement ``leq`` (a partial order).
    """

    _elements: FrozenSet[Any]

    def __init__(self, elements: FrozenSet[Any] = frozenset()) -> None:
        self._elements = elements

    @staticmethod
    def bottom() -> ElementSetDomain:
        return ElementSetDomain(frozenset())

    @staticmethod
    def empty() -> ElementSetDomain:
        return ElementSetDomain(frozenset())

    def is_bottom(self) -> bool:
        return len(self._elements) == 0

    def elements(self) -> FrozenSet[Any]:
        return self._elements

    @staticmethod
    def singleton(element: Any) -> ElementSetDomain:
        return ElementSetDomain(frozenset([element]))

    @staticmethod
    def of(*elements: Any) -> ElementSetDomain:
        d: ElementSetDomain = ElementSetDomain.bottom()
        for e in elements:
            d = d.add(e)
        return d

    def _is_subsumed(self, element: Any) -> bool:
        leq = getattr(element, "leq", None)
        if leq is None:
            return element in self._elements
        return any(leq(other) for other in self._elements)

    def add(self, element: Any) -> ElementSetDomain:
        if self._is_subsumed(element):
            return self
        leq = getattr(element, "leq", None)
        if leq is None:
            remaining = self._elements
        else:
            remaining = frozenset(
                e for e in self._elements if not (leq(e) if hasattr(e, "leq") else False)
            )
        return ElementSetDomain(remaining | {element})

    def join(self, other: Any) -> ElementSetDomain:
        if not isinstance(other, ElementSetDomain):
            return NotImplemented
        result = self
        for e in other._elements:
            result = result.add(e)
        return result

    def meet(self, other: Any) -> ElementSetDomain:
        if not isinstance(other, ElementSetDomain):
            return NotImplemented
        return ElementSetDomain(self._elements & other._elements)

    def leq(self, other: Any) -> bool:
        if not isinstance(other, ElementSetDomain):
            return NotImplemented
        if self.is_bottom():
            return True
        if other.is_bottom():
            return False
        return all(
            other._is_subsumed(e) if hasattr(other, "_is_subsumed") else e in other._elements
            for e in self._elements
        )

    def widen(self, other: Any, iteration: int = 0) -> ElementSetDomain:
        joined = self.join(other)
        elements_list = list(joined._elements)
        widened = getattr(elements_list[0], "widen", None) if elements_list else None
        if widened:
            return ElementSetDomain.of(*widened(elements_list))
        return joined

    def subtract(self, other: Any) -> ElementSetDomain:
        if not isinstance(other, ElementSetDomain):
            return NotImplemented
        keep = frozenset(
            e for e in self._elements
            if not (other._is_subsumed(e) if hasattr(other, "_is_subsumed") else e in other._elements)
        )
        return ElementSetDomain(keep)

    def __hash__(self) -> int:
        return hash(("ElementSetDomain", self._elements))

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, ElementSetDomain):
            return NotImplemented
        return self._elements == other._elements

    def __repr__(self) -> str:
        return f"ElementSetDomain({set(self._elements)})"

    # --- parts ---

    def parts(self) -> Sequence[PartId]:
        return ["Self", "Element"]

    def transform(self, part: PartId, op: TransformOp, f: Any) -> ElementSetDomain:
        if part == "Self":
            return self._transform_self(op, f)
        if part == "Element":
            return self._transform_element(op, f)
        raise ValueError(f"{type(self).__name__} has no part {part!r}")

    def _transform_element(self, op: TransformOp, f: Any) -> ElementSetDomain:
        if op == OP_MAP:
            result: ElementSetDomain = self.bottom()
            for e in self._elements:
                result = result.add(f(e))
            return result
        elif op == OP_ADD:
            return self.add(f)
        elif op == OP_FILTER:
            return ElementSetDomain(frozenset(e for e in self._elements if f(e)))
        elif op == OP_FILTER_MAP:
            result = self.bottom()
            for e in self._elements:
                mapped = f(e)
                if mapped is not None:
                    result = result.add(mapped)
            return result
        else:
            return self._transform_self(op, f)

    def reduce(self, part: PartId, op: ReduceOp, f: Any, init: V) -> V:
        if part == "Self":
            return self._reduce_self(op, f, init)
        if part == "Element":
            if op == OP_ACC:
                acc = init
                for e in self._elements:
                    acc = f(e, acc)
                return acc
            elif op == OP_EXISTS:
                if init:
                    return init
                for e in self._elements:
                    if f(e):
                        return True  # type: ignore
                return False  # type: ignore
        raise ValueError(f"{type(self).__name__} has no part {part!r}")

    def partition(
        self, part: PartId, op: PartitionOp, f: Any
    ) -> Mapping[Any, ElementSetDomain]:
        if part == "Self":
            return self._partition_self(op, f)
        if part == "Element":
            result: dict[Any, set[Any]] = {}
            if op == OP_BY:
                for e in self._elements:
                    key = f(e)
                    result.setdefault(key, set()).add(e)
            elif op == OP_BY_FILTER:
                for e in self._elements:
                    key = f(e)
                    if key is not None:
                        result.setdefault(key, set()).add(e)
            return {k: ElementSetDomain(frozenset(v)) for k, v in result.items()}
        raise ValueError(f"{type(self).__name__} has no part {part!r}")

    def __iter__(self) -> Iterator[Any]:
        return iter(self._elements)


V = TypeVar("V")
