"""Inverted set domain — starts as the universe and shrinks via join.

Mirrors ``AbstractInvertedSetDomain`` from Pysa.  In this domain,
``bottom`` is the full universe, ``join`` is intersection (the domain
inverts the usual subset ordering), and ``meet`` is union.

This is useful for "must-not" analyses where tracking what has been
ruled out grows monotonically.
"""

from __future__ import annotations

from typing import (
    Any,
    FrozenSet,
    Iterator,
    List,
    Mapping,
    Optional,
    Sequence,
    Set,
    TypeVar,
    Union,
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


class InvertedSetDomain(AbstractDomain):
    """A universe set that shrinks through join (intersection).

    Bottom is the universe of all possible elements, top is the empty set.
    """

    _elements: Optional[FrozenSet[Any]]

    def __init__(self, elements: Optional[FrozenSet[Any]] = None) -> None:
        self._elements = elements

    @staticmethod
    def bottom() -> InvertedSetDomain:
        return InvertedSetDomain(None)

    @staticmethod
    def full() -> InvertedSetDomain:
        return InvertedSetDomain(None)

    @staticmethod
    def singleton(element: Any) -> InvertedSetDomain:
        return InvertedSetDomain(frozenset([element]))

    def is_bottom(self) -> bool:
        return self._elements is None

    def is_universe(self) -> bool:
        return self._elements is None

    def elements(self) -> FrozenSet[Any]:
        if self._elements is None:
            return frozenset()
        return self._elements

    def join(self, other: Any) -> InvertedSetDomain:
        if not isinstance(other, InvertedSetDomain):
            return NotImplemented
        if self.is_bottom():
            return other
        if other.is_bottom():
            return self
        assert self._elements is not None and other._elements is not None
        return InvertedSetDomain(self._elements & other._elements)

    def meet(self, other: Any) -> InvertedSetDomain:
        if not isinstance(other, InvertedSetDomain):
            return NotImplemented
        if self.is_bottom():
            return self.bottom()
        if other.is_bottom():
            return other
        assert self._elements is not None and other._elements is not None
        return InvertedSetDomain(self._elements | other._elements)

    def leq(self, other: Any) -> bool:
        if not isinstance(other, InvertedSetDomain):
            return NotImplemented
        if self.is_bottom():
            return True
        if other.is_bottom():
            return False
        assert self._elements is not None and other._elements is not None
        return other._elements <= self._elements

    def widen(self, other: Any, iteration: int = 0) -> InvertedSetDomain:
        return self.join(other)

    def subtract(self, other: Any) -> InvertedSetDomain:
        return self

    def __hash__(self) -> int:
        return hash(("InvertedSetDomain", self._elements))

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, InvertedSetDomain):
            return NotImplemented
        return self._elements == other._elements

    def __repr__(self) -> str:
        if self.is_bottom():
            return "Universe"
        return f"InvertedSet({set(self._elements)})"  # type: ignore

    def add(self, element: Any) -> InvertedSetDomain:
        if self.is_bottom():
            return InvertedSetDomain.singleton(element)
        assert self._elements is not None
        return InvertedSetDomain(self._elements | {element})

    def contains(self, element: Any) -> bool:
        if self.is_bottom():
            return True
        return element in self._elements

    def parts(self) -> Sequence[PartId]:
        return ["Self", "Element"]

    def transform(self, part: PartId, op: TransformOp, f: Any) -> InvertedSetDomain:
        if part == "Self":
            return self._transform_self(op, f)
        if part == "Element":
            return self._transform_element(op, f)
        raise ValueError(f"{type(self).__name__} has no part {part!r}")

    def _transform_element(self, op: TransformOp, f: Any) -> InvertedSetDomain:
        if self.is_bottom():
            if op == OP_ADD:
                return InvertedSetDomain.singleton(f)
            return self
        if op == OP_MAP:
            result = self.bottom()
            for e in self._elements:  # type: ignore
                result = result.add(f(e))
            return result
        elif op == OP_ADD:
            return self.add(f)
        elif op == OP_FILTER:
            return InvertedSetDomain(frozenset(e for e in self._elements if f(e)))  # type: ignore
        elif op == OP_FILTER_MAP:
            result = self.bottom()
            for e in self._elements:  # type: ignore
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
            if self.is_bottom():
                return init
            if op == OP_ACC:
                acc = init
                for e in self._elements:  # type: ignore
                    acc = f(e, acc)
                return acc
            elif op == OP_EXISTS:
                if init:
                    return init
                for e in self._elements:  # type: ignore
                    if f(e):
                        return True  # type: ignore
                return False  # type: ignore
        raise ValueError(f"{type(self).__name__} has no part {part!r}")

    def partition(
        self, part: PartId, op: PartitionOp, f: Any
    ) -> Mapping[Any, InvertedSetDomain]:
        if part == "Self":
            return self._partition_self(op, f)
        if part == "Element":
            if self.is_bottom():
                return {}
            result: dict[Any, set[Any]] = {}
            if op == OP_BY:
                for e in self._elements:  # type: ignore
                    key = f(e)
                    result.setdefault(key, set()).add(e)
            elif op == OP_BY_FILTER:
                for e in self._elements:  # type: ignore
                    key = f(e)
                    if key is not None:
                        result.setdefault(key, set()).add(e)
            return {k: InvertedSetDomain(frozenset(v)) for k, v in result.items()}
        raise ValueError(f"{type(self).__name__} has no part {part!r}")
