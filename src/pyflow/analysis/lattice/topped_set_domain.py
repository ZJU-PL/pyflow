"""Topped set domain — adds a top element above a base set domain.

Mirrors ``AbstractToppedSetDomain`` from Pysa.  Top represents
"all possible elements" (the full universe), distinguishing it from
an empty set.  Join of incompatible elements goes to Top.
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


class ToppedSetDomain(AbstractDomain):
    """A set domain with an explicit Top element (the universe).

    Lattice::
        Top
       / | \\
      {a} {b} {c}
       \\ | /
       Bottom
    """

    _elements: Optional[FrozenSet[Any]]

    def __init__(self, elements: Optional[FrozenSet[Any]] = None) -> None:
        self._elements = elements

    @staticmethod
    def bottom() -> ToppedSetDomain:
        return ToppedSetDomain(frozenset())

    @staticmethod
    def top() -> ToppedSetDomain:
        return ToppedSetDomain(None)

    @staticmethod
    def singleton(element: Any) -> ToppedSetDomain:
        return ToppedSetDomain(frozenset([element]))

    def is_bottom(self) -> bool:
        return self._elements is not None and len(self._elements) == 0

    def is_top(self) -> bool:
        return self._elements is None

    def elements(self) -> FrozenSet[Any]:
        if self._elements is None:
            return frozenset()
        return self._elements

    def join(self, other: Any) -> ToppedSetDomain:
        if not isinstance(other, ToppedSetDomain):
            return NotImplemented
        if self.is_top() or other.is_top():
            return self.top()
        if self.is_bottom():
            return other
        if other.is_bottom():
            return self
        assert self._elements is not None and other._elements is not None
        return ToppedSetDomain(self._elements | other._elements)

    def meet(self, other: Any) -> ToppedSetDomain:
        if not isinstance(other, ToppedSetDomain):
            return NotImplemented
        if self.is_bottom() or other.is_bottom():
            return self.bottom()
        if self.is_top():
            return other
        if other.is_top():
            return self
        assert self._elements is not None and other._elements is not None
        return ToppedSetDomain(self._elements & other._elements)

    def leq(self, other: Any) -> bool:
        if not isinstance(other, ToppedSetDomain):
            return NotImplemented
        if self.is_top():
            return other.is_top()
        if other.is_top():
            return True
        if self.is_bottom():
            return True
        assert self._elements is not None and other._elements is not None
        return self._elements <= other._elements

    def widen(self, other: Any, iteration: int = 0) -> ToppedSetDomain:
        return self.join(other)

    def subtract(self, other: Any) -> ToppedSetDomain:
        if self.is_top() or self.is_bottom():
            return self
        if other.is_top() or other.is_bottom():
            return self
        assert self._elements is not None and other._elements is not None
        return ToppedSetDomain(self._elements - other._elements)

    def add(self, element: Any) -> ToppedSetDomain:
        if self.is_top():
            return self
        if self.is_bottom():
            return ToppedSetDomain.singleton(element)
        assert self._elements is not None
        return ToppedSetDomain(self._elements | {element})

    def contains(self, element: Any) -> bool:
        if self.is_top():
            return True
        if self.is_bottom():
            return False
        return element in self._elements

    def __hash__(self) -> int:
        return hash(("ToppedSetDomain", self._elements))

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, ToppedSetDomain):
            return NotImplemented
        return self._elements == other._elements

    def __repr__(self) -> str:
        if self.is_top():
            return "Top"
        if self.is_bottom():
            return "<bottom>"
        return f"{{{', '.join(repr(e) for e in self._elements)}}}"  # type: ignore

    def __len__(self) -> int:
        if self.is_top():
            return 0
        if self.is_bottom():
            return 0
        return len(self._elements)  # type: ignore

    def __iter__(self) -> Iterator[Any]:
        if self._elements is not None:
            return iter(self._elements)
        return iter([])

    def parts(self) -> Sequence[PartId]:
        return ["Self", "Element"]

    def transform(self, part: PartId, op: TransformOp, f: Any) -> ToppedSetDomain:
        if part == "Self":
            return self._transform_self(op, f)
        if part == "Element":
            return self._transform_element(op, f)
        raise ValueError(f"{type(self).__name__} has no part {part!r}")

    def _transform_element(self, op: TransformOp, f: Any) -> ToppedSetDomain:
        if self.is_top():
            return self
        if op == OP_MAP:
            if self.is_bottom():
                return self
            return ToppedSetDomain(frozenset(f(e) for e in self._elements))  # type: ignore
        elif op == OP_ADD:
            return self.add(f)
        elif op == OP_FILTER:
            if self.is_bottom():
                return self
            return ToppedSetDomain(frozenset(e for e in self._elements if f(e)))  # type: ignore
        elif op == OP_FILTER_MAP:
            if self.is_bottom():
                return self
            result: Set[Any] = set()
            for e in self._elements:  # type: ignore
                mapped = f(e)
                if mapped is not None:
                    result.add(mapped)
            return ToppedSetDomain(frozenset(result))
        elif op == OP_EXPAND:
            if self.is_bottom():
                return self
            result = set()
            for e in self._elements:  # type: ignore
                for expanded in f(e):
                    result.add(expanded)
            return ToppedSetDomain(frozenset(result))
        else:
            return self._transform_self(op, f)

    def reduce(self, part: PartId, op: ReduceOp, f: Any, init: V) -> V:
        if part == "Self":
            return self._reduce_self(op, f, init)
        if part == "Element":
            if self.is_bottom() or self.is_top():
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
    ) -> Mapping[Any, ToppedSetDomain]:
        if part == "Self":
            return self._partition_self(op, f)
        if part == "Element":
            if self.is_bottom() or self.is_top():
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
            return {k: ToppedSetDomain(frozenset(v)) for k, v in result.items()}
        raise ValueError(f"{type(self).__name__} has no part {part!r}")
