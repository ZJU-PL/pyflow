"""Product domain — Cartesian product of two abstract domains.

Mirrors ``AbstractProductDomain`` from Pysa.  Join/meet/leq are
component-wise.  This is the standard product lattice construction.
"""

from __future__ import annotations

from typing import (
    Any,
    Callable,
    Dict,
    List,
    Mapping,
    Optional,
    Sequence,
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
from .set_domain import SetDomain

T = TypeVar("T")
V = TypeVar("V")
U = TypeVar("U")


class ProductDomain(AbstractDomain):
    """Cartesian product of two lattices.

    Lattice::
        (a,b) ≤ (a',b')  iff  a ≤ a' and b ≤ b'
        (a,b) ⊔ (a',b') = (a⊔a', b⊔b')
        (a,b) ⊓ (a',b') = (a⊓a', b⊓b')
    """

    _left: AbstractDomain
    _right: AbstractDomain

    def __init__(self, left: AbstractDomain, right: AbstractDomain) -> None:
        self._left = left
        self._right = right

    @property
    def left(self) -> AbstractDomain:
        return self._left

    @property
    def right(self) -> AbstractDomain:
        return self._right

    def __iter__(self):
        yield self._left
        yield self._right

    @staticmethod
    def bottom() -> ProductDomain:
        return ProductDomain(SetDomain.bottom(), SetDomain.bottom())

    def is_bottom(self) -> bool:
        return self._left.is_bottom() and self._right.is_bottom()

    def join(self, other: Any) -> ProductDomain:
        if not isinstance(other, ProductDomain):
            return NotImplemented
        return ProductDomain(
            self._left.join(other._left),
            self._right.join(other._right),
        )

    def meet(self, other: Any) -> ProductDomain:
        if not isinstance(other, ProductDomain):
            return NotImplemented
        return ProductDomain(
            self._left.meet(other._left),
            self._right.meet(other._right),
        )

    def leq(self, other: Any) -> bool:
        if not isinstance(other, ProductDomain):
            return NotImplemented
        return self._left.leq(other._left) and self._right.leq(other._right)

    def widen(self, other: Any, iteration: int = 0) -> ProductDomain:
        if not isinstance(other, ProductDomain):
            return NotImplemented
        return ProductDomain(
            self._left.widen(other._left, iteration),
            self._right.widen(other._right, iteration),
        )

    def subtract(self, other: Any) -> ProductDomain:
        if not isinstance(other, ProductDomain):
            return NotImplemented
        return ProductDomain(
            self._left.subtract(other._left),
            self._right.subtract(other._right),
        )

    def __hash__(self) -> int:
        return hash(("ProductDomain", self._left, self._right))

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, ProductDomain):
            return NotImplemented
        return self._left == other._left and self._right == other._right

    def __repr__(self) -> str:
        return f"({self._left}, {self._right})"

    def parts(self) -> Sequence[PartId]:
        return ["Self", "Left", "Right"]

    def transform(self, part: PartId, op: TransformOp, f: Any) -> ProductDomain:
        if part == "Self":
            return self._transform_self(op, f)
        if part == "Left":
            new_left = self._left.transform("Self", op, f)
            return ProductDomain(new_left, self._right)
        if part == "Right":
            new_right = self._right.transform("Self", op, f)
            return ProductDomain(self._left, new_right)
        raise ValueError(f"{type(self).__name__} has no part {part!r}")

    def reduce(self, part: PartId, op: ReduceOp, f: Any, init: V) -> V:
        if part == "Self":
            return self._reduce_self(op, f, init)
        if part == "Left":
            return self._left.reduce("Self", op, f, init)
        if part == "Right":
            return self._right.reduce("Self", op, f, init)
        raise ValueError(f"{type(self).__name__} has no part {part!r}")

    def partition(
        self, part: PartId, op: PartitionOp, f: Any
    ) -> Mapping[Any, ProductDomain]:
        if part == "Self":
            return self._partition_self(op, f)
        if part == "Left":
            parts = self._left.partition("Self", op, f)
            return {k: ProductDomain(v, self._right) for k, v in parts.items()}
        if part == "Right":
            parts = self._right.partition("Self", op, f)
            return {k: ProductDomain(self._left, v) for k, v in parts.items()}
        raise ValueError(f"{type(self).__name__} has no part {part!r}")
