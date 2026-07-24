"""Wrapper domain — delegates all lattice operations to a wrapped domain.

Mirrors ``AbstractWrapperDomain`` from Pysa.  Useful for creating new
domain types that behave identically to an existing domain but have
a distinct type (for type-safety in multi-domain analyses).
"""

from __future__ import annotations

from typing import (
    Any,
    Dict,
    FrozenSet,
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
from .set_domain import SetDomain

V = TypeVar("V")


class WrapperDomain(AbstractDomain):
    """Delegates all operations to the wrapped inner domain.

    This is a transparent wrapper — all lattice operations forward
    to the inner domain's implementation.
    """

    _inner: AbstractDomain

    def __init__(self, inner: AbstractDomain) -> None:
        self._inner = inner

    @property
    def inner(self) -> AbstractDomain:
        return self._inner

    @staticmethod
    def bottom() -> WrapperDomain:
        return WrapperDomain(SetDomain.bottom())

    def is_bottom(self) -> bool:
        return self._inner.is_bottom()

    def join(self, other: Any) -> WrapperDomain:
        if not isinstance(other, WrapperDomain):
            return NotImplemented
        return WrapperDomain(self._inner.join(other._inner))

    def meet(self, other: Any) -> WrapperDomain:
        if not isinstance(other, WrapperDomain):
            return NotImplemented
        return WrapperDomain(self._inner.meet(other._inner))

    def leq(self, other: Any) -> bool:
        if not isinstance(other, WrapperDomain):
            return NotImplemented
        return self._inner.leq(other._inner)

    def widen(self, other: Any, iteration: int = 0) -> WrapperDomain:
        if not isinstance(other, WrapperDomain):
            return NotImplemented
        return WrapperDomain(self._inner.widen(other._inner, iteration))

    def subtract(self, other: Any) -> WrapperDomain:
        if not isinstance(other, WrapperDomain):
            return NotImplemented
        return WrapperDomain(self._inner.subtract(other._inner))

    def __hash__(self) -> int:
        return hash(("WrapperDomain", self._inner))

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, WrapperDomain):
            return NotImplemented
        return self._inner == other._inner

    def __repr__(self) -> str:
        return f"Wrap({self._inner})"

    def parts(self) -> Sequence[PartId]:
        return ["Self", "Inner"]

    def transform(self, part: PartId, op: TransformOp, f: Any) -> WrapperDomain:
        if part == "Self":
            return self._transform_self(op, f)
        if part == "Inner":
            return WrapperDomain(self._inner.transform("Self", op, f))
        raise ValueError(f"{type(self).__name__} has no part {part!r}")

    def reduce(self, part: PartId, op: ReduceOp, f: Any, init: V) -> V:
        if part == "Self":
            return self._reduce_self(op, f, init)
        if part == "Inner":
            return self._inner.reduce("Self", op, f, init)
        raise ValueError(f"{type(self).__name__} has no part {part!r}")

    def partition(
        self, part: PartId, op: PartitionOp, f: Any
    ) -> Mapping[Any, WrapperDomain]:
        if part == "Self":
            return self._partition_self(op, f)
        if part == "Inner":
            parts = self._inner.partition("Self", op, f)
            return {k: WrapperDomain(v) for k, v in parts.items()}
        raise ValueError(f"{type(self).__name__} has no part {part!r}")
