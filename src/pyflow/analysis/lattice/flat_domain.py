"""Flat domain — discrete lattice with top/bottom.

Mirrors ``AbstractFlatDomain`` from Pysa.  Elements are incomparable
(the flat ordering): bottom < element < top.  Join of two distinct
non-bottom elements goes to top.
"""

from __future__ import annotations

from typing import (
    Any,
    Dict,
    FrozenSet,
    Iterator,
    List,
    Mapping,
    Optional,
    Sequence,
    Set,
    Tuple,
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


_TOP_SENTINEL = object()
_BOTTOM_SENTINEL = object()


class FlatDomain(AbstractDomain):
    """Flat lattice with top and bottom.

    bottom < element < top, all non-bottom/non-top elements are incomparable.
    """

    _value: Any

    def __init__(self, value: Any = _BOTTOM_SENTINEL) -> None:
        self._value = value

    @staticmethod
    def bottom() -> FlatDomain:
        return FlatDomain(_BOTTOM_SENTINEL)

    @staticmethod
    def top() -> FlatDomain:
        return FlatDomain(_TOP_SENTINEL)

    @staticmethod
    def of(value: Any) -> FlatDomain:
        return FlatDomain(value)

    def is_bottom(self) -> bool:
        return self._value is _BOTTOM_SENTINEL

    def is_top(self) -> bool:
        return self._value is _TOP_SENTINEL

    def value(self) -> Any:
        return self._value

    def join(self, other: Any) -> FlatDomain:
        if not isinstance(other, FlatDomain):
            return NotImplemented
        if self.is_bottom():
            return other
        if other.is_bottom():
            return self
        if self.is_top() or other.is_top():
            return self.top()
        if self._value == other._value:
            return self
        return self.top()

    def meet(self, other: Any) -> FlatDomain:
        if not isinstance(other, FlatDomain):
            return NotImplemented
        if self.is_top():
            return other
        if other.is_top():
            return self
        if self.is_bottom() or other.is_bottom():
            return self.bottom()
        if self._value == other._value:
            return self
        return self.bottom()

    def leq(self, other: Any) -> bool:
        if not isinstance(other, FlatDomain):
            return NotImplemented
        if self.is_bottom():
            return True
        if other.is_top():
            return True
        if self.is_top():
            return other.is_top()
        if other.is_bottom():
            return False
        return self._value == other._value

    def widen(self, other: Any, iteration: int = 0) -> FlatDomain:
        return self.join(other)

    def subtract(self, other: Any) -> FlatDomain:
        return self

    def __hash__(self) -> int:
        return hash(("FlatDomain", self._value))

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, FlatDomain):
            return NotImplemented
        return self._value is other._value

    def __repr__(self) -> str:
        if self.is_bottom():
            return "<bottom>"
        if self.is_top():
            return "Top"
        return repr(self._value)

    def parts(self) -> Sequence[PartId]:
        return ["Self", "Value"]

    def transform(self, part: PartId, op: TransformOp, f: Any) -> FlatDomain:
        if part == "Self":
            return self._transform_self(op, f)
        if part == "Value":
            return self._transform_value(op, f)
        raise ValueError(f"{type(self).__name__} has no part {part!r}")

    def _transform_value(self, op: TransformOp, f: Any) -> FlatDomain:
        if self.is_bottom() or self.is_top():
            return self
        if op == OP_MAP:
            return FlatDomain(f(self._value))
        elif op == OP_FILTER:
            if f(self._value):
                return self
            return self.bottom()
        elif op == OP_FILTER_MAP:
            mapped = f(self._value)
            if mapped is not None:
                return FlatDomain(mapped)
            return self.bottom()
        elif op == OP_ADD:
            if not self.is_bottom():
                return self
            return FlatDomain(f)
        elif op == OP_EXPAND:
            result_list = list(f(self._value))
            if len(result_list) == 1:
                return FlatDomain(result_list[0])
            return FlatDomain(tuple(result_list))
        else:
            return self._transform_self(op, f)

    def reduce(self, part: PartId, op: ReduceOp, f: Any, init: V) -> V:
        if part == "Self":
            return self._reduce_self(op, f, init)
        if part == "Value":
            if self.is_bottom() or self.is_top():
                return init
            if op == OP_ACC:
                return f(self._value, init)
            elif op == OP_EXISTS:
                if init:
                    return init
                return f(self._value)  # type: ignore
        raise ValueError(f"{type(self).__name__} has no part {part!r}")

    def partition(
        self, part: PartId, op: PartitionOp, f: Any
    ) -> Mapping[Any, FlatDomain]:
        if part == "Self":
            return self._partition_self(op, f)
        if part == "Value":
            if self.is_bottom() or self.is_top():
                return {}
            key = f(self._value)
            if op == OP_BY_FILTER and key is None:
                return {}
            return {key: self}
        raise ValueError(f"{type(self).__name__} has no part {part!r}")
