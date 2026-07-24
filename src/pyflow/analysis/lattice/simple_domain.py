"""Simple domain — a generic hash-consed abstract domain wrapper.

Mirrors ``AbstractSimpleDomain`` from Pysa.  Wraps an arbitrary value
and uses its natural equality/hash for lattice operations.  Only
the identity join (self == other → self) and the trivial meet are
supported — this is used for domains where values are only compared,
not merged.
"""

from __future__ import annotations

from typing import (
    Any,
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

V = TypeVar("V")


class SimpleDomain(AbstractDomain):
    """Domain wrapping an arbitrary hashable value.

    Bottom is a sentinel.  Join only succeeds on equal values (returns
    self), otherwise raises or returns bottom.
    """

    _value: Optional[Any]

    def __init__(self, value: Optional[Any] = None) -> None:
        self._value = value

    @staticmethod
    def bottom() -> SimpleDomain:
        return SimpleDomain(None)

    @staticmethod
    def of(value: Any) -> SimpleDomain:
        return SimpleDomain(value)

    def is_bottom(self) -> bool:
        return self._value is None

    def value(self) -> Optional[Any]:
        return self._value

    def join(self, other: Any) -> SimpleDomain:
        if not isinstance(other, SimpleDomain):
            return NotImplemented
        if self.is_bottom():
            return other
        if other.is_bottom():
            return self
        if self._value == other._value:
            return self
        return self.bottom()

    def meet(self, other: Any) -> SimpleDomain:
        if not isinstance(other, SimpleDomain):
            return NotImplemented
        if self.is_bottom() or other.is_bottom():
            return self.bottom()
        if self._value == other._value:
            return self
        return self.bottom()

    def leq(self, other: Any) -> bool:
        if not isinstance(other, SimpleDomain):
            return NotImplemented
        if self.is_bottom():
            return True
        if other.is_bottom():
            return False
        return self._value == other._value

    def widen(self, other: Any, iteration: int = 0) -> SimpleDomain:
        return self.join(other)

    def subtract(self, other: Any) -> SimpleDomain:
        return self

    def __hash__(self) -> int:
        return hash(("SimpleDomain", self._value))

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, SimpleDomain):
            return NotImplemented
        return self._value == other._value

    def __repr__(self) -> str:
        if self.is_bottom():
            return "<bottom>"
        return repr(self._value)

    def parts(self) -> Sequence[PartId]:
        return ["Self", "Value"]

    def transform(self, part: PartId, op: TransformOp, f: Any) -> SimpleDomain:
        if part == "Self":
            return self._transform_self(op, f)
        if part == "Value":
            return self._transform_value(op, f)
        raise ValueError(f"{type(self).__name__} has no part {part!r}")

    def _transform_value(self, op: TransformOp, f: Any) -> SimpleDomain:
        if self.is_bottom():
            return self
        if op == OP_MAP:
            return SimpleDomain(f(self._value))
        elif op == OP_FILTER:
            if f(self._value):
                return self
            return self.bottom()
        elif op == OP_FILTER_MAP:
            mapped = f(self._value)
            if mapped is not None:
                return SimpleDomain(mapped)
            return self.bottom()
        elif op == OP_ADD:
            return SimpleDomain(f)
        else:
            return self._transform_self(op, f)

    def reduce(self, part: PartId, op: ReduceOp, f: Any, init: V) -> V:
        if part == "Self":
            return self._reduce_self(op, f, init)
        if part == "Value":
            if self.is_bottom():
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
    ) -> Mapping[Any, SimpleDomain]:
        if part == "Self":
            return self._partition_self(op, f)
        if part == "Value":
            if self.is_bottom():
                return {}
            key = f(self._value)
            if op == OP_BY_FILTER and key is None:
                return {}
            return {key: self}
        raise ValueError(f"{type(self).__name__} has no part {part!r}")
