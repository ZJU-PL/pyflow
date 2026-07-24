"""Bucketed element set domain — groups ElementSetDomain by a key function.

Mirrors ``AbstractBucketedElementSetDomain`` from Pysa.  Each element
is categorized into a bucket by a key function, and subsumption is
applied within each bucket independently.
"""

from __future__ import annotations

from typing import (
    Any,
    Callable,
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
from .element_set_domain import ElementSetDomain

T = TypeVar("T")
V = TypeVar("V")


class BucketedElementSetDomain(AbstractDomain):
    """A map from bucket keys to ElementSetDomains.

    Each bucket is an independent ElementSetDomain with its own
    subsumption ordering.  Elements with different keys are incomparable.
    """

    _buckets: Dict[Any, ElementSetDomain]

    def __init__(self, buckets: Optional[Dict[Any, ElementSetDomain]] = None) -> None:
        self._buckets = {} if buckets is None else buckets

    @staticmethod
    def bottom() -> BucketedElementSetDomain:
        return BucketedElementSetDomain()

    def is_bottom(self) -> bool:
        return len(self._buckets) == 0

    @staticmethod
    def empty() -> BucketedElementSetDomain:
        return BucketedElementSetDomain()

    def is_empty(self) -> bool:
        return self.is_bottom()

    def join(self, other: Any) -> BucketedElementSetDomain:
        if not isinstance(other, BucketedElementSetDomain):
            return NotImplemented
        if self.is_bottom():
            return other
        if other.is_bottom():
            return self
        all_keys = set(self._buckets) | set(other._buckets)
        result: Dict[Any, ElementSetDomain] = {}
        for key in all_keys:
            left = self._buckets.get(key)
            right = other._buckets.get(key)
            if left is None and right is None:
                continue
            if left is None:
                result[key] = right  # type: ignore
            elif right is None:
                result[key] = left
            else:
                result[key] = left.join(right)
        return BucketedElementSetDomain(result)

    def meet(self, other: Any) -> BucketedElementSetDomain:
        if not isinstance(other, BucketedElementSetDomain):
            return NotImplemented
        if self.is_bottom() or other.is_bottom():
            return self.bottom()
        all_keys = set(self._buckets) | set(other._buckets)
        result: Dict[Any, ElementSetDomain] = {}
        for key in all_keys:
            left = self._buckets.get(key)
            right = other._buckets.get(key)
            if left is None or right is None:
                continue
            result[key] = left.meet(right)
        return BucketedElementSetDomain(result)

    def leq(self, other: Any) -> bool:
        if not isinstance(other, BucketedElementSetDomain):
            return NotImplemented
        if self.is_bottom():
            return True
        if other.is_bottom():
            return False
        for key, left in self._buckets.items():
            right = other._buckets.get(key)
            if right is None:
                return False
            if not left.leq(right):
                return False
        return True

    def widen(self, other: Any, iteration: int = 0) -> BucketedElementSetDomain:
        if not isinstance(other, BucketedElementSetDomain):
            return NotImplemented
        if self.is_bottom():
            return other
        if other.is_bottom():
            return self
        all_keys = set(self._buckets) | set(other._buckets)
        result: Dict[Any, ElementSetDomain] = {}
        for key in all_keys:
            left = self._buckets.get(key)
            right = other._buckets.get(key)
            if left is None and right is None:
                continue
            if left is None:
                result[key] = right  # type: ignore
            elif right is None:
                result[key] = left
            else:
                result[key] = left.widen(right, iteration)
        return BucketedElementSetDomain(result)

    def subtract(self, other: Any) -> BucketedElementSetDomain:
        return self

    @staticmethod
    def empty_of(key: Any) -> BucketedElementSetDomain:
        return BucketedElementSetDomain({key: ElementSetDomain.empty()})

    def add(self, element: Any, key: Any) -> BucketedElementSetDomain:
        bucket = self._buckets.get(key, ElementSetDomain.empty())
        new_bucket = bucket.add(element)
        new_buckets = dict(self._buckets)
        new_buckets[key] = new_bucket
        return BucketedElementSetDomain(new_buckets)

    def get(self, key: Any) -> ElementSetDomain:
        return self._buckets.get(key, ElementSetDomain.empty())

    def keys(self) -> Iterator[Any]:
        return iter(self._buckets.keys())

    def items(self) -> Iterator[Tuple[Any, ElementSetDomain]]:
        return iter(self._buckets.items())

    def values(self) -> Iterator[ElementSetDomain]:
        return iter(self._buckets.values())

    def __hash__(self) -> int:
        items = tuple(sorted(self._buckets.items(), key=lambda x: str(x[0])))
        return hash(("BucketedElementSetDomain", items))

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, BucketedElementSetDomain):
            return NotImplemented
        return self._buckets == other._buckets

    def __repr__(self) -> str:
        parts = [f"{k}: {v}" for k, v in self._buckets.items()]
        return "{" + ", ".join(parts) + "}"

    def parts(self) -> Sequence[PartId]:
        return ["Self", "Bucket"]

    def transform(self, part: PartId, op: TransformOp, f: Any) -> BucketedElementSetDomain:
        if part == "Self":
            return self._transform_self(op, f)
        if part == "Bucket":
            return self._transform_bucket(op, f)
        raise ValueError(f"{type(self).__name__} has no part {part!r}")

    def _transform_bucket(self, op: TransformOp, f: Any) -> BucketedElementSetDomain:
        if self.is_bottom():
            return self
        if op == OP_MAP:
            result: Dict[Any, ElementSetDomain] = {}
            for k, v in self._buckets.items():
                mapped = f(k, v)
                if mapped is not None and not mapped.is_bottom():
                    result[k] = mapped
            return BucketedElementSetDomain(result)
        else:
            return self._transform_self(op, f)

    def reduce(self, part: PartId, op: ReduceOp, f: Any, init: V) -> V:
        if part == "Self":
            return self._reduce_self(op, f, init)
        if part == "Bucket":
            if self.is_bottom():
                return init
            if op == OP_ACC:
                acc = init
                for k, v in self._buckets.items():
                    acc = f(k, v, acc)
                return acc
            elif op == OP_EXISTS:
                if init:
                    return init
                for k, v in self._buckets.items():
                    if f(k, v):
                        return True  # type: ignore
                return False  # type: ignore
        raise ValueError(f"{type(self).__name__} has no part {part!r}")

    def partition(
        self, part: PartId, op: PartitionOp, f: Any
    ) -> Mapping[Any, BucketedElementSetDomain]:
        if part == "Self":
            return self._partition_self(op, f)
        if part == "Bucket":
            if self.is_bottom():
                return {}
            result: dict[Any, dict[Any, ElementSetDomain]] = {}
            if op == OP_BY:
                for k, v in self._buckets.items():
                    key = f(k, v)
                    result.setdefault(key, {})[k] = v
            elif op == OP_BY_FILTER:
                for k, v in self._buckets.items():
                    key = f(k, v)
                    if key is not None:
                        result.setdefault(key, {})[k] = v
            return {
                k: BucketedElementSetDomain(v) for k, v in result.items()
            }
        raise ValueError(f"{type(self).__name__} has no part {part!r}")
