"""Map domain — a lattice of maps from keys to abstract values.

Mirrors ``AbstractMapDomain`` from Pysa.  Join/meet are pointwise
applications of the value domain's join/meet.  Missing keys are treated
as bottom values of the codomain.
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
    EP_CONST,
    EP_LOCAL,
    AbstractDomain,
    PartId,
    TransformOp,
    ReduceOp,
    PartitionOp,
)

K = TypeVar("K")
V = TypeVar("V")
T = TypeVar("T")


class MapDomain(AbstractDomain):
    """Lattice of mappings K -> V where V is an AbstractDomain.

    Bottom = empty map.  Join = pointwise join of codomain values.
    Missing keys in join are treated as bottom.
    """

    _mapping: Dict[Any, AbstractDomain]
    _default: Optional[Any]

    def __init__(
        self,
        mapping: Optional[Dict[Any, AbstractDomain]] = None,
        default: Optional[Any] = None,
    ) -> None:
        self._mapping = {} if mapping is None else dict(mapping)
        self._default = default

    @staticmethod
    def bottom() -> MapDomain:
        return MapDomain()

    def is_bottom(self) -> bool:
        return len(self._mapping) == 0 and self._default is None

    @staticmethod
    def of(key: Any, value: AbstractDomain) -> MapDomain:
        return MapDomain({key: value})

    def get(self, key: Any) -> Optional[AbstractDomain]:
        if key in self._mapping:
            return self._mapping[key]
        return self._default

    def set(self, key: Any, value: AbstractDomain) -> MapDomain:
        new_map = dict(self._mapping)
        new_map[key] = value
        return MapDomain(new_map, self._default)

    def remove(self, key: Any) -> MapDomain:
        new_map = dict(self._mapping)
        new_map.pop(key, None)
        return MapDomain(new_map, self._default)

    def keys(self) -> Iterator[Any]:
        return iter(self._mapping.keys())

    def items(self) -> Iterator[Tuple[Any, AbstractDomain]]:
        return iter(self._mapping.items())

    def values(self) -> Iterator[AbstractDomain]:
        return iter(self._mapping.values())

    def __contains__(self, key: Any) -> bool:
        return key in self._mapping

    def __len__(self) -> int:
        return len(self._mapping)

    def __iter__(self) -> Iterator[Any]:
        return iter(self._mapping.keys())

    def __hash__(self) -> int:
        items = tuple(sorted(self._mapping.items(), key=lambda x: str(x[0])))
        return hash(("MapDomain", items))

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, MapDomain):
            return NotImplemented
        return self._mapping == other._mapping

    def __repr__(self) -> str:
        return f"Map({self._mapping})"

    def join(self, other: Any) -> MapDomain:
        if not isinstance(other, MapDomain):
            return NotImplemented
        if self.is_bottom():
            return other
        if other.is_bottom():
            return self
        all_keys = set(self._mapping) | set(other._mapping)
        result: Dict[Any, AbstractDomain] = {}
        for key in all_keys:
            left = self._mapping.get(key)
            right = other._mapping.get(key)
            if left is None and right is None:
                continue
            if left is None:
                result[key] = right  # type: ignore
            elif right is None:
                result[key] = left
            else:
                result[key] = left.join(right)
        return MapDomain(result)

    def meet(self, other: Any) -> MapDomain:
        if not isinstance(other, MapDomain):
            return NotImplemented
        if self.is_bottom() or other.is_bottom():
            return self.bottom()
        all_keys = set(self._mapping) | set(other._mapping)
        result: Dict[Any, AbstractDomain] = {}
        for key in all_keys:
            left = self._mapping.get(key)
            right = other._mapping.get(key)
            if left is None or right is None:
                continue
            result[key] = left.meet(right)
        return MapDomain(result)

    def leq(self, other: Any) -> bool:
        if not isinstance(other, MapDomain):
            return NotImplemented
        if self.is_bottom():
            return True
        if other.is_bottom():
            return False
        for key, left in self._mapping.items():
            right = other._mapping.get(key)
            if right is None:
                return False
            if not left.leq(right):
                return False
        return True

    def widen(self, other: Any, iteration: int = 0) -> MapDomain:
        if not isinstance(other, MapDomain):
            return NotImplemented
        if self.is_bottom():
            return other
        if other.is_bottom():
            return self
        all_keys = set(self._mapping) | set(other._mapping)
        result: Dict[Any, AbstractDomain] = {}
        for key in all_keys:
            left = self._mapping.get(key)
            right = other._mapping.get(key)
            if left is None and right is None:
                continue
            if left is None:
                result[key] = right  # type: ignore
            elif right is None:
                result[key] = left
            else:
                result[key] = left.widen(right, iteration)
        return MapDomain(result)

    def subtract(self, other: Any) -> MapDomain:
        return self

    def parts(self) -> Sequence[PartId]:
        return ["Self", "KeyValue"]

    def transform(self, part: PartId, op: TransformOp, f: Any) -> MapDomain:
        if part == "Self":
            return self._transform_self(op, f)
        if part == "KeyValue":
            return self._transform_keyvalue(op, f)
        raise ValueError(f"{type(self).__name__} has no part {part!r}")

    def _transform_keyvalue(self, op: TransformOp, f: Any) -> MapDomain:
        if self.is_bottom():
            return self
        if op == OP_MAP:
            result: Dict[Any, AbstractDomain] = {}
            for k, v in self._mapping.items():
                new_k, new_v = f(k, v)
                result[new_k] = new_v
            return MapDomain(result)
        elif op == OP_FILTER:
            result = {}
            for k, v in self._mapping.items():
                if f(k, v):
                    result[k] = v
            return MapDomain(result)
        elif op == OP_FILTER_MAP:
            result = {}
            for k, v in self._mapping.items():
                kv = f(k, v)
                if kv is not None:
                    new_k, new_v = kv
                    result[new_k] = new_v
            return MapDomain(result)
        elif op == OP_EXPAND:
            result = {}
            for k, v in self._mapping.items():
                for new_k, new_v in f(k, v):
                    result[new_k] = new_v
            return MapDomain(result)
        elif op == OP_ADD:
            new_k, new_v = f
            return self.set(new_k, new_v)
        else:
            return self._transform_self(op, f)

    def reduce(self, part: PartId, op: ReduceOp, f: Any, init: V) -> V:
        if part == "Self":
            return self._reduce_self(op, f, init)
        if part == "KeyValue":
            if self.is_bottom():
                return init
            if op == OP_ACC:
                acc = init
                for k, v in self._mapping.items():
                    acc = f(k, v, acc)
                return acc
            elif op == OP_EXISTS:
                if init:
                    return init
                for k, v in self._mapping.items():
                    if f(k, v):
                        return True  # type: ignore
                return False  # type: ignore
        raise ValueError(f"{type(self).__name__} has no part {part!r}")

    def partition(
        self, part: PartId, op: PartitionOp, f: Any
    ) -> Mapping[Any, MapDomain]:
        if part == "Self":
            return self._partition_self(op, f)
        if part == "KeyValue":
            if self.is_bottom():
                return {}
            result: dict[Any, dict[Any, AbstractDomain]] = {}
            if op == OP_BY:
                for k, v in self._mapping.items():
                    key = f(k, v)
                    result.setdefault(key, {})[k] = v
            elif op == OP_BY_FILTER:
                for k, v in self._mapping.items():
                    key = f(k, v)
                    if key is not None:
                        result.setdefault(key, {})[k] = v
            return {k: MapDomain(v) for k, v in result.items()}
        raise ValueError(f"{type(self).__name__} has no part {part!r}")
