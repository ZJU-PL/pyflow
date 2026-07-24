"""Tree domain — hierarchical lattice of nested abstract values.

Mirrors ``AbstractTreeDomain`` from Pysa.  A tree maps string keys to
child abstract domain values, forming a prefix-ordered lattice.
"""

from __future__ import annotations

from typing import (
    Any,
    Callable,
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

T = TypeVar("T")
V = TypeVar("V")


class TreeDomain(AbstractDomain):
    """A tree where each node maps child keys to abstract values.

    The lattice structure follows the tree hierarchy: deeper nesting
    means more precise (smaller) values.
    """

    _children: Dict[str, AbstractDomain]

    def __init__(self, children: Optional[Dict[str, AbstractDomain]] = None) -> None:
        self._children = {} if children is None else children

    @staticmethod
    def bottom() -> TreeDomain:
        return TreeDomain()

    def is_bottom(self) -> bool:
        return len(self._children) == 0

    @staticmethod
    def leaf(value: AbstractDomain) -> TreeDomain:
        return TreeDomain({"": value})

    @staticmethod
    def of(*path_values: Tuple[str, AbstractDomain]) -> TreeDomain:
        return TreeDomain(dict(path_values))

    def get(self, key: str) -> Optional[AbstractDomain]:
        return self._children.get(key)

    def set(self, key: str, value: AbstractDomain) -> TreeDomain:
        new = dict(self._children)
        new[key] = value
        return TreeDomain(new)

    def remove(self, key: str) -> TreeDomain:
        new = dict(self._children)
        new.pop(key, None)
        return TreeDomain(new)

    def keys(self) -> Sequence[str]:
        return list(self._children.keys())

    def items(self) -> Sequence[Tuple[str, AbstractDomain]]:
        return list(self._children.items())

    def __contains__(self, key: str) -> bool:
        return key in self._children

    def __len__(self) -> int:
        return len(self._children)

    def __iter__(self):
        return iter(self._children.items())

    def __hash__(self) -> int:
        items = tuple(sorted(self._children.items()))
        return hash(("TreeDomain", items))

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, TreeDomain):
            return NotImplemented
        return self._children == other._children

    def __repr__(self) -> str:
        return f"Tree({self._children})"

    def join(self, other: Any) -> TreeDomain:
        if not isinstance(other, TreeDomain):
            return NotImplemented
        if self.is_bottom():
            return other
        if other.is_bottom():
            return self
        all_keys = set(self._children) | set(other._children)
        result: Dict[str, AbstractDomain] = {}
        for key in all_keys:
            left = self._children.get(key)
            right = other._children.get(key)
            if left is None:
                result[key] = right  # type: ignore
            elif right is None:
                result[key] = left
            else:
                result[key] = left.join(right)
        return TreeDomain(result)

    def meet(self, other: Any) -> TreeDomain:
        if not isinstance(other, TreeDomain):
            return NotImplemented
        if self.is_bottom() or other.is_bottom():
            return self.bottom()
        all_keys = set(self._children) | set(other._children)
        result: Dict[str, AbstractDomain] = {}
        for key in all_keys:
            left = self._children.get(key)
            right = other._children.get(key)
            if left is None or right is None:
                continue
            result[key] = left.meet(right)
        return TreeDomain(result)

    def leq(self, other: Any) -> bool:
        if not isinstance(other, TreeDomain):
            return NotImplemented
        if self.is_bottom():
            return True
        if other.is_bottom():
            return False
        for key, left in self._children.items():
            right = other._children.get(key)
            if right is None:
                return False
            if not left.leq(right):
                return False
        return True

    def widen(self, other: Any, iteration: int = 0) -> TreeDomain:
        if not isinstance(other, TreeDomain):
            return NotImplemented
        if self.is_bottom():
            return other
        if other.is_bottom():
            return self
        all_keys = set(self._children) | set(other._children)
        result: Dict[str, AbstractDomain] = {}
        for key in all_keys:
            left = self._children.get(key)
            right = other._children.get(key)
            if left is None:
                result[key] = right  # type: ignore
            elif right is None:
                result[key] = left
            else:
                result[key] = left.widen(right, iteration)
        return TreeDomain(result)

    def subtract(self, other: Any) -> TreeDomain:
        return self

    def parts(self) -> Sequence[PartId]:
        return ["Self", "Tree"]

    def transform(self, part: PartId, op: TransformOp, f: Any) -> TreeDomain:
        if part == "Self":
            return self._transform_self(op, f)
        if part == "Tree":
            return self._transform_tree(op, f)
        raise ValueError(f"{type(self).__name__} has no part {part!r}")

    def _transform_tree(self, op: TransformOp, f: Any) -> TreeDomain:
        if self.is_bottom():
            return self
        if op == OP_MAP:
            result: Dict[str, AbstractDomain] = {}
            for k, v in self._children.items():
                new_k, new_v = f(k, v)
                result[new_k] = new_v
            return TreeDomain(result)
        elif op == OP_FILTER:
            result = {}
            for k, v in self._children.items():
                if f(k, v):
                    result[k] = v
            return TreeDomain(result)
        elif op == OP_FILTER_MAP:
            result = {}
            for k, v in self._children.items():
                kv = f(k, v)
                if kv is not None:
                    new_k, new_v = kv
                    result[new_k] = new_v
            return TreeDomain(result)
        elif op == OP_EXPAND:
            result = {}
            for k, v in self._children.items():
                for new_k, new_v in f(k, v):
                    result[new_k] = new_v
            return TreeDomain(result)
        elif op == OP_ADD:
            new_k, new_v = f
            return self.set(new_k, new_v)
        else:
            return self._transform_self(op, f)

    def reduce(self, part: PartId, op: ReduceOp, f: Any, init: V) -> V:
        if part == "Self":
            return self._reduce_self(op, f, init)
        if part == "Tree":
            if self.is_bottom():
                return init
            if op == OP_ACC:
                acc = init
                for k, v in self._children.items():
                    acc = f(k, v, acc)
                return acc
            elif op == OP_EXISTS:
                if init:
                    return init
                for k, v in self._children.items():
                    if f(k, v):
                        return True  # type: ignore
                return False  # type: ignore
        raise ValueError(f"{type(self).__name__} has no part {part!r}")

    def partition(
        self, part: PartId, op: PartitionOp, f: Any
    ) -> Mapping[Any, TreeDomain]:
        if part == "Self":
            return self._partition_self(op, f)
        if part == "Tree":
            if self.is_bottom():
                return {}
            result: dict[Any, dict[str, AbstractDomain]] = {}
            if op == OP_BY:
                for k, v in self._children.items():
                    key = f(k, v)
                    result.setdefault(key, {})[k] = v
            elif op == OP_BY_FILTER:
                for k, v in self._children.items():
                    key = f(k, v)
                    if key is not None:
                        result.setdefault(key, {})[k] = v
            return {k: TreeDomain(v) for k, v in result.items()}
        raise ValueError(f"{type(self).__name__} has no part {part!r}")
