"""Rooted tree domain — a tree with a distinguished root value.

Mirrors ``AbstractRootedTreeDomain`` from Pysa.  Like TreeDomain but
each node also carries its own abstract value alongside child subtrees.
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
from .flat_domain import FlatDomain

V = TypeVar("V")
T = TypeVar("T")


class RootedTreeDomain(AbstractDomain):
    """A tree node with a root value and child subtrees.

    The lattice orders by root-value leq and pointwise child leq.
    """

    _root: AbstractDomain
    _children: Dict[str, "RootedTreeDomain"]

    def __init__(
        self,
        root: AbstractDomain,
        children: Optional[Dict[str, RootedTreeDomain]] = None,
    ) -> None:
        self._root = root
        self._children = {} if children is None else children

    @property
    def root(self) -> AbstractDomain:
        return self._root

    @property
    def children(self) -> Dict[str, "RootedTreeDomain"]:
        return self._children

    @staticmethod
    def bottom() -> RootedTreeDomain:
        return RootedTreeDomain(FlatDomain.bottom())

    def is_bottom(self) -> bool:
        return self._root.is_bottom()

    @staticmethod
    def of(value: AbstractDomain) -> RootedTreeDomain:
        return RootedTreeDomain(value)

    def get(self, key: str) -> Optional[RootedTreeDomain]:
        return self._children.get(key)

    def set(self, key: str, child: RootedTreeDomain) -> RootedTreeDomain:
        new_children = dict(self._children)
        new_children[key] = child
        return RootedTreeDomain(self._root, new_children)

    def __hash__(self) -> int:
        items = tuple(sorted(self._children.items()))
        return hash(("RootedTreeDomain", self._root, items))

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, RootedTreeDomain):
            return NotImplemented
        return self._root == other._root and self._children == other._children

    def __repr__(self) -> str:
        return f"RootedTree(root={self._root}, children={self._children})"

    def join(self, other: Any) -> RootedTreeDomain:
        if not isinstance(other, RootedTreeDomain):
            return NotImplemented
        if self.is_bottom():
            return other
        if other.is_bottom():
            return self
        new_root = self._root.join(other._root)
        all_keys = set(self._children) | set(other._children)
        new_children: Dict[str, RootedTreeDomain] = {}
        for key in all_keys:
            left = self._children.get(key)
            right = other._children.get(key)
            if left is None:
                new_children[key] = right  # type: ignore
            elif right is None:
                new_children[key] = left
            else:
                new_children[key] = left.join(right)
        return RootedTreeDomain(new_root, new_children)

    def meet(self, other: Any) -> RootedTreeDomain:
        if not isinstance(other, RootedTreeDomain):
            return NotImplemented
        if self.is_bottom() or other.is_bottom():
            return self.bottom()
        new_root = self._root.meet(other._root)
        all_keys = set(self._children) | set(other._children)
        new_children: Dict[str, RootedTreeDomain] = {}
        for key in all_keys:
            left = self._children.get(key)
            right = other._children.get(key)
            if left is not None and right is not None:
                new_children[key] = left.meet(right)
        return RootedTreeDomain(new_root, new_children)

    def leq(self, other: Any) -> bool:
        if not isinstance(other, RootedTreeDomain):
            return NotImplemented
        if self.is_bottom():
            return True
        if other.is_bottom():
            return False
        if not self._root.leq(other._root):
            return False
        for key, left in self._children.items():
            right = other._children.get(key)
            if right is None:
                return False
            if not left.leq(right):
                return False
        return True

    def widen(self, other: Any, iteration: int = 0) -> RootedTreeDomain:
        if not isinstance(other, RootedTreeDomain):
            return NotImplemented
        if self.is_bottom():
            return other
        if other.is_bottom():
            return self
        new_root = self._root.widen(other._root, iteration)
        all_keys = set(self._children) | set(other._children)
        new_children: Dict[str, RootedTreeDomain] = {}
        for key in all_keys:
            left = self._children.get(key)
            right = other._children.get(key)
            if left is None:
                new_children[key] = right  # type: ignore
            elif right is None:
                new_children[key] = left
            else:
                new_children[key] = left.widen(right, iteration)
        return RootedTreeDomain(new_root, new_children)

    def subtract(self, other: Any) -> RootedTreeDomain:
        return self

    def parts(self) -> Sequence[PartId]:
        return ["Self", "Root", "Tree"]

    def transform(self, part: PartId, op: TransformOp, f: Any) -> RootedTreeDomain:
        if part == "Self":
            return self._transform_self(op, f)
        if part == "Root":
            return RootedTreeDomain(
                self._root.transform("Self", op, f),
                self._children,
            )
        if part == "Tree":
            return self._transform_tree(op, f)
        raise ValueError(f"{type(self).__name__} has no part {part!r}")

    def _transform_tree(self, op: TransformOp, f: Any) -> RootedTreeDomain:
        if self.is_bottom():
            return self
        if op == OP_MAP:
            new_root = self._root
            new_children: Dict[str, RootedTreeDomain] = {}
            for k, v in self._children.items():
                nk, nv = f(k, v)
                new_children[nk] = nv
            return RootedTreeDomain(new_root, new_children)
        elif op == OP_FILTER:
            new_root = self._root
            new_children = {
                k: v for k, v in self._children.items() if f(k, v)
            }
            return RootedTreeDomain(new_root, new_children)
        elif op == OP_ADD:
            new_k, new_v = f
            return self.set(new_k, new_v)
        elif op == OP_FILTER_MAP:
            new_root = self._root
            new_children = {}
            for k, v in self._children.items():
                kv = f(k, v)
                if kv is not None:
                    new_k, new_v = kv
                    new_children[new_k] = new_v
            return RootedTreeDomain(new_root, new_children)
        else:
            return self._transform_self(op, f)

    def reduce(self, part: PartId, op: ReduceOp, f: Any, init: V) -> V:
        if part == "Self":
            return self._reduce_self(op, f, init)
        if part == "Root":
            return self._root.reduce("Self", op, f, init)
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
    ) -> Mapping[Any, RootedTreeDomain]:
        if part == "Self":
            return self._partition_self(op, f)
        if part == "Tree":
            if self.is_bottom():
                return {}
            result: dict[Any, dict[str, RootedTreeDomain]] = {}
            if op == OP_BY:
                for k, v in self._children.items():
                    key = f(k, v)
                    result.setdefault(key, {})[k] = v
            elif op == OP_BY_FILTER:
                for k, v in self._children.items():
                    key = f(k, v)
                    if key is not None:
                        result.setdefault(key, {})[k] = v
            return {
                k: RootedTreeDomain(self._root, v)
                for k, v in result.items()
            }
        raise ValueError(f"{type(self).__name__} has no part {part!r}")
