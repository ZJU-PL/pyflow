"""Standard set domain — a powerset lattice ordered by subset inclusion.

Mirrors ``AbstractSetDomain`` from Pysa.  Elements are hashable values;
the bottom is the empty set, join is union, meet is intersection, and
the partial order is subset inclusion.

Exposes parts ``Self`` (the set itself) and ``Element`` (individual
elements), enabling ``transform(Element, Map, f)`` to map elements,
``reduce(Element, Acc, f, init)`` to fold over elements, etc.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import (
    Any,
    Callable,
    FrozenSet,
    Generic,
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
    Element,
    Part,
    PartId,
    TransformOp,
    ReduceOp,
    PartitionOp,
    ValuePart,
)

E = TypeVar("E")
T = TypeVar("T")


# ---------------------------------------------------------------------------
# Abstract set domain — base for all set-like domains
# ---------------------------------------------------------------------------

# Re-export key helpers
Element = Element


def _format_elements(elements: Sequence[Any], show: Callable[[Any], str]) -> str:
    return "{" + ", ".join(show(e) for e in elements) + "}"


class SetDomain(AbstractDomain, Generic[E]):
    """A powerset lattice: elements are sets; join = union; meet = intersection.

    Type parameter ``E`` is the element type (must be hashable).
    """

    _elements: FrozenSet[E]

    def __init__(self, elements: FrozenSet[E] = frozenset()) -> None:
        self._elements = elements

    # --- construction helpers ---

    @staticmethod
    def bottom() -> SetDomain[E]:
        return SetDomain(frozenset())

    @staticmethod
    def singleton(element: E) -> SetDomain[E]:
        return SetDomain(frozenset([element]))

    @staticmethod
    def of(*elements: E) -> SetDomain[E]:
        return SetDomain(frozenset(elements))

    @staticmethod
    def of_iter(elements: Iterator[E]) -> SetDomain[E]:
        return SetDomain(frozenset(elements))

    # --- lattice ops ---

    def is_bottom(self) -> bool:
        return len(self._elements) == 0

    def elements(self) -> FrozenSet[E]:
        return self._elements

    def join(self, other: Any) -> SetDomain[E]:
        if not isinstance(other, SetDomain):
            return NotImplemented
        if self._elements == other._elements:
            return self
        return SetDomain(self._elements | other._elements)

    def meet(self, other: Any) -> SetDomain[E]:
        if not isinstance(other, SetDomain):
            return NotImplemented
        if self._elements == other._elements:
            return self
        return SetDomain(self._elements & other._elements)

    def leq(self, other: Any) -> bool:
        if not isinstance(other, SetDomain):
            return NotImplemented
        if self.is_bottom():
            return True
        if other.is_bottom():
            return False
        return self._elements <= other._elements

    def widen(self, other: Any, iteration: int = 0) -> SetDomain[E]:
        return self.join(other)

    def subtract(self, other: Any) -> SetDomain[E]:
        if not isinstance(other, SetDomain):
            return NotImplemented
        if self._elements == other._elements or self.is_bottom():
            return self.bottom()
        if other.is_bottom():
            return self
        return SetDomain(self._elements - other._elements)

    def __hash__(self) -> int:
        return hash(("SetDomain", self._elements))

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, SetDomain):
            return NotImplemented
        return self._elements == other._elements

    def __repr__(self) -> str:
        return f"SetDomain({set(self._elements)})"

    __str__ = __repr__

    # --- parts ---

    def parts(self) -> Sequence[PartId]:
        return ["Self", "Element"]

    def structure(self) -> List[str]:
        return [f"Set" + self._element_name()]

    @classmethod
    def _element_name(cls) -> str:
        return ""

    def transform(self, part: PartId, op: TransformOp, f: Any) -> SetDomain[E]:
        if part == "Self":
            return self._transform_self(op, f)
        if part == "Element":
            return self._transform_element(op, f)
        raise ValueError(f"{type(self).__name__} has no part {part!r}")

    def _transform_element(self, op: TransformOp, f: Any) -> SetDomain[E]:
        if op == OP_MAP:
            # Map each element
            return SetDomain(frozenset(f(e) for e in self._elements))
        elif op == OP_ADD:
            return self.join(SetDomain.singleton(f))
        elif op == OP_FILTER:
            return SetDomain(frozenset(e for e in self._elements if f(e)))
        elif op == OP_FILTER_MAP:
            result: Set[E] = set()
            for e in self._elements:
                mapped = f(e)
                if mapped is not None:
                    result.add(mapped)
            return SetDomain(frozenset(result))
        elif op == OP_EXPAND:
            result: Set[E] = set()
            for e in self._elements:
                for expanded in f(e):
                    result.add(expanded)
            return SetDomain(frozenset(result))
        else:
            return self._transform_self(op, f)

    def reduce(self, part: PartId, op: ReduceOp, f: Any, init: V) -> V:
        if part == "Self":
            return self._reduce_self(op, f, init)
        if part == "Element":
            return self._reduce_element(op, f, init)
        raise ValueError(f"{type(self).__name__} has no part {part!r}")

    def _reduce_element(self, op: ReduceOp, f: Any, init: V) -> V:
        if op == OP_ACC:
            acc = init
            for e in self._elements:
                acc = f(e, acc)
            return acc
        elif op == OP_EXISTS:
            if init:
                return init
            for e in self._elements:
                if f(e):
                    return True  # type: ignore
            return False  # type: ignore
        else:
            return self._reduce_self(op, f, init)

    def partition(
        self, part: PartId, op: PartitionOp, f: Any
    ) -> Mapping[Any, SetDomain[E]]:
        if part == "Self":
            return self._partition_self(op, f)
        if part == "Element":
            return self._partition_element(op, f)
        raise ValueError(f"{type(self).__name__} has no part {part!r}")

    def _partition_element(
        self, op: PartitionOp, f: Any
    ) -> Mapping[Any, SetDomain[E]]:
        result: dict[Any, set[E]] = {}
        if op == OP_BY:
            for e in self._elements:
                key = f(e)
                if key not in result:
                    result[key] = set()
                result[key].add(e)
        elif op == OP_BY_FILTER:
            for e in self._elements:
                key = f(e)
                if key is not None:
                    if key not in result:
                        result[key] = set()
                    result[key].add(e)
        else:
            return self._partition_self(op, f)
        return {k: SetDomain(frozenset(v)) for k, v in result.items()}

    # --- extra ---

    def add(self, element: E) -> SetDomain[E]:
        return self.join(SetDomain.singleton(element))

    def remove(self, element: E) -> SetDomain[E]:
        return SetDomain(self._elements - {element})

    def contains(self, element: E) -> bool:
        return element in self._elements

    def __len__(self) -> int:
        return len(self._elements)

    def __iter__(self) -> Iterator[E]:
        return iter(self._elements)

    def __contains__(self, element: object) -> bool:
        return element in self._elements


V = TypeVar("V")
