"""Abstract domain core — the fundamental lattice interface for PyFlow.

This module provides the base abstractions for the lattice/abstract domain
library, mirroring Pysa's ``AbstractDomainCore`` module.  Every domain
implements ``AbstractDomain`` (join-semilattice + meet + widening + subtraction)
and can be composed via ``Part``-based transformation/reduction.

The design follows Pysa's "part" system: each composite domain registers
named parts (e.g. ``Self``, ``Element``, ``Key``, ``Path``) and dispatches
``transform``, ``reduce``, and ``partition`` operations to the appropriate
sub-domain.  The Python implementation uses strings as part identifiers
and a simple recursive dispatch, trading OCaml's GADT safety for readability.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import (
    Any,
    Callable,
    Generic,
    Iterator,
    List,
    Mapping,
    Optional,
    Sequence,
    Tuple,
    TypeVar,
    Union,
    cast,
)

T = TypeVar("T")
S = TypeVar("S")
V = TypeVar("V")


# ---------------------------------------------------------------------------
# Part system
# ---------------------------------------------------------------------------

PartId = str
"""A named part of a composite domain, e.g. ``"Self"``, ``"Element"``."""


@dataclass(frozen=True)
class Part(Generic[T]):
    """A typed part value for constructing composite abstract values."""

    part_id: PartId
    value: T


ValuePart = Part[Any]
"""An untyped value part (erasued after construction)."""


# ---------------------------------------------------------------------------
# Operation descriptors
# ---------------------------------------------------------------------------

TransformOp = str
"""Operation kind for ``transform`` dispatch: ``"Map"``, ``"Add"``, ``"Filter"``,
``"FilterMap"``, ``"Expand"``."""

# Canonical operation names
OP_MAP: TransformOp = "Map"
OP_ADD: TransformOp = "Add"
OP_FILTER: TransformOp = "Filter"
OP_FILTER_MAP: TransformOp = "FilterMap"
OP_EXPAND: TransformOp = "Expand"

ReduceOp = str
"""Operation kind for ``reduce`` dispatch: ``"Acc"``, ``"Exists"``."""

OP_ACC: ReduceOp = "Acc"
OP_EXISTS: ReduceOp = "Exists"

PartitionOp = str
"""Operation kind for ``partition`` dispatch: ``"By"``, ``"ByFilter"``."""

OP_BY: PartitionOp = "By"
OP_BY_FILTER: PartitionOp = "ByFilter"

# Expansion policies (Epolicy): how nested expansion operators behave
EP_LOCAL: str = "EpLocal"
"""Expansion policy: only expand the immediate element."""
EP_CONST: str = "EpConst"
"""Expansion policy: recurse into composite elements."""


# ---------------------------------------------------------------------------
# AbstractDomain — the central lattice interface
# ---------------------------------------------------------------------------


class AbstractDomain(ABC):
    """A join-semilattice with meet, widening, and subtraction.

    Every concrete domain value is immutable and hashable.
    Subclasses must override the core lattice operations.
    """

    # --- Lattice primitives ------------------------------------------------

    @staticmethod
    @abstractmethod
    def bottom() -> Any:
        """The bottom element of the lattice (∅ / ⊥)."""

    @abstractmethod
    def is_bottom(self) -> bool:
        """Return ``True`` when this value is bottom."""

    @abstractmethod
    def join(self, other: Any) -> Any:
        """Upper bound / union (⊔).  Must be commutative, associative,
        idempotent, and have ``bottom`` as identity."""

    @abstractmethod
    def meet(self, other: Any) -> Any:
        """Lower bound / intersection (⊓).  Over-approximation of the
        intersection when the domain is not a true meet-semilattice."""

    @abstractmethod
    def leq(self, other: Any) -> bool:
        """Partial order (⊑).  ``self ⊑ other`` iff ``self join other == other``."""

    @abstractmethod
    def widen(self, other: Any, iteration: int = 0) -> Any:
        """Widening operator for accelerating fixpoint computation.
        ``widen(prev, next)`` must be an upper bound of both ``prev`` and
        ``next``, and the chain of successive widenings must stabilise."""

    @abstractmethod
    def subtract(self, other: Any) -> Any:
        """Removal / difference: returns an element ``d`` such that
        ``d ⊑ self`` and ``self ⊑ d ⊔ other``."""

    # --- Structural interface (transform / reduce / partition) -------------

    def transform(
        self, part: PartId, op: TransformOp, f: Any
    ) -> Any:
        """Navigate to *part* of the domain, apply *op* with function *f*,
        and return the updated composite value.

        The default implementation only handles ``"Self"``.
        Subclasses that introduce new parts must override this.
        """
        if part == "Self":
            return self._transform_self(op, f)
        raise ValueError(
            f"{type(self).__name__} does not have a part named {part!r}"
        )

    def _transform_self(self, op: TransformOp, f: Any) -> Any:
        """Apply a transform operation to the whole domain."""
        if op == OP_MAP:
            return f(self)
        elif op == OP_ADD:
            return self.join(f)
        elif op == OP_FILTER:
            return self if f(self) else self.__class__.bottom()
        elif op == OP_FILTER_MAP:
            result = f(self)
            return result if result is not None else self.__class__.bottom()
        elif op == OP_EXPAND:
            result = self.__class__.bottom()
            for item in f(self):
                result = result.join(item)
            return result
        else:
            raise ValueError(f"Unknown transform operation: {op}")

    def reduce(
        self, part: PartId, op: ReduceOp, f: Any, init: V
    ) -> V:
        """Navigate to *part*, apply reduction *op*, and return the result.

        The default implementation only handles ``"Self"``.
        """
        if part == "Self":
            return self._reduce_self(op, f, init)
        raise ValueError(
            f"{type(self).__name__} does not have a part named {part!r}"
        )

    def _reduce_self(self, op: ReduceOp, f: Any, init: V) -> V:
        if op == OP_ACC:
            return f(self, init)
        elif op == OP_EXISTS:
            return cast(V, init or f(self))
        else:
            raise ValueError(f"Unknown reduce operation: {op}")

    def partition(
        self,
        part: PartId,
        op: PartitionOp,
        f: Any,
    ) -> Mapping[Any, Any]:
        """Navigate to *part*, apply partition *op*, and return a map
        from partition keys to sub-values.

        The default implementation only handles ``"Self"``.
        """
        if part == "Self":
            return self._partition_self(op, f)
        raise ValueError(
            f"{type(self).__name__} does not have a part named {part!r}"
        )

    def _partition_self(
        self, op: PartitionOp, f: Any
    ) -> Mapping[Any, Any]:
        """Partition the domain itself."""
        if op == OP_BY:
            return {f(self): self}
        elif op == OP_BY_FILTER:
            key = f(self)
            return {key: self} if key is not None else {}
        else:
            raise ValueError(f"Unknown partition operation: {op}")

    # --- Introspection ----------------------------------------------------

    def parts(self) -> Sequence[PartId]:
        """Return the list of part identifiers this domain exposes."""
        return ["Self"]

    def structure(self) -> List[str]:
        """Human-readable structural description of the domain."""
        return [type(self).__name__]

    # --- Convenience ------------------------------------------------------

    def __eq__(self, other: object) -> bool:
        if type(self) is not type(other):
            return NotImplemented
        assert isinstance(other, type(self))
        return self.leq(other) and other.leq(self)

    def __ne__(self, other: object) -> bool:
        return not self.__eq__(other)


# ---------------------------------------------------------------------------
# Element interface (for SetDomain etc.)
# ---------------------------------------------------------------------------


class Element(ABC):
    """Protocol for elements stored in set-like domains.

    Each element must be hashable and comparable.
    """

    @abstractmethod
    def name(self) -> str:
        """Human-readable name of this element type."""

    @abstractmethod
    def show(self) -> str:
        """Human-readable representation of an element value."""


# ---------------------------------------------------------------------------
# Sanity helpers
# ---------------------------------------------------------------------------


def check_lattice_properties(d: AbstractDomain) -> None:
    """Run basic lattice-law checks on *d* for debugging."""
    bot = d.__class__.bottom()
    assert bot.is_bottom()
    assert bot.leq(d)
    assert d.leq(d)
    assert d.join(d) == d  # idempotent
    assert d.join(bot) == d  # bottom identity
    assert bot.join(d) == d
    assert d.meet(d) == d  # idempotent
    assert d.widen(d) == d  # widen identity
    assert d.subtract(bot) == d  # subtract bottom is identity
    # subtract self is NOT required to be bottom for all domains
    # (FlatDomain, SimpleDomain, MapDomain return self)
