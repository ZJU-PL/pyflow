"""Deterministic abstract domain for static type inference.

The legacy type-inference facilities in :mod:`pyflow.analysis.typeinfo` are
primarily concerned with runtime signatures and test generation.  This module
defines the small, monotone domain used by the standalone static inference
engine.  In particular, lack of knowledge is represented independently from
``Any``: an unresolved value is not silently converted into an opt-out from
type checking or analysis.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Iterable

from pyflow.analysis.typeinfo.core.typesystem import (
    ANY,
    AnyType,
    ProperType,
    TypeSystem,
    UnionType,
)


@dataclass(frozen=True)
class AbstractTypeValue:
    """A finite set of possible types plus independent uncertainty.

    ``unknown`` means that additional, presently unmodelled types may be
    possible.  An empty value with ``unknown=False`` is lattice bottom and is
    used internally before any evidence reaches a symbol.

    Callable and class targets are retained alongside the nominal types.  They
    let the engine propagate precise user-defined call summaries without
    embedding analysis identities into the public ``ProperType`` hierarchy.
    """

    types: frozenset[ProperType] = field(default_factory=frozenset)
    unknown: bool = False
    callable_targets: frozenset[str] = field(default_factory=frozenset)
    class_targets: frozenset[str] = field(default_factory=frozenset)

    @classmethod
    def bottom(cls) -> AbstractTypeValue:
        """Return the least element of the inference lattice."""
        return cls()

    @classmethod
    def unresolved(cls) -> AbstractTypeValue:
        """Return a value for which no closed-world type is known."""
        return cls(unknown=True)

    @classmethod
    def from_type(
        cls,
        typ: ProperType | None,
        *,
        unknown: bool = False,
        callable_target: str | None = None,
        class_target: str | None = None,
    ) -> AbstractTypeValue:
        """Construct a value from a public type and optional semantic target."""
        return cls(
            frozenset(() if typ is None else (typ,)),
            unknown=unknown or typ is None,
            callable_targets=frozenset(
                () if callable_target is None else (callable_target,)
            ),
            class_targets=frozenset(
                () if class_target is None else (class_target,)
            ),
        )

    @property
    def is_bottom(self) -> bool:
        """Whether this value contains no evidence at all."""
        return (
            not self.types
            and not self.unknown
            and not self.callable_targets
            and not self.class_targets
        )

    @property
    def is_complete(self) -> bool:
        """Whether the known types form a closed set of possibilities."""
        return not self.unknown

    @property
    def has_unknown_alternatives(self) -> bool:
        """Whether additional unmodelled types may also be possible."""
        return self.unknown

    def join(
        self,
        other: AbstractTypeValue,
        type_system: TypeSystem,
        *,
        max_union_size: int = 16,
    ) -> AbstractTypeValue:
        """Compute the least upper bound, applying finite-union widening."""
        candidates = _normalize_types((*self.types, *other.types), type_system)
        unknown = self.unknown or other.unknown
        if len(candidates) > max_union_size:
            candidates = frozenset((ANY,))
            unknown = True
        return AbstractTypeValue(
            candidates,
            unknown=unknown,
            callable_targets=self.callable_targets | other.callable_targets,
            class_targets=self.class_targets | other.class_targets,
        )

    def without_type(self, rejected: type[ProperType]) -> AbstractTypeValue:
        """Remove all members represented by ``rejected``."""
        return AbstractTypeValue(
            frozenset(t for t in self.types if not isinstance(t, rejected)),
            unknown=self.unknown,
            callable_targets=self.callable_targets,
            class_targets=self.class_targets,
        )

    def retain(self, accepted: Iterable[ProperType]) -> AbstractTypeValue:
        """Retain a known subset while preserving semantic targets."""
        return AbstractTypeValue(
            frozenset(accepted),
            unknown=False,
            callable_targets=self.callable_targets,
            class_targets=self.class_targets,
        )

    def public_type(self) -> ProperType | None:
        """Convert the closed portion of the value to a public ``ProperType``."""
        if not self.types:
            return None
        if any(isinstance(item, AnyType) for item in self.types):
            return ANY
        if len(self.types) == 1:
            return next(iter(self.types))
        return UnionType(tuple(sorted(self.types)))


def join_all(
    values: Iterable[AbstractTypeValue],
    type_system: TypeSystem,
    *,
    max_union_size: int = 16,
) -> AbstractTypeValue:
    """Join an iterable of values without introducing artificial unknowns."""
    result = AbstractTypeValue.bottom()
    for value in values:
        result = result.join(
            value,
            type_system,
            max_union_size=max_union_size,
        )
    return result


def _normalize_types(
    values: Iterable[ProperType],
    type_system: TypeSystem,
) -> frozenset[ProperType]:
    flattened: set[ProperType] = set()
    for value in values:
        if isinstance(value, UnionType):
            flattened.update(value.items)
        else:
            flattened.add(value)

    if any(isinstance(value, AnyType) for value in flattened):
        return frozenset((ANY,))

    # If T is already covered by a known supertype U, ``T | U`` simplifies to U.
    result: set[ProperType] = set(flattened)
    for candidate in flattened:
        for other in flattened:
            if candidate is other or candidate == other:
                continue
            try:
                covered = type_system.is_subtype(candidate, other)
            except (AssertionError, KeyError, TypeError):
                covered = False
            if covered:
                result.discard(candidate)
                break
    return frozenset(result)
