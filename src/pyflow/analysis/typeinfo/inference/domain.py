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
    Instance,
    ProperType,
    TypeType,
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
    # Exact string-key layouts of dictionary values, independent of their
    # homogeneous public dict type. None means the keys are not known.
    dict_shapes: frozenset[tuple[tuple[str, ProperType], ...]] | None = None

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
            callable_targets=frozenset(() if callable_target is None else (callable_target,)),
            class_targets=frozenset(() if class_target is None else (class_target,)),
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
        if self.is_bottom:
            shapes = other.dict_shapes
        elif other.is_bottom:
            shapes = self.dict_shapes
        elif self.dict_shapes is not None and other.dict_shapes is not None:
            shapes = self.dict_shapes | other.dict_shapes
            if len(shapes) > max_union_size:
                shapes = None
        else:
            shapes = None
        return AbstractTypeValue(
            candidates,
            unknown=unknown,
            callable_targets=self.callable_targets | other.callable_targets,
            class_targets=self.class_targets | other.class_targets,
            dict_shapes=shapes,
        )

    def without_type(self, rejected: type[ProperType]) -> AbstractTypeValue:
        """Remove all members represented by ``rejected``."""
        return AbstractTypeValue(
            frozenset(
                part
                for typ in self.types
                for part in (typ.items if isinstance(typ, UnionType) else (typ,))
                if not isinstance(part, rejected)
            ),
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

    def runtime_type(self) -> ProperType | None:
        """Return the runtime type, projecting class objects to ``type[T]``.

        ``public_type`` is also used for declaration-style facts, where a class
        name denotes an instance type (for example a parameter annotated with
        ``Client``).  Values that are actually class objects, however, have the
        runtime type ``type[Client]``.  The engine records that distinction in
        ``class_targets``; this projection makes it visible to clients without
        changing the declaration-oriented ``public_type`` representation.
        """

        if not self.types:
            return None
        if any(isinstance(item, AnyType) for item in self.types):
            return ANY
        projected: list[ProperType] = []
        for item in self.types:
            if isinstance(item, Instance) and item.type.full_name in self.class_targets:
                projected.append(TypeType(item))
            else:
                projected.append(item)
        if len(projected) == 1:
            return projected[0]
        return UnionType(tuple(sorted(projected)))


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

    def rank(typ):
        def anys(item):
            if isinstance(item, AnyType):
                return 1
            children = (
                *getattr(item, "args", ()),
                *getattr(item, "items", ()),
                *(getattr(item, "arg_types", None) or ()),
            )
            extra = getattr(item, "return_type", None) or getattr(item, "item", None)
            return sum(anys(child) for child in children) + (
                anys(extra) if extra is not None else 0
            )

        return anys(typ), type(typ).__name__, str(typ)

    def subtype(left, right):
        # Numeric assignment compatibility is not runtime inheritance. Keep
        # distinct runtime numeric alternatives in inferred unions.
        if isinstance(left, Instance) and isinstance(right, Instance):
            numeric = {bool, int, float, complex}
            if left.type.raw_type in numeric and right.type.raw_type in numeric:
                return left.type == right.type
        try:
            return type_system.is_subtype(left, right)
        except (AssertionError, KeyError, TypeError):
            return False

    # Any consistency is symmetric but not an equivalence relation. Compare
    # only surviving representatives, preferring concrete nested arguments.
    result = []
    for candidate in sorted(flattened, key=rank):
        if any(subtype(candidate, other) for other in result):
            continue
        result = [other for other in result if not subtype(other, candidate)]
        result.append(candidate)
    return frozenset(result)
