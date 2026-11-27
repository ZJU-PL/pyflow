# This file is part of PyFlow.
#
# SPDX-FileCopyrightText: 2019–2026 Pynguin Contributors
# SPDX-License-Identifier: MIT
#
"""Core immutable type representations, canonical Union/Generic helpers, and metadata."""

from __future__ import annotations

import dataclasses
import enum
import re
import typing
from abc import ABC, abstractmethod
from collections import defaultdict
from typing import Final, Iterable, TypeVar

if typing.TYPE_CHECKING:
    from .descriptors import ClassDescriptor
    from .visitors import TypeVisitor


@dataclasses.dataclass
class SignatureInfo:
    """Another utility class to group information per callable."""

    # A dictionary mapping parameter names to their developer annotated parameter
    # types. Does not include self, etc.
    annotated_parameter_types: dict[str, str] = dataclasses.field(default_factory=dict)

    # Similar to above, but with guessed parameter types.
    # Contains multiple type guesses.
    guessed_parameter_types: dict[str, list[str]] = dataclasses.field(default_factory=dict)

    # Needed to compute top-n accuracy in the evaluation.
    # Elements are of form (A,B); A is a guess, B is an annotated type.
    # (A,B) is only present when A is a base type match of B.
    partial_type_matches: dict[str, str] = dataclasses.field(default_factory=dict)

    # Annotated return type, if any. Does not include constructors.
    annotated_return_type: str | None = None

    # Recorded return type, if any.
    recorded_return_type: str | None = None


@dataclasses.dataclass
class TypeGuessingStats:
    """Class to gather some type guessing related statistics."""

    # Number of constructors in the MUT.
    number_of_constructors: int = 0

    # Maps names of callables to a signature info object.
    signature_infos: dict[str, SignatureInfo] = dataclasses.field(
        default_factory=lambda: defaultdict(SignatureInfo)
    )


T = TypeVar("T")

_STRING_VISITOR: TypeVisitor[str] | None = None
_REPR_VISITOR: TypeVisitor[str] | None = None


class ProperType(ABC):
    """Base class for all immutable types in PyFlow's type system."""

    @abstractmethod
    def accept(self, visitor: TypeVisitor[T]) -> T:
        """Accept a type visitor."""

    def __str__(self) -> str:
        # ProperType instances are immutable, and unions are sorted repeatedly
        # while inference reaches a fixed point.  Cache each rendered node so
        # comparing two large nested types does not walk the same tree over
        # and over again.
        cached = getattr(self, "_string_cache", None)
        if cached is None:
            global _STRING_VISITOR
            if _STRING_VISITOR is None:
                from .visitors import TypeStringVisitor

                _STRING_VISITOR = TypeStringVisitor()
            cached = self.accept(_STRING_VISITOR)
            self._string_cache = cached
        return cached

    def __repr__(self) -> str:
        global _REPR_VISITOR
        if _REPR_VISITOR is None:
            from .visitors import TypeReprVisitor

            _REPR_VISITOR = TypeReprVisitor()
        return self.accept(_REPR_VISITOR)

    def __lt__(self, other):
        return str(self) < str(other)


class AnyType(ProperType):
    """The gradual Any type."""

    def accept(self, visitor: TypeVisitor[T]) -> T:  # noqa: D102
        return visitor.visit_any_type(self)

    def __hash__(self):
        return hash(AnyType)

    def __eq__(self, other):
        return isinstance(other, AnyType)


class NoneType(ProperType):
    """The None type."""

    def accept(self, visitor: TypeVisitor[T]) -> T:  # noqa: D102
        return visitor.visit_none_type(self)

    def __hash__(self):
        return hash(NoneType)

    def __eq__(self, other):
        return isinstance(other, NoneType)


class NeverType(ProperType):
    """The bottom type used by ``Never`` and ``NoReturn`` annotations."""

    def accept(self, visitor: TypeVisitor[T]) -> T:  # noqa: D102
        return visitor.visit_never_type(self)

    def __hash__(self):
        return hash(NeverType)

    def __eq__(self, other):
        return isinstance(other, NeverType)


class Instance(ProperType):
    """An instance type of form ``C[T1, ..., Tn]``."""

    def __init__(  # noqa: D107
        self, typ: ClassDescriptor, args: tuple[ProperType, ...] | None = None
    ):
        assert typ.raw_type is not tuple, "Use TupleType instead!"
        self.type = typ
        if args is None:
            args = ()
        self.args: Final[tuple[ProperType, ...]] = tuple(args)
        self._hash: int | None = None

    def accept(self, visitor: TypeVisitor[T]) -> T:  # noqa: D102
        return visitor.visit_instance(self)

    def __hash__(self):
        if self._hash is None:
            self._hash = hash((self.type, self.args))
        return self._hash

    def __eq__(self, other):
        return isinstance(other, Instance) and self.type == other.type and self.args == other.args


class LiteralType(Instance):
    """An instance type carrying an exact literal value for annotation checks."""

    def __init__(self, value: object, base: Instance) -> None:
        super().__init__(base.type, base.args)
        self.value = value
        self.base = base

    def __hash__(self):
        return hash((super().__hash__(), self.value))

    def __eq__(self, other):
        return (
            isinstance(other, LiteralType) and self.value == other.value and self.base == other.base
        )


class TupleType(ProperType):
    """Tuple type ``tuple[T1, ..., Tn]`` or ``tuple[T, ...]``.

    Intentionally separate from :class:`Instance` because Python tuples are
    variadic generics.
    """

    def __init__(self, args: tuple[ProperType, ...], *, unknown_size: bool = False):  # noqa: D107
        self.args: Final[tuple[ProperType, ...]] = tuple(args)
        self.unknown_size: Final[bool] = unknown_size
        self._hash: int | None = None

    def accept(self, visitor: TypeVisitor[T]) -> T:  # noqa: D102
        return visitor.visit_tuple_type(self)

    def __hash__(self):
        if self._hash is None:
            self._hash = hash((self.args, self.unknown_size))
        return self._hash

    def __eq__(self, other):
        return (
            isinstance(other, TupleType)
            and self.args == other.args
            and self.unknown_size == other.unknown_size
        )


class UnionType(ProperType):
    """Normalized union type ``T1 | ... | Tn`` (at least one item).

    Flattens nested unions, deduplicates identical arms, and drops redundant
    ``Never`` arms when at least one inhabited alternative is present.
    """

    def __init__(self, items: tuple[ProperType, ...]):  # noqa: D107
        flattened: set[ProperType] = set()
        for item in items:
            if isinstance(item, UnionType):
                flattened.update(item.items)
            else:
                flattened.add(item)
        if len(flattened) > 1:
            non_never = {item for item in flattened if not isinstance(item, NeverType)}
            if non_never:
                flattened = non_never
        self.items: Final[tuple[ProperType, ...]] = tuple(sorted(flattened))
        assert len(self.items) > 0
        self._hash: int | None = None

    def accept(self, visitor: TypeVisitor[T]) -> T:  # noqa: D102
        return visitor.visit_union_type(self)

    def __hash__(self):
        if self._hash is None:
            self._hash = hash(self.items)
        return self._hash

    def __eq__(self, other):
        return isinstance(other, UnionType) and self.items == other.items


class CallableType(ProperType):
    """A callable type ``Callable[[A, ...], R]``.

    ``arg_types`` is ``None`` for an ellipsis callable, i.e. ``Callable[..., R]``.
    """

    def __init__(
        self,
        arg_types: tuple[ProperType, ...] | None,
        return_type: ProperType,
        overloads: tuple["CallableType", ...] = (),
    ) -> None:
        self.arg_types: Final[tuple[ProperType, ...] | None] = arg_types
        self.return_type: Final[ProperType] = return_type
        self.overloads: Final[tuple[CallableType, ...]] = overloads
        self._hash: int | None = None

    def accept(self, visitor: TypeVisitor[T]) -> T:  # noqa: D102
        return visitor.visit_callable_type(self)

    def __hash__(self):
        if self._hash is None:
            self._hash = hash((self.arg_types, self.return_type, self.overloads))
        return self._hash

    def __eq__(self, other):
        return (
            isinstance(other, CallableType)
            and self.arg_types == other.arg_types
            and self.return_type == other.return_type
            and self.overloads == other.overloads
        )


class TypeType(ProperType):
    """A class-object type of the form ``type[T]``."""

    def __init__(self, item: ProperType) -> None:
        self.item: Final[ProperType] = item
        self._hash: int | None = None

    def accept(self, visitor: TypeVisitor[T]) -> T:  # noqa: D102
        return visitor.visit_type_type(self)

    def __hash__(self):
        if self._hash is None:
            self._hash = hash((TypeType, self.item))
        return self._hash

    def __eq__(self, other):
        return isinstance(other, TypeType) and self.item == other.item


class StringSubtype(ProperType):
    """A subtype of ``str`` constrained by a regular expression."""

    def __init__(self, regex: re.Pattern):  # noqa: D107
        self.regex = regex
        self._hash: int | None = None

    def __eq__(self, other):
        return isinstance(other, StringSubtype) and other.regex == self.regex

    def __hash__(self):
        return hash(self.regex)

    def __str__(self):
        return f"StringSubtype({self.regex})"

    def accept(self, visitor: TypeVisitor[T]) -> T:  # noqa: D102
        return visitor.visit_string_subtype(self)


class NumericString(StringSubtype):
    """A string that only contains numerical characters and an optional decimal point."""

    def __init__(self):  # noqa: D107
        super().__init__(re.compile(r"^\d+(\.\d+)?$"))


class EmailString(StringSubtype):
    """A string that follows the general pattern of an email address."""

    def __init__(self):  # noqa: D107
        super().__init__(re.compile(r"^[^@]+@[^@]+\.[^@]+$"))


class HexadecimalString(StringSubtype):
    """A string that represents a hexadecimal number."""

    def __init__(self):  # noqa: D107
        super().__init__(re.compile(r"^(0x|0X)?[0-9a-fA-F]+$"))


class ISOColorString(StringSubtype):
    """A string that represents a hexadecimal color code."""

    def __init__(self):  # noqa: D107
        super().__init__(re.compile(r"^#([0-9a-fA-F]{6}|[0-9a-fA-F]{3})$"))


class UUIDString(StringSubtype):
    """A string that represents a UUID."""

    def __init__(self):  # noqa: D107
        super().__init__(
            re.compile(
                r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
            )
        )


class ISODateString(StringSubtype):
    """A string that represents a date in ISO 8601 format."""

    def __init__(self):  # noqa: D107
        super().__init__(re.compile(r"^\d{4}-\d{2}-\d{2}$"))


class ISOTimeString(StringSubtype):
    """A string that represents a time in ISO 8601 format."""

    def __init__(self):  # noqa: D107
        super().__init__(re.compile(r"^\d{2}:\d{2}:\d{2}$"))


class CSVString(StringSubtype):
    """A string that represents comma-separated values."""

    def __init__(self):  # noqa: D107
        super().__init__(re.compile(r"^([^,]+,)*[^,]+$"))


class URLString(StringSubtype):
    """A string that represents a URL."""

    def __init__(self):  # noqa: D107
        super().__init__(re.compile(r"^(https?|ftp)://[^\s/$.?#].[^\s]*$"))


class IPv4String(StringSubtype):
    """A string that represents an IPv4 address."""

    def __init__(self):  # noqa: D107
        super().__init__(
            re.compile(
                r"^(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\."
                r"(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\."
                r"(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\."
                r"(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$"
            )
        )


class IPv6String(StringSubtype):
    """A string that represents an IPv6 address."""

    def __init__(self):  # noqa: D107
        super().__init__(re.compile(r"^([0-9A-Fa-f]{1,4}:){7}[0-9A-Fa-f]{1,4}$"))


class PhoneNumberString(StringSubtype):
    """A string that represents a phone number."""

    def __init__(self):  # noqa: D107
        super().__init__(re.compile(r"^\+?[\d\s\-\(\)]+$"))


class SHA256String(StringSubtype):
    """A string that represents a SHA-256 hash."""

    def __init__(self):  # noqa: D107
        super().__init__(re.compile(r"^[a-fA-F0-9]{64}$"))


class Unsupported(ProperType):
    """Marks an unsupported type in the type system (used for statistics)."""

    def __eq__(self, other):
        return isinstance(other, Unsupported)

    def __hash__(self):
        return hash(Unsupported)

    def accept(self, visitor: TypeVisitor[T]) -> T:  # noqa: D102
        return visitor.visit_unsupported_type(self)


class Variance(enum.Enum):
    """Type variable variance kinds as defined in PEP 484."""

    INVARIANT = 0
    COVARIANT = 1
    CONTRAVARIANT = 2


class TypeVarType(ProperType):
    """A PEP 484 ``TypeVar`` in the type system."""

    def __init__(  # noqa: D107
        self,
        name: str,
        *,
        constraints: tuple[ProperType, ...] = (),
        bound: ProperType | None = None,
        variance: Variance = Variance.INVARIANT,
    ) -> None:
        self.name: Final[str] = name
        self.constraints: Final[tuple[ProperType, ...]] = constraints
        self.bound: Final[ProperType | None] = bound
        self.variance: Final[Variance] = variance
        self._hash: int | None = None

    def accept(self, visitor: TypeVisitor[T]) -> T:  # noqa: D102
        return visitor.visit_type_var_type(self)

    @property
    def has_constraints(self) -> bool:
        """Whether this type var has explicit constraints (e.g. ``T = TypeVar('T', int, str)``)."""
        return len(self.constraints) > 0

    @property
    def has_bound(self) -> bool:
        """Whether this type var has an upper bound (e.g. ``T = TypeVar('T', bound=Number)``)."""
        return self.bound is not None

    def __hash__(self) -> int:
        if self._hash is None:
            self._hash = hash((self.name, self.constraints, self.bound, self.variance))
        return self._hash

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, TypeVarType):
            return False
        return (
            self.name == other.name
            and self.constraints == other.constraints
            and self.bound == other.bound
            and self.variance == other.variance
        )

    def __repr__(self) -> str:
        parts = [f"TypeVarType({self.name!r}"]
        if self.has_constraints:
            parts.append(f"constraints={self.constraints!r}")
        if self.has_bound:
            parts.append(f"bound={self.bound!r}")
        if self.variance != Variance.INVARIANT:
            parts.append(f"variance={self.variance.name}")
        parts.append(")")
        return "".join(parts)


# Static singletons to avoid repeated construction.
ANY = AnyType()
NONE_TYPE = NoneType()
NEVER = NeverType()
UNSUPPORTED = Unsupported()


def make_union(
    items: Iterable[ProperType],
    *,
    collapse_any: bool = False,
) -> ProperType:
    """Build a canonical type from union arms.

    Flattens nested :class:`UnionType` instances, removes redundant
    :class:`NeverType` arms, deduplicates identical entries, unwraps a
    single-arm union to its element, and returns :data:`NEVER` for an empty
    iterable.  When ``collapse_any=True``, any presence of :data:`ANY`
    absorbs the union to :data:`ANY`; by default ``Any`` is retained so
    gradual forms like ``Any | None`` remain explicit.
    """
    flattened: set[ProperType] = set()
    for item in items:
        if isinstance(item, UnionType):
            flattened.update(item.items)
        else:
            flattened.add(item)
    if not flattened:
        return NEVER
    non_never = {item for item in flattened if not isinstance(item, NeverType)}
    if non_never:
        flattened = non_never
    if collapse_any and any(isinstance(item, AnyType) for item in flattened):
        return ANY
    if len(flattened) == 1:
        return next(iter(flattened))
    return UnionType(tuple(sorted(flattened)))


def normalize_generic_args(
    descriptor: ClassDescriptor,
    args: tuple[ProperType, ...],
    *,
    pad_unparameterized: bool = False,
) -> tuple[ProperType, ...]:
    """Normalize generic type arguments against *descriptor*'s declared arity.

    Pads missing arguments with :data:`ANY` and truncates excess arguments when
    *descriptor* has a known arity.  When ``pad_unparameterized`` is ``False``,
    an empty ``args`` tuple on user generics without a hardcoded builtin arity
    is left empty (bare generic).
    """
    arity = descriptor.num_hardcoded_generic_parameters
    if arity is None and pad_unparameterized and descriptor.type_parameters:
        arity = len(descriptor.type_parameters)
    if arity is None:
        return tuple(args)
    normalized = tuple(args)
    if len(normalized) < arity:
        normalized += (ANY,) * (arity - len(normalized))
    elif len(normalized) > arity:
        normalized = normalized[:arity]
    return normalized
