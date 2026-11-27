# This file is part of PyFlow.
#
# SPDX-FileCopyrightText: 2019–2026 Pynguin Contributors
# SPDX-License-Identifier: MIT
#
"""Type visitors for formatting, subtyping, variance-aware generics, and classification."""

from __future__ import annotations

import collections.abc as cabc
import io as _io
import typing
from abc import abstractmethod
from itertools import starmap
from typing import Generic, TypeVar

import pyflow.analysis.typeinfo.config as config

from .types import (
    ANY,
    NEVER,
    NONE_TYPE,
    AnyType,
    CallableType,
    Instance,
    LiteralType,
    NeverType,
    NoneType,
    ProperType,
    StringSubtype,
    TupleType,
    TypeType,
    TypeVarType,
    UnionType,
    Unsupported,
    Variance,
)

if typing.TYPE_CHECKING:
    from collections.abc import Callable, Sequence
    from typing import ClassVar

    from .typesystem import TypeSystem

T = TypeVar("T")


class TypeVisitor(Generic[T]):
    """A type visitor over :class:`ProperType` nodes."""

    @abstractmethod
    def visit_any_type(self, left: AnyType) -> T:
        """Visit the Any type."""

    @abstractmethod
    def visit_none_type(self, left: NoneType) -> T:
        """Visit the None type."""

    def visit_never_type(self, left: NeverType) -> T:
        """Visit the bottom type."""
        return None  # type: ignore[return-value]

    @abstractmethod
    def visit_instance(self, left: Instance) -> T:
        """Visit an instance."""

    @abstractmethod
    def visit_tuple_type(self, left: TupleType) -> T:
        """Visit a tuple type."""

    @abstractmethod
    def visit_union_type(self, left: UnionType) -> T:
        """Visit a union."""

    @abstractmethod
    def visit_unsupported_type(self, left: Unsupported) -> T:
        """Visit unsupported type."""

    def visit_string_subtype(self, left: StringSubtype) -> T:
        """Visit a string subtype."""
        return None  # type: ignore[return-value]

    def visit_type_var_type(self, left: TypeVarType) -> T:
        """Visit a type variable type."""
        return None  # type: ignore[return-value]

    def visit_callable_type(self, left: CallableType) -> T:
        """Visit a callable type."""
        return None  # type: ignore[return-value]

    def visit_type_type(self, left: TypeType) -> T:
        """Visit a class-object type."""
        return None  # type: ignore[return-value]


class _PartialTypeMatch(TypeVisitor[ProperType | None]):
    """A type visitor to check for base type matches."""

    def __init__(self, right: ProperType):
        self.right = right

    def visit_any_type(self, left: AnyType) -> ProperType | None:
        return None

    def visit_none_type(self, left: NoneType) -> ProperType | None:
        if isinstance(self.right, NoneType):
            return NONE_TYPE
        return None

    def visit_never_type(self, left: NeverType) -> ProperType | None:
        return NEVER if isinstance(self.right, NeverType) else None

    def visit_instance(self, left: Instance) -> ProperType | None:
        if isinstance(self.right, Instance) and left.type == self.right.type:
            return Instance(left.type)
        return None

    def visit_tuple_type(self, left: TupleType) -> ProperType | None:
        if isinstance(self.right, TupleType):
            return TupleType(())
        return None

    def visit_union_type(self, left: UnionType) -> ProperType | None:
        matches: tuple[ProperType, ...] = tuple(
            elem
            for elem in (_is_partial_type_match(left_elem, self.right) for left_elem in left.items)
            if elem
        )
        if matches:
            return UnionType(matches)
        return None

    def visit_unsupported_type(self, left: Unsupported) -> ProperType | None:
        return None

    def visit_callable_type(self, left: CallableType) -> ProperType | None:
        return left if left == self.right else None

    def visit_type_type(self, left: TypeType) -> ProperType | None:
        return left if isinstance(self.right, TypeType) else None


def _is_partial_type_match(left: ProperType, right: ProperType) -> ProperType | None:
    """Return a fuzzy base-type match between guessed *left* and ground truth *right*."""
    if isinstance(right, UnionType):
        matches: tuple[ProperType, ...] = tuple(
            elem
            for elem in (_is_partial_type_match(left, right_elem) for right_elem in right.items)
            if elem is not None
        )
        if matches:
            return UnionType(matches)
        return None
    return left.accept(_PartialTypeMatch(right))


class TypeStringVisitor(TypeVisitor[str]):
    """Convert a :class:`ProperType` to its human-readable type string."""

    def visit_any_type(self, left: AnyType) -> str:  # noqa: D102
        return "Any"

    def visit_none_type(self, left: NoneType) -> str:  # noqa: D102
        return "None"

    def visit_never_type(self, left: NeverType) -> str:  # noqa: D102
        return "Never"

    def visit_instance(self, left: Instance) -> str:  # noqa: D102
        if isinstance(left, LiteralType):
            if isinstance(left.value, tuple) and len(left.value) == 3 and left.value[0] == "enum":
                return f"Literal[{left.value[1].rsplit('.', 1)[-1]}.{left.value[2]}]"
            return f"Literal[{left.value!r}]"
        rep = left.type.name if left.type.module == "builtins" else left.type.full_name
        if len(left.args) > 0:
            rep += "[" + self._sequence_str(left.args) + "]"
        return rep

    def visit_tuple_type(self, left: TupleType) -> str:  # noqa: D102
        rep = "tuple"
        if len(left.args) > 0:
            args = self._sequence_str(left.args)
            if left.unknown_size:
                args += ", ..."
            rep += f"[{args}]"
        return rep

    def visit_union_type(self, left: UnionType) -> str:  # noqa: D102
        if len(left.items) == 1:
            return left.items[0].accept(self)
        return self._sequence_str(left.items, sep=" | ")

    def _sequence_str(self, typs: Sequence[ProperType], sep=", ") -> str:
        return sep.join(t.accept(self) for t in typs)

    def visit_unsupported_type(self, left: Unsupported) -> str:  # noqa: D102
        return "<?>"

    def visit_type_var_type(self, left: TypeVarType) -> str:
        return left.name

    def visit_callable_type(self, left: CallableType) -> str:
        if left.arg_types is None:
            args = "..."
        else:
            args = "[" + self._sequence_str(left.arg_types) + "]"
        return f"Callable[{args}, {left.return_type.accept(self)}]"

    def visit_type_type(self, left: TypeType) -> str:
        return f"type[{left.item.accept(self)}]"

    def visit_string_subtype(self, left: StringSubtype) -> str:
        return f"StringSubtype({left.regex})"


class TypeReprVisitor(TypeVisitor[str]):
    """Create a diagnostic ``repr`` string for a :class:`ProperType`."""

    def visit_any_type(self, left: AnyType) -> str:  # noqa: D102
        return "AnyType()"

    def visit_none_type(self, left: NoneType) -> str:  # noqa: D102
        return "NoneType()"

    def visit_never_type(self, left: NeverType) -> str:  # noqa: D102
        return "NeverType()"

    def visit_instance(self, left: Instance) -> str:  # noqa: D102
        rep = f"Instance({left.type!r}"
        if len(left.args) > 0:
            rep += "(" + self._sequence_str(left.args) + ")"
        return rep + ")"

    def visit_tuple_type(self, left: TupleType) -> str:  # noqa: D102
        unknown_size = ", unknown_size=True" if left.unknown_size else ""
        return f"TupleType({self._sequence_str(left.args)}{unknown_size})"

    def visit_union_type(self, left: UnionType) -> str:  # noqa: D102
        return f"UnionType({self._sequence_str(left.items)})"

    def _sequence_str(self, typs: Sequence[ProperType]) -> str:
        return ", ".join(t.accept(self) for t in typs)

    def visit_unsupported_type(self, left: Unsupported) -> str:  # noqa: D102
        return "Unsupported()"

    def visit_type_var_type(self, left: TypeVarType) -> str:
        parts = [f"name={left.name!r}"]
        if left.has_constraints:
            parts.append(f"constraints=({', '.join(c.accept(self) for c in left.constraints)})")
        if left.has_bound and left.bound is not None:
            parts.append(f"bound={left.bound.accept(self)}")
        if left.variance != Variance.INVARIANT:
            parts.append(f"variance={left.variance.name}")
        return f"TypeVarType({', '.join(parts)})"

    def visit_callable_type(self, left: CallableType) -> str:
        args = "..." if left.arg_types is None else self._sequence_str(left.arg_types)
        return f"CallableType(({args}), {left.return_type.accept(self)})"

    def visit_type_type(self, left: TypeType) -> str:
        return f"TypeType({left.item.accept(self)})"

    def visit_string_subtype(self, left: StringSubtype) -> str:
        return f"StringSubtype({left.regex!r})"


_COVARIANT_ABC_ORIGINS = frozenset(
    {
        cabc.Iterable,
        cabc.Iterator,
        cabc.Collection,
        cabc.Container,
        cabc.Sequence,
        cabc.Reversible,
        cabc.Set,
        cabc.AsyncIterable,
        cabc.AsyncIterator,
    }
)


class _SubtypeVisitor(TypeVisitor[bool]):
    """Check whether ``left <: right`` (handling variance, protocols, and TypedDicts).

    The caller handles ``right is AnyType`` before dispatching here.
    """

    def __init__(
        self,
        graph: TypeSystem,
        right: ProperType,
        sub_type_check: Callable[[ProperType, ProperType], bool],
    ):
        self.graph = graph
        self.right = right
        self.sub_type_check = sub_type_check

    def visit_any_type(self, left: AnyType) -> bool:
        return True

    def visit_none_type(self, left: NoneType) -> bool:
        return (
            isinstance(self.right, NoneType)
            or isinstance(self.right, Instance)
            and self.right.type.raw_type is object
        )

    def visit_never_type(self, left: NeverType) -> bool:
        return True

    def _generic_arg_compatible(
        self,
        left_arg: ProperType,
        right_arg: ProperType,
        variance: Variance,
    ) -> bool:
        if isinstance(left_arg, NeverType):
            return True
        if variance is Variance.COVARIANT:
            return self.sub_type_check(left_arg, right_arg)
        if variance is Variance.CONTRAVARIANT:
            return self.sub_type_check(right_arg, left_arg)
        return self.sub_type_check(left_arg, right_arg) and self.sub_type_check(right_arg, left_arg)

    def visit_instance(self, left: Instance) -> bool:
        if left.type.tuple_fields is not None and (
            isinstance(self.right, TupleType)
            or isinstance(self.right, Instance)
            and self.right.type.raw_type
            in {cabc.Iterable, cabc.Collection, cabc.Sequence, cabc.Reversible, cabc.Container}
        ):
            return self.sub_type_check(
                TupleType(
                    tuple(left.type.members.get(name, ANY) for name in left.type.tuple_fields)
                ),
                self.right,
            )
        if isinstance(self.right, CallableType):
            call = self.graph.get_members(left.type).get("__call__")
            if not isinstance(call, CallableType):
                return False
            if left.args and left.type.type_parameters:
                from pyflow.analysis.typeinfo.resolution.typing_syntax import (
                    substitute_type_vars,
                )

                call = substitute_type_vars(
                    call,
                    {
                        parameter.name: argument
                        for parameter, argument in zip(left.type.type_parameters, left.args)
                    },
                )
                assert isinstance(call, CallableType)
            if self.right.arg_types is None or call.arg_types is None:
                return self.sub_type_check(call.return_type, self.right.return_type)
            if len(call.arg_types) != len(self.right.arg_types):
                return False
            return all(
                self.sub_type_check(expected, actual)
                for expected, actual in zip(self.right.arg_types, call.arg_types)
            ) and self.sub_type_check(call.return_type, self.right.return_type)

        if isinstance(self.right, Instance):
            expected_fields = self.right.type.typed_dict_fields
            if expected_fields is not None:
                actual_fields = left.type.typed_dict_fields
                if actual_fields is None:
                    return False
                pair = (left, self.right)
                active = self.graph._structural_checks
                if pair in active:
                    return True
                active.add(pair)
                try:
                    return self.right.type.required_keys <= left.type.required_keys and all(
                        name in actual_fields
                        and self.sub_type_check(actual_fields[name], typ)
                        and self.sub_type_check(typ, actual_fields[name])
                        for name, typ in expected_fields.items()
                    )
                finally:
                    active.remove(pair)
            if self.right.type.is_protocol:
                required = self.graph.get_members(self.right.type)
                from pyflow.analysis.typeinfo.resolution.typing_syntax import (
                    substitute_type_vars,
                )

                parameters = {
                    parameter.name: argument
                    for parameter, argument in zip(self.right.type.type_parameters, self.right.args)
                }
                parameters["Self"] = left
                if parameters:
                    required = {
                        name: substitute_type_vars(member, parameters)
                        for name, member in required.items()
                    }
                available = self.graph.get_members(left.type)
                pair = (left, self.right)
                active = self.graph._structural_checks
                if pair in active:
                    return True
                active.add(pair)
                try:
                    missing = [name for name in required if name not in available]
                    if missing and getattr(left.type, "has_unresolved_bases", False):
                        return True
                    return all(
                        name in available and self.sub_type_check(available[name], typ)
                        for name, typ in required.items()
                    )
                finally:
                    active.remove(pair)

            is_sub = self.graph.is_subclass(left.type, self.right.type)
            target = self.right.type.raw_type
            if not is_sub and target in {
                cabc.Iterable,
                cabc.Iterator,
                cabc.Collection,
                cabc.Sequence,
                cabc.Reversible,
            }:
                iter_sig = self.graph.get_members(left.type).get("__iter__")
                if isinstance(iter_sig, CallableType):
                    returned = iter_sig.return_type
                    element: ProperType | None = None
                    if isinstance(returned, Instance) and returned.args:
                        element = returned.args[0]
                    elif isinstance(returned, Instance) and returned.type.raw_type in {
                        list,
                        set,
                        frozenset,
                        dict,
                    }:
                        element = ANY
                    if element is not None:
                        if self.right.args:
                            return self.sub_type_check(element, self.right.args[0])
                        return True
            if not is_sub:
                if target in {typing.IO, typing.TextIO, typing.BinaryIO}:
                    source_cls = left.type.raw_type
                    if isinstance(source_cls, type):
                        if target is typing.IO and issubclass(source_cls, _io.IOBase):
                            is_sub = True
                        elif target is typing.TextIO and (
                            issubclass(
                                source_cls, (_io.TextIOBase, _io.TextIOWrapper, _io.StringIO)
                            )
                            or source_cls is _io.TextIOWrapper
                        ):
                            is_sub = True
                        elif target is typing.BinaryIO and issubclass(
                            source_cls, (_io.BufferedIOBase, _io.RawIOBase, _io.BytesIO)
                        ):
                            is_sub = True
            if not is_sub:
                return False

            source = left.type.raw_type
            if target in _COVARIANT_ABC_ORIGINS and self.right.args:
                if source is str:
                    elements = (Instance(self.graph.to_class_descriptor(str)),)
                elif source is bytes:
                    elements = (Instance(self.graph.to_class_descriptor(int)),)
                elif source is cabc.ItemsView and len(left.args) >= 2:
                    elements = (TupleType(left.args[:2]),)
                else:
                    elements = left.args[:1] or (ANY,)
                return all(self.sub_type_check(element, self.right.args[0]) for element in elements)
            if target in {cabc.MutableSequence, cabc.MutableSet} and self.right.args:
                elements = left.args[:1] or (ANY,)
                return all(
                    self._generic_arg_compatible(element, self.right.args[0], Variance.INVARIANT)
                    for element in elements
                )
            if target in {cabc.Mapping, cabc.MutableMapping} and self.right.args:
                arguments = left.args[:2] or (ANY, ANY)
                if len(arguments) != len(self.right.args):
                    return False
                return all(
                    self._generic_arg_compatible(
                        actual,
                        expected,
                        (
                            Variance.COVARIANT
                            if target is cabc.Mapping and index == 1
                            else Variance.INVARIANT
                        ),
                    )
                    for index, (actual, expected) in enumerate(zip(arguments, self.right.args))
                )
            if left.type == self.right.type and (left.args or self.right.args):
                # A bare generic is treated as an Any-parameterized instance.
                if not self.right.args or not left.args:
                    return True
                if len(left.args) != len(self.right.args):
                    return False
                return all(
                    self._generic_arg_compatible(
                        left_elem,
                        right_elem,
                        left.type.parameter_variance(index),
                    )
                    for index, (left_elem, right_elem) in enumerate(zip(left.args, self.right.args))
                )
            return True
        return False

    def visit_tuple_type(self, left: TupleType) -> bool:
        if isinstance(self.right, Instance) and self.right.type.raw_type is object:
            return True
        if isinstance(self.right, Instance) and self.right.type.raw_type in {
            cabc.Iterable,
            cabc.Collection,
            cabc.Sequence,
            cabc.Reversible,
            cabc.Container,
        }:
            return not self.right.args or all(
                self.sub_type_check(element, self.right.args[0]) for element in left.args
            )
        if isinstance(self.right, TupleType):
            if self.right.unknown_size:
                if not self.right.args:
                    return True
                right_element = self.right.args[0]
                if left.unknown_size:
                    return not left.args or self.sub_type_check(left.args[0], right_element)
                return all(
                    self.sub_type_check(left_element, right_element) for left_element in left.args
                )
            if left.unknown_size:
                return False
            if len(left.args) != len(self.right.args):
                return False
            return all(starmap(self.sub_type_check, zip(left.args, self.right.args)))
        return False

    def visit_union_type(self, left: UnionType) -> bool:
        return all(self.sub_type_check(left_elem, self.right) for left_elem in left.items)

    def visit_unsupported_type(self, left: Unsupported) -> bool:
        raise NotImplementedError("This type shall not be used during runtime")

    def visit_type_var_type(self, left: TypeVarType) -> bool:
        if isinstance(self.right, TypeVarType) and left.name == self.right.name:
            return True
        if left.has_constraints:
            return all(self.sub_type_check(c, self.right) for c in left.constraints)
        if left.has_bound:
            return self.sub_type_check(left.bound, self.right)  # type: ignore[arg-type]
        return isinstance(self.right, Instance) and self.right.type.raw_type is object

    def visit_callable_type(self, left: CallableType) -> bool:
        if isinstance(self.right, Instance):
            if self.right.type.raw_type is object or (
                self.right.type.raw_type is cabc.Callable
                and all(isinstance(argument, AnyType) for argument in self.right.args)
            ):
                return True
            if self.right.type.is_protocol:
                member = self.graph.get_members(self.right.type).get("__call__")
                if isinstance(member, CallableType):
                    return self.sub_type_check(left, member)
            return False
        if not isinstance(self.right, CallableType):
            return False
        if not self.sub_type_check(left.return_type, self.right.return_type):
            return False
        if self.right.arg_types is None:
            return True
        if left.arg_types is None:
            return True
        if len(left.arg_types) != len(self.right.arg_types):
            return False
        return all(
            self.sub_type_check(right_arg, left_arg)
            for left_arg, right_arg in zip(left.arg_types, self.right.arg_types)
        )

    def visit_type_type(self, left: TypeType) -> bool:
        if isinstance(self.right, TypeType):
            return self.sub_type_check(left.item, self.right.item)
        if isinstance(self.right, CallableType):
            if isinstance(left.item, Instance):
                if not self.sub_type_check(left.item, self.right.return_type):
                    return False
                if self.right.arg_types is None:
                    return True
                init = self.graph.get_members(left.item.type).get("__init__")
                if isinstance(init, CallableType) and init.arg_types is not None:
                    ctor_args = init.arg_types
                    if len(ctor_args) != len(self.right.arg_types):
                        return False
                    return all(
                        self.sub_type_check(expected, actual)
                        for expected, actual in zip(self.right.arg_types, ctor_args)
                    )
                return True
            return self.sub_type_check(left.item, self.right.return_type)
        return isinstance(self.right, Instance) and self.right.type.raw_type in {
            type,
            object,
            cabc.Callable,
        }

    def visit_string_subtype(self, left: StringSubtype) -> bool:
        if isinstance(self.right, StringSubtype):
            return left == self.right
        return isinstance(self.right, Instance) and self.right.type.raw_type is str


def _sum_distances(distances: typing.Iterable[int | None]) -> int | None:
    """Sum structural distances, rejecting any disconnected component."""
    total = 0
    for distance in distances:
        if distance is None:
            return None
        total += distance
    return total


class _SubtypeDistanceVisitor(TypeVisitor[int | None]):
    """Compute shortest inheritance distance from *supertype* to *subtype*."""

    def __init__(
        self,
        graph: TypeSystem,
        subtype: ProperType,
        any_distance: int = config.settings.generator_selection.generator_any_distance,
    ):
        self.graph = graph
        self.subtype = subtype
        self.any_distance = any_distance

    def visit_any_type(self, supertype: AnyType) -> int:
        return self.any_distance

    def visit_none_type(self, supertype: NoneType) -> int | None:
        return 0 if isinstance(self.subtype, NoneType) else None

    def visit_never_type(self, supertype: NeverType) -> int | None:
        return 0 if isinstance(self.subtype, NeverType) else None

    def visit_instance(self, supertype: Instance) -> int | None:
        if supertype.type.raw_type is object and isinstance(
            self.subtype, (NoneType, TupleType, CallableType)
        ):
            return 1
        if (
            supertype.type.raw_type is cabc.Callable
            and isinstance(self.subtype, CallableType)
            and all(isinstance(argument, AnyType) for argument in supertype.args)
        ):
            return 1
        if isinstance(self.subtype, Instance):
            class_distance = self.graph.get_shortest_path_length(supertype.type, self.subtype.type)
            if class_distance is None:
                return None
            if supertype.type != self.subtype.type:
                return class_distance
            if len(supertype.args) != len(self.subtype.args):
                return None
            argument_distance = _sum_distances(
                (
                    self.graph.subtype_distance(subtype_arg, supertype_arg)
                    if supertype.type.parameter_variance(index) is Variance.CONTRAVARIANT
                    else self.graph.subtype_distance(supertype_arg, subtype_arg)
                )
                for index, (supertype_arg, subtype_arg) in enumerate(
                    zip(supertype.args, self.subtype.args)
                )
            )
            return None if argument_distance is None else class_distance + argument_distance

        if isinstance(self.subtype, UnionType):
            distances = [
                self.graph.subtype_distance(supertype, elem) for elem in self.subtype.items
            ]
            valid_distances = [dist for dist in distances if dist is not None]
            if valid_distances:
                return min(valid_distances)
            return None

        if isinstance(self.subtype, AnyType):
            return self.any_distance

        return None

    def visit_tuple_type(self, supertype: TupleType) -> int | None:
        if not isinstance(self.subtype, TupleType):
            return None
        if supertype.unknown_size:
            if not supertype.args:
                return 0
            supertype_element = supertype.args[0]
            subtype_elements = (
                self.subtype.args[:1] if self.subtype.unknown_size else self.subtype.args
            )
            return _sum_distances(
                self.graph.subtype_distance(supertype_element, subtype_element)
                for subtype_element in subtype_elements
            )
        if self.subtype.unknown_size or len(supertype.args) != len(self.subtype.args):
            return None
        return _sum_distances(
            self.graph.subtype_distance(supertype_arg, subtype_arg)
            for supertype_arg, subtype_arg in zip(supertype.args, self.subtype.args)
        )

    def visit_union_type(self, supertype: UnionType) -> int | None:
        distances = [self.graph.subtype_distance(elem, self.subtype) for elem in supertype.items]
        valid_distances = [dist for dist in distances if dist is not None]
        if valid_distances:
            return min(valid_distances)
        return None

    def visit_unsupported_type(self, supertype: Unsupported) -> int | None:
        raise NotImplementedError("This type shall not be used during runtime")

    def visit_callable_type(self, supertype: CallableType) -> int | None:
        if not isinstance(self.subtype, CallableType):
            return None
        return_distance = self.graph.subtype_distance(
            supertype.return_type, self.subtype.return_type
        )
        if return_distance is None:
            return None
        if supertype.arg_types is None:
            return return_distance
        if self.subtype.arg_types is None or len(supertype.arg_types) != len(
            self.subtype.arg_types
        ):
            return None
        parameter_distance = _sum_distances(
            self.graph.subtype_distance(subtype_arg, supertype_arg)
            for supertype_arg, subtype_arg in zip(supertype.arg_types, self.subtype.arg_types)
        )
        return None if parameter_distance is None else return_distance + parameter_distance

    def visit_type_type(self, supertype: TypeType) -> int | None:
        if not isinstance(self.subtype, TypeType):
            return None
        return self.graph.subtype_distance(supertype.item, self.subtype.item)


class _MaybeSubtypeVisitor(_SubtypeVisitor):
    """Weaker subtype check where any arm of a left Union may match *right*."""

    def visit_union_type(self, left: UnionType) -> bool:
        return any(self.sub_type_check(left_elem, self.right) for left_elem in left.items)

    def visit_unsupported_type(self, left: Unsupported) -> bool:
        raise NotImplementedError("This type shall not be used during runtime")


class _CollectionTypeVisitor(TypeVisitor[bool]):
    Collections: ClassVar[set[type]] = {dict, list, set}

    def visit_any_type(self, left: AnyType) -> bool:
        return False

    def visit_none_type(self, left: NoneType) -> bool:
        return False

    def visit_never_type(self, left: NeverType) -> bool:
        return False

    def visit_instance(self, left: Instance) -> bool:
        return left.type.raw_type in _CollectionTypeVisitor.Collections

    def visit_tuple_type(self, left: TupleType) -> bool:
        return True

    def visit_union_type(self, left: UnionType) -> bool:
        return False

    def visit_unsupported_type(self, left: Unsupported) -> bool:
        raise NotImplementedError("This type shall not be used during runtime")

    def visit_callable_type(self, left: CallableType) -> bool:
        return False

    def visit_type_type(self, left: TypeType) -> bool:
        return False


is_collection_type = _CollectionTypeVisitor()


class _PrimitiveTypeVisitor(TypeVisitor[bool]):
    Primitives: ClassVar[set[type]] = {int, str, bool, float, complex, bytes, type}

    def visit_any_type(self, left: AnyType) -> bool:
        return False

    def visit_none_type(self, left: NoneType) -> bool:
        return False

    def visit_never_type(self, left: NeverType) -> bool:
        return False

    def visit_instance(self, left: Instance) -> bool:
        return left.type.raw_type in _PrimitiveTypeVisitor.Primitives

    def visit_tuple_type(self, left: TupleType) -> bool:
        return False

    def visit_union_type(self, left: UnionType) -> bool:
        return False

    def visit_unsupported_type(self, left: Unsupported) -> bool:
        raise NotImplementedError("This type shall not be used during runtime")

    def visit_callable_type(self, left: CallableType) -> bool:
        return False

    def visit_type_type(self, left: TypeType) -> bool:
        return False


is_primitive_type = _PrimitiveTypeVisitor()
