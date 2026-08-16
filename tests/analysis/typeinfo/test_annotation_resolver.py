#  This file is part of PyFlow.
#
#  SPDX-FileCopyrightText: 2019–2026 PyFlow Contributors
#
#  SPDX-License-Identifier: MIT
#

from __future__ import annotations

import pytest

from pyflow.analysis.typeinfo.core.typesystem import (
    ANY,
    NEVER,
    CallableType,
    Instance,
    TupleType,
    ClassDescriptor,
    TypeVarType,
    TypeType,
    UnionType,
)
from pyflow.analysis.typeinfo.resolution.annotations import (
    BuiltinTypeLookup,
    resolve_annotation,
    resolve_forward_reference,
)


# ---------------------------------------------------------------------------
# Type lookup fixture
# ---------------------------------------------------------------------------


def _make_lookup(*names_and_types: tuple[str, type | Instance | TypeVarType]):
    """Build a simple TypeLookup from (name, type) pairs."""

    def lookup(name: str):
        for n, t in names_and_types:
            if n == name:
                if isinstance(t, Instance):
                    return t
                if isinstance(t, TypeVarType):
                    return t
                return Instance(ClassDescriptor(t))
        return None

    return lookup


_INT = Instance(ClassDescriptor(int))
_STR = Instance(ClassDescriptor(str))
_FLOAT = Instance(ClassDescriptor(float))
_BOOL = Instance(ClassDescriptor(bool))
_LIST = Instance(ClassDescriptor(list))
_DICT = Instance(ClassDescriptor(dict))
_SET = Instance(ClassDescriptor(set))

_BASIC_LOOKUP = _make_lookup(
    ("int", int),
    ("str", str),
    ("float", float),
    ("bool", bool),
    ("list", list),
    ("dict", dict),
    ("set", set),
    ("None", type(None)),
    ("MyClass", int),  # pretend MyClass is int for testing
)


# ---------------------------------------------------------------------------
# resolve_forward_reference
# ---------------------------------------------------------------------------


def test_resolve_forward_reference_bare_name() -> None:
    result = resolve_forward_reference("int", _BASIC_LOOKUP)
    assert result is not None
    assert isinstance(result, Instance)
    assert result.type.raw_type is int


def test_resolve_forward_reference_invalid_syntax() -> None:
    result = resolve_forward_reference("!!!invalid!!!", _BASIC_LOOKUP)
    assert result is None


def test_resolve_forward_reference_unknown_name() -> None:
    result = resolve_forward_reference("UnknownType", _BASIC_LOOKUP)
    assert result is None


# ---------------------------------------------------------------------------
# resolve_annotation — simple types
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("annotation", "expected_raw_type"),
    [
        ("int", int),
        ("str", str),
        ("float", float),
        ("bool", bool),
    ],
)
def test_resolve_simple_type(annotation: str, expected_raw_type: type) -> None:
    result = resolve_annotation(annotation, _BASIC_LOOKUP)
    assert result is not None
    assert isinstance(result, Instance)
    assert result.type.raw_type is expected_raw_type


# ---------------------------------------------------------------------------
# resolve_annotation — generic subscriptions
# ---------------------------------------------------------------------------


def test_resolve_list_int() -> None:
    result = resolve_annotation("list[int]", _BASIC_LOOKUP)
    assert isinstance(result, Instance)
    assert result.type.raw_type is list
    assert len(result.args) == 1
    assert result.args[0].type.raw_type is int  # type: ignore[union-attr]


def test_resolve_typing_list_int() -> None:
    result = resolve_annotation("typing.List[int]", _BASIC_LOOKUP)
    assert isinstance(result, Instance)
    assert result.type.raw_type is list
    assert len(result.args) == 1
    assert result.args[0].type.raw_type is int  # type: ignore[union-attr]


def test_resolve_dict_str_int() -> None:
    result = resolve_annotation("dict[str, int]", _BASIC_LOOKUP)
    assert isinstance(result, Instance)
    assert result.type.raw_type is dict
    assert len(result.args) == 2


def test_resolve_qualified_attribute_without_resolving_module_base() -> None:
    lookup = _make_lookup(("pkg.mod.Client", int))

    result = resolve_annotation("pkg.mod.Client", lookup)

    assert isinstance(result, Instance)
    assert result.type.raw_type is int


def test_resolve_builtin_tuple_generic() -> None:
    result = resolve_annotation("tuple[int, str]", _BASIC_LOOKUP)
    assert isinstance(result, TupleType)
    assert not result.unknown_size
    assert len(result.args) == 2
    assert isinstance(result.args[0], Instance)
    assert result.args[0].type.raw_type is int
    assert isinstance(result.args[1], Instance)
    assert result.args[1].type.raw_type is str


def test_resolve_builtin_bare_tuple() -> None:
    result = resolve_annotation("tuple", BuiltinTypeLookup())
    assert isinstance(result, TupleType)
    assert result.unknown_size
    assert result.args == (ANY,)


def test_builtin_lookup_canonicalizes_bare_known_generics() -> None:
    lookup = BuiltinTypeLookup()

    list_ = resolve_annotation("list", lookup)
    dict_ = resolve_annotation("dict", lookup)

    assert isinstance(list_, Instance) and list_.args == (ANY,)
    assert isinstance(dict_, Instance) and dict_.args == (ANY, ANY)


# ---------------------------------------------------------------------------
# resolve_annotation — Optional
# ---------------------------------------------------------------------------


def test_resolve_optional_int() -> None:
    result = resolve_annotation("Optional[int]", _BASIC_LOOKUP)
    assert isinstance(result, UnionType)
    items = list(result.items)
    assert len(items) == 2
    types = {i.type.raw_type if isinstance(i, Instance) else None for i in items}  # type: ignore[union-attr]
    assert int in types
    assert None in types


def test_resolve_typing_optional_int() -> None:
    result = resolve_annotation("typing.Optional[int]", _BASIC_LOOKUP)
    assert isinstance(result, UnionType)
    item_types = {
        i.type.raw_type if isinstance(i, Instance) else type(None)
        for i in result.items
    }
    assert int in item_types
    assert type(None) in item_types


def test_resolve_optional_str() -> None:
    result = resolve_annotation("Optional[str]", _BASIC_LOOKUP)
    assert isinstance(result, UnionType)
    items = list(result.items)
    item_types = {
        i.type.raw_type if isinstance(i, Instance) else type(None) for i in items  # type: ignore[union-attr]
    }
    assert str in item_types


# ---------------------------------------------------------------------------
# resolve_annotation — Union
# ---------------------------------------------------------------------------


def test_resolve_union_two() -> None:
    result = resolve_annotation("Union[int, str]", _BASIC_LOOKUP)
    assert isinstance(result, UnionType)
    assert len(result.items) == 2


def test_resolve_typing_union_two() -> None:
    result = resolve_annotation("typing.Union[int, str]", _BASIC_LOOKUP)
    assert isinstance(result, UnionType)
    assert len(result.items) == 2


def test_resolve_union_is_flattened_and_deduplicated() -> None:
    result = resolve_annotation("Union[int, Union[str, int]]", _BASIC_LOOKUP)
    assert isinstance(result, UnionType)
    assert len(result.items) == 2


def test_resolve_union_three() -> None:
    result = resolve_annotation("Union[int, str, float]", _BASIC_LOOKUP)
    assert isinstance(result, UnionType)
    assert len(result.items) == 3


def test_resolve_union_with_none() -> None:
    result = resolve_annotation("Union[int, None]", _BASIC_LOOKUP)
    assert isinstance(result, UnionType)
    assert len(result.items) == 2


# ---------------------------------------------------------------------------
# resolve_annotation — PEP 604 X | Y
# ---------------------------------------------------------------------------


def test_resolve_pep604_union() -> None:
    result = resolve_annotation("int | str", _BASIC_LOOKUP)
    assert isinstance(result, UnionType)
    assert len(result.items) == 2


def test_resolve_pep604_triple() -> None:
    result = resolve_annotation("int | str | float", _BASIC_LOOKUP)
    assert isinstance(result, UnionType)
    assert len(result.items) == 3


def test_resolve_literal_to_value_type_union() -> None:
    result = resolve_annotation("Literal['x', 1, None]", _BASIC_LOOKUP)
    assert isinstance(result, UnionType)
    assert len(result.items) == 3


def test_resolve_callable_signature() -> None:
    result = resolve_annotation("Callable[[int, str], bool]", _BASIC_LOOKUP)
    assert isinstance(result, CallableType)
    assert result.arg_types is not None
    assert len(result.arg_types) == 2
    assert isinstance(result.return_type, Instance)
    assert result.return_type.type.raw_type is bool


def test_unresolved_nested_annotation_parts_preserve_shape() -> None:
    union = resolve_annotation("Union[int, Missing]", _BASIC_LOOKUP)
    tuple_ = resolve_annotation("Tuple[int, Missing]", _BASIC_LOOKUP)
    callable_ = resolve_annotation(
        "Callable[[int, Missing], str]", _BASIC_LOOKUP
    )
    generic = resolve_annotation("list[Missing]", _BASIC_LOOKUP)

    assert isinstance(union, UnionType) and ANY in union.items
    assert isinstance(tuple_, TupleType) and tuple_.args == (_INT, ANY)
    assert isinstance(callable_, CallableType)
    assert callable_.arg_types == (_INT, ANY)
    assert isinstance(generic, Instance) and generic.args == (ANY,)


def test_resolve_never_and_noreturn_as_bottom() -> None:
    assert resolve_annotation("Never", _BASIC_LOOKUP) is NEVER
    assert resolve_annotation("typing.NoReturn", _BASIC_LOOKUP) is NEVER


def test_resolve_type_preserves_class_object_distinction() -> None:
    result = resolve_annotation("Type[int]", _BASIC_LOOKUP)

    assert isinstance(result, TypeType)
    assert result.item == _INT


def test_builtin_type_lookup_resolves_common_builtins() -> None:
    lookup = BuiltinTypeLookup()
    result = resolve_annotation("typing.Dict[str, int]", lookup)
    assert isinstance(result, Instance)
    assert result.type.raw_type is dict
    assert len(result.args) == 2


# ---------------------------------------------------------------------------
# resolve_annotation — Tuple
# ---------------------------------------------------------------------------


def test_resolve_tuple_variable() -> None:
    result = resolve_annotation("Tuple[int, ...]", _BASIC_LOOKUP)
    assert isinstance(result, TupleType)
    assert result.unknown_size is True
    assert len(result.args) == 1


def test_resolve_tuple_fixed() -> None:
    result = resolve_annotation("Tuple[int, str]", _BASIC_LOOKUP)
    assert isinstance(result, TupleType)
    assert result.unknown_size is False
    assert len(result.args) == 2


def test_resolve_tuple_single() -> None:
    result = resolve_annotation("Tuple[int]", _BASIC_LOOKUP)
    assert isinstance(result, TupleType)
    assert len(result.args) == 1


# ---------------------------------------------------------------------------
# resolve_annotation — wrapper forms
# ---------------------------------------------------------------------------


def test_resolve_classvar() -> None:
    result = resolve_annotation("ClassVar[int]", _BASIC_LOOKUP)
    assert isinstance(result, Instance)
    assert result.type.raw_type is int


def test_resolve_final() -> None:
    result = resolve_annotation("Final[str]", _BASIC_LOOKUP)
    assert isinstance(result, Instance)
    assert result.type.raw_type is str


# ---------------------------------------------------------------------------
# resolve_annotation — forward references (quoted strings)
# ---------------------------------------------------------------------------


def test_resolve_quoted_string() -> None:
    result = resolve_annotation('"int"', _BASIC_LOOKUP)
    assert isinstance(result, Instance)
    assert result.type.raw_type is int


def test_resolve_single_quoted() -> None:
    result = resolve_annotation("'str'", _BASIC_LOOKUP)
    assert isinstance(result, Instance)
    assert result.type.raw_type is str


# ---------------------------------------------------------------------------
# resolve_annotation — TypeVar references
# ---------------------------------------------------------------------------


def test_resolve_typevar_name() -> None:
    t = TypeVarType("T")
    lookup = _make_lookup(("T", t))
    result = resolve_annotation("T", lookup)
    assert result is t


def test_resolve_optional_with_typevar() -> None:
    t = TypeVarType("T")
    lookup = _make_lookup(
        ("T", t),
        ("int", int),
    )
    result = resolve_annotation("Optional[T]", lookup)
    assert isinstance(result, UnionType)
    items = list(result.items)
    # T should be in there
    assert t in items


# ---------------------------------------------------------------------------
# resolve_annotation — edge cases
# ---------------------------------------------------------------------------


def test_resolve_empty_string() -> None:
    result = resolve_annotation("", _BASIC_LOOKUP)
    assert result is None


def test_resolve_whitespace_only() -> None:
    result = resolve_annotation("   ", _BASIC_LOOKUP)
    assert result is None


def test_resolve_invalid_syntax() -> None:
    result = resolve_annotation("!!!bad!!!", _BASIC_LOOKUP)
    assert result is None


def test_resolve_unknown_name() -> None:
    result = resolve_annotation("NonExistent", _BASIC_LOOKUP)
    assert result is None


def test_resolve_none() -> None:
    result = resolve_annotation("None", _BASIC_LOOKUP)
    assert result is not None


def test_resolve_callable_basic() -> None:
    result = resolve_annotation("Callable[[int, str], bool]", _BASIC_LOOKUP)
    assert result is not None


def test_resolve_callable_no_args() -> None:
    result = resolve_annotation("Callable[..., int]", _BASIC_LOOKUP)
    assert result is not None
