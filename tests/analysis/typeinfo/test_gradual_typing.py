#  This file is part of PyFlow.
#
#  SPDX-FileCopyrightText: 2019–2026 PyFlow Contributors
#
#  SPDX-License-Identifier: MIT
#

from __future__ import annotations

import pytest

from pyflow.analysis.typeinfo.core.typesystem import (
    Instance,
    TupleType,
    ClassDescriptor,
    TypeVarType,
    UnionType,
    Variance,
)
from pyflow.analysis.typeinfo.resolution.typing_syntax import (
    collect_type_vars,
    is_proxy_class,
    is_proxy_type,
    parse_type_comment,
    resolve_type_alias,
    should_ignore_annotation_part,
    split_comment_param_declaration,
    substitute_type_vars,
)


# ---------------------------------------------------------------------------
# Type alias resolution
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("name", "expected"),
    [
        ("List", "builtins.list"),
        ("Dict", "builtins.dict"),
        ("Set", "builtins.set"),
        ("FrozenSet", "builtins.frozenset"),
        ("DefaultDict", "collections.defaultdict"),
        ("Deque", "collections.deque"),
        ("Counter", "collections.Counter"),
        ("ChainMap", "collections.ChainMap"),
    ],
)
def test_resolve_type_alias_known(name: str, expected: str) -> None:
    assert resolve_type_alias(name) == expected


@pytest.mark.parametrize("name", ["str", "int", "float", "UnknownType", ""])
def test_resolve_type_alias_unknown(name: str) -> None:
    assert resolve_type_alias(name) is None


@pytest.mark.parametrize(
    ("name", "expected"),
    [
        ("Tuple", True),
        ("Generic", True),
        ("Protocol", True),
        ("Callable", True),
        ("Type", True),
        ("List", False),
        ("int", False),
    ],
)
def test_is_proxy_class(name: str, expected: bool) -> None:
    assert is_proxy_class(name) is expected


@pytest.mark.parametrize(
    ("name", "expected"),
    [
        ("Optional", True),
        ("Union", True),
        ("ClassVar", True),
        ("Annotated", True),
        ("Final", True),
        ("List", False),
        ("int", False),
    ],
)
def test_is_proxy_type(name: str, expected: bool) -> None:
    assert is_proxy_type(name) is expected


def test_should_ignore_annotation_part() -> None:
    assert should_ignore_annotation_part("ClassVar") is True
    assert should_ignore_annotation_part("Annotated") is True
    assert should_ignore_annotation_part("Final") is True
    assert should_ignore_annotation_part("int") is False


# ---------------------------------------------------------------------------
# Type variable substitution
# ---------------------------------------------------------------------------


def test_substitute_type_vars_simple() -> None:
    t = TypeVarType("T")
    result = substitute_type_vars(t, {"T": Instance(ClassDescriptor(int))})
    assert isinstance(result, Instance)
    assert result.type.raw_type is int


def test_substitute_type_vars_no_match() -> None:
    t = TypeVarType("T")
    result = substitute_type_vars(t, {"U": Instance(ClassDescriptor(int))})
    assert result is t  # unchanged


def test_substitute_type_vars_in_instance() -> None:
    t = TypeVarType("T")
    ti = ClassDescriptor(list)
    instance = Instance(ti, (t,))
    result = substitute_type_vars(instance, {"T": Instance(ClassDescriptor(int))})
    assert isinstance(result, Instance)
    assert result.type.raw_type is list
    assert len(result.args) == 1
    assert isinstance(result.args[0], Instance)
    assert result.args[0].type.raw_type is int


def test_substitute_type_vars_in_union() -> None:
    t1 = TypeVarType("T")
    t2 = TypeVarType("U")
    union = UnionType((t1, t2))
    result = substitute_type_vars(
        union,
        {"T": Instance(ClassDescriptor(int)), "U": Instance(ClassDescriptor(str))},
    )
    assert isinstance(result, UnionType)
    items = list(result.items)
    assert len(items) == 2
    assert items[0].type.raw_type is int  # type: ignore[union-attr]
    assert items[1].type.raw_type is str  # type: ignore[union-attr]


def test_substitute_type_vars_in_tuple() -> None:
    t = TypeVarType("T")
    tt = TupleType((t, t))
    result = substitute_type_vars(tt, {"T": Instance(ClassDescriptor(int))})
    assert isinstance(result, TupleType)
    assert result.args[0].type.raw_type is int  # type: ignore[union-attr]
    assert result.args[1].type.raw_type is int  # type: ignore[union-attr]


def test_substitute_type_vars_no_change() -> None:
    inst = Instance(ClassDescriptor(int))
    result = substitute_type_vars(inst, {"T": Instance(ClassDescriptor(str))})
    assert result is inst


# ---------------------------------------------------------------------------
# collect_type_vars
# ---------------------------------------------------------------------------


def test_collect_type_vars_simple() -> None:
    t = TypeVarType("T")
    result = collect_type_vars(t)
    assert len(result) == 1
    assert result[0] is t


def test_collect_type_vars_nested() -> None:
    t = TypeVarType("T")
    u = TypeVarType("U")
    ti = ClassDescriptor(dict)
    instance = Instance(ti, (t, u))
    result = collect_type_vars(instance)
    names = {tv.name for tv in result}
    assert names == {"T", "U"}


def test_collect_type_vars_union() -> None:
    t = TypeVarType("T")
    u = TypeVarType("U")
    union = UnionType((t, u, Instance(ClassDescriptor(int))))
    result = collect_type_vars(union)
    names = {tv.name for tv in result}
    assert names == {"T", "U"}


def test_collect_type_vars_no_vars() -> None:
    result = collect_type_vars(Instance(ClassDescriptor(int)))
    assert result == []


def test_collect_type_vars_dedup() -> None:
    t = TypeVarType("T")
    union = UnionType((t, t))
    result = collect_type_vars(union)
    assert len(result) == 1


# ---------------------------------------------------------------------------
# TypeVarType properties
# ---------------------------------------------------------------------------


def test_type_var_constraints() -> None:
    t = TypeVarType("T", constraints=(Instance(ClassDescriptor(int)), Instance(ClassDescriptor(str))))
    assert t.has_constraints is True
    assert t.has_bound is False
    assert len(t.constraints) == 2


def test_type_var_bound() -> None:
    t = TypeVarType("T", bound=Instance(ClassDescriptor(int)))
    assert t.has_bound is True
    assert t.has_constraints is False


def test_type_var_variance() -> None:
    t = TypeVarType("T", variance=Variance.COVARIANT)
    assert t.variance == Variance.COVARIANT


def test_type_var_equality() -> None:
    t1 = TypeVarType("T")
    t2 = TypeVarType("T")
    t3 = TypeVarType("U")
    assert t1 == t2
    assert t1 != t3


def test_type_var_hash() -> None:
    t1 = TypeVarType("T")
    t2 = TypeVarType("T")
    assert hash(t1) == hash(t2)


# ---------------------------------------------------------------------------
# Type-comment parsing
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("decl_text", "expected"),
    [
        ("int, str", ["int", "str"]),
        ("int, str, float", ["int", "str", "float"]),
        ("Dict[str, int], bool", ["Dict[str, int]", "bool"]),
        ("Dict[str, int]", ["Dict[str, int]"]),
        ("int", ["int"]),
        ("", []),
    ],
)
def test_split_comment_param_declaration(
    decl_text: str, expected: list[str]
) -> None:
    assert split_comment_param_declaration(decl_text) == expected


def test_split_nested_brackets() -> None:
    result = split_comment_param_declaration(
        "Mapping[str, List[int]], Callable[[int], str]"
    )
    assert result == ["Mapping[str, List[int]]", "Callable[[int], str]"]


@pytest.mark.parametrize(
    ("comment", "expected_params", "expected_return"),
    [
        ("# type: (int, str) -> bool", ["int", "str"], "bool"),
        ("# type: (int) -> None", ["int"], "None"),
        ("# type: (Dict[str, int], bool) -> Optional[str]",
         ["Dict[str, int]", "bool"], "Optional[str]"),
    ],
)
def test_parse_type_comment(
    comment: str, expected_params: list[str], expected_return: str
) -> None:
    params, ret = parse_type_comment(comment)
    assert params == expected_params
    assert ret == expected_return


def test_parse_type_comment_no_match() -> None:
    params, ret = parse_type_comment("no type comment here")
    assert params == []
    assert ret is None


def test_parse_type_comment_no_return() -> None:
    params, ret = parse_type_comment("# type: (int, str)")
    assert params == []
    assert ret is None
