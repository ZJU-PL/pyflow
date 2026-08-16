#  This file is part of PyFlow.
#
#  SPDX-FileCopyrightText: 2019–2026 PyFlow Contributors
#
#  SPDX-License-Identifier: MIT
#
# ruff: noqa: PLC2701

from __future__ import annotations

import inspect
import operator
import re
from typing import Any, Callable, NoReturn, TypeVar, Union
from unittest import mock

import pytest

import pyflow.analysis.typeinfo.config as _config
from pyflow.analysis.typeinfo.inference.providers import HintInference, NoInference
from pyflow.analysis.typeinfo.core.typesystem import (
    NEVER,
    _DICT_KEY_ATTRIBUTES,
    _DICT_KEY_FROM_ARGUMENT_TYPES,
    _DICT_VALUE_ATTRIBUTES,
    _DICT_VALUE_FROM_ARGUMENT_TYPES,
    _LIST_ELEMENT_ATTRIBUTES,
    _LIST_ELEMENT_FROM_ARGUMENT_TYPES,
    _SET_ELEMENT_ATTRIBUTES,
    _SET_ELEMENT_FROM_ARGUMENT_TYPES,
    UNSUPPORTED,
    AnyType,
    CallableType,
    InferredSignature,
    Instance,
    NoneType,
    StringSubtype,
    TupleType,
    ClassDescriptor,
    TypeSystem,
    TypeType,
    UnionType,
    _is_partial_type_match,
    is_collection_type,
    is_primitive_type,
)
from pyflow.util.orderedset import OrderedSet
from pyflow.analysis.typeinfo.inference.tracing import UsageTraceNode
from tests.analysis.typeinfo.conftest import _build_type_system_from_module
from tests.analysis.typeinfo.fixtures.types.subtyping import Sub, Super


def __dummy(x: int, y: int) -> int:  # noqa: FURB118
    return x * y  # pragma: no cover


def __func_1(x: int) -> int:
    return x  # pragma: no cover


def __typed_dummy(a: int, b: float, c) -> str:
    return f"int {a} float {b} any {c}"  # pragma: no cover


def __untyped_dummy(a, b, c):
    return f"int {a} float {b} any {c}"  # pragma: no cover


def __union_dummy(  # noqa: FURB118
    a: int | float,  # noqa: PYI041
    b: int | float,  # noqa: PYI041
) -> int | float:
    return a + b  # pragma: no cover


def __return_tuple() -> tuple[int, int]:
    return 23, 42  # pragma: no cover


def __return_tuple_no_annotation():
    return 23, 42  # pragma: no cover


class __TypedDummy:
    def __init__(self, a: Any) -> None:
        self.__a = a  # pragma: no cover

    def get_a(self) -> Any:
        return self.__a  # pragma: no cover


class __UntypedDummy:
    def __init__(self, a):
        self.__a = a  # pragma: no cover

    def get_a(self):
        return self.__a  # pragma: no cover


@pytest.fixture
def signature():
    return inspect.signature(__dummy)


@pytest.fixture
def inferred_signature(signature, type_system):
    return InferredSignature(
        signature=signature,
        original_parameters={
            "x": type_system.convert_type_hint(int),
            "y": type_system.convert_type_hint(int),
        },
        original_return_type=type_system.convert_type_hint(int),
        type_system=type_system,
    )


@pytest.mark.parametrize(
    "func, infer_types, expected_parameters, expected_return",
    [
        pytest.param(
            __func_1,
            HintInference(),
            {"x": Instance(ClassDescriptor(int))},
            Instance(ClassDescriptor(int)),
        ),
        pytest.param(__func_1, NoInference(), {"x": AnyType()}, AnyType()),
        pytest.param(
            __typed_dummy,
            HintInference(),
            {
                "a": Instance(ClassDescriptor(int)),
                "b": Instance(ClassDescriptor(float)),
                "c": AnyType(),
            },
            Instance(ClassDescriptor(str)),
        ),
        pytest.param(
            __untyped_dummy,
            HintInference(),
            {"a": AnyType(), "b": AnyType(), "c": AnyType()},
            AnyType(),
        ),
        pytest.param(
            __union_dummy,
            HintInference(),
            {
                "a": UnionType((Instance(ClassDescriptor(float)), Instance(ClassDescriptor(int)))),
                "b": UnionType((Instance(ClassDescriptor(float)), Instance(ClassDescriptor(int)))),
            },
            UnionType((Instance(ClassDescriptor(float)), Instance(ClassDescriptor(int)))),
        ),
        pytest.param(
            __return_tuple,
            HintInference(),
            {},
            TupleType((Instance(ClassDescriptor(int)), Instance(ClassDescriptor(int)))),
        ),
        pytest.param(
            __return_tuple_no_annotation,
            HintInference(),
            {},
            AnyType(),
        ),
        pytest.param(
            __TypedDummy.__init__,
            HintInference(),
            {"a": AnyType()},
            NoneType(),
        ),
        pytest.param(
            __UntypedDummy.__init__,
            HintInference(),
            {"a": AnyType()},
            AnyType(),
        ),
        pytest.param(
            __TypedDummy.__init__,
            NoInference(),
            {"a": AnyType()},
            AnyType(),
        ),
        pytest.param(
            __UntypedDummy.__init__,
            NoInference(),
            {"a": AnyType()},
            AnyType(),
        ),
    ],
)
def test_infer_type_info(func, infer_types, expected_parameters, expected_return):
    type_system = TypeSystem()
    result = type_system.infer_signature_with_provider(func, type_inference_provider=infer_types)
    assert result.original_parameters == expected_parameters
    assert result.return_type == expected_return


A = TypeVar("A")


@pytest.mark.parametrize(
    "hint,expected",
    [
        (list, Instance(ClassDescriptor(list), (AnyType(),))),
        (
            list[int],
            Instance(ClassDescriptor(list), (Instance(ClassDescriptor(int)),)),
        ),
        (
            set[int],
            Instance(ClassDescriptor(set), (Instance(ClassDescriptor(int)),)),
        ),
        (
            set,
            Instance(ClassDescriptor(set), (AnyType(),)),
        ),
        (
            dict[int, str],
            Instance(
                ClassDescriptor(dict),
                (Instance(ClassDescriptor(int)), Instance(ClassDescriptor(str))),
            ),
        ),
        (
            int | str,
            UnionType(
                (Instance(ClassDescriptor(int)), Instance(ClassDescriptor(str))),
            ),
        ),
        (
            Union[int, str],  # noqa: UP007
            UnionType(
                (Instance(ClassDescriptor(int)), Instance(ClassDescriptor(str))),
            ),
        ),
        (
            Union[int, type(None)],  # noqa: UP007
            UnionType(
                (NoneType(), Instance(ClassDescriptor(int))),
            ),
        ),
        (
            tuple[int, str],
            TupleType(
                (Instance(ClassDescriptor(int)), Instance(ClassDescriptor(str))),
            ),
        ),
        (
            tuple[int, ...],
            TupleType((Instance(ClassDescriptor(int)),), unknown_size=True),
        ),
        (
            tuple,
            TupleType((AnyType(),), unknown_size=True),
        ),
        (
            Callable[[int], str],
            CallableType(
                (Instance(ClassDescriptor(int)),), Instance(ClassDescriptor(str))
            ),
        ),
        (type[int], TypeType(Instance(ClassDescriptor(int)))),
        (NoReturn, NEVER),
        (
            Any,
            AnyType(),
        ),
        (
            type(None),
            NoneType(),
        ),
        (A, AnyType()),
    ],
)
def test_convert_type_hints(hint, expected):
    graph = TypeSystem()
    assert graph.convert_type_hint(hint) == expected
    assert repr(graph.convert_type_hint(hint)) == repr(expected)


@pytest.mark.parametrize(
    "hint, expected",
    [(A, UNSUPPORTED), (list[A], Instance(ClassDescriptor(list), (UNSUPPORTED,)))],
)
def test_convert_type_hint_unsupported(hint, expected):  # noqa: ARG001
    ts = TypeSystem()
    ts.convert_type_hint(hint, unsupported=UNSUPPORTED)


def test_unsupported_str():
    assert str(UNSUPPORTED) == "<?>"


@pytest.mark.parametrize(
    "left_hint,right_hint,subtype_result, maybe_subtype_result",
    [
        (int, int, True, True),
        (int, str, False, False),
        (str, str, True, True),
        (str, tuple[str], False, False),
        (tuple, int, False, False),
        (int, type(None), False, False),
        (type(None), type(None), True, True),
        (type(None), int, False, False),
        (tuple[str], tuple[str, int], False, False),
        (tuple[int, str], tuple[int, str], True, True),
        (tuple[int, int], tuple[int, str], False, False),
        (tuple[Any, Any], tuple[int, int], True, True),
        (tuple[int, int], tuple[Any, Any], True, True),
        (tuple[Any, Any], tuple[Any, Any], True, True),
        (tuple[int, str], tuple[int, str] | str, True, True),
        (tuple[bool, bool], tuple[int, int], True, True),
        (tuple[int, int], tuple[bool, bool], False, False),
        (int, int | str, True, True),
        (int | str, str, False, True),
        (float, int | str, False, False),
        (int | str, int | str, True, True),
        (int | str | float, int | str, False, True),
        (int | str, int | str | float, True, True),
        (int, Union[int, None], True, True),  # noqa: UP007
        (Sub, Super, True, True),
        (Sub, Super | int, True, True),
        (Sub, Sub | int, True, True),
        (Sub, object | int, True, True),
        (object, Sub | int, False, False),
        (Sub, float | int, False, False),
        (Super, Sub, False, False),
        (Sub, Sub, True, True),
        (Super, Super, True, True),
        (tuple[int | str | bytes, int | str | bytes], tuple[int, int], False, True),
        (int | float, float, True, True),
        (int | str, float, False, True),
        (float | bool, int, False, True),
        (list[int], list[bool], False, False),
        (list[int], list[int], True, True),
        (set[int], set[bool], False, False),
        (set[bool], set[bool], True, True),
        (dict[str, int], dict[str, bool], False, False),
        (dict[int, int], dict[float, int], False, False),
        (dict[str, int], dict[str, int], True, True),
        (Any, int, True, True),
        (int, Any, True, True),
        (Any, Any, True, True),
    ],
)
def test_is_subtype(subtyping_cluster, left_hint, right_hint, subtype_result, maybe_subtype_result):
    type_system = subtyping_cluster.type_system
    left = type_system.convert_type_hint(left_hint)
    right = type_system.convert_type_hint(right_hint)
    assert type_system.is_subtype(left, right) is subtype_result
    assert type_system.is_maybe_subtype(left, right) is maybe_subtype_result


def test_callable_subtyping_is_total_and_contravariant(subtyping_cluster) -> None:
    type_system = subtyping_cluster.type_system
    integer = type_system.convert_type_hint(int)
    object_ = type_system.convert_type_hint(object)
    accepts_object = CallableType((object_,), integer)
    accepts_integer = CallableType((integer,), object_)

    assert type_system.is_subtype(accepts_object, accepts_integer) is True
    assert type_system.is_subtype(accepts_integer, accepts_object) is False
    assert type_system.is_subtype(accepts_object, accepts_object) is True
    assert type_system.is_subtype(accepts_object, integer) is False


def test_generic_arity_mismatch_returns_false_instead_of_raising(type_system) -> None:
    parameterized = type_system.convert_type_hint(list[int])
    assert isinstance(parameterized, Instance)
    bare_internal_instance = Instance(parameterized.type)

    assert type_system.is_subtype(parameterized, bare_internal_instance) is False


def test_variadic_tuple_subtyping(type_system) -> None:
    fixed = type_system.convert_type_hint(tuple[int, int])
    variadic = type_system.convert_type_hint(tuple[int, ...])
    mixed = type_system.convert_type_hint(tuple[int, str])

    assert type_system.is_subtype(fixed, variadic) is True
    assert type_system.is_subtype(mixed, variadic) is False
    assert type_system.is_subtype(variadic, fixed) is False


def test_never_is_bottom_type(type_system) -> None:
    integer = type_system.convert_type_hint(int)

    assert type_system.is_subtype(NEVER, integer) is True
    assert type_system.is_subtype(integer, NEVER) is False
    assert type_system.is_subtype(NEVER, NEVER) is True
    assert str(NEVER) == "Never"


def test_type_type_is_distinct_and_covariant(subtyping_cluster) -> None:
    type_system = subtyping_cluster.type_system
    integer = type_system.convert_type_hint(int)
    object_ = type_system.convert_type_hint(object)

    assert type_system.is_subtype(TypeType(integer), TypeType(object_)) is True
    assert type_system.is_subtype(TypeType(integer), integer) is False


@pytest.mark.parametrize(
    "hint, hint_str",
    [
        (type(None), "None"),
        (type(None) | int, "None | int"),
        (str, "str"),
        (Any, "Any"),
        (tuple[int, int], "tuple[int, int]"),
        (list[int], "list[int]"),
    ],
)
def test_str_proper_type(type_system, hint, hint_str):
    proper = type_system.convert_type_hint(hint)
    assert str(proper) == hint_str


def test_variadic_tuple_string_preserves_ellipsis(type_system) -> None:
    proper = type_system.convert_type_hint(tuple[int, ...])

    assert str(proper) == "tuple[int, ...]"
    assert "unknown_size=True" in repr(proper)


@pytest.mark.parametrize(
    "subclass,superclass,result",
    [
        (int, int, True),
        (int, str, False),
        (Sub, Super, True),
        (Super, Sub, False),
    ],
)
def test_is_subclass(subtyping_cluster, subclass, superclass, result):
    type_system = subtyping_cluster.type_system
    assert (
        type_system.is_subclass(
            type_system.to_class_descriptor(subclass), type_system.to_class_descriptor(superclass)
        )
        == result
    )


@pytest.mark.parametrize(
    "kind,type_,result",
    [
        (inspect.Parameter.VAR_POSITIONAL, None, list[Any]),
        (inspect.Parameter.VAR_POSITIONAL, str, list[str]),
        (inspect.Parameter.VAR_KEYWORD, None, dict[str, Any]),
        (inspect.Parameter.VAR_KEYWORD, str, dict[str, str]),
        (inspect.Parameter.POSITIONAL_OR_KEYWORD, dict, dict),
    ],
)
def test_wrap_var_param_type(kind, type_, result):
    system = TypeSystem()
    proper = system.convert_type_hint(type_)
    assert system.wrap_var_param_type(proper, kind) == system.convert_type_hint(result)


def test_inferred_signature_identity(type_system):
    assert InferredSignature(None, None, {}, type_system) != InferredSignature(
        None, None, {}, type_system
    )


def test_get_parameter_types_consistent(inferred_signature):
    assert inferred_signature.get_parameter_types({inferred_signature: 42}) == 42


def test_get_parameter_types_consistent_2(inferred_signature):
    cache = {}
    assert inferred_signature.get_parameter_types(cache)
    assert cache


@pytest.mark.parametrize(
    "left,right,result",
    [
        (AnyType(), AnyType(), True),
        (AnyType(), NoneType(), False),
        (NoneType(), NoneType(), True),
        (NoneType(), AnyType(), False),
        (TupleType((AnyType(),)), TupleType((AnyType(),)), True),
        (TupleType((AnyType(),)), TupleType((NoneType(),)), False),
        (Instance(ClassDescriptor(int), ()), Instance(ClassDescriptor(int), ()), True),
        (Instance(ClassDescriptor(int), ()), AnyType(), False),
        (UnionType((AnyType(),)), UnionType((AnyType(),)), True),
        (UnionType((AnyType(),)), UnionType((NoneType(),)), False),
    ],
)
def test_types_equality_self(left, right, result):
    assert (left == right) == result


@pytest.mark.parametrize(
    "typ,result",
    [
        (AnyType(), False),
        (TupleType((AnyType(),)), False),
        (Instance(ClassDescriptor(int)), True),
        (Instance(ClassDescriptor(float)), True),
        (Instance(ClassDescriptor(str)), True),
        (Instance(ClassDescriptor(complex)), True),
        (Instance(ClassDescriptor(bool)), True),
        (Instance(ClassDescriptor(bytes)), True),
        (Instance(ClassDescriptor(list)), False),
        (UnionType((AnyType(),)), False),
        (NoneType(), False),
    ],
)
def test_is_primitive_type(typ, result):
    assert typ.accept(is_primitive_type) is result


@pytest.mark.parametrize(
    "typ,result",
    [
        (AnyType(), False),
        (TupleType((AnyType(),)), True),
        (Instance(ClassDescriptor(list)), True),
        (Instance(ClassDescriptor(set)), True),
        (Instance(ClassDescriptor(dict)), True),
        (Instance(ClassDescriptor(int)), False),
        (UnionType((AnyType(),)), False),
        (NoneType(), False),
    ],
)
def test_is_collection_type(typ, result):
    assert typ.accept(is_collection_type) is result


@pytest.mark.parametrize(
    "symbol,types",
    [
        ("a", ("tests.analysis.typeinfo.fixtures.types.symbols.Foo", "tests.analysis.typeinfo.fixtures.types.symbols.Baz")),
        ("b", ("tests.analysis.typeinfo.fixtures.types.symbols.Bar",)),
        ("foo", ("tests.analysis.typeinfo.fixtures.types.symbols.Foo",)),
        (
            "bar",
            (
                "tests.analysis.typeinfo.fixtures.types.symbols.Foo",
                "tests.analysis.typeinfo.fixtures.types.symbols.Baz",
            ),
        ),
        ("not_defined", ()),
        (
            "__lt__",
            (
                "builtins.str",
                "builtins.bytes",
                "builtins.complex",
                "builtins.list",
                "builtins.set",
                "builtins.dict",
                "builtins.tuple",
            ),
        ),
        ("isspace", ("builtins.str", "builtins.bytes")),
        ("e", ("tests.analysis.typeinfo.fixtures.types.symbols.E",)),
        ("f", ("tests.analysis.typeinfo.fixtures.types.symbols.F",)),
        ("g", ("tests.analysis.typeinfo.fixtures.types.symbols.G",)),
    ],
)
def test_find_by_symbols(symbol, types):
    type_system = _build_type_system_from_module("tests.analysis.typeinfo.fixtures.types.symbols")
    assert type_system.find_by_attribute(symbol) == OrderedSet([
        type_system.find_class_descriptor("" + t) for t in types
    ])


@pytest.mark.parametrize(
    "outside_of,expected_types",
    [
        (
            ("tests.analysis.typeinfo.fixtures.types.outside.Foo",),
            (
                "builtins.int",
                "builtins.str",
                "builtins.bool",
                "builtins.float",
                "builtins.bytes",
                "builtins.complex",
                "builtins.list",
                "builtins.set",
                "builtins.dict",
                "builtins.tuple",
                "builtins.object",
            ),
        ),
        (
            ("tests.analysis.typeinfo.fixtures.types.outside.Bar",),
            (
                "tests.analysis.typeinfo.fixtures.types.outside.Foo",
                "builtins.int",
                "builtins.str",
                "builtins.bool",
                "builtins.float",
                "builtins.bytes",
                "builtins.complex",
                "builtins.list",
                "builtins.set",
                "builtins.dict",
                "builtins.tuple",
                "builtins.object",
            ),
        ),
        (
            ("tests.analysis.typeinfo.fixtures.types.outside.Bar", "builtins.complex"),
            (
                "tests.analysis.typeinfo.fixtures.types.outside.Foo",
                "builtins.str",
                "builtins.bytes",
                "builtins.list",
                "builtins.set",
                "builtins.dict",
                "builtins.tuple",
                "builtins.object",
            ),
        ),
        (("builtins.object",), ()),
    ],
)
def test_get_type_outside_of(outside_of, expected_types):
    type_system = _build_type_system_from_module("tests.analysis.typeinfo.fixtures.types.outside")
    outside_set = OrderedSet(type_system.find_class_descriptor(t) for t in outside_of)
    assert set(type_system.get_type_outside_of(outside_set)) == {
        type_system.find_class_descriptor(t) for t in expected_types
    }


@pytest.mark.parametrize(
    "tp, expected",
    [
        (tuple, TupleType((AnyType(),), unknown_size=True)),
        (int, Instance(ClassDescriptor(int))),
    ],
)
def test_make_instance(tp, expected):
    tps = TypeSystem()
    type_info = tps.to_class_descriptor(tp)
    assert tps.make_instance(type_info) == expected


@pytest.mark.parametrize(
    "tp, expected",
    [
        (Instance(ClassDescriptor(list)), Instance(ClassDescriptor(list), (AnyType(),))),
        (
            Instance(ClassDescriptor(list), (AnyType(), AnyType())),
            Instance(ClassDescriptor(list), (AnyType(),)),
        ),
        (Instance(ClassDescriptor(set)), Instance(ClassDescriptor(set), (AnyType(),))),
        (
            Instance(ClassDescriptor(set), (AnyType(), AnyType())),
            Instance(ClassDescriptor(set), (AnyType(),)),
        ),
        (Instance(ClassDescriptor(dict)), Instance(ClassDescriptor(dict), (AnyType(), AnyType()))),
        (
            Instance(ClassDescriptor(dict), (AnyType(), AnyType(), AnyType())),
            Instance(ClassDescriptor(dict), (AnyType(), AnyType())),
        ),
    ],
)
def test_fixup_generics(tp, expected):
    assert TypeSystem._fixup_known_generics(tp) == expected


def test_union_single_element():
    assert str(UnionType((NoneType(),))) == "None"


@pytest.mark.parametrize(
    "symbol, typ, result",
    [(sym, list, list[int]) for sym in _LIST_ELEMENT_ATTRIBUTES]
    + [(sym, set, set[int]) for sym in _SET_ELEMENT_ATTRIBUTES],
)
def test_guess_generic_types_list_set_from_elements(inferred_signature, symbol, typ, result):
    _config.settings.test_creation.negate_type = 0.0
    knowledge = UsageTraceNode("ROOT")
    knowledge.children[symbol].type_checks.add(int)
    with mock.patch("pyflow.util.randomness.choice") as choice_mock:
        choice_mock.side_effect = operator.itemgetter(0)
        assert inferred_signature._guess_generic_type_parameters_for_builtins(
            inferred_signature.type_system.convert_type_hint(typ), knowledge, 0
        ) == inferred_signature.type_system.convert_type_hint(result)


@pytest.mark.parametrize(
    "symbol, typ, result",
    [(sym, dict, dict[int, Any]) for sym in _DICT_KEY_ATTRIBUTES],
)
def test_guess_generic_types_dict_key_from_elements(inferred_signature, symbol, typ, result):
    _config.settings.test_creation.negate_type = 0.0
    knowledge = UsageTraceNode("ROOT")
    knowledge.children[symbol].type_checks.add(int)
    with mock.patch("pyflow.util.randomness.choice") as choice_mock:
        choice_mock.side_effect = operator.itemgetter(0)
        assert inferred_signature._guess_generic_type_parameters_for_builtins(
            inferred_signature.type_system.convert_type_hint(typ), knowledge, 0
        ) == inferred_signature.type_system.convert_type_hint(result)


@pytest.mark.parametrize(
    "symbol, typ, result",
    [(sym, dict, dict[int, Any]) for sym in _DICT_KEY_FROM_ARGUMENT_TYPES],
)
def test_guess_generic_types_dict_key_from_arguments(inferred_signature, symbol, typ, result):
    _config.settings.test_creation.negate_type = 0.0
    knowledge = UsageTraceNode("ROOT")
    knowledge.children[symbol].arg_types[0].add(int)
    with mock.patch("pyflow.util.randomness.choice") as choice_mock:
        choice_mock.side_effect = operator.itemgetter(0)
        assert inferred_signature._guess_generic_type_parameters_for_builtins(
            inferred_signature.type_system.convert_type_hint(typ), knowledge, 0
        ) == inferred_signature.type_system.convert_type_hint(result)


@pytest.mark.parametrize(
    "symbol, typ, result",
    [(sym, dict, dict[Any, int]) for sym in _DICT_VALUE_ATTRIBUTES],
)
def test_guess_generic_types_dict_value_from_elements(inferred_signature, symbol, typ, result):
    _config.settings.test_creation.negate_type = 0.0
    knowledge = UsageTraceNode("ROOT")
    knowledge.children[symbol].type_checks.add(int)
    with mock.patch("pyflow.util.randomness.choice") as choice_mock:
        choice_mock.side_effect = operator.itemgetter(0)
        assert inferred_signature._guess_generic_type_parameters_for_builtins(
            inferred_signature.type_system.convert_type_hint(typ), knowledge, 0
        ) == inferred_signature.type_system.convert_type_hint(result)


@pytest.mark.parametrize(
    "symbol, typ, result",
    [(sym, dict, dict[Any, int]) for sym in _DICT_VALUE_FROM_ARGUMENT_TYPES],
)
def test_guess_generic_types_dict_value_from_arguments(inferred_signature, symbol, typ, result):
    _config.settings.test_creation.negate_type = 0.0
    knowledge = UsageTraceNode("ROOT")
    knowledge.children[symbol].arg_types[1].add(int)
    with mock.patch("pyflow.util.randomness.choice") as choice_mock:
        choice_mock.side_effect = operator.itemgetter(0)
        assert inferred_signature._guess_generic_type_parameters_for_builtins(
            inferred_signature.type_system.convert_type_hint(typ), knowledge, 0
        ) == inferred_signature.type_system.convert_type_hint(result)


@pytest.mark.parametrize(
    "symbol, typ, result",
    [(sym, list, list[int]) for sym in _LIST_ELEMENT_FROM_ARGUMENT_TYPES]
    + [(sym, set, set[int]) for sym in _SET_ELEMENT_FROM_ARGUMENT_TYPES],
)
def test_guess_generic_types_list_set_from_arguments(inferred_signature, symbol, typ, result):
    _config.settings.test_creation.negate_type = 0.0
    knowledge = UsageTraceNode("ROOT")
    knowledge.children[symbol].arg_types[0].add(int)
    with mock.patch("pyflow.util.randomness.choice") as choice_mock:
        choice_mock.side_effect = operator.itemgetter(0)
        assert inferred_signature._guess_generic_type_parameters_for_builtins(
            inferred_signature.type_system.convert_type_hint(typ), knowledge, 0
        ) == inferred_signature.type_system.convert_type_hint(result)


@pytest.mark.parametrize("inp, result", [(int, int), (Any, Any)])
def test_guess_generic_types_falltrough(inferred_signature, inp, result):
    assert inferred_signature._guess_generic_type_parameters_for_builtins(
        inferred_signature.type_system.convert_type_hint(inp), None, None
    ) == inferred_signature.type_system.convert_type_hint(result)


def test_choose_type_or_negate_empty(inferred_signature):
    assert inferred_signature._choose_type_or_negate(OrderedSet()) is None


def test_choose_type_or_negate(inferred_signature):
    _config.settings.test_creation.negate_type = 0.0
    assert inferred_signature._choose_type_or_negate(
        OrderedSet((inferred_signature.type_system.to_class_descriptor(int),))
    ) == inferred_signature.type_system.convert_type_hint(int)


def test_choose_type_or_negate_negate(inferred_signature):
    _config.settings.test_creation.negate_type = 1.0
    assert inferred_signature._choose_type_or_negate(
        OrderedSet((inferred_signature.type_system.to_class_descriptor(int),))
    ) != inferred_signature.type_system.convert_type_hint(int)


def test_choose_type_or_negate_empty_2(inferred_signature):
    _config.settings.test_creation.negate_type = 1.0
    with mock.patch.object(inferred_signature.type_system, "get_type_outside_of") as outside_mock:
        outside_mock.return_value = OrderedSet()
        assert inferred_signature._choose_type_or_negate(
            OrderedSet((inferred_signature.type_system.to_class_descriptor(object),))
        ) == inferred_signature.type_system.convert_type_hint(object)


def test_update_guess(inferred_signature):
    inferred_signature._update_guess("x", None)
    assert "x" not in inferred_signature.current_guessed_parameters


def test_update_guess_single(inferred_signature):
    inferred_signature._update_guess("x", inferred_signature.type_system.convert_type_hint(int))
    assert inferred_signature.current_guessed_parameters["x"] == [
        inferred_signature.type_system.convert_type_hint(int)
    ]


def test_update_guess_multi(inferred_signature):
    inferred_signature._update_guess("x", inferred_signature.type_system.convert_type_hint(int))
    inferred_signature._update_guess("x", inferred_signature.type_system.convert_type_hint(int))
    assert inferred_signature.current_guessed_parameters["x"] == [
        inferred_signature.type_system.convert_type_hint(int)
    ]


def test_update_guess_multi_drop(inferred_signature):
    _config.settings.test_creation.type_tracing_kept_guesses = 5
    inferred_signature._update_guess("x", inferred_signature.type_system.convert_type_hint(int))
    inferred_signature._update_guess("x", inferred_signature.type_system.convert_type_hint(float))
    inferred_signature._update_guess("x", inferred_signature.type_system.convert_type_hint(str))
    inferred_signature._update_guess("x", inferred_signature.type_system.convert_type_hint(bytes))
    inferred_signature._update_guess("x", inferred_signature.type_system.convert_type_hint(bool))
    inferred_signature._update_guess("x", inferred_signature.type_system.convert_type_hint(complex))
    assert inferred_signature.current_guessed_parameters["x"] == [
        inferred_signature.type_system.convert_type_hint(tp)
        for tp in [float, str, bytes, bool, complex]
    ]


@pytest.mark.parametrize(
    "symbol,kind",
    [
        ("__getitem__", inspect.Parameter.VAR_KEYWORD),
        ("__iter__", inspect.Parameter.VAR_POSITIONAL),
    ],
)
def test__guess_parameter_type(inferred_signature, symbol, kind):
    knowledge = UsageTraceNode("ROOT")
    assert knowledge.children[symbol] is not None
    with mock.patch.object(inferred_signature, "_guess_parameter_type_from") as guess:
        inferred_signature._guess_parameter_type(knowledge, kind)
        guess.assert_called_with(knowledge.children[symbol])


@pytest.mark.parametrize("kind", [inspect.Parameter.VAR_KEYWORD, inspect.Parameter.VAR_POSITIONAL])
def test__guess_parameter_type_2(inferred_signature, kind):
    knowledge = UsageTraceNode("ROOT")
    assert inferred_signature._guess_parameter_type(knowledge, kind) is None


def test__guess_parameter_type_3(inferred_signature):
    knowledge = UsageTraceNode("ROOT")
    with mock.patch.object(inferred_signature, "_guess_parameter_type_from") as guess:
        inferred_signature._guess_parameter_type(knowledge, 42)
        guess.assert_called_with(knowledge)


def test_from_symbol_table(inferred_signature):
    knowledge = UsageTraceNode("ROOT")
    assert knowledge.children["foo"] is not None
    assert inferred_signature._from_attr_table(knowledge) is None


def test_from_symbol_table_2(inferred_signature):
    _config.settings.test_creation.negate_type = 0.0
    knowledge = UsageTraceNode("ROOT")
    assert knowledge.children["foo"] is not None
    inferred_signature.type_system._attribute_map["foo"].add(
        inferred_signature.type_system.to_class_descriptor(int)
    )
    assert inferred_signature._from_attr_table(
        knowledge
    ) == inferred_signature.type_system.convert_type_hint(int)


def test_from_symbol_table_3(inferred_signature):
    _config.settings.test_creation.negate_type = 0.0
    with mock.patch("pyflow.util.randomness.next_float") as float_mock:
        float_mock.return_value = 0.0
        knowledge = UsageTraceNode("ROOT")
        knowledge.children["__eq__"].arg_types[0].add(int)
        assert inferred_signature._from_attr_table(
            knowledge
        ) == inferred_signature.type_system.convert_type_hint(int)


def test_from_symbol_table_4(inferred_signature):
    _config.settings.test_creation.negate_type = 1.0
    with mock.patch("pyflow.util.randomness.next_float") as float_mock:
        float_mock.return_value = 0.0
        knowledge = UsageTraceNode("ROOT")
        knowledge.children["__eq__"].arg_types[0].add(int)
        assert inferred_signature._from_attr_table(
            knowledge
        ) != inferred_signature.type_system.convert_type_hint(int)


@pytest.mark.parametrize(
    "numeric,subtypes",
    [
        (complex, [complex, float, int, bool]),
        (float, [float, int, bool]),
        (int, [int, bool]),
        (bool, [bool]),
    ],
)
def test_numeric_tower(type_system, numeric, subtypes):
    assert type_system.numeric_tower[type_system.convert_type_hint(numeric)] == [
        type_system.convert_type_hint(typ) for typ in subtypes
    ]


@pytest.mark.parametrize(
    "left,right,result",
    [
        (int, int, "int"),
        (tuple[int, int], tuple[int, str], "tuple"),
        (dict[int, int], dict[bool, str], "dict"),
        (int | bool, bool | str | float, "bool"),
        (bool | float, bool | str | float, "bool | float"),
        (int, int | str | float, "int"),
        (int | str | float, int | str | float, "float | int | str"),
        (int | str, str, "str"),
        (list[bool], list | bool, "list"),
        (bool, list | bool, "bool"),
        (type(None), type(None), "None"),
    ],
)
def test_partial_type_match(type_system, left, right, result):
    match = _is_partial_type_match(
        type_system.convert_type_hint(left), type_system.convert_type_hint(right)
    )
    assert str(match) == result


@pytest.mark.parametrize(
    "left,right",
    [
        (int | float, bool | str),
        (int | str, bool),
        (dict[int, int], list),
        (int, bool),
        (Any, bool),
        (bool, Any),
        (type(None), str),
        (str, type(None)),
    ],
)
def test_no_partial_type_match(type_system, left, right):
    match = _is_partial_type_match(
        type_system.convert_type_hint(left), type_system.convert_type_hint(right)
    )
    assert match is None


def test_to_type_info_union_type(subtyping_cluster):
    type_system = subtyping_cluster.type_system
    type_system.to_class_descriptor(float | int)


def test__guess_parameter_type_with_type_knowledge_simple(inferred_signature):
    _config.settings.test_creation.negate_type = 0
    knowledge = UsageTraceNode("ROOT")
    kind = ""  # not inspect.Parameter.VAR_KEYWORD or inspect.Parameter.VAR_POSITIONAL
    knowledge.type_checks.add(float)
    expected = Instance(ClassDescriptor(float))
    actual = inferred_signature._guess_parameter_type(knowledge, kind)
    assert actual == expected


def pick_0_generator():
    while True:
        yield 0


def pick_1_generator():
    while True:
        yield 0
        yield 1
        yield 0


pick_1 = pick_1_generator()
pick_0 = pick_0_generator()


@pytest.mark.parametrize(
    "pick, expected_type",
    [
        (pick_0, Instance(ClassDescriptor(float))),
        (pick_1, Instance(ClassDescriptor(int))),
    ],
)
def test__guess_parameter_type_with_type_knowledge(inferred_signature, pick, expected_type):
    _config.settings.test_creation.negate_type = 0
    knowledge = UsageTraceNode("ROOT")
    kind = ""  # not inspect.Parameter.VAR_KEYWORD or inspect.Parameter.VAR_POSITIONAL
    knowledge.type_checks.add(float | int)

    with mock.patch("pyflow.util.randomness.choice") as choice_mock:
        choice_mock.side_effect = lambda x: x[next(pick)]  # noqa: FURB118
        actual = inferred_signature._guess_parameter_type(knowledge, kind)
        assert actual == expected_type


def test_string_subtype():
    string_subtype = StringSubtype(re.compile(r"^bar"))
    assert str(string_subtype) == "StringSubtype(re.compile('^bar'))"


@pytest.mark.xfail(reason="Not implemented yet")
def test_is_subtype_string_subtype(subtyping_cluster):
    type_system = subtyping_cluster.type_system
    left = StringSubtype(re.compile(r"^bar"))
    right = StringSubtype(re.compile(r"^bar"))
    assert type_system.is_subtype(left, right) is True
    assert type_system.is_maybe_subtype(left, right) is True


def test__from_str_values_empty():
    knowledge = UsageTraceNode("ROOT")
    assert InferredSignature._from_str_values(knowledge) is None


def _make_usage_trace_with_strings(strings_by_attr):
    root = UsageTraceNode("ROOT")
    for attr, strings in strings_by_attr.items():
        root.children[attr].children["__call__"].arg_values[0].update(strings)
    return root


def test__from_str_values():
    knowledge = _make_usage_trace_with_strings({"startswith": {"bar"}})
    assert InferredSignature._from_str_values(knowledge) == StringSubtype(re.compile(r"^(?:bar)"))


any_distance = _config.settings.generator_selection.generator_any_distance


@pytest.mark.parametrize(
    "left_hint,right_hint,subtype_distance",
    [
        # basic
        (int, int, 0),
        (int, str, None),
        # none
        (type(None), int, None),
        (int, type(None), None),
        (type(None), type(None), 0),
        # any
        (Any, int, any_distance),
        (int, Any, any_distance),
        # builtins
        (complex, int, 2),
        (float, int, 1),
        (int, bool, 1),
        (object, str, 1),
        (object, bytes, 1),
        (object, list, 1),
        (object, tuple, None),  # To match a tuple, both must be a tuple
        (tuple, Any, None),  # To match a tuple, both must be a tuple
        (object, set, 1),
        (object, dict, 1),
        (object, int, 1),
        (object, float, 1),
        (object, bool, 2),
        (object, complex, 1),
        # classes
        (object, Super, 1),
        (object, Sub, 2),
        (Super, Sub, 1),
        (Sub, Super, None),
        # union-right
        (int, bytes | str, None),
        (object, object | int, 0),
        (object, Super | int, 1),
        (object, Sub | Sub, 2),
        (object, Super | Sub, 1),
        (object, Super | Any, 1),
        (object, Super | type(None), 1),
        # union-left
        (bytes | int, str, None),
        (object | int, object, 0),
        (object | int, Super, 1),
        (object | int, Sub, 2),
        (object | Sub, Super, 1),
        (object | Any, Super, 1),
        (object | type(None), Super, 1),
        # union-both
        (int | bytes, str | type(None), None),
        (object | int, object | str, 0),
        (object | str, int | float, 1),
        (object | int, Sub | Sub, 2),
        (object | Super, Sub | Sub, 1),
        (object | Any, Super | Sub, 1),
        (object | type(None), Super | Sub, 1),
        # list
        (list, list, any_distance),
        (list[int], list, any_distance),
        (list[int], list[int], 0),
        (list[object], list[int], None),
        (list[int], list[str], None),
        (list[int], dict[int, str], None),
        # set
        (set, set, any_distance),
        (set[int], set, any_distance),
        (set[int], set[int], 0),
        (set[object], set[int], None),
        (set[int], set[str], None),
        # dict
        (dict, dict, 2 * any_distance),
        (dict[int, int], dict[int], any_distance),
        (dict[int], dict[int, int], any_distance),
        (dict[int, int], dict, 2 * any_distance),
        (dict[int, int], dict[int, int], 0),
        (dict[object, int], dict[int, int], None),
        (dict[object, object], dict[int, int], None),
        (dict[int, int], dict[str, int], None),
        # tuple
        (tuple, tuple, any_distance),
        (tuple[int], tuple, None),
        (tuple[int], tuple[int], 0),
        (tuple[object], tuple[int], 1),
        (tuple[int], tuple[str], None),
        (tuple[object, ...], tuple[int, int], 2),
        # callable
        (Callable[[int], object], Callable[[object], int], 2),
        (Callable[[int], int], Callable[[int], int], 0),
    ],
)
def test_subtype_distance(subtyping_cluster, left_hint, right_hint, subtype_distance):
    type_system = subtyping_cluster.type_system
    left = type_system.convert_type_hint(left_hint)
    right = type_system.convert_type_hint(right_hint)
    assert type_system.subtype_distance(left, right) == subtype_distance
