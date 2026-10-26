"""Typing aliases and structural object assignability regressions."""

import collections.abc as cabc
import pytest
from pyflow.analysis.typeinfo.core.typesystem import (
    ANY,
    NONE_TYPE,
    CallableType,
    Instance,
    TupleType,
    TypeSystem,
)
from pyflow.analysis.typeinfo.resolution.annotations import BuiltinTypeLookup, resolve_annotation


@pytest.mark.parametrize("alias", ["t", "typing_alias", "cabc"])
def test_explicit_typing_aliases_resolve_special_forms_and_forward_references(alias):
    lookup = BuiltinTypeLookup()
    module = "collections.abc" if alias == "cabc" else "typing"
    aliases = {alias: module}
    result = resolve_annotation(f"{alias}.Callable[[int], str]", lookup, aliases=aliases)
    assert isinstance(result, CallableType)
    assert isinstance(result.return_type, Instance) and result.return_type.type.raw_type is str
    assert isinstance(
        resolve_annotation(f'"{alias}.Callable[[int], str]"', lookup, aliases=aliases), CallableType
    )
    assert isinstance(
        resolve_annotation(f"{alias}.Callable", lookup, aliases=aliases), CallableType
    )


def test_aliases_are_not_guessed_from_identifier_spelling():
    assert resolve_annotation("t.Callable[[int], str]", BuiltinTypeLookup()) is None
    assert (
        resolve_annotation("t.Callable[[int], str]", BuiltinTypeLookup(), aliases={"t": "custom"})
        is None
    )


@pytest.mark.parametrize("kind", ["none", "tuple", "callable"])
def test_structural_values_are_objects_and_have_consistent_distance(kind):
    system = TypeSystem()
    integer = Instance(system.to_class_descriptor(int))
    obj = Instance(system.to_class_descriptor(object))
    value = {
        "none": NONE_TYPE,
        "tuple": TupleType((integer,)),
        "callable": CallableType((integer,), integer),
    }[kind]
    assert system.is_subtype(value, obj)
    assert system.subtype_distance(obj, value) == 1
    assert not system.is_subtype(obj, value)


def test_nominal_callable_accepts_structural_callable_without_relaxing_signature_checks():
    system = TypeSystem()
    integer = Instance(system.to_class_descriptor(int))
    string = Instance(system.to_class_descriptor(str))
    value = CallableType((integer,), integer)
    nominal = Instance(system.to_class_descriptor(cabc.Callable))
    assert system.is_subtype(value, nominal)
    assert system.subtype_distance(nominal, value) == 1
    assert not system.is_subtype(value, CallableType((string,), string))


def test_dictionary_value_object_remains_invariant_for_aliases():
    system = TypeSystem()
    integer = Instance(system.to_class_descriptor(int))
    obj = Instance(system.to_class_descriptor(object))
    dictionary = system.to_class_descriptor(dict)
    string = Instance(system.to_class_descriptor(str))
    assert not system.is_subtype(
        Instance(dictionary, (string, integer)), Instance(dictionary, (string, obj))
    )


def test_qualified_non_special_typing_generics_keep_their_base_model():
    result = resolve_annotation("t.IO[str]", BuiltinTypeLookup(), aliases={"t": "typing"})
    assert isinstance(result, Instance)
    assert result.type.raw_type.__name__ == "IO"
    assert isinstance(result.args[0], Instance) and result.args[0].type.raw_type is str


def test_nested_forward_references_retain_typing_alias_context():
    from pyflow.analysis.typeinfo.core.typesystem import UnionType

    result = resolve_annotation(
        'list["t.Optional[int]"]', BuiltinTypeLookup(), aliases={"t": "typing"}
    )
    assert isinstance(result, Instance) and isinstance(result.args[0], UnionType)


def test_builtin_type_lookup_bare_typing_collections_have_arity_and_tuple_type():
    lookup = BuiltinTypeLookup()
    dict_type = lookup("typing.Dict")
    assert isinstance(dict_type, Instance)
    assert dict_type.type.raw_type is dict
    assert len(dict_type.args) == 2
    assert all(arg == ANY for arg in dict_type.args)

    list_type = lookup("typing.List")
    assert isinstance(list_type, Instance)
    assert list_type.type.raw_type is list
    assert len(list_type.args) == 1
    assert list_type.args[0] == ANY

    tuple_type = lookup("typing.Tuple")
    assert isinstance(tuple_type, TupleType)
    assert tuple_type.unknown_size is True


def test_bare_typing_dict_and_optional_dict_return_annotations_accept_specialized_dict():
    from pyflow.analysis.typeinfo import StaticTypeInferenceEngine

    src = """
from typing import Dict, Optional

def get_stats() -> Dict:
    return {"a": 1, "b": 2}

def get_maybe_stats(flag: bool) -> Optional[Dict]:
    if flag:
        return {"a": 1}
    return None
"""
    engine = StaticTypeInferenceEngine()
    result = engine.infer_source("test_bare_dict", src)
    errors = [d for d in result.diagnostics if d.severity == "error"]
    assert not errors


def test_fixed_point_iteration_clears_intermediate_call_diagnostics():
    from pyflow.analysis.typeinfo import StaticTypeInferenceEngine

    src = """
class Config:
    pass

def serialize(obj):
    if obj is None:
        return None
    if isinstance(obj, (str, int)):
        return obj
    return {"data": 1}

def test() -> dict:
    c = Config()
    return serialize(c)
"""
    engine = StaticTypeInferenceEngine()
    result = engine.infer_source("test_fp", src)
    assert not result.diagnostics
