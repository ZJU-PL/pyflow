"""Regressions minimized from TypeEvalPy's builtin/callback evidence."""

import itertools

import pytest

from pyflow.analysis.typeinfo.core.typesystem import Instance
from pyflow.analysis.typeinfo.inference.engine import StaticTypeInferenceEngine


def infer(source):
    return StaticTypeInferenceEngine().infer_source("sample", source)


def test_named_map_callback_receives_every_iterable_argument():
    result = infer("""
def combine(number, text):
    return text * number

callback = combine
mapped = map(callback, [1, 2], ["a", "b"])
item = next(mapped)
""")
    assert str(result.type_of("item")) == "str"
    assert str(result.functions["sample.combine"].parameters["number"].public_type()) == "int"
    assert str(result.functions["sample.combine"].parameters["text"].public_type()) == "str"
    mapped = result.type_of("mapped")
    assert isinstance(mapped, Instance)
    assert mapped.type.raw_type is map
    assert str(mapped.args[0]) == "str"
    assert not result.diagnostics


@pytest.mark.parametrize("key", ["key=key", "key", "key=None", ""])
def test_groupby_keeps_key_group_and_element_types(key):
    result = infer(f"""
import itertools

def key(value):
    return str(value)

groups = itertools.groupby([1, 2], {key})
for label, group in groups:
    item = next(group)
""")
    assert str(result.type_of("label")) == ("str" if key in {"key=key", "key"} else "int")
    assert str(result.type_of("item")) == "int"
    assert result.type_of("groups").type.raw_type is itertools.groupby
    assert result.type_of("group").type.raw_type is itertools._grouper


@pytest.mark.parametrize(
    "expression, raw",
    [
        ("itertools.chain([1], [2])", itertools.chain),
        ("itertools.chain.from_iterable([[1], [2]])", itertools.chain),
        ("itertools.cycle([1])", itertools.cycle),
        ("itertools.repeat(1)", itertools.repeat),
        ("itertools.islice([1], 1)", itertools.islice),
        ("itertools.compress([1], [True])", itertools.compress),
        ("itertools.count()", itertools.count),
        ("itertools.count(start=1, step=2)", itertools.count),
    ],
)
def test_nominal_iterators_still_project_elements_and_satisfy_iterator(expression, raw):
    result = infer(f"""
import itertools
from typing import Iterator

def consume(values: Iterator[int]):
    return next(values)

values = {expression}
item = next(values)
consumed = consume(values)
""")
    assert result.type_of("values").type.raw_type is raw
    assert str(result.type_of("item")) == "int"
    assert str(result.type_of("consumed")) == "int"
    assert not [d for d in result.diagnostics if d.code == "annotation-mismatch"]


def test_count_keyword_float_step_is_not_reported_as_int():
    result = infer("""
import itertools
values = itertools.count(start=1.0, step=0.5)
item = next(values)
""")
    assert str(result.type_of("item")) == "float"


def test_unknown_map_callback_does_not_fabricate_an_element_type():
    result = infer("""
def apply(callback):
    return next(map(callback, [1]))
""")
    assert str(result.functions["sample.apply"].return_type) == "Any"


@pytest.mark.parametrize(
    "access, declarations",
    [
        ("instance.value()", "def value(self): return {value}"),
        ("instance.value", "value = {value}"),
        ("instance.value", "@property\n    def value(self): return {value}"),
    ],
)
def test_diamond_lookup_uses_c3_for_methods_fields_and_properties(access, declarations):
    result = infer(f"""
class Root:
    {declarations.format(value="'root'")}
class Left(Root):
    pass
class Right(Root):
    {declarations.format(value="42")}
class Diamond(Left, Right):
    pass
instance = Diamond()
answer = {access}
""")
    assert str(result.type_of("answer")) == "int"
