"""Key-specific callable contexts and dictionary value layouts."""

import pytest

from pyflow.analysis.typeinfo.inference.engine import StaticTypeInferenceEngine


def infer(source):
    return StaticTypeInferenceEngine().infer_source("sample", source)


def test_dictionary_keys_retain_callback_identity_and_argument_evidence():
    result = infer("""
def identity(value): return value
def stringify(value): return str(value)
callbacks = {"first": identity, 1: stringify}
a = callbacks["first"](42)
b = callbacks[1](42)
""")
    assert str(result.type_of("a")) == "int"
    assert str(result.type_of("b")) == "str"
    assert str(result.functions["sample.identity"].parameters["value"].public_type()) == "int"


def test_subscript_parameter_specializes_literal_keys_including_default_calls():
    result = infer("""
def text(): return "a"
def integer(): return 1
callbacks = {"a": text, "b": integer}
def invoke(key="a"):
    return callbacks[key]()
a = invoke()
b = invoke("b")
""")
    assert str(result.type_of("a")) == "str"
    assert str(result.type_of("b")) == "int"
    assert str(result.functions["sample.invoke"].return_type) == "int | str"
    assert len(result.functions["sample.invoke"].specializations) == 2


def test_non_selector_literals_do_not_split_type_based_call_contexts():
    result = infer("""
def identity(value): return value
a = identity("a")
b = identity("b")
""")
    assert len(result.functions["sample.identity"].specializations) == 1


def test_integer_and_string_keys_stay_distinct():
    result = infer("""
values = {1: "a", "1": 42}
a = values[1]
b = values["1"]
""")
    assert str(result.type_of("a")) == "str"
    assert str(result.type_of("b")) == "int"


def test_python_equal_numeric_keys_overwrite_the_same_entry():
    result = infer("""
values = {1: "a", True: 42}
a = values[1]
b = values[True]
""")
    assert str(result.type_of("a")) == "int"
    assert str(result.type_of("b")) == "int"


@pytest.mark.parametrize(
    "mutation", ["alias['a'] = text", "alias.update({'a': text})", "alias.update(a=text)"]
)
def test_dictionary_mutation_updates_aliases_and_discards_stale_subscript_cache(mutation):
    result = infer(f"""
def integer(): return 1
def text(): return "a"
values = {{"a": integer}}
values['a'] = integer
alias = values
{mutation}
answer = values['a']()
""")
    assert str(result.type_of("answer")) == "str"


def test_nested_mutable_dictionary_alias_updates_outer_values():
    result = infer("""
inner = {"value": 1}
outer = {"inner": inner}
inner["value"] = "a"
answer = outer["inner"]["value"]
""")
    assert str(result.type_of("answer")) == "str"


def test_nested_dictionary_write_updates_alias_to_inner_dictionary():
    result = infer("""
outer = {"inner": {"value": 1}}
alias = outer["inner"]
outer["inner"]["value"] = "a"
answer = alias["value"]
""")
    assert str(result.type_of("answer")) == "str"


def test_dictionary_copy_has_separate_root_but_shares_nested_values():
    result = infer("""
original = {"inner": {"value": 1}, "other": 1}
copy = original.copy()
copy["other"] = "a"
a = original["other"]
copy["inner"]["value"] = "a"
b = original["inner"]["value"]
""")
    assert str(result.type_of("a")) == "int"
    assert str(result.type_of("b")) == "str"


def test_get_pop_setdefault_and_delete_do_not_keep_stale_keys():
    result = infer("""
values = {"a": 1}
a = values.get("a")
b = values.get("missing", "a")
c = values.setdefault("new", "a")
d = values.pop("new")
e = values.get("new")
del values["a"]
f = values.get("a")
""")
    assert [str(result.type_of(name)) for name in "abcdef"] == [
        "int",
        "str",
        "str",
        "str",
        "None",
        "None",
    ]


def test_unknown_key_unions_all_possible_callbacks_instead_of_guessing():
    result = infer("""
def integer(): return 1
def text(): return "a"
callbacks = {"a": integer, "b": text}
def invoke(key): return callbacks[key]()
""")
    assert str(result.functions["sample.invoke"].return_type) == "int | str"


def test_unknown_update_discards_precise_mapping_layout():
    result = infer("""
def apply(other):
    values = {"a": 1}
    values.update(other)
    return values["a"]
""")
    summary = result.functions["sample.apply"]
    assert summary.return_value.unknown or str(summary.return_type) == "Any"


def test_unknown_subscript_assignment_is_not_a_strong_key_update():
    result = infer("""
def apply(key):
    values = {"a": 1}
    values[key] = "a"
    return values["a"]
""")
    assert str(result.functions["sample.apply"].return_type) == "int | str"


def test_same_keys_join_values_and_different_keys_drop_closed_layout():
    result = infer("""
def same(flag):
    values = {"a": 1} if flag else {"a": "a"}
    return values["a"]
def different(flag):
    values = {"a": 1} if flag else {"b": "a"}
    return values["a"]
""")
    assert str(result.functions["sample.same"].return_type) == "int | str"
    assert result.functions["sample.different"].return_value.unknown


@pytest.mark.parametrize("method", ["get", "pop", "setdefault"])
def test_mapping_method_key_parameters_use_literal_sensitive_contexts(method):
    result = infer(f"""
def pick(key: str):
    values = {{"a": 1, "b": "a"}}
    return values.{method}(key)
a = pick("a")
b = pick("b")
""")
    assert str(result.type_of("a")) == "int"
    assert str(result.type_of("b")) == "str"


def test_annotated_mapping_and_selector_keep_compatible_callsite_layout():
    result = infer("""
from typing import Callable
def integer(): return 1
def text(): return "a"
def pick(values: dict[str, Callable[[], int | str]], key: str):
    return values[key]()
values = {"a": integer, "b": text}
a = pick(values, "a")
b = pick(values, "b")
""")
    assert str(result.type_of("a")) == "int"
    assert str(result.type_of("b")) == "str"


def test_mapping_read_preserves_unknown_container_alternatives():
    result = infer("""
values = {"a": 1} if unknown_flag else missing
answer = values["a"]
""")
    assert result.value_of("answer").unknown


def test_unknown_keyword_update_does_not_keep_definite_existing_values():
    result = infer("""
def apply(other):
    values = {"a": 1}
    values.update(**other)
    return values["a"]
""")
    summary = result.functions["sample.apply"]
    assert summary.return_value.unknown or str(summary.return_type) == "Any"


def test_callback_overloads_inside_dictionary_keep_argument_specific_returns():
    result = infer("""
from typing import overload
@overload
def convert(value: int) -> str: ...
@overload
def convert(value: str) -> int: ...
def convert(value): return str(value) if isinstance(value, int) else 1
callbacks = {"convert": convert}
a = callbacks["convert"](1)
b = callbacks["convert"]("a")
""")
    assert str(result.type_of("a")) == "str"
    assert str(result.type_of("b")) == "int"


def test_compound_key_write_updates_public_key_type_and_retained_value():
    result = infer("""
values = {"a": 1}
values[(1, 2)] = "a"
answer = values[(1, 2)]
""")
    assert str(result.type_of("answer")) == "str"
    assert "tuple[int, int]" in str(result.type_of("values").args[0])


def test_unknown_value_write_does_not_keep_old_definite_element_type():
    result = infer("""
def apply(value):
    values = {"a": 1}
    values["a"] = value
    return values["a"]
""")
    summary = result.functions["sample.apply"]
    assert summary.return_value.unknown or str(summary.return_type) == "Any"


def test_precise_dictionary_layout_keeps_invalid_key_type_diagnostics():
    result = infer('''
values = {1: "a"}
answer = values["wrong"]
''')
    assert any(item.code == "index" for item in result.diagnostics)
