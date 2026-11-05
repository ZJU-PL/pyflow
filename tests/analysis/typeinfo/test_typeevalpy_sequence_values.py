"""Positional container evidence must retain runtime alternatives and targets."""

from pyflow.analysis.typeinfo.inference.engine import StaticTypeInferenceEngine


def infer(source):
    return StaticTypeInferenceEngine().infer_source("sample", source)


def test_list_callable_positions_do_not_drop_numeric_return_alternatives():
    result = infer("""
def integer(): return 1
def decimal(): return 1.5
def text(): return "a"
callbacks = [integer, decimal, text]
a = callbacks[0]()
b = callbacks[1]()
c = callbacks[-1]()
""")
    assert [str(result.type_of(name)) for name in "abc"] == ["int", "float", "str"]


def test_starred_unpack_keeps_callback_identity_in_middle_list():
    result = infer("""
def text(): return "a"
def integer(): return 1
def decimal(): return 1.5
def items(): return [1]
first, *middle, last = text, integer, decimal, items
a = first()
b = middle[0]()
c = middle[1]()
d = last()
""")
    assert [str(result.type_of(name)) for name in "abcd"] == ["str", "int", "float", "list[int]"]


def test_slices_nested_lists_and_unpacking_keep_positions():
    result = infer("""
values = [[1, "a"], [2.5, False]]
left, right = values
number, text = left
copy = right[::-1]
flag = copy[0]
real = copy[1]
""")
    assert [str(result.type_of(name)) for name in ("number", "text", "flag", "real")] == [
        "int",
        "str",
        "bool",
        "float",
    ]


def test_call_specializations_keep_sequence_callable_targets():
    result = infer("""
def first(callbacks): return callbacks[0]()
def integer(): return 1
def text(): return "a"
a = first([integer])
b = first([text])
""")
    assert str(result.type_of("a")) == "int"
    assert str(result.type_of("b")) == "str"


def test_equal_length_join_combines_each_position():
    result = infer("""
def choose(flag):
    if flag:
        values = [1, "a"]
    else:
        values = [2.5, "b"]
    return values[0]
""")
    assert str(result.functions["sample.choose"].return_type) == "float | int"


def test_different_length_join_drops_positional_certainty():
    result = infer("""
def choose(flag):
    if flag:
        values = [1, "a"]
    else:
        values = [2.5]
    return values[0]
""")
    assert str(result.functions["sample.choose"].return_type) == "float | int | str"


def test_mutation_through_alias_drops_stale_layout():
    result = infer("""
values = [1, "a"]
alias = values
alias[0] = False
changed = values[0]
alias.reverse()
reversed_item = values[0]
""")
    assert "bool" in str(result.type_of("changed"))
    assert "str" in str(result.type_of("reversed_item"))


def test_mutating_list_methods_drop_positional_certainty():
    for operation in (
        "pop(0)",
        "reverse()",
        "sort(key=str)",
        "remove(1)",
        "clear()",
        "append(False)",
    ):
        result = infer(f"""
values = [1, "a"]
alias = values
alias.{operation}
item = values[0]
""")
        # A mutation may move or remove the first element. It must never
        # retain the original exact int-only layout.
        assert str(result.type_of("item")) != "int", operation


def test_starred_call_through_list_alias_keeps_callback_values():
    result = infer("""
def invoke(callback): return callback()
def text(): return "a"
args = [text]
answer = invoke(*args)
""")
    assert str(result.type_of("answer")) == "str"


def test_nested_mutation_through_alias_updates_outer_layout():
    result = infer("""
outer = [[1]]
inner = outer[0]
inner.append("a")
item = outer[0][0]
""")
    assert "str" in str(result.type_of("item"))


def test_slice_of_list_tuple_join_preserves_both_runtime_container_types():
    result = infer("""
def choose(flag):
    values = [1, "a"] if flag else (1, "a")
    return values[:1]
""")
    actual = str(result.functions["sample.choose"].return_type)
    assert "list[int]" in actual
    assert "tuple[int]" in actual


def test_widened_callable_container_keeps_int_and_float_returns():
    result = infer("""
def integer(): return 1
def decimal(): return 1.5
callbacks = [integer, decimal]
callbacks.reverse()
answer = callbacks[0]()
""")
    assert str(result.type_of("answer")) == "float | int"


def test_list_literal_keeps_identity_of_preexisting_nested_alias():
    result = infer("""
inner = [1]
outer = [inner]
inner.append("a")
item = outer[0][0]
""")
    assert "str" in str(result.type_of("item"))


def test_layout_budget_widens_metadata_without_losing_known_element_type():
    source = "values = [" + ", ".join("1" for _ in range(65)) + "]\nitem = values[0]\n"
    result = infer(source)
    assert result.value_of("values").sequence_items is None
    assert str(result.type_of("item")) == "int"


def test_callback_signature_refinement_does_not_retain_stale_any():
    result = infer("""
def text(): return "a"
def invoke(mapping): return mapping["callback"]()
callbacks = {"callback": text}
answer = invoke(callbacks)
""")
    assert str(result.type_of("answer")) == "str"
    assert str(result.functions["sample.invoke"].return_type) == "str"


def test_bound_callback_field_signature_refines_after_method_evidence():
    result = infer("""
class Parent:
    def invoke(self): return self.callback()
class Child(Parent):
    def __init__(self): self.callback = self.text
    def text(self): return "a"
answer = Child().invoke()
""")
    assert str(result.type_of("answer")) == "str"
