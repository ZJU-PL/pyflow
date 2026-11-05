"""Pattern reachability must use closed evidence and preserve fallthrough."""

import pytest

from pyflow.analysis.typeinfo.inference.engine import InferenceOptions, StaticTypeInferenceEngine


def infer(source):
    return StaticTypeInferenceEngine().infer_source("sample", source)


def test_literal_call_contexts_select_only_reachable_case_returns():
    result = infer("""
def choose(value):
    match value:
        case "a": return 1
        case "b": return 1.5
        case _: return "other"
a = choose("a")
b = choose("b")
c = choose("c")
""")
    assert [str(result.type_of(name)) for name in "abc"] == ["int", "float", "str"]


def test_sequence_literal_cases_and_same_shaped_call_arguments():
    result = infer("""
def choose(value):
    match value:
        case (1, 2): return 1
        case (3, 4): return "other"
        case _: return 1.5
a = choose((1, 2))
b = choose((3, 4))
c = choose((1, 4))
""")
    assert [str(result.type_of(name)) for name in "abc"] == ["int", "str", "float"]


@pytest.mark.parametrize("expression", ['"ab"', 'b"ab"', 'bytearray(b"ab")', "{1, 2}"])
def test_non_sequence_pattern_subjects_do_not_match_sequence_patterns(expression):
    result = infer(f"""
value = {expression}
match value:
    case [first, second]: answer = 1
    case _: answer = "other"
""")
    assert str(result.type_of("answer")) == "str"


def test_sequence_length_checks_and_starred_suffix_bindings():
    result = infer("""
match (1, "middle", 2.5, False):
    case [first, *middle, last]:
        a = first
        b = middle[0]
        c = middle[1]
        d = last
match [1]:
    case [first, second]: answer = 1
    case _: answer = "other"
""")
    assert [str(result.type_of(name)) for name in "abcd"] == ["int", "str", "float", "bool"]
    assert str(result.type_of("answer")) == "str"


def test_sequence_as_capture_keeps_container_type_instead_of_last_element():
    result = infer("""
match [1, "a"]:
    case [1, last] as whole:
        container = whole
        item = last
""")
    assert str(result.type_of("container")) == "list[int | str]"
    assert str(result.type_of("item")) == "str"


def test_mapping_pattern_uses_keys_and_excludes_consumed_keys_from_rest():
    result = infer("""
match {"a": 1, "b": "text"}:
    case {"missing": item}: answer = False
    case {"a": number, **rest}:
        answer = number
        text = rest["b"]
""")
    assert str(result.type_of("answer")) == "int"
    assert str(result.type_of("text")) == "str"
    assert set(dict(result.value_of("rest").mapping_items)) == {"b"}


def test_or_pattern_filters_impossible_alternatives_and_consumes_values():
    result = infer("""
def choose(value):
    match value:
        case (1 | 2) as captured: return captured
        case _: return "other"
a = choose(1)
b = choose(2)
c = choose(3)
""")
    assert [str(result.type_of(name)) for name in "abc"] == ["int", "int", "str"]


def test_numeric_value_patterns_preserve_actual_bool_int_and_float_types():
    result = infer("""
def choose(value):
    match value:
        case 1 as captured: return captured
        case _: return None
a = choose(True)
b = choose(1)
c = choose(1.0)
d = choose(2)
""")
    assert [str(result.type_of(name)) for name in "abcd"] == ["bool", "int", "float", "None"]


def test_singleton_patterns_use_identity_instead_of_numeric_equality():
    result = infer("""
def choose(value):
    match value:
        case True: return "singleton"
        case 1: return 1.5
        case _: return None
a = choose(True)
b = choose(1)
c = choose(1.0)
""")
    assert [str(result.type_of(name)) for name in "abc"] == ["str", "float", "float"]


def test_unknown_guard_keeps_matching_type_available_to_later_cases():
    result = infer("""
def choose(value: int | str, flag: bool):
    match value:
        case int() if flag: return 1
        case int(): return "fallback"
        case _: return None
""")
    assert str(result.functions["sample.choose"].return_type) == "None | int | str"


def test_guard_inputs_distinguish_same_type_call_contexts():
    result = infer("""
def choose(value, flag):
    match value:
        case int() if flag: return 1
        case _: return "fallback"
a = choose(1, True)
b = choose(1, False)
""")
    assert [str(result.type_of(name)) for name in "ab"] == ["int", "str"]


def test_guard_comparison_uses_literal_capture_values():
    result = infer("""
def choose(value):
    match value:
        case [first, *rest] if first > 0: return first
        case _: return "fallback"
a = choose([1])
b = choose([-1])
""")
    assert [str(result.type_of(name)) for name in "ab"] == ["int", "str"]


@pytest.mark.parametrize(
    "guard", ["False", "not True", "1 > 2", "False and missing", "True is None"]
)
def test_definitely_false_guards_do_not_execute_case_bodies(guard):
    result = infer(f"""
match 1:
    case int() if {guard}: answer = "unreachable"
    case _: answer = 1
""")
    assert str(result.type_of("answer")) == "int"


def test_non_exhaustive_match_has_normal_fallthrough_and_implicit_none():
    result = infer("""
def choose(value: int):
    match value:
        case 1: return "one"
a = choose(1)
b = choose(2)
""")
    assert str(result.functions["sample.choose"].return_type) == "None | str"
    assert str(result.type_of("a")) == "str"
    assert str(result.type_of("b")) == "None"


def test_exhaustive_literal_annotation_excludes_unreachable_default():
    result = infer("""
from typing import Literal
def choose(value: Literal[1, 2]):
    match value:
        case 1: return 1
        case 2: return 1.5
        case _: return "unreachable"
""")
    assert str(result.functions["sample.choose"].return_type) == "float | int"


def test_join_with_nonliteral_evidence_does_not_make_literal_hint_exhaustive():
    result = infer("""
def choose(other: int, flag: bool):
    value = 1 if flag else other
    match value:
        case 1: return "one"
        case _: return 1.5
""")
    assert str(result.functions["sample.choose"].return_type) == "float | str"


def test_unknown_subject_keeps_both_case_and_default_reachable():
    result = infer("""
value = 1 if unknown_flag else missing
match value:
    case 1: answer = "one"
    case _: answer = 1.5
""")
    assert str(result.type_of("answer")) == "float | str"


def test_guarded_class_pattern_does_not_exclude_type_on_false_guard():
    result = infer("""
def choose(value: int | str):
    match value:
        case int() if False: return None
        case _: return value
""")
    assert str(result.functions["sample.choose"].return_type) == "int | str"


def test_class_field_pattern_does_not_consume_whole_class_type():
    result = infer("""
class Record:
    __match_args__ = ("value",)
    value: int

def choose(record: Record):
    match record:
        case Record(1): return "one"
        case _: return 1.5
""")
    assert str(result.functions["sample.choose"].return_type) == "float | str"


def test_match_class_checks_runtime_inheritance_not_numeric_assignment_tower():
    result = infer("""
match 1:
    case float(): answer = "wrong"
    case int(): answer = 1
""")
    assert str(result.type_of("answer")) == "int"


def test_terminated_case_environment_does_not_pollute_code_after_match():
    result = infer("""
def choose(value: int | str):
    match value:
        case int():
            label = 1
            return "finished"
        case _:
            label = "active"
    return label
""")
    assert str(result.functions["sample.choose"].return_type) == "str"


@pytest.mark.parametrize("action", ["break", "continue"])
def test_match_propagates_loop_control_without_collecting_unreachable_return(action):
    result = infer(f"""
def choose():
    for _ in [1]:
        match None:
            case None: {action}
        return "unreachable"
    return 1
""")
    assert str(result.functions["sample.choose"].return_type) == "int"


def test_failed_guard_preserves_captures_for_the_following_case():
    result = infer("""
def choose():
    match (1,):
        case [item] if False: return None
        case _: return item
""")
    assert str(result.functions["sample.choose"].return_type) == "int"


def test_bool_singleton_remains_possible_for_open_int_annotation():
    result = infer("""
def choose(value: int):
    match value:
        case True: return "bool"
        case _: return 1
""")
    assert str(result.functions["sample.choose"].return_type) == "int | str"


def test_none_remains_possible_for_hashable_annotation():
    result = infer("""
from collections.abc import Hashable
def choose(value: Hashable):
    match value:
        case None: return "none"
        case _: return 1
""")
    assert str(result.functions["sample.choose"].return_type) == "int | str"


def test_class_pattern_uses_known_runtime_values_even_with_numeric_annotation():
    result = infer("""
def choose(value: float):
    match value:
        case int(): return "int"
        case _: return 1.5
a = choose(1)
b = choose(1.0)
""")
    assert str(result.type_of("a")) == "str"
    assert str(result.type_of("b")) == "float"


def test_match_specialization_budget_is_bounded_and_converges():
    source = """
def choose(value):
    match value:
        case "target": return 1
        case _: return "other"
"""
    source += "\n".join(f"value_{i} = choose('item_{i}')" for i in range(24))
    result = StaticTypeInferenceEngine(
        options=InferenceOptions(max_specializations_per_function=4)
    ).infer_source("sample", source)
    summary = result.functions["sample.choose"]
    assert result.converged
    assert len(summary.specializations) <= 5
    assert any(item.widened for item in summary.specializations)
    assert "str" in str(result.type_of("value_23"))


def test_guard_rebinding_does_not_replace_saved_match_subject_or_current_name():
    result = infer("""
def choose(value):
    match value:
        case _ if (value := ""): return None
        case 1 as original: return original, value
        case _: return False
answer = choose(1)
""")
    assert str(result.type_of("answer")) == "tuple[int, str]"


def test_positive_bool_singleton_refines_open_int_capture_to_bool():
    result = infer("""
def choose(value: int):
    match value:
        case True as captured: return captured
        case _: return "other"
""")
    assert str(result.functions["sample.choose"].return_type) == "bool | str"


def test_open_numeric_annotation_retains_narrower_runtime_class_case():
    result = infer("""
def choose(value: float):
    match value:
        case int(): return "int"
        case _: return 1.5
""")
    assert str(result.functions["sample.choose"].return_type) == "float | str"


@pytest.mark.parametrize("singleton", ["True", "False", "None"])
def test_tuple_subject_cannot_match_boolean_or_none_singleton(singleton):
    result = infer(f"""
match (1, 2):
    case {singleton}: answer = 1
    case _: answer = "other"
""")
    assert str(result.type_of("answer")) == "str"
