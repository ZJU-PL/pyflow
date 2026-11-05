"""The benchmark adapter must not manufacture facts from nearby expressions."""

import ast

from tools.typeinfo_typeevalpy import Adapter, load_comparator, render_types
from pyflow.analysis.typeinfo.inference.engine import StaticTypeInferenceEngine


def infer(source):
    return StaticTypeInferenceEngine().infer_source("sample", source)


def test_exact_span_mapping_for_binding_and_synthetic_nested_element():
    source = 'items = [[1, "a"]]\nanswer = items[0][1]\n'
    result = infer(source)
    adapter = Adapter(source)
    for name, expected in (("items", ["list"]), ("items[0]", ["list"]), ("items[0][1]", ["str"])):
        fact = dict(file="main.py", line_number=1, col_offset=1, variable=name)
        prediction, _ = adapter.predict(fact, result)
        assert prediction["type"] == expected
    fact = dict(file="main.py", line_number=2, col_offset=1, variable="answer")
    assert adapter.predict(fact, result)[0]["type"] == ["str"]


def test_wrong_column_does_not_borrow_covering_expression():
    source = "answer = str(1)\n"
    adapter = Adapter(source)
    fact = dict(file="main.py", line_number=1, col_offset=11, variable="answer")
    prediction, evidence = adapter.predict(fact, infer(source))
    assert prediction is None
    assert evidence["category"] == "adapter_missing"


def test_omitted_enclosing_scope_resolves_only_at_definition_position():
    source = "def outer():\n    def inner():\n        return 1\n    return inner\n"
    fact = dict(file="main.py", line_number=2, col_offset=9, function="inner")
    prediction, _ = Adapter(source).predict(fact, infer(source))
    assert prediction["type"] == ["int"]


def test_qualified_class_field_at_local_ast_name():
    source = "class Box:\n    value = 1\n"
    fact = dict(file="main.py", line_number=2, col_offset=5, variable="Box.value")
    prediction, _ = Adapter(source).predict(fact, infer(source))
    assert prediction["type"] == ["int"]


def test_generator_definition_exports_call_result_not_body_return():
    source = "def items():\n    yield 1\n"
    fact = dict(file="main.py", line_number=1, col_offset=5, function="items")
    assert Adapter(source).predict(fact, infer(source))[0]["type"] == ["generator"]


def test_union_normalization_and_none_spelling_are_deterministic():
    result = infer('value = None if missing else (1 if other else "a")\n')
    assert render_types(result.type_of("value"), "sample") == ["int", "nonetype", "str"]


def test_utf8_ast_column_for_function_parameter():
    source = "def café(entrée):\n    return entrée\na = café(1)\n"
    # Columns follow AST UTF-8 byte offsets, not Unicode codepoint offsets.
    argument = ast.parse(source).body[0].args.args[0]
    fact = dict(
        file="main.py",
        line_number=1,
        col_offset=argument.col_offset + 1,
        function="café",
        parameter="entrée",
    )
    assert Adapter(source).predict(fact, infer(source))[0]["type"] == ["int"]


def test_missing_base_is_inference_gap_not_synthesis_failure():
    source = "value = missing\n"
    fact = dict(file="main.py", line_number=1, col_offset=1, variable="value[0]")
    prediction, evidence = Adapter(source).predict(fact, infer(source))
    assert prediction is None
    assert evidence["category"] == "pyflow_missing"


def test_comparator_is_loaded_from_configured_src_and_sorts_alternatives(tmp_path):
    target = tmp_path / "src/result_analyzer/analysis_utils.py"
    target.parent.mkdir(parents=True)
    target.write_text('def format_type(types): return [["str", "int"]]\n')
    comparator, digest = load_comparator(tmp_path)
    assert comparator.__file__ == str(target)
    assert comparator.format_type([]) == [["int", "str"]]
    assert len(digest) == 64
