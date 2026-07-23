"""Tests for IFDS annotation fallback behavior."""

from __future__ import annotations

from pyflow.analysis.ifds.frontend.annotation_fallback import ensure_ifds_annotations_complete
from pyflow.language.python import ast

from tests.analysis.ifds._support import make_code


def test_annotation_fallback_marks_call_callee_expression_as_read():
    fn = ast.Local("fn")
    arg = ast.Local("arg")
    code, _ = make_code(
        "main",
        [fn, arg],
        [ast.Discard(ast.Call(fn, [arg], [], None, None))],
    )

    ensure_ifds_annotations_complete((code,))

    call = code.ast.blocks[0].expr
    labels = {slot.label for slot in call.annotation.opReads.merged}
    assert "fn" in labels
    assert "arg" in labels


def test_annotation_fallback_distinguishes_cells_with_same_name():
    left = ast.Cell("cell")
    right = ast.Cell("cell")
    code, _ = make_code(
        "main",
        [],
        [ast.Return([ast.GetCellDeref(left), ast.GetCellDeref(right)])],
    )

    ensure_ifds_annotations_complete((code,))

    reads = code.ast.blocks[0].annotation.opReads.merged
    labels = {slot.label for slot in reads}
    assert len(reads) == 2
    assert len(labels) == 2


def test_annotation_fallback_distinguishes_heap_paths_with_same_base_label():
    left = ast.Local("value")
    attr = ast.Existing(ast.program.Object("payload"))
    right = ast.Local("value")
    left_code, _ = make_code(
        "left",
        [left],
        [ast.Return([ast.GetAttr(left, attr)])],
    )
    right_code, _ = make_code(
        "right",
        [right],
        [ast.Return([ast.GetAttr(right, attr)])],
    )

    ensure_ifds_annotations_complete((left_code, right_code))

    left_slot = left_code.ast.blocks[0].annotation.opReads.merged[0]
    right_slot = right_code.ast.blocks[0].annotation.opReads.merged[0]
    assert left_slot.label == "value.payload"
    assert right_slot.label == "value.payload"
    assert left_slot is not right_slot


def _labels(annotation):
    return {slot.label for slot in annotation.merged}


def _allocation_labels(annotation):
    return {allocation.label for allocation in annotation.merged}


def test_annotation_fallback_marks_write_base_key_and_value_as_reads():
    container = ast.Local("container")
    key = ast.Local("key")
    value = ast.Local("value")
    code, _ = make_code(
        "main",
        [container, key, value],
        [ast.SetSubscript(value, container, key)],
    )

    ensure_ifds_annotations_complete((code,))

    statement = code.ast.blocks[0]
    assert _labels(statement.annotation.opReads) == {"container", "key", "value"}
    assert _labels(statement.annotation.opModifies) == {"container[*]"}


def test_annotation_fallback_handles_raise_assert_print_and_build_nodes():
    exc = ast.Local("exc")
    cause = ast.Local("cause")
    traceback = ast.Local("traceback")
    condition = ast.Local("condition")
    message = ast.Local("message")
    target = ast.Local("target")
    printed = ast.Local("printed")
    tuple_value = ast.Local("tuple_value")
    list_value = ast.Local("list_value")
    code, _ = make_code(
        "main",
        [
            exc,
            cause,
            traceback,
            condition,
            message,
            target,
            printed,
            tuple_value,
            list_value,
        ],
        [
            ast.Raise(exc, cause, traceback),
            ast.Assert(condition, message),
            ast.Print(target, printed),
            ast.Discard(ast.BuildTuple([tuple_value, ast.BuildList([list_value])])),
        ],
    )

    ensure_ifds_annotations_complete((code,))

    assert _labels(code.ast.blocks[0].annotation.opReads) == {
        "exc",
        "cause",
        "traceback",
    }
    assert _labels(code.ast.blocks[1].annotation.opReads) == {"condition", "message"}
    assert _labels(code.ast.blocks[2].annotation.opReads) == {"target", "printed"}
    assert _labels(code.ast.blocks[3].annotation.opReads) == {
        "tuple_value",
        "list_value",
    }
    assert _allocation_labels(code.ast.blocks[3].annotation.opAllocates) == {
        "tuple literal",
        "list literal",
    }


def test_annotation_fallback_synthesizes_collection_literal_element_writes():
    first = ast.Local("first")
    second = ast.Local("second")
    key = ast.Existing(ast.program.Object("safe"))
    mapped = ast.Local("mapped")
    items = ast.Local("items")
    mapping = ast.Local("mapping")
    code, _ = make_code(
        "main",
        [first, second, mapped, items, mapping],
        [
            ast.Assign(ast.BuildList([first, second]), [items]),
            ast.Assign(ast.BuildMap([key, mapped]), [mapping]),
        ],
    )

    ensure_ifds_annotations_complete((code,))

    list_assign, map_assign = code.ast.blocks
    assert _labels(list_assign.annotation.opModifies) == {
        "items",
        "items[0]",
        "items[1]",
    }
    assert _allocation_labels(list_assign.annotation.opAllocates) == {"list literal"}
    assert _labels(map_assign.annotation.opModifies) == {"mapping", "mapping['safe']"}
    assert _allocation_labels(map_assign.annotation.opAllocates) == {"dict literal"}


def test_annotation_fallback_marks_definition_style_bindings():
    decorator = ast.Local("decorator")
    base = ast.Local("base")
    alias_value = ast.Local("alias_value")
    function_code, _ = make_code("inner", [], [])
    class_body = ast.Suite([ast.Return([base])])
    code, _ = make_code(
        "main",
        [decorator, base, alias_value],
        [
            ast.FunctionDef("built_fn", function_code, [decorator], None),
            ast.ClassDef("BuiltClass", [base], [], class_body, [decorator], None),
            ast.TypeAlias("Alias", [], alias_value),
        ],
    )

    ensure_ifds_annotations_complete((code,))

    function_def, class_def, type_alias = code.ast.blocks
    assert _labels(function_def.annotation.opReads) == {"decorator"}
    assert _labels(function_def.annotation.opModifies) == {"built_fn"}
    assert _labels(class_def.annotation.opReads) == {"base", "decorator"}
    assert _labels(class_def.annotation.opModifies) == {"BuiltClass"}
    assert _labels(type_alias.annotation.opReads) == {"alias_value"}
    assert _labels(type_alias.annotation.opModifies) == {"Alias"}


def test_annotation_fallback_handles_exception_target_and_make_function_cells():
    error_type = ast.Local("error_type")
    error_value = ast.Local("error_value")
    default = ast.Local("default")
    captured = ast.Cell("captured")
    inner_code, _ = make_code("inner", [], [])
    handler = ast.ExceptionHandler(
        ast.Suite([]),
        error_type,
        error_value,
        ast.Suite([ast.Discard(ast.MakeFunction([default], [captured], inner_code))]),
    )
    code, _ = make_code(
        "main",
        [error_type, error_value, default],
        [ast.TryExceptFinally(ast.Suite([]), [handler], None, None, None)],
    )

    ensure_ifds_annotations_complete((code,))

    try_statement = code.ast.blocks[0]
    make_function = handler.body.blocks[0].expr
    assert "error_type" in _labels(try_statement.annotation.opReads)
    assert "default" in _labels(try_statement.annotation.opReads)
    assert any(
        label.startswith("captured@")
        for label in _labels(try_statement.annotation.opReads)
    )
    assert _labels(try_statement.annotation.opModifies) == {"error_value"}
    assert "default" in _labels(make_function.annotation.opReads)
    assert any(
        label.startswith("captured@")
        for label in _labels(make_function.annotation.opReads)
    )
