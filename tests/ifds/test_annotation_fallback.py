"""Tests for IFDS annotation fallback behavior."""

from __future__ import annotations

from pyflow.analysis.ifds.annotation_fallback import ensure_ifds_annotations_complete
from pyflow.language.python import ast

from tests.ifds._support import make_code


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
