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
