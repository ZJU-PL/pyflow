"""Tests for the conservative Python source optimizer."""

import ast
import pytest

from pyflow.optimization.source import (
    emit_optimized_sources,
    legacy_transformation_report,
    optimization_report,
    optimize_source,
)


def _run(source, name):
    namespace = {}
    exec(compile(source, "<optimized>", "exec"), namespace)
    return namespace[name]


def _candidate(kind, node):
    return {
        "kind": kind,
        "origin": {
            "path": "sample.py",
            "start_line": node.lineno,
            "start_column": node.col_offset,
            "end_line": node.end_lineno,
            "end_column": node.end_col_offset,
        },
    }


def test_optimize_source_folds_constants_and_removes_dead_if_branch():
    result = optimize_source(
        """\
def calculate():
    value = 2 * (3 + 4)
    if 1 < 2:
        return value
    return 0
"""
    )

    assert result.constant_folds >= 2
    assert result.dead_branches_removed == 1
    assert "value = 14" in result.source
    assert _run(result.source, "calculate")() == 14


def test_optimize_source_keeps_expressions_that_raise_at_runtime():
    source = """\
def calculate():
    return 1 / 0
"""
    result = optimize_source(source)

    assert result.constant_folds == 0
    with pytest.raises(ZeroDivisionError):
        _run(result.source, "calculate")()


def test_optimize_source_preserves_while_else_semantics():
    result = optimize_source(
        """\
def calculate():
    while False:
        raise AssertionError("unreachable")
    else:
        return 1 + 1
"""
    )

    assert result.dead_branches_removed == 1
    assert _run(result.source, "calculate")() == 2


def test_optimize_source_removes_statements_after_return():
    result = optimize_source(
        """\
def calculate():
    return 42
    raise AssertionError("unreachable")
"""
    )

    assert result.unreachable_statements_removed == 1
    assert "AssertionError" not in result.source
    assert _run(result.source, "calculate")() == 42


def test_static_branch_is_preserved_when_it_establishes_local_scope():
    source = """\
def calculate():
    if False:
        value = 1
    return value
"""
    result = optimize_source(source)

    assert result.dead_branches_removed == 0
    with pytest.raises(UnboundLocalError):
        _run(source, "calculate")()
    with pytest.raises(UnboundLocalError):
        _run(result.source, "calculate")()


def test_unreachable_assignment_is_preserved_when_it_establishes_local_scope():
    source = """\
def calculate():
    return value
    value = 1
"""
    result = optimize_source(source)

    assert result.unreachable_statements_removed == 0
    with pytest.raises(UnboundLocalError):
        _run(result.source, "calculate")()


def test_optimize_source_removes_a_statically_true_assert_without_evaluating_message():
    result = optimize_source(
        """\
def calculate():
    assert 2 * 3 == 6, fail_if_evaluated()
    return 42
"""
    )

    assert result.redundant_assertions_removed == 1
    assert "fail_if_evaluated" not in result.source
    assert _run(result.source, "calculate")() == 42


def test_optimize_source_preserves_a_statically_false_assert():
    source = """\
def calculate():
    assert False, "expected failure"
"""
    result = optimize_source(source)

    assert result.redundant_assertions_removed == 0
    with pytest.raises(AssertionError, match="expected failure"):
        _run(result.source, "calculate")()


def test_optimize_source_eliminates_short_circuited_boolean_operands():
    result = optimize_source(
        """\
def calculate():
    return False and fail_if_evaluated(), True or fail_if_evaluated()
"""
    )

    assert result.boolean_simplifications == 2
    assert "fail_if_evaluated" not in result.source
    assert _run(result.source, "calculate")() == (False, True)


def test_short_circuit_is_preserved_when_skipped_operand_binds_a_name():
    source = """\
def calculate():
    False and (value := 1)
    return value
"""
    result = optimize_source(source)

    assert result.boolean_simplifications == 0
    with pytest.raises(UnboundLocalError):
        _run(result.source, "calculate")()


def test_conditional_expression_preserves_binding_in_unselected_branch():
    source = """\
def calculate():
    value = 1 if True else (shadow := 2)
    return shadow
"""
    result = optimize_source(source)

    assert result.dead_branches_removed == 0
    with pytest.raises(UnboundLocalError):
        _run(result.source, "calculate")()


def test_true_assert_is_preserved_when_message_establishes_local_scope():
    source = """\
def calculate():
    assert True, (shadow := 2)
    return shadow
"""
    result = optimize_source(source)

    assert result.redundant_assertions_removed == 0
    with pytest.raises(UnboundLocalError):
        _run(result.source, "calculate")()


def test_o2_propagates_constants_across_a_straight_line_basic_block():
    source = """\
def calculate():
    x = 2
    y = x + 3
    return y * 4
"""

    result = optimize_source(source, level=2)

    assert result.constant_propagations == 2
    assert "y = 5" in result.source
    assert "return 20" in result.source
    assert _run(result.source, "calculate")() == 20


def test_o2_skips_functions_with_dynamic_local_scope_access():
    source = """\
def calculate():
    x = 2
    locals()
    return x + 3
"""

    result = optimize_source(source, level=2)

    assert result.guarded_functions == 1
    assert result.constant_propagations == 0
    assert "return x + 3" in result.source


def test_o2_skips_comprehension_scopes_that_shadow_a_local():
    source = """\
def calculate():
    x = 2
    values = [x + 1 for x in range(3)]
    return values, x
"""

    result = optimize_source(source, level=2)

    assert result.guarded_functions == 1
    assert _run(result.source, "calculate")() == ([1, 2, 3], 2)


def test_o2_skips_walrus_assignments_that_rebind_a_constant():
    source = """\
def calculate():
    x = 2
    (x := 3)
    return x + 1
"""

    result = optimize_source(source, level=2)

    assert result.guarded_functions == 1
    assert _run(result.source, "calculate")() == 4


def test_o2_skips_imports_that_can_rebind_a_constant():
    source = """\
def calculate():
    value = 2
    import builtins as value
    return value + 1
"""

    result = optimize_source(source, level=2)

    assert result.guarded_functions == 1
    with pytest.raises(TypeError):
        _run(result.source, "calculate")()


def test_source_emitter_revalidates_and_applies_a_legacy_fold_candidate():
    source = """\
def calculate():
    return 6 * 7
"""
    expression = ast.parse(source).body[0].body[0].value

    result = optimize_source(source, legacy_candidates=[_candidate("fold", expression)])

    assert result.legacy_candidates_applied == 1
    assert result.legacy_candidates_rejected == 0
    assert result.legacy_candidate_rejections == ()
    assert "return 42" in result.source
    assert _run(result.source, "calculate")() == 42


def test_source_emitter_revalidates_and_applies_a_legacy_dce_candidate():
    source = """\
def calculate():
    1 + 1
    return 42
"""
    statement = ast.parse(source).body[0].body[0]

    result = optimize_source(
        source, legacy_candidates=[_candidate("dce_discard", statement)]
    )

    assert result.legacy_candidates_applied == 1
    assert result.legacy_candidates_rejected == 0
    assert result.legacy_candidate_rejections == ()
    assert "1 + 1" not in result.source
    assert _run(result.source, "calculate")() == 42


def test_source_emitter_rejects_an_unlowerable_legacy_load_candidate():
    source = """\
def calculate():
    return 6 * 7
"""
    expression = ast.parse(source).body[0].body[0].value

    result = optimize_source(
        source, legacy_candidates=[_candidate("load_elimination", expression)]
    )

    assert result.legacy_candidates_applied == 0
    assert result.legacy_candidates_rejected == 1
    assert result.legacy_candidate_rejections == (("unsupported_source_kind", 1),)
    assert _run(result.source, "calculate")() == 42


def test_optimization_report_marks_ir_only_legacy_passes(tmp_path):
    output = tmp_path / "optimized.py"
    result = optimize_source("answer = 40 + 2\n")
    legacy = {
        "simplify": type("Result", (), {"success": True, "changed": True, "error": None})(),
        "clone": type("Result", (), {"success": True, "changed": True, "error": None})(),
    }

    report = optimization_report({output: result}, level=1, legacy_results=legacy)

    assert report["totals"]["constant_folds"] == 1
    assert report["legacy_passes"] == [
        {
            "name": "simplify",
            "success": True,
            "changed": True,
            "emission": "safe_subset_emitted",
            "time_seconds": None,
            "error": None,
        },
        {
            "name": "clone",
            "success": True,
            "changed": True,
            "emission": "ir_only",
            "time_seconds": None,
            "error": None,
        },
    ]
    assert report["legacy_transformations"] == {
        "count": 0,
        "by_kind": {},
        "records": [],
    }
    assert report["legacy_source_candidates"] == {
        "recorded": 0,
        "applied": 0,
        "rejected": 0,
        "not_routed": 0,
        "rejection_reasons": {},
        "by_kind": {},
        "source_span_coverage": {},
        "records": [],
    }


def test_optimization_report_exposes_legacy_candidate_yield(tmp_path):
    output = tmp_path / "optimized.py"
    result = optimize_source(
        "answer = 40 + 2\n",
        legacy_candidates=[
            {
                "kind": "load_elimination",
                "origin": {
                    "path": "sample.py",
                    "start_line": 1,
                    "start_column": 9,
                    "end_line": 1,
                    "end_column": 15,
                },
            }
        ],
    )

    report = optimization_report(
        {output: result},
        level=1,
        legacy_candidates=[
            {
                "kind": "load_elimination",
                "origin": {
                    "path": "sample.py",
                    "start_line": 1,
                    "start_column": 9,
                    "end_line": 1,
                    "end_column": 15,
                },
            }
        ],
    )

    assert report["legacy_source_candidates"] == {
        "recorded": 1,
        "applied": 0,
        "rejected": 1,
        "not_routed": 0,
        "rejection_reasons": {"unsupported_source_kind": 1},
        "by_kind": {"load_elimination": 1},
        "source_span_coverage": {
            "load_elimination": {
                "recorded": 1,
                "with_complete_span": 1,
                "without_complete_span": 0,
            }
        },
        "records": [
            {
                "kind": "load_elimination",
                "origin": {
                    "path": "sample.py",
                    "start_line": 1,
                    "start_column": 9,
                    "end_line": 1,
                    "end_column": 15,
                },
            }
        ],
    }


def test_optimization_report_distinguishes_candidates_not_routed_to_source(tmp_path):
    source_file = tmp_path / "input.py"
    source_file.write_text("answer = 40 + 2\n", encoding="utf-8")
    output = tmp_path / "optimized.py"
    candidates = (
        {
            "kind": "fold",
            "origin": {
                "path": "not-an-emitted-source.py",
                "start_line": 1,
                "start_column": 9,
                "end_line": 1,
                "end_column": 15,
            },
        },
    )

    results = emit_optimized_sources(
        [source_file], source_file, output, legacy_candidates=candidates
    )
    report = optimization_report(
        results, level=1, legacy_candidates=candidates
    )

    assert report["legacy_source_candidates"]["recorded"] == 1
    assert report["legacy_source_candidates"]["applied"] == 0
    assert report["legacy_source_candidates"]["rejected"] == 0
    assert report["legacy_source_candidates"]["not_routed"] == 1
    assert report["legacy_source_candidates"]["rejection_reasons"] == {}


def test_legacy_transformation_report_preserves_ir_provenance():
    origin = type(
        "Origin",
        (),
        {
            "span": type(
                "Span",
                (),
                {
                    "path": "sample.py",
                    "start_line": 3,
                    "start_column": 4,
                    "end_line": 3,
                    "end_column": 10,
                },
            )(),
            "name": "answer",
            "construct_kind": "expression",
        },
    )()
    node = "module:answer/n7"
    frame = type(
        "Frame", (), {"kind": "fold", "inputs": ("module:answer/n2",), "detail": ""}
    )()
    catalog = type(
        "Catalog",
        (),
        {
            "nodes": lambda self: ((node, object()),),
            "provenance_of": lambda self, _node: (frame,),
            "source_of": lambda self, _node: origin,
        },
    )()

    report = legacy_transformation_report(type("Program", (), {"ir": catalog})())

    assert report == {
        "count": 1,
        "by_kind": {"fold": 1},
        "records": [
            {
                "node": node,
                "transform": "fold",
                "inputs": ["module:answer/n2"],
                "detail": "",
                "origin": {
                    "kind": "source",
                    "path": "sample.py",
                    "start_line": 3,
                    "start_column": 4,
                    "end_line": 3,
                    "end_column": 10,
                    "name": "answer",
                    "construct_kind": "expression",
                },
                "source_emission": "not_directly_emitted",
            }
        ],
    }


def test_emit_optimized_sources_preserves_directory_layout(tmp_path):
    source_root = tmp_path / "source"
    source_root.mkdir()
    nested = source_root / "pkg"
    nested.mkdir()
    source_file = nested / "sample.py"
    source_file.write_text("answer = 40 + 2\n", encoding="utf-8")
    destination = tmp_path / "optimized"

    results = emit_optimized_sources([source_file], source_root, destination)

    emitted = destination / "pkg" / "sample.py"
    assert list(results) == [emitted]
    assert emitted.read_text(encoding="utf-8") == "answer = 42\n"


def test_emit_optimized_sources_rejects_in_place_output(tmp_path):
    source_file = tmp_path / "sample.py"
    source_file.write_text("answer = 1\n", encoding="utf-8")

    with pytest.raises(ValueError, match="must not overwrite"):
        emit_optimized_sources([source_file], source_file, source_file)


def test_emit_optimized_sources_rejects_output_nested_in_input_directory(tmp_path):
    source_root = tmp_path / "source"
    source_root.mkdir()
    source_file = source_root / "sample.py"
    source_file.write_text("answer = 1\n", encoding="utf-8")

    with pytest.raises(ValueError, match="outside the input directory"):
        emit_optimized_sources([source_file], source_root, source_root / "optimized")
