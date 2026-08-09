"""Tests for the legacy-to-source candidate ledger."""

from types import SimpleNamespace

from pyflow.optimization.source_candidates import (
    record_source_candidate,
    source_candidate_coverage,
    source_candidates,
)


def test_candidate_ledger_records_a_complete_source_span():
    origin = SimpleNamespace(
        span=SimpleNamespace(
            path="sample.py",
            start_line=2,
            start_column=4,
            end_line=2,
            end_column=9,
        )
    )
    node = object()
    catalog = SimpleNamespace(source_of=lambda _node, **_kwargs: origin)
    code = SimpleNamespace(ir_catalog=catalog)
    compiler = SimpleNamespace(stats={})

    record_source_candidate(
        compiler, code, node, "load_elimination", replacement_local="cached"
    )

    assert source_candidates(compiler) == (
        {
            "kind": "load_elimination",
            "origin": {
                "path": "sample.py",
                "start_line": 2,
                "start_column": 4,
                "end_line": 2,
                "end_column": 9,
            },
            "replacement_local": "cached",
        },
    )


def test_candidate_coverage_distinguishes_unmappable_ir_candidates():
    coverage = source_candidate_coverage(
        [
            {
                "kind": "load_elimination",
                "origin": {
                    "path": "sample.py",
                    "start_line": 2,
                    "start_column": 4,
                    "end_line": 2,
                    "end_column": 9,
                },
            },
            {"kind": "load_elimination", "origin": None},
            {"kind": "store_elimination", "origin": None},
        ]
    )

    assert coverage == {
        "load_elimination": {
            "recorded": 2,
            "with_complete_span": 1,
            "without_complete_span": 1,
        },
        "store_elimination": {
            "recorded": 1,
            "with_complete_span": 0,
            "without_complete_span": 1,
        },
    }
