"""Tests for IFDS procedure-level heap summaries."""

from __future__ import annotations

from dataclasses import dataclass

from pyflow.analysis.heap import (
    HeapAbstraction,
    HeapPolicy,
    UpdatePolicy,
)
from pyflow.analysis.heap.heap_effects import HeapEffectBuilder
from pyflow.analysis.heap.heap_summary import HeapSummaryBuilder
from pyflow.language.python import ast as py_ast


@dataclass(frozen=True, eq=False)
class RawStorage:
    label: str


def test_heap_summary_collects_writes_returns_and_escapes():
    obj = py_ast.Local("obj")
    value = py_ast.Local("value")
    payload = py_ast.Existing(py_ast.program.Object("payload"))
    code = py_ast.Code(
        "init",
        py_ast.CodeParameters(
            selfparam=None,
            posonlyparams=[],
            posonlynames=[],
            params=[obj, value],
            paramnames=["obj", "value"],
            defaults=[],
            vparam=None,
            kparam=None,
            returnparams=[],
            type_params=None,
        ),
        py_ast.Suite(
            [
                py_ast.SetAttr(value, obj, payload),
                py_ast.Return([obj]),
            ]
        ),
    )
    raw = {
        id(obj): (RawStorage("obj"),),
        id(value): (RawStorage("value"),),
    }
    heap = HeapAbstraction(
        lambda _procedure, local: raw.get(id(local), ()),
        policy=HeapPolicy(allow_strong_nested_fresh=True),
    )
    builder = HeapSummaryBuilder(HeapEffectBuilder(heap, heap.locations_for_local))

    summary = builder.summarize(code)

    assert heap.dynamic_attribute_location(heap.locations_for_local(code, obj)[0], "payload") in {
        write.location for write in summary.writes
    }
    assert heap.locations_for_local(code, value)[0] in summary.escapes
    assert heap.locations_for_local(code, obj)[0] in summary.returns


def test_heap_summary_reports_strong_writes_for_fresh_objects():
    obj = py_ast.Local("obj")
    value = py_ast.Local("value")
    payload = py_ast.Existing(py_ast.program.Object("payload"))
    code = py_ast.Code(
        "init",
        py_ast.CodeParameters(
            selfparam=None,
            posonlyparams=[],
            posonlynames=[],
            params=[obj, value],
            paramnames=["obj", "value"],
            defaults=[],
            vparam=None,
            kparam=None,
            returnparams=[],
            type_params=None,
        ),
        py_ast.Suite([py_ast.SetAttr(value, obj, payload)]),
    )
    raw = {id(value): (RawStorage("value"),)}
    heap = HeapAbstraction(
        lambda _procedure, local: raw.get(id(local), ()),
        policy=HeapPolicy(allow_strong_nested_fresh=True),
    )
    heap.bind_allocation_targets(code, (obj,), object(), label="fresh object")
    builder = HeapSummaryBuilder(HeapEffectBuilder(heap, heap.locations_for_local))

    summary = builder.summarize(code)

    assert any(write.policy is UpdatePolicy.STRONG for write in summary.writes)
