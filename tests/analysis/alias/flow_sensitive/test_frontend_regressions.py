"""Source-to-analysis regressions for flow-sensitive heap behavior.

These tests complement focused hand-built IR cases by exercising Python
parsing and frontend lowering before running the heap transfer engine.
"""

from __future__ import annotations

from pyflow.analysis.alias.flow_sensitive import HeapAnalysis
from pyflow.application.context import CompilerContext
from pyflow.frontend.extractor import Extractor
from pyflow.language.python import ast as py_ast


def _code_from_source(source: str, name: str = "main") -> tuple[object, object]:
    compiler = CompilerContext(None)
    program = Extractor(compiler, verbose=False).extract_from_source(
        source,
        "flow_sensitive_regression.py",
    )
    code = next(code for code in program.liveCode if code.codeName() == name)
    return compiler, code


def _walk(node: object):
    if node is None or isinstance(node, py_ast.leafTypes):
        return
    if isinstance(node, (tuple, list)):
        for item in node:
            yield from _walk(item)
        return
    yield node
    if isinstance(node, py_ast.Code):
        return
    for child in node.children():
        yield from _walk(child)


def _local(code: object, name: str) -> py_ast.Local:
    return next(
        node
        for node in _walk(code.ast)
        if isinstance(node, py_ast.Local) and node.name == name
    )


def test_source_loop_idempotent_write_converges_without_degradation():
    compiler, code = _code_from_source(
        """
def main(cond, value):
    obj = []
    while cond:
        obj.payload = value
    loaded = obj.payload
    return loaded
"""
    )

    analysis = HeapAnalysis()
    analysis.analyze(compiler, code)
    heap = analysis.heap
    assert heap is not None

    assert "loop-iteration-bound" not in {
        reason for reasons in analysis.precision_degradations.values() for reason in reasons
    }
    assert heap.locations_for_local(code, _local(code, "value"))[0] in (
        heap.locations_for_local(code, _local(code, "loaded"))
    )


def test_source_branch_join_retains_both_field_values():
    compiler, code = _code_from_source(
        """
def main(cond, left, right):
    obj = []
    if cond:
        obj.payload = left
    else:
        obj.payload = right
    loaded = obj.payload
    return loaded
"""
    )

    analysis = HeapAnalysis()
    analysis.analyze(compiler, code)
    heap = analysis.heap
    assert heap is not None

    loaded_locations = heap.locations_for_local(code, _local(code, "loaded"))
    assert heap.locations_for_local(code, _local(code, "left"))[0] in loaded_locations
    assert heap.locations_for_local(code, _local(code, "right"))[0] in loaded_locations
