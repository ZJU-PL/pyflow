"""Regression tests for Wave 11 issues uncovered on the top-100 Python corpus."""

from __future__ import annotations

import contextlib
import io
from pathlib import Path
from types import SimpleNamespace

import pytest

from pyflow.analysis import fsdf, shape
from pyflow.api.queries import create_query_components
from pyflow.application.context import CompilerContext
from pyflow.application.passes.builtin import LifetimeAnalysisPass, StoreEliminationPass
from pyflow.application.pipeline import Pipeline
from pyflow.application.program import Program
from pyflow.frontend.extractor import Extractor, extract_program
from pyflow.frontend.interface_builder import (
    InterfaceBuildOptions,
    build_interface_from_paths,
)
from pyflow.ir.cfg import (
    simplify as cfg_simp,
    structuralanalysis,
    transform as cfg_transform,
)
from pyflow.ir.core import Capabilities, FactStore
from pyflow.language.python import ast as pyflow_ast
from pyflow.optimization import callconverter, convertboolelimination, fold
from pyflow.util.application.console import Console


def _build_program(tmp_path: Path, source: str, filename: str = "sample.py"):
    path = tmp_path / filename
    path.write_text(source, encoding="utf-8")
    compiler = CompilerContext(Console(out=io.StringIO(), verbose=False))
    program = Program()
    opts = InterfaceBuildOptions(
        verbose=False,
        dependency_strategy="stubs",
        include_main_entry_points=True,
    )
    program.interface, all_src = build_interface_from_paths([path], opts)
    compiler.extractor = Extractor(compiler, verbose=False, source_code=all_src)
    extract_program(compiler, program)
    return compiler, program


def test_fold_try_finally_preserves_fact_remaps_for_store_elimination_and_lifetime(
    tmp_path: Path,
):
    """Discarded finally-contour evaluations must not overwrite live fact remaps."""
    source = """
class Guard:
    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        return False


def run(flag):
    with Guard() as g:
        if flag:
            return 1
    return 0


def main():
    return run(True) + run(False)
"""
    compiler, program = _build_program(tmp_path, source)
    Pipeline().run_custom_pipeline(compiler, program, ["ipa", "cpa", "lifetime"])

    for code in list(program.liveCode):
        if code.isStandardCode() and not code.annotation.descriptive:
            fold.evaluateCode(compiler, program, code)

    store_res = StoreEliminationPass().run(compiler, program)
    assert store_res.success, store_res.error

    life_res = LifetimeAnalysisPass().run(compiler, program)
    assert life_res.success, life_res.error


def test_fold_loop_fixpoint_and_existing_backfill_keep_references_complete(
    tmp_path: Path,
):
    """Multi-iteration loop folding and folded Existing nodes preserve REFERENCES."""
    source = """
def compute(n):
    x = 1
    y = 2
    z = x + y
    i = 0
    total = 0
    while i < n:
        total = total + z
        i = i + 1
    return total


def main():
    return compute(5)
"""
    compiler, program = _build_program(tmp_path, source)
    Pipeline().run_custom_pipeline(compiler, program, ["ipa", "cpa", "lifetime"])

    for code in list(program.liveCode):
        if code.isStandardCode() and not code.annotation.descriptive:
            fold.evaluateCode(compiler, program, code)

    assert program.ir.facts.has(Capabilities.REFERENCES)
    life_res = LifetimeAnalysisPass().run(compiler, program)
    assert life_res.success, life_res.error


def test_fact_store_merge_producer_accumulates_entries():
    store = FactStore()
    from pyflow.ir.core import FactResult

    store.merge_producer("cap", "fold", {"a": FactResult.exact(("v1",), "fold")})
    store.merge_producer("cap", "fold", {"b": FactResult.exact(("v2",), "fold")})

    assert store.query("cap", "a").values == frozenset(("v1",))
    assert store.query("cap", "b").values == frozenset(("v2",))


def test_cpa_catalog_rebuild_preserves_ipa_summaries_and_query_handles_synthetics(
    tmp_path: Path,
):
    """CPA adding runtime helpers must keep IPA_SUMMARIES queryable."""
    source = """
class Box:
    def __init__(self, v):
        self.v = v

    def get(self):
        return self.v


def main(x):
    b = Box(x)
    return b.get()
"""
    compiler, program = _build_program(tmp_path, source)
    Pipeline().run_custom_pipeline(compiler, program, ["ipa", "cpa", "lifetime"])

    assert program.ir.facts.has(Capabilities.IPA_SUMMARIES)
    qc = create_query_components(compiler, program)
    summaries = qc.data_flow.get_ipa_function_summaries()
    assert isinstance(summaries, list)
    assert any("main" in s.name for s in summaries)


def test_experimental_inlining_modern_ast_multi_context_and_cull_program(
    tmp_path: Path,
):
    """Experimental inlining handles modern AST, multi-context calls, and IR identity."""
    source = """
def helper(a, b=1):
    return a + b


def make_data(x):
    items = [helper(x), helper(x, 2)]
    mapping = {"first": items[0], "second": items[1]}
    try:
        val = mapping["first"]
    except KeyError:
        val = 0
    return val


def main():
    a = helper(10)
    b = helper(20, 3)
    c = make_data(a + b)
    return c
"""
    compiler, program = _build_program(tmp_path, source)
    results = Pipeline().run(
        program,
        compiler=compiler,
        name="inline_test",
        include_experimental_inlining=True,
    )
    assert all(rec.success for rec in results.records)


def test_convertboolelimination_handles_modern_python_ast(tmp_path: Path):
    """InferBoolean traverses modern Python AST without TypeDispatchError."""
    source = """
def sample(xs, flag):
    y: int = 0
    for a, b in xs:
        assert a == b
        if flag:
            y = a
    try:
        def inner():
            return True
        if inner():
            del flag
    except Exception:
        pass
    return y
"""
    compiler, program = _build_program(tmp_path, source)
    for code in list(program.liveCode):
        if code.isStandardCode():
            callconverter.callConverter(compiler.extractor, code)
            convertboolelimination.evaluateCode(compiler, code)


def test_structural_analysis_raises_structural_error_on_suspension_cfgs():
    """Yield/Await CFGs raise StructuralAnalysisError instead of TypeDispatchError."""
    source = """
def gen(n):
    for i in range(n):
        yield i


async def coro(x):
    return await x()
"""
    compiler = CompilerContext(Console(out=io.StringIO(), verbose=False))
    compiler.extractor = Extractor(compiler, verbose=False)
    program = compiler.extractor.extract_from_source(source, filename="susp.py")

    checked = 0
    for code in program.liveCode:
        if not code.isStandardCode():
            continue
        if code.codeName().endswith(("gen", "coro")):
            checked += 1
            cfg = cfg_transform.evaluate(compiler, code)
            cfg_simp.evaluate(compiler, cfg)
            with pytest.raises(structuralanalysis.StructuralAnalysisError):
                structuralanalysis.evaluate(compiler, cfg)
    assert checked == 2


def test_clone_handles_untranslated_interface_from_extract_from_source():
    """Pipeline().run on extract_from_source does not assert interface.translated."""
    source = """
def add(a, b):
    return a + b
"""
    compiler = CompilerContext(Console(out=io.StringIO(), verbose=False))
    compiler.extractor = Extractor(compiler, verbose=False)
    program = compiler.extractor.extract_from_source(source, filename="direct.py")
    assert not program.interface.translated

    results = Pipeline().run(program, compiler=compiler, name="direct")
    assert all(rec.success for rec in results.records)


def test_fsdf_and_programculler_handle_modern_ast_and_nested_lambdas(tmp_path: Path):
    """fsdf.evaluate resolves compiler.program, modern AST, and nested lambdas."""
    source = """
import math


def run(xs):
    fn = lambda v: v + 1
    out = [fn(x) for x in xs]
    try:
        pair = (out, math.sqrt(4))
    except Exception:
        pair = ([], 0)
    return pair


def main():
    return run([1, 2, 3])
"""
    compiler, program = _build_program(tmp_path, source)
    Pipeline().run_custom_pipeline(compiler, program, ["ipa", "cpa", "lifetime"])
    compiler.program = program

    with contextlib.redirect_stdout(io.StringIO()):
        result = fsdf.evaluate(compiler)
    assert isinstance(result, bool)


def test_shape_evaluate_handles_classes_kwargs_discards_and_sorting(tmp_path: Path):
    """shape.evaluate runs cleanly on real Python with classes, kwargs, and discards."""
    source = """
class Worker:
    def __init__(self, name, **kwargs):
        self.name = name
        self.meta = kwargs

    def run(self, x):
        x
        return (self.name, x)


def main():
    w = Worker("a", mode="fast")
    return w.run(1)
"""
    compiler, program = _build_program(tmp_path, source)
    Pipeline().run_custom_pipeline(compiler, program, ["ipa", "cpa", "lifetime"])
    compiler.program = program

    with contextlib.redirect_stdout(io.StringIO()):
        rbsa = shape.evaluate(compiler)
    assert rbsa is not None
