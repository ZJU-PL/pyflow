"""Semantic regressions from real-project IR evaluation."""

import ast as python_ast
import textwrap

import pytest

from pyflow.frontend.conversion.ast import ASTConverter
from pyflow.ir.cfg import graph, ssa, transform, verify_cfg, verify_ssa
from pyflow.ir.cfg.dump import generate_clang_style_cfg
from pyflow.language.python import ast


def lower(source):
    tree = python_ast.parse(textwrap.dedent(source))
    code = ASTConverter(verbose=False)._convert_function_def(tree.body[0]).code
    return code, transform.evaluate(None, code)


def blocks(cfg):
    pending, seen = [cfg.entryTerminal], set()
    while pending:
        block = pending.pop()
        if block in seen:
            continue
        seen.add(block)
        yield block
        pending.extend(block.forward())


@pytest.mark.parametrize("initial", ["", "row = [999]"])
def test_inner_iterator_uses_outer_body_binding(initial):
    code, cfg = lower(f"""
        def f(matrix):
            {initial}
            for row in matrix:
                for value in row:
                    if value == 42:
                        return True
            return False
    """)
    ssa.evaluate(None, cfg)
    outer = next(
        block
        for block in blocks(cfg)
        if isinstance(block, graph.ForIter) and block.index.name == "row"
    )
    inner = next(
        block
        for block in blocks(cfg)
        if isinstance(block, graph.ForIter) and block.index.name == "value"
    )
    assert inner.iterator is outer.index
    assert not code.ir_catalog.value_for(inner.iterator, code).undefined
    verify_ssa(cfg)


def test_named_copy_and_phi_preserve_lexical_symbol():
    code, cfg = lower("""
        def f(cond, x):
            if cond:
                a = x
            else:
                a = -x
            return a
    """)
    ssa.evaluate(None, cfg)
    catalog = code.ir_catalog
    phis = [phi for block in blocks(cfg) for phi in getattr(block, "phi", ())]
    assert phis
    for phi in phis:
        symbol = catalog.symbol_id(phi.target, code)
        assert all(
            catalog.symbol_id(arg, code) == symbol for arg in phi.arguments if arg is not None
        )
    verify_ssa(cfg)


def test_exception_safe_copies_do_not_erase_named_targets():
    code, cfg = lower("""
        def f(x):
            try:
                a, b = x
            except ValueError:
                a, b = 0, 0
            return a, b
    """)
    ssa.evaluate(None, cfg)
    returned = next(
        op
        for block in blocks(cfg)
        for op in getattr(block, "ops", ())
        if isinstance(op, ast.Return)
    )
    assert [value.name for value in returned.exprs[0].args] == ["a", "b"]
    assert "%None.v" not in generate_clang_style_cfg(cfg, code.ir_catalog)
    verify_ssa(cfg)


def test_expression_yields_split_before_binding_received_values():
    code, cfg = lower("""
        def f():
            yield 1
            x = yield 2
            y = (yield 3) + 10
            return x, y
    """)
    pauses = [block for block in blocks(cfg) if isinstance(block, graph.Yield)]
    assert len(pauses) == 3
    resumed = [block.getExit("normal") for block in pauses]
    assert (
        sum(
            any(isinstance(op, ast.InputBlock) for op in getattr(block, "ops", ()))
            for block in resumed
        )
        == 2
    )
    ssa.evaluate(None, cfg)
    verify_cfg(cfg, code.ir_catalog)
    verify_ssa(cfg)


@pytest.mark.parametrize("expression", ["flag and (yield 1)", "(yield 1) if flag else 0"])
def test_suspension_in_lazy_expression_keeps_a_bypass_path(expression):
    code, cfg = lower(f"def f(flag):\n    return {expression}\n")
    pause = next(block for block in blocks(cfg) if isinstance(block, graph.Yield))
    pending, seen = [cfg.entryTerminal], set()
    while pending:
        block = pending.pop()
        if block is pause or block in seen:
            continue
        seen.add(block)
        pending.extend(block.normalForward())
    assert cfg.normalTerminal in seen
    ssa.evaluate(None, cfg)
    verify_ssa(cfg)


def test_await_and_async_iteration_have_explicit_cfg_blocks():
    code, cfg = lower("""
        async def f(items, work):
            first = await work()
            async for item in items:
                await work(item)
            return first
    """)
    assert sum(isinstance(block, graph.Await) for block in blocks(cfg)) == 2
    assert sum(isinstance(block, graph.AsyncForIter) for block in blocks(cfg)) == 1
    ssa.evaluate(None, cfg)
    verify_ssa(cfg)


@pytest.mark.parametrize("cleanup", ["x = 0", "return 2", "raise ValueError()"])
def test_finally_precedes_the_only_executed_return(cleanup):
    code, cfg = lower(
        f"def f(x):\n    try:\n        return x + 1\n    finally:\n        {cleanup}\n"
    )
    returns = [
        block
        for block in blocks(cfg)
        if any(isinstance(op, ast.Return) for op in getattr(block, "ops", ()))
    ]
    assert bool(returns) == (not cleanup.startswith("raise"))
    if cleanup.startswith("return"):
        assert all(block.ops[-1].exprs[0].object.pyobj == 2 for block in returns)
    for block in returns:
        successor = block.getExit("normal")
        while isinstance(successor, graph.Merge):
            successor = successor.getExit("normal")
        assert successor is cfg.normalTerminal
    ssa.evaluate(None, cfg)
    verify_ssa(cfg)
