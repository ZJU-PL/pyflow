"""Exception edges must carry the state at the operation that raised."""

import ast as python_ast
import textwrap

import pytest

from pyflow.frontend.conversion.ast import ASTConverter
from pyflow.ir.cfg import expandphi, graph, inline, ssa, transform, verify_cfg
from pyflow.ir.core import verify_catalog
from pyflow.language.python import ast


def make_code(source):
    return (
        ASTConverter()._convert_function_def(python_ast.parse(textwrap.dedent(source)).body[0]).code
    )


def blocks(entry, stop=()):
    pending, seen = [entry], set()
    while pending:
        block = pending.pop()
        if block is None or block in seen or block in stop:
            continue
        seen.add(block)
        pending.extend(block.next.values())
    return seen


def calls(block, name):
    return any(
        isinstance(getattr(op, "expr", None), ast.Call)
        and isinstance(op.expr.expr, ast.Local)
        and op.expr.expr.name == name
        for op in getattr(block, "ops", ())
    )


@pytest.mark.parametrize("assignment", ["x = risky()", "x: int = risky()"])
def test_failed_rhs_keeps_old_definition_in_handler_and_merges_at_finally(assignment):
    code = make_code(f"""
        def f(x, risky, observe, cleanup):
            try:
                x = 1
                {assignment}
            except:
                observe(x)
            finally:
                cleanup(x)
            return x
    """)
    cfg = transform.evaluate(None, code)
    ssa.evaluate(None, cfg)
    nodes = blocks(cfg.entryTerminal)
    operations = [op for block in nodes for op in getattr(block, "ops", ())]
    initial = next(
        op.lcls[0]
        for op in operations
        if isinstance(op, ast.Assign)
        and isinstance(op.expr, ast.Existing)
        and op.expr.object.pyobj == 1
    )
    failure = next(block for block in nodes if calls(block, "risky"))
    handler = next(block for block in nodes if calls(block, "observe"))
    observe = next(op.expr for op in handler.ops if isinstance(op, ast.Discard))
    assert observe.args[0] is initial
    assert handler in blocks(failure.getExit("error"))
    phis = [phi for block in nodes for phi in getattr(block, "phi", ())]
    assert any(initial in phi.arguments and phi.target.name == "x" for phi in phis)
    verify_cfg(cfg, code.ir_catalog)
    verify_catalog(code.ir_catalog)
    # Copies on exceptional incoming edges must preserve Phi arity/backlinks.
    expandphi.evaluate(None, cfg)
    verify_cfg(cfg, code.ir_catalog)


def test_cloning_keeps_exception_region_marker():
    cfg = transform.evaluate(
        None,
        make_code("""
        def f(x):
            try:
                return x()
            finally:
                cleanup()
    """),
    )
    cloned = inline.CFGCloner().process(cfg)
    assert cloned.has_exception_regions
    verify_cfg(cloned)


def test_handler_and_else_exceptions_bypass_sibling_handlers():
    code = make_code("""
        def f(risky, first, second, otherwise, cleanup):
            try:
                risky()
            except ValueError:
                first()
            except TypeError:
                second()
            else:
                otherwise()
            finally:
                cleanup()
    """)
    cfg = transform.evaluate(None, code)
    nodes = blocks(cfg.entryTerminal)
    handler = next(block for block in nodes if calls(block, "second"))
    for name in ("first", "otherwise"):
        source = next(block for block in nodes if calls(block, name))
        assert handler not in blocks(source.getExit("error"))
        assert any(calls(block, "cleanup") for block in blocks(source.getExit("error")))
    assert not any(
        isinstance(op, ast.TryExceptFinally) for block in nodes for op in getattr(block, "ops", ())
    )
    verify_cfg(cfg)


@pytest.mark.parametrize("transfer", ["return x", "break", "continue", "raise x"])
def test_finally_runs_on_every_abrupt_exit(transfer):
    code = make_code(f"""
        def f(x, flag, marker, cleanup):
            while flag:
                try:
                    marker()
                    {transfer}
                finally:
                    cleanup()
            return x
    """)
    cfg = transform.evaluate(None, code)
    nodes = blocks(cfg.entryTerminal)
    cleanup = {block for block in nodes if calls(block, "cleanup")}
    marker = next(block for block in nodes if calls(block, "marker"))
    before_cleanup = blocks(marker.getExit("normal"), stop=cleanup)
    assert not any(isinstance(block, (graph.Exit, graph.Switch)) for block in before_cleanup)
    ssa.evaluate(None, cfg)
    verify_cfg(cfg, code.ir_catalog)


def test_nested_finally_and_cleanup_override_support_ssa():
    code = make_code("""
        def f(x, cleanup):
            try:
                try:
                    return x
                finally:
                    x = cleanup(x)
            finally:
                return x
    """)
    cfg = transform.evaluate(None, code)
    ssa.evaluate(None, cfg)
    verify_cfg(cfg, code.ir_catalog)
    assert not ssa._contains_try_except_finally(cfg.entryTerminal)


@pytest.mark.parametrize("prefix", ["", "async "])
def test_context_manager_return_reaches_exit_protocol(prefix):
    code = make_code(f"""
        {prefix}def f(cm):
            {prefix}with cm as value:
                return value
    """)
    cfg = transform.evaluate(None, code)
    ssa.evaluate(None, cfg)
    verify_cfg(cfg, code.ir_catalog)
    returns = [
        block
        for block in blocks(cfg.entryTerminal)
        if any(isinstance(op, ast.Return) for op in getattr(block, "ops", ()))
    ]
    assert returns
    for block in returns:
        successors = blocks(block.getExit("normal"))
        assert any(isinstance(node, graph.Switch) for node in successors)
        assert any(getattr(node, "ops", ()) for node in successors)
