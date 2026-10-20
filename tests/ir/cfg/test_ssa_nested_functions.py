"""SSA must bind definitions in the enclosing scope without renaming their bodies."""

import ast as python_ast

from pyflow.application.context import CompilerContext
from pyflow.frontend.conversion.ast import ASTConverter
from pyflow.frontend.extractor import Extractor
from pyflow.ir.cfg import transform, ssa, graph as cfg
from pyflow.ir.core import verify_catalog
from pyflow.language.python import ast
from pyflow.language.python.ir_metadata import code_closure_cells


def convert(source):
    compiler = CompilerContext(None)
    compiler.extractor = Extractor(compiler)
    code = ASTConverter()._convert_function_def(python_ast.parse(source).body[0]).code
    return compiler, code, transform.evaluate(compiler, code)


def blocks(graph):
    pending, seen = [graph.entryTerminal], set()
    while pending:
        block = pending.pop()
        if block in seen:
            continue
        seen.add(block)
        yield block
        pending.extend(block.forward())


def test_nested_defaults_and_decorators_use_outer_ssa_values():
    compiler, code, graph = convert('''
def outer(value, decorate):
    @decorate
    def inner(item=value):
        return item
    return inner
''')
    inner = next(node.code for node in code.ast.blocks if isinstance(node, ast.FunctionDef))
    original_body, original_parameters = inner.ast, inner.codeparameters
    ssa.evaluate(compiler, graph)
    operations = [op for block in blocks(graph) if isinstance(block, cfg.Suite) for op in block.ops]
    creation = next(op for op in operations if isinstance(op, ast.Assign) and isinstance(op.expr, ast.MakeFunction))
    decoration = next(op for op in operations if isinstance(op, ast.Assign) and isinstance(op.expr, ast.Call))
    returned = next(op for op in operations if isinstance(op, ast.Return))
    assert creation.expr.defaults == [code.codeparameters.params[0]]
    assert decoration.expr.expr is code.codeparameters.params[1]
    assert decoration.expr.args == creation.lcls
    assert returned.exprs == decoration.lcls
    assert inner.ast is original_body
    assert inner.codeparameters is original_parameters
    verify_catalog(code.ir_catalog)


def test_conditional_nested_definitions_reach_a_phi():
    compiler, code, graph = convert('''
def outer(flag):
    if flag:
        def choice(): return 1
    else:
        def choice(): return 2
    return choice
''')
    ssa.evaluate(compiler, graph)
    phis = [phi for block in blocks(graph) if isinstance(block, cfg.Merge) for phi in block.phi]
    assert len(phis) == 1
    assert len(set(phis[0].arguments)) == 2
    returned = next(op for block in blocks(graph) if isinstance(block, cfg.Suite) for op in block.ops if isinstance(op, ast.Return))
    assert returned.exprs == [phis[0].target]
    verify_catalog(code.ir_catalog)


def test_recursive_nested_binding_preserves_shared_cell():
    compiler, code, graph = convert('''
def outer():
    def inner(): return inner
    return inner
''')
    inner = next(node.code for node in code.ast.blocks if isinstance(node, ast.FunctionDef))
    cell = code_closure_cells(inner)[0]
    ssa.evaluate(compiler, graph)
    stores = [op for block in blocks(graph) if isinstance(block, cfg.Suite) for op in block.ops if isinstance(op, ast.SetCellDeref)]
    assert len(stores) == 1
    assert stores[0].cell is cell
    assert code_closure_cells(inner) == (cell,)


def test_try_in_nested_body_does_not_reject_outer_ssa():
    compiler, code, graph = convert('''
def outer():
    def inner(value):
        try: return value()
        except ValueError: return None
    return inner
''')
    ssa.evaluate(compiler, graph)
    verify_catalog(code.ir_catalog)
