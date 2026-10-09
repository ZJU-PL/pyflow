"""Annotated assignments preserve bindings, annotation effects, and provenance."""

import io

from pyflow.application.context import CompilerContext
from pyflow.frontend.extractor import Extractor
from pyflow.ir.core import ensure_code_indexed
from pyflow.language.python import ast, program
from pyflow.optimization import fold, simplify, dce
from pyflow.optimization.dataflow import forward, base
from pyflow.util.application.console import Console


def _existing(value):
    return ast.Existing(program.Object(value))


def _simplify(blocks):
    parameters = ast.CodeParameters(None, [], [], [], [], [], None, None, [], None)
    code = ast.Code("settings", parameters, ast.Suite(blocks))
    ensure_code_indexed(code)
    compiler = CompilerContext(Console(out=io.StringIO()))
    compiler.extractor = Extractor(compiler, verbose=False)
    simplify.evaluateCode(compiler, None, code)
    return code


def test_initialized_annotation_overwrites_previous_constant_without_rewriting_target():
    target = ast.Local("block_size")
    annotation = ast.Local("int")
    declaration = ast.AnnAssign(target, annotation, _existing(1024))
    code = _simplify([ast.Assign(_existing(1), [target]), declaration, ast.Return([target])])
    annotated = next(node for node in code.ast.blocks if isinstance(node, ast.AnnAssign))
    assert annotated.target is target
    assert annotated.annotation_expr is annotation
    assert annotated.annotation is declaration.annotation
    assert code.ast.blocks[-1].exprs[0].object.pyobj == 1024


def test_annotation_only_keeps_the_existing_binding_and_declaration():
    target = ast.Local("value")
    declaration = ast.AnnAssign(target, ast.Local("int"), None)
    code = _simplify([ast.Assign(_existing(7), [target]), declaration, ast.Return([target])])
    assert any(isinstance(node, ast.AnnAssign) and node.value is None for node in code.ast.blocks)
    assert code.ast.blocks[-1].exprs[0].object.pyobj == 7


def test_annotation_dependencies_and_initializer_side_effects_survive_dce():
    initializer = ast.Local("factory")
    annotation = ast.Local("annotation_type")
    target = ast.Local("unused")
    code = _simplify(
        [
            ast.Assign(ast.Local("external_type"), [annotation]),
            ast.Assign(ast.Local("external_factory"), [initializer]),
            ast.AnnAssign(target, annotation, ast.Call(initializer, [], [], None, None)),
        ]
    )
    assert any(
        isinstance(node, ast.AnnAssign) and isinstance(node.value, ast.Call)
        for node in code.ast.blocks
    )
    assert any(isinstance(node, ast.Assign) and annotation in node.lcls for node in code.ast.blocks)


def test_annotation_exception_contour_sees_the_new_binding_after_initialization():
    target = ast.Local("value")
    analysis = fold.FoldAnalysis()
    traverse = forward.ForwardFlowTraverse(fold.constMeet, analysis, lambda node: node)
    analysis.flow = traverse.flow
    traverse(ast.Assign(_existing(1), [target]))
    traverse.flow.tryLevel = 1
    traverse(
        ast.AnnAssign(target, ast.Call(ast.Local("annotation"), [], [], None, None), _existing(2))
    )
    assert traverse.flow.lookup(target).pyobj == 2
    assert traverse.flow.bags["raise"][0].lookup(target).pyobj == 2
    assert base.MayRaise()(ast.AnnAssign(target, ast.Local("int"), None)) is False


def test_fold_preserves_immutable_keyword_argument_payloads():
    payload = (("flag", ast.Local("value")),)
    folded = fold.FoldTraverse(lambda node: node, None)(payload)
    assert isinstance(folded, tuple) and isinstance(folded[0], tuple)
    call = ast.Call(ast.Local("callee"), (), (("flag", ast.Local("value")),), None, None)
    rewritten = fold.FoldTraverse(lambda node: node, None)(call)
    assert rewritten.args == []
    assert isinstance(rewritten.kwds[0], tuple)
    assert rewritten.kwds[0][0] == "flag"


def test_dce_preserves_old_binding_when_annotated_initializer_raises():
    target = ast.Local("value")
    previous = ast.Assign(_existing(1), [target])
    declaration = ast.AnnAssign(
        target, ast.Local("int"), ast.Call(ast.Local("may_fail"), [], [], None, None)
    )
    handler = ast.Suite([ast.Return([target])])
    guarded = ast.TryExceptFinally(ast.Suite([declaration]), [], handler, None, ast.Suite([]))
    parameters = ast.CodeParameters(None, [], [], [], [], [], None, None, [], None)
    code = ast.Code("guarded", parameters, ast.Suite([previous, guarded, ast.Return([target])]))
    ensure_code_indexed(code)
    dce.evaluateCode(CompilerContext(Console(out=io.StringIO())), code)
    assert any(isinstance(node, ast.Assign) and target in node.lcls for node in code.ast.blocks)
