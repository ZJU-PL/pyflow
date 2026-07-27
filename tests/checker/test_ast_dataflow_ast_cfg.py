import ast

from pyflow.checker.ast_dataflow.frontend import ASTCFGBuilder, ASTNodeKind
from pyflow.checker.ast_dataflow.solver import EdgeKind


def _build(source: str):
    function = ast.parse(source).body[0]
    return ASTCFGBuilder(function.name).build(function)


def test_if_branches_are_independent_predecessors_of_join():
    built = _build("""
def f(flag):
    if flag:
        x = 1
    else:
        x = 2
    return x
""")
    branch = next(node for node in built.graph.nodes if node.kind is ASTNodeKind.BRANCH)
    outgoing = built.graph.outgoing(branch)

    assert {edge.kind for edge in outgoing} == {EdgeKind.TRUE, EdgeKind.FALSE}
    assert outgoing[0].target != outgoing[1].target


def test_while_body_has_back_edge_and_false_exit():
    built = _build("""
def f(flag):
    while flag:
        consume(flag)
    return flag
""")
    loop = next(node for node in built.graph.nodes if node.kind is ASTNodeKind.LOOP)
    outgoing = built.graph.outgoing(loop)
    body = next(edge.target for edge in outgoing if edge.kind is EdgeKind.TRUE)

    assert any(edge.target == loop for edge in built.graph.outgoing(body))
    assert any(edge.kind is EdgeKind.FALSE for edge in outgoing)


def test_break_targets_post_loop_continuation():
    built = _build("""
def f(flag):
    while flag:
        break
    return flag
""")
    break_node = next(
        node for node in built.graph.nodes if node.kind is ASTNodeKind.BREAK
    )
    edge = built.graph.outgoing(break_node)[0]

    assert edge.kind is EdgeKind.BREAK
    assert edge.target.kind is ASTNodeKind.RETURN


def test_try_body_has_exceptional_route_to_handler_dispatch():
    built = _build("""
def f():
    try:
        risky()
    except ValueError:
        recover()
""")
    risky = next(
        node
        for node in built.graph.nodes
        if node.kind is ASTNodeKind.STATEMENT
        and isinstance(node.syntax, ast.Expr)
        and isinstance(node.syntax.value, ast.Call)
        and node.syntax.value.func.id == "risky"
    )

    assert any(
        edge.kind is EdgeKind.EXCEPTION
        and edge.target.kind is ASTNodeKind.HANDLER_DISPATCH
        for edge in built.graph.outgoing(risky)
    )


def test_with_body_is_part_of_cfg_after_context_expression():
    built = _build("""
def f(manager):
    with manager as value:
        consume(value)
    return value
""")
    with_node = next(
        node for node in built.graph.nodes if isinstance(node.syntax, ast.With)
    )
    body = built.graph.outgoing(with_node)[0].target

    assert isinstance(body.syntax, ast.Expr)
