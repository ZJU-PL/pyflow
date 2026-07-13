from __future__ import annotations

from pyflow.application import context
from pyflow.analysis.ifds import build_supergraph_from_cfgs
from pyflow.analysis.ifds.cfg_adapter import CallEffect
from pyflow.language.python import ast

from tests.ifds._support import build_cfg, make_code


def _reachable_nodes(adapter, start):
    pending = [start]
    reached = set()
    while pending:
        node = pending.pop()
        if node in reached:
            continue
        reached.add(node)
        pending.extend(adapter.supergraph.ordered_normal_successors(node))
    return reached


def test_typed_exception_routes_only_to_first_matching_handler():
    compiler = context.CompilerContext(None)
    handled_type = ast.Local("handled_type")
    handled_value = ast.Local("handled_value")
    main_code, _ = make_code(
        "main",
        [],
        [
            ast.TryExceptFinally(
                ast.Suite(
                    [
                        ast.Raise(
                            ast.Call(ast.Local("ValueError"), [], [], None, None),
                            None,
                            None,
                        )
                    ]
                ),
                [
                    ast.ExceptionHandler(
                        ast.Suite([]),
                        ast.Local("TypeError"),
                        None,
                        ast.Suite(
                            [
                                ast.Assign(
                                    ast.Existing(ast.program.Object(1)), [handled_type]
                                )
                            ]
                        ),
                    ),
                    ast.ExceptionHandler(
                        ast.Suite([]),
                        ast.Local("ValueError"),
                        None,
                        ast.Suite(
                            [
                                ast.Assign(
                                    ast.Existing(ast.program.Object(1)), [handled_value]
                                )
                            ]
                        ),
                    ),
                ],
                None,
                None,
                None,
            ),
            ast.Return([]),
        ],
        return_name="ret",
    )
    cfg = build_cfg(compiler, main_code)
    adapter = build_supergraph_from_cfgs([cfg])
    raise_node = next(
        node
        for node in adapter.supergraph.ordered_nodes_of(cfg)
        if isinstance(adapter.operation_of(node), ast.Raise) and node.kind != "call"
    )
    successor_scopes = {
        node.scope for node in adapter.supergraph.ordered_normal_successors(raise_node)
    }

    assert any("1" in scope for scope in successor_scopes)
    assert not any(
        scope[:4] == ("0", "try", "handler", "0") for scope in successor_scopes
    )


def test_typed_exception_uses_builtin_subclass_and_first_match_semantics():
    compiler = context.CompilerContext(None)
    broad = ast.Local("broad")
    narrow = ast.Local("narrow")
    main_code, _ = make_code(
        "main",
        [],
        [
            ast.TryExceptFinally(
                ast.Suite(
                    [
                        ast.Raise(
                            ast.Call(ast.Local("ValueError"), [], [], None, None),
                            None,
                            None,
                        )
                    ]
                ),
                [
                    ast.ExceptionHandler(
                        ast.Suite([]),
                        ast.Local("Exception"),
                        None,
                        ast.Suite(
                            [ast.Assign(ast.Existing(ast.program.Object(1)), [broad])]
                        ),
                    ),
                    ast.ExceptionHandler(
                        ast.Suite([]),
                        ast.Local("ValueError"),
                        None,
                        ast.Suite(
                            [ast.Assign(ast.Existing(ast.program.Object(1)), [narrow])]
                        ),
                    ),
                ],
                None,
                None,
                None,
            ),
            ast.Return([]),
        ],
    )
    cfg = build_cfg(compiler, main_code)
    adapter = build_supergraph_from_cfgs([cfg])
    raise_node = next(
        node
        for node in adapter.supergraph.ordered_nodes_of(cfg)
        if isinstance(adapter.operation_of(node), ast.Raise) and node.kind != "call"
    )
    successors = adapter.supergraph.ordered_normal_successors(raise_node)

    assert {node.scope[:4] for node in successors} == {("0", "try", "handler", "0")}


def test_context_manager_calls_are_classified_semantically(tmp_path):
    from pyflow.analysis.ifds.api import load_analysis_session

    target = tmp_path / "ctx.py"
    target.write_text("""
def main():
    with open('x') as handle:
        handle.read()
""")
    session = load_analysis_session([target], root_function="main")
    roles = {
        effect.semantic_role
        for node in session.adapter.supergraph.ordered_nodes()
        for effect in (session.adapter.effect_of(node),)
        if isinstance(effect, CallEffect) and effect.semantic_role
    }
    assert "context_enter" in roles
    assert "context_exit" in roles


def test_async_and_generator_procedure_semantics_are_retained(tmp_path):
    from pyflow.analysis.ifds.api import load_analysis_session

    target = tmp_path / "async_gen.py"
    target.write_text("""
async def async_value(value):
    return value

async def async_main(value):
    return await async_value(value)

async def async_protocols(manager, values):
    async with manager as resource:
        await resource.read()
    async for value in values:
        await async_value(value)

def generate(values):
    for value in values:
        yield value
""")
    session = load_analysis_session([target])
    semantics = {
        cfg.code.codeName(): session.adapter.procedure_semantics(cfg)
        for cfg in session.adapter.cfgs
    }

    assert semantics["async_main"].is_async
    assert semantics["generate"].is_generator

    suspension_kinds = {
        effect.kind
        for node in session.adapter.supergraph.ordered_nodes()
        for effect in session.adapter.suspension_effects_of(node)
    }
    assert {"await", "yield"} <= suspension_kinds

    roles = {
        effect.semantic_role
        for node in session.adapter.supergraph.ordered_nodes()
        for effect in (session.adapter.effect_of(node),)
        if isinstance(effect, CallEffect) and effect.semantic_role
    }
    assert {"async_context_enter", "async_context_exit", "async_iter"} <= roles


def test_return_inside_try_runs_finally_before_procedure_exit():
    compiler = context.CompilerContext(None)
    cleanup = ast.Local("cleanup")
    unreachable = ast.Local("unreachable")
    main_code, _ = make_code(
        "main",
        [],
        [
            ast.TryExceptFinally(
                ast.Suite([ast.Return([])]),
                [],
                None,
                None,
                ast.Suite([ast.Assign(ast.Existing(ast.program.Object(1)), [cleanup])]),
            ),
            ast.Assign(ast.Existing(ast.program.Object(2)), [unreachable]),
        ],
    )
    cfg = build_cfg(compiler, main_code)
    adapter = build_supergraph_from_cfgs([cfg])
    return_node = next(
        node
        for node in adapter.supergraph.ordered_nodes_of(cfg)
        if isinstance(adapter.operation_of(node), ast.Return)
    )
    reached = _reachable_nodes(adapter, return_node)

    assert any(
        isinstance(adapter.operation_of(node), ast.Assign)
        and cleanup in adapter.operation_of(node).lcls
        for node in reached
    )
    assert any(node.kind == "exit" for node in reached)
    assert not any(
        isinstance(adapter.operation_of(node), ast.Assign)
        and unreachable in adapter.operation_of(node).lcls
        for node in reached
    )


def test_break_inside_try_skips_loop_else_after_finally():
    compiler = context.CompilerContext(None)
    condition = ast.Local("condition")
    cleanup = ast.Local("cleanup")
    else_only = ast.Local("else_only")
    after_loop = ast.Local("after_loop")
    main_code, _ = make_code(
        "main",
        [condition],
        [
            ast.While(
                ast.Condition(ast.Suite([]), condition),
                ast.Suite(
                    [
                        ast.TryExceptFinally(
                            ast.Suite([ast.Break()]),
                            [],
                            None,
                            None,
                            ast.Suite(
                                [
                                    ast.Assign(
                                        ast.Existing(ast.program.Object(1)),
                                        [cleanup],
                                    )
                                ]
                            ),
                        )
                    ]
                ),
                ast.Suite(
                    [ast.Assign(ast.Existing(ast.program.Object(2)), [else_only])]
                ),
            ),
            ast.Assign(ast.Existing(ast.program.Object(3)), [after_loop]),
            ast.Return([]),
        ],
    )
    cfg = build_cfg(compiler, main_code)
    adapter = build_supergraph_from_cfgs([cfg])
    break_node = next(
        node
        for node in adapter.supergraph.ordered_nodes_of(cfg)
        if isinstance(adapter.operation_of(node), ast.Break)
    )
    reached = _reachable_nodes(adapter, break_node)

    assigned = {
        local
        for node in reached
        if isinstance(adapter.operation_of(node), ast.Assign)
        for local in adapter.operation_of(node).lcls
    }
    assert cleanup in assigned
    assert after_loop in assigned
    assert else_only not in assigned


def test_continue_inside_try_skips_remaining_body_after_finally():
    compiler = context.CompilerContext(None)
    condition = ast.Local("condition")
    cleanup = ast.Local("cleanup")
    skipped = ast.Local("skipped")
    main_code, _ = make_code(
        "main",
        [condition],
        [
            ast.While(
                ast.Condition(ast.Suite([]), condition),
                ast.Suite(
                    [
                        ast.TryExceptFinally(
                            ast.Suite([ast.Continue()]),
                            [],
                            None,
                            None,
                            ast.Suite(
                                [
                                    ast.Assign(
                                        ast.Existing(ast.program.Object(1)),
                                        [cleanup],
                                    )
                                ]
                            ),
                        ),
                        ast.Assign(ast.Existing(ast.program.Object(2)), [skipped]),
                    ]
                ),
                ast.Suite([]),
            ),
            ast.Return([]),
        ],
    )
    cfg = build_cfg(compiler, main_code)
    adapter = build_supergraph_from_cfgs([cfg])
    continue_node = next(
        node
        for node in adapter.supergraph.ordered_nodes_of(cfg)
        if isinstance(adapter.operation_of(node), ast.Continue)
    )
    reached = _reachable_nodes(adapter, continue_node)

    assert any(
        isinstance(adapter.operation_of(node), ast.Assign)
        and cleanup in adapter.operation_of(node).lcls
        for node in reached
    )
    assert not any(
        isinstance(adapter.operation_of(node), ast.Assign)
        and skipped in adapter.operation_of(node).lcls
        for node in reached
    )


def test_abrupt_finally_action_overrides_pending_break():
    compiler = context.CompilerContext(None)
    condition = ast.Local("condition")
    after_loop = ast.Local("after_loop")
    main_code, _ = make_code(
        "main",
        [condition],
        [
            ast.While(
                ast.Condition(ast.Suite([]), condition),
                ast.Suite(
                    [
                        ast.TryExceptFinally(
                            ast.Suite([ast.Break()]),
                            [],
                            None,
                            None,
                            ast.Suite([ast.Return([])]),
                        )
                    ]
                ),
                ast.Suite([]),
            ),
            ast.Assign(ast.Existing(ast.program.Object(1)), [after_loop]),
            ast.Return([]),
        ],
    )
    cfg = build_cfg(compiler, main_code)
    adapter = build_supergraph_from_cfgs([cfg])
    break_node = next(
        node
        for node in adapter.supergraph.ordered_nodes_of(cfg)
        if isinstance(adapter.operation_of(node), ast.Break)
    )
    reached = _reachable_nodes(adapter, break_node)

    assert any(node.kind == "exit" for node in reached)
    assert not any(
        isinstance(adapter.operation_of(node), ast.Assign)
        and after_loop in adapter.operation_of(node).lcls
        for node in reached
    )
