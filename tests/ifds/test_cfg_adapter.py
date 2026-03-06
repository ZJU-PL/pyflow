"""Tests for the CFG-backed IFDS adapter."""

from __future__ import annotations

from types import SimpleNamespace

from pyflow.application import context
from pyflow.analysis.ifds import bind_call_arguments, build_supergraph_from_cfgs
from pyflow.analysis.ifds.cfg_adapter import annotation_invokes_cfg_resolver
from pyflow.language.python import ast
from pyflow.language.python.default_markers import MISSING_DEFAULT

from tests.ifds._support import build_cfg, make_code


def test_cfg_adapter_discovers_direct_call_edges_and_return_sites():
    compiler = context.CompilerContext(None)

    x = ast.Local("x")
    helper_code, _ = make_code("helper", [x], [ast.Return([x])], return_name="helper_ret")

    a = ast.Local("a")
    b = ast.Local("b")
    main_code, _ = make_code(
        "main",
        [a],
        [
            ast.Assign(ast.DirectCall(helper_code, None, [a], [], None, None), [b]),
            ast.Return([b]),
        ],
        return_name="main_ret",
    )

    helper_cfg = build_cfg(compiler, helper_code)
    main_cfg = build_cfg(compiler, main_code)
    adapter = build_supergraph_from_cfgs([main_cfg, helper_cfg])

    call_nodes = [
        node
        for node in adapter.supergraph.nodes_of(main_cfg)
        if adapter.call_expression_of(node) is not None
    ]
    assert len(call_nodes) == 1

    call_node = call_nodes[0]
    assert adapter.callees_of(call_node) == (helper_cfg,)

    return_sites = adapter.supergraph.return_sites_of_call_at(call_node)
    assert len(return_sites) == 1
    return_site = next(iter(return_sites))
    assert isinstance(adapter.operation_of(return_site), ast.Assign)
    successors = adapter.supergraph.normal_successors(return_site)
    assert len(successors) == 1
    assert isinstance(adapter.operation_of(next(iter(successors))), ast.Return)


def test_cfg_adapter_resolves_source_level_named_calls_without_directcall_nodes():
    compiler = context.CompilerContext(None)

    x = ast.Local("x")
    helper_code, _ = make_code("helper", [x], [ast.Return([x])], return_name="helper_ret")

    a = ast.Local("a")
    b = ast.Local("b")
    call = ast.Call(ast.Local("helper"), [a], [], None, None)
    main_code, _ = make_code(
        "main",
        [a],
        [
            ast.Assign(call, [b]),
            ast.Return([b]),
        ],
        return_name="main_ret",
    )

    helper_cfg = build_cfg(compiler, helper_code)
    main_cfg = build_cfg(compiler, main_code)
    adapter = build_supergraph_from_cfgs([main_cfg, helper_cfg])

    call_nodes = [
        node
        for node in adapter.supergraph.nodes_of(main_cfg)
        if adapter.call_expression_of(node) is not None
    ]
    assert len(call_nodes) == 1
    assert adapter.callees_of(call_nodes[0]) == (helper_cfg,)


def test_cfg_adapter_does_not_resolve_ambiguous_named_calls_by_short_name():
    compiler = context.CompilerContext(None)

    x1 = ast.Local("x1")
    helper_code_a, _ = make_code(
        "helper", [x1], [ast.Return([x1])], return_name="helper_ret_a"
    )
    x2 = ast.Local("x2")
    helper_code_b, _ = make_code(
        "helper", [x2], [ast.Return([x2])], return_name="helper_ret_b"
    )

    a = ast.Local("a")
    b = ast.Local("b")
    main_code, _ = make_code(
        "main",
        [a],
        [
            ast.Assign(ast.Call(ast.Local("helper"), [a], [], None, None), [b]),
            ast.Return([b]),
        ],
        return_name="main_ret",
    )

    cfgs = [
        build_cfg(compiler, main_code),
        build_cfg(compiler, helper_code_a),
        build_cfg(compiler, helper_code_b),
    ]
    adapter = build_supergraph_from_cfgs(cfgs)

    call_nodes = [
        node
        for node in adapter.supergraph.nodes_of(cfgs[0])
        if adapter.call_expression_of(node) is not None
    ]
    assert len(call_nodes) == 1
    assert adapter.callees_of(call_nodes[0]) == ()


def test_cfg_adapter_normal_flow_raise_has_no_successor_to_following_statement():
    compiler = context.CompilerContext(None)

    value = ast.Local("value")
    main_code, _ = make_code(
        "main",
        [],
        [
            ast.Raise(ast.Existing(ast.program.Object(ValueError)), None, None),
            ast.Return([value]),
        ],
        return_name="main_ret",
    )

    cfg = build_cfg(compiler, main_code)
    adapter = build_supergraph_from_cfgs([cfg])

    raise_nodes = [
        node
        for node in adapter.supergraph.nodes_of(cfg)
        if isinstance(adapter.operation_of(node), ast.Raise)
    ]
    assert len(raise_nodes) == 1
    assert adapter.supergraph.normal_successors(raise_nodes[0]) == frozenset()


def test_cfg_adapter_routes_try_body_raise_into_except_handler():
    compiler = context.CompilerContext(None)

    handler_value = ast.Local("handler_value")
    handler = ast.ExceptionHandler(
        ast.Suite([]),
        ast.Existing(ast.program.Object(ValueError)),
        None,
        ast.Suite([ast.Assign(ast.Existing(ast.program.Object(1)), [handler_value])]),
    )
    main_code, _ = make_code(
        "main",
        [],
        [
            ast.TryExceptFinally(
                ast.Suite([ast.Raise(ast.Existing(ast.program.Object(ValueError)), None, None)]),
                [handler],
                None,
                None,
                None,
            ),
            ast.Return([handler_value]),
        ],
        return_name="main_ret",
    )

    cfg = build_cfg(compiler, main_code)
    adapter = build_supergraph_from_cfgs([cfg])

    raise_node = next(
        node
        for node in adapter.supergraph.nodes_of(cfg)
        if node.scope == ("0", "try", "body", "0")
    )
    successor_scopes = {successor.scope for successor in adapter.supergraph.normal_successors(raise_node)}
    assert ("0", "try", "handler", "0", "preamble", "empty") in successor_scopes


def test_cfg_adapter_routes_try_finally_normal_and_exceptional_paths_through_finally():
    compiler = context.CompilerContext(None)

    cleanup = ast.Local("cleanup")
    normal_code, _ = make_code(
        "main",
        [],
        [
            ast.TryExceptFinally(
                ast.Suite([ast.Assign(ast.Existing(ast.program.Object(1)), [cleanup])]),
                [],
                None,
                None,
                ast.Suite([ast.Assign(ast.Existing(ast.program.Object(2)), [cleanup])]),
            ),
            ast.Return([cleanup]),
        ],
        return_name="normal_ret",
    )
    exceptional_code, _ = make_code(
        "main_exc",
        [],
        [
            ast.TryExceptFinally(
                ast.Suite([ast.Raise(ast.Existing(ast.program.Object(ValueError)), None, None)]),
                [],
                None,
                None,
                ast.Suite([ast.Assign(ast.Existing(ast.program.Object(3)), [cleanup])]),
            ),
            ast.Return([cleanup]),
        ],
        return_name="exc_ret",
    )

    normal_cfg = build_cfg(compiler, normal_code)
    exceptional_cfg = build_cfg(compiler, exceptional_code)
    normal_adapter = build_supergraph_from_cfgs([normal_cfg])
    exceptional_adapter = build_supergraph_from_cfgs([exceptional_cfg])

    normal_body = next(
        node
        for node in normal_adapter.supergraph.nodes_of(normal_cfg)
        if node.scope == ("0", "try", "body", "0")
    )
    normal_successors = {successor.scope for successor in normal_adapter.supergraph.normal_successors(normal_body)}
    assert ("0", "try", "finally", "normal", "0") in normal_successors

    exceptional_body = next(
        node
        for node in exceptional_adapter.supergraph.nodes_of(exceptional_cfg)
        if node.scope == ("0", "try", "body", "0")
    )
    exceptional_successors = {
        successor.scope
        for successor in exceptional_adapter.supergraph.normal_successors(exceptional_body)
    }
    assert ("0", "try", "finally", "exceptional", "0") in exceptional_successors

    exceptional_finally = next(
        node
        for node in exceptional_adapter.supergraph.nodes_of(exceptional_cfg)
        if node.scope == ("0", "try", "finally", "exceptional", "0")
    )
    assert exceptional_adapter.supergraph.normal_successors(exceptional_finally) == frozenset()


def test_cfg_adapter_preserves_exceptional_successor_for_call_inside_try_finally():
    compiler = context.CompilerContext(None)

    helper_param = ast.Local("helper_param")
    helper_code, _ = make_code(
        "helper",
        [helper_param],
        [ast.Return([helper_param])],
        return_name="helper_ret",
    )
    value = ast.Local("value")
    cleanup = ast.Local("cleanup")
    main_code, _ = make_code(
        "main",
        [],
        [
            ast.TryExceptFinally(
                ast.Suite([ast.Discard(ast.DirectCall(helper_code, None, [value], [], None, None))]),
                [],
                None,
                None,
                ast.Suite([ast.Assign(ast.Existing(ast.program.Object(1)), [cleanup])]),
            ),
            ast.Return([cleanup]),
        ],
        return_name="main_ret",
    )

    helper_cfg = build_cfg(compiler, helper_code)
    main_cfg = build_cfg(compiler, main_code)
    adapter = build_supergraph_from_cfgs([main_cfg, helper_cfg])

    call_node = next(
        node
        for node in adapter.supergraph.nodes_of(main_cfg)
        if node.kind == "call"
    )
    return_sites = adapter.supergraph.return_sites_of_call_at(call_node)
    assert {site.scope for site in return_sites} == {("0", "try", "body", "0")}


def test_bind_call_arguments_maps_keywords_to_matching_formals():
    x = ast.Local("x")
    y = ast.Local("y")
    params = ast.CodeParameters(
        selfparam=None,
        posonlyparams=[],
        posonlynames=[],
        params=[x, y],
        paramnames=["x", "y"],
        defaults=[],
        vparam=None,
        kparam=None,
        returnparams=[],
        type_params=None,
    )
    left = ast.Local("left")
    right = ast.Local("right")
    call = ast.Call(
        ast.Local("choose"),
        [],
        [("y", right), ("x", left)],
        None,
        None,
    )

    assert bind_call_arguments(call, params) == ((right, y), (left, x))


def test_bind_call_arguments_maps_extra_positionals_into_varargs():
    first = ast.Local("first")
    rest = ast.Local("rest")
    params = ast.CodeParameters(
        selfparam=None,
        posonlyparams=[],
        posonlynames=[],
        params=[first],
        paramnames=["first"],
        defaults=[],
        vparam=rest,
        kparam=None,
        returnparams=[],
        type_params=None,
    )
    a = ast.Local("a")
    b = ast.Local("b")
    c = ast.Local("c")
    call = ast.Call(ast.Local("collect"), [a, b, c], [], None, None)

    assert bind_call_arguments(call, params) == ((a, first), (b, rest), (c, rest))


def test_bind_call_arguments_maps_unmatched_keywords_into_kwargs():
    named = ast.Local("named")
    extras = ast.Local("extras")
    params = ast.CodeParameters(
        selfparam=None,
        posonlyparams=[],
        posonlynames=[],
        params=[named],
        paramnames=["named"],
        defaults=[],
        vparam=None,
        kparam=extras,
        returnparams=[],
        type_params=None,
    )
    value = ast.Local("value")
    other = ast.Local("other")
    call = ast.Call(
        ast.Local("collect"),
        [],
        [("named", value), ("other", other)],
        None,
        None,
    )

    assert bind_call_arguments(call, params) == ((value, named), (other, extras))


def test_cfg_adapter_creates_call_nodes_for_nested_calls_in_evaluation_order():
    compiler = context.CompilerContext(None)

    source_code, _ = make_code("source", [], [ast.Return([])], return_name="source_ret")
    wrapper_param = ast.Local("value")
    wrapper_code, _ = make_code(
        "wrapper", [wrapper_param], [ast.Return([wrapper_param])], return_name="wrapper_ret"
    )
    sink_param = ast.Local("sink_value")
    sink_code, _ = make_code("sink", [sink_param], [], return_name="sink_ret")
    main_code, _ = make_code(
        "main",
        [],
        [
            ast.Discard(
                ast.DirectCall(
                    sink_code,
                    None,
                    [
                        ast.DirectCall(
                            wrapper_code,
                            None,
                            [ast.DirectCall(source_code, None, [], [], None, None)],
                            [],
                            None,
                            None,
                        )
                    ],
                    [],
                    None,
                    None,
                )
            ),
            ast.Return([]),
        ],
        return_name="main_ret",
    )

    cfgs = [
        build_cfg(compiler, main_code),
        build_cfg(compiler, source_code),
        build_cfg(compiler, wrapper_code),
        build_cfg(compiler, sink_code),
    ]
    adapter = build_supergraph_from_cfgs(cfgs)

    ordered_nodes = sorted(
        adapter.supergraph.nodes_of(cfgs[0]),
        key=lambda node: (
            node.index if node.index is not None else -1,
            node.call_index if node.call_index is not None else 99,
            node.kind,
        ),
    )
    call_names = [
        adapter.call_expression_of(node).code.codeName()
        for node in ordered_nodes
        if adapter.call_expression_of(node) is not None
    ]

    assert call_names == ["source", "wrapper", "sink"]


def test_annotation_invokes_cfg_resolver_uses_adapter_lookup():
    adapter = SimpleNamespace(cfg_by_ast_code={"target": "cfg_target"})
    call = SimpleNamespace(
        annotation=SimpleNamespace(invokes=((("target", object()),),))
    )

    resolved = annotation_invokes_cfg_resolver(adapter, None, call)

    assert resolved == ("cfg_target",)


def test_bind_call_arguments_does_not_bind_keyword_only_marker_positionally():
    regular = ast.Local("regular")
    kwonly = ast.Local("flag")
    params = ast.CodeParameters(
        selfparam=None,
        posonlyparams=[],
        posonlynames=[],
        params=[regular, kwonly],
        paramnames=["regular", "kwonly:flag"],
        defaults=[],
        vparam=None,
        kparam=None,
        returnparams=[],
        type_params=None,
    )
    first = ast.Local("first")
    second = ast.Local("second")
    call = ast.Call(ast.Local("f"), [first, second], [], None, None)

    assert bind_call_arguments(call, params) == ((first, regular),)


def test_bind_call_arguments_binds_keyword_only_marker_by_name():
    regular = ast.Local("regular")
    kwonly = ast.Local("flag")
    params = ast.CodeParameters(
        selfparam=None,
        posonlyparams=[],
        posonlynames=[],
        params=[regular, kwonly],
        paramnames=["regular", "kwonly:flag"],
        defaults=[],
        vparam=None,
        kparam=None,
        returnparams=[],
        type_params=None,
    )
    first = ast.Local("first")
    enabled = ast.Local("enabled")
    call = ast.Call(ast.Local("f"), [first], [("flag", enabled)], None, None)

    assert bind_call_arguments(call, params) == ((first, regular), (enabled, kwonly))


def test_bind_call_arguments_skips_missing_kwonly_default_placeholders():
    a = ast.Local("a")
    b = ast.Local("b")
    c = ast.Local("c")
    params = ast.CodeParameters(
        selfparam=None,
        posonlyparams=[],
        posonlynames=[],
        params=[a, b, c],
        paramnames=["a", "kwonly:b", "kwonly:c"],
        defaults=[
            ast.Existing(ast.program.Object(1)),
            ast.Existing(ast.program.Object(MISSING_DEFAULT)),
            ast.Existing(ast.program.Object(2)),
        ],
        vparam=None,
        kparam=None,
        returnparams=[],
        type_params=None,
    )
    call = ast.Call(ast.Local("f"), [], [], None, None)

    bindings = bind_call_arguments(call, params)

    assert tuple(formal for _actual, formal in bindings) == (a, c)
    assert tuple(
        getattr(getattr(actual, "object", None), "pyobj", None)
        for actual, _formal in bindings
    ) == (1, 2)


def test_cfg_adapter_handles_yield_expression_in_operation():
    compiler = context.CompilerContext(None)
    value = ast.Local("value")
    main_code, _ = make_code(
        "main",
        [value],
        [ast.Discard(ast.Yield(value)), ast.Return([value])],
        return_name="main_ret",
    )

    cfg = build_cfg(compiler, main_code)
    adapter = build_supergraph_from_cfgs([cfg])
    op_nodes = [
        node
        for node in adapter.supergraph.nodes_of(cfg)
        if isinstance(adapter.operation_of(node), ast.Discard)
    ]
    assert op_nodes


def test_cfg_adapter_handles_await_expression_in_operation():
    compiler = context.CompilerContext(None)
    value = ast.Local("value")
    main_code, _ = make_code(
        "main",
        [value],
        [ast.Discard(ast.Await(ast.Call(ast.Local("coro"), [], [], None, None))), ast.Return([value])],
        return_name="main_ret",
    )

    cfg = build_cfg(compiler, main_code)
    adapter = build_supergraph_from_cfgs([cfg])
    op_nodes = [
        node
        for node in adapter.supergraph.nodes_of(cfg)
        if isinstance(adapter.operation_of(node), ast.Discard)
    ]
    assert op_nodes


def test_cfg_adapter_preserves_yield_edges_when_exceptional_edges_disabled():
    compiler = context.CompilerContext(None)
    value = ast.Local("value")
    main_code, _ = make_code(
        "main",
        [value],
        [ast.Discard(ast.Yield(value)), ast.Return([value])],
        return_name="main_ret",
    )

    cfg = build_cfg(compiler, main_code)
    adapter = build_supergraph_from_cfgs([cfg], include_exceptional_edges=False)

    yield_nodes = [
        node
        for node in adapter.supergraph.nodes_of(cfg)
        if isinstance(getattr(adapter.operation_of(node), "expr", None), ast.Yield)
    ]
    return_nodes = [
        node
        for node in adapter.supergraph.nodes_of(cfg)
        if isinstance(adapter.operation_of(node), ast.Return)
    ]
    assert len(yield_nodes) == 1
    assert len(return_nodes) == 1

    seen = set()
    work = [yield_nodes[0]]
    while work:
        current = work.pop()
        if current in seen:
            continue
        seen.add(current)
        work.extend(adapter.supergraph.normal_successors(current))

    assert return_nodes[0] in seen
