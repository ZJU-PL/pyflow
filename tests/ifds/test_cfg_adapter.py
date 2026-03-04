"""Tests for the CFG-backed IFDS adapter."""

from __future__ import annotations

from pyflow.application import context
from pyflow.analysis.ifds import bind_call_arguments, build_supergraph_from_cfgs
from pyflow.language.python import ast

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
