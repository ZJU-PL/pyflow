"""Tests for CFG-backed IFDS adapter and shipped taint analysis."""

from __future__ import annotations

from pyflow.application import context
from pyflow.analysis.cfg import transform
from pyflow.analysis.ifds import (
    TaintConfiguration,
    analyze_taint,
    build_supergraph_from_cfgs,
)
from pyflow.language.python import ast


def make_code(name: str, params, body_blocks, *, return_name: str = "ret0"):
    return_param = ast.Local(return_name)
    code = ast.Code(
        name,
        ast.CodeParameters(
            selfparam=None,
            posonlyparams=[],
            posonlynames=[],
            params=list(params),
            paramnames=[param.name for param in params],
            defaults=[],
            vparam=None,
            kparam=None,
            returnparams=[return_param],
            type_params=None,
        ),
        ast.Suite(list(body_blocks)),
    )
    return code, return_param


def build_cfg(compiler, code):
    return transform.evaluate(compiler, code)


def call_stmt(callee_code, args, targets=()):
    direct = ast.DirectCall(callee_code, None, list(args), [], None, None)
    if targets:
        return ast.Assign(direct, list(targets))
    return ast.Discard(direct)


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
            call_stmt(helper_code, [a], [b]),
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
    assert isinstance(adapter.operation_of(return_site), ast.Return)


def test_interprocedural_taint_analysis_reports_only_unsanitized_sink_flow():
    compiler = context.CompilerContext(None)

    source_code, _ = make_code("source", [], [], return_name="source_ret")

    param = ast.Local("param")
    helper_code, _ = make_code(
        "helper", [param], [ast.Return([param])], return_name="helper_ret"
    )

    sanitizer_param = ast.Local("value")
    sanitizer_code, _ = make_code(
        "sanitize",
        [sanitizer_param],
        [ast.Return([sanitizer_param])],
        return_name="sanitize_ret",
    )

    sink_param = ast.Local("sink_value")
    sink_code, _ = make_code("sink", [sink_param], [], return_name="sink_ret")

    a = ast.Local("a")
    b = ast.Local("b")
    c = ast.Local("c")
    main_code, _ = make_code(
        "main",
        [],
        [
            call_stmt(source_code, [], [a]),
            call_stmt(helper_code, [a], [b]),
            call_stmt(sanitizer_code, [b], [c]),
            call_stmt(sink_code, [b]),
            call_stmt(sink_code, [c]),
            ast.Return([c]),
        ],
        return_name="main_ret",
    )

    cfgs = [
        build_cfg(compiler, main_code),
        build_cfg(compiler, source_code),
        build_cfg(compiler, helper_code),
        build_cfg(compiler, sanitizer_code),
        build_cfg(compiler, sink_code),
    ]
    adapter = build_supergraph_from_cfgs(cfgs)
    result = analyze_taint(
        adapter,
        TaintConfiguration(
            source_names=frozenset({"source"}),
            sink_names=frozenset({"sink"}),
            sanitizer_names=frozenset({"sanitize"}),
        ),
        entry_nodes=[adapter.supergraph.entry_of(cfgs[0])],
    )

    assert len(result.findings) == 1
    finding = result.findings[0]
    assert finding.sink_name == "sink"
    assert [local.name for local in finding.tainted_arguments] == ["b"]


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
