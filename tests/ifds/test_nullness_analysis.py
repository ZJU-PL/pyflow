"""Tests for the IFDS nullness analysis."""

from __future__ import annotations

from pyflow.application import context
from pyflow.analysis.ifds import analyze_nullness, build_supergraph_from_cfgs
from pyflow.language.python import ast

from tests.ifds._support import build_cfg, make_code


def test_nullness_reports_attribute_access_on_nullable_local():
    compiler = context.CompilerContext(None)

    value = ast.Local("value")
    payload = ast.Existing(ast.program.Object("payload"))
    main_code, _ = make_code(
        "main",
        [],
        [
            ast.Assign(ast.Existing(ast.program.Object(None)), [value]),
            ast.Discard(ast.GetAttr(value, payload)),
            ast.Return([]),
        ],
        return_name="main_ret",
    )

    cfg = build_cfg(compiler, main_code)
    adapter = build_supergraph_from_cfgs([cfg])
    result = analyze_nullness(adapter, entry_nodes=[adapter.supergraph.entry_of(cfg)])

    assert len(result.findings) == 1
    assert result.findings[0].kind == "attribute_access"
    assert result.findings[0].expression_label == "value"


def test_nullness_refines_is_not_none_guard():
    compiler = context.CompilerContext(None)

    value = ast.Local("value")
    payload = ast.Existing(ast.program.Object("payload"))
    main_code, _ = make_code(
        "main",
        [value],
        [
            ast.Switch(
                ast.Condition(
                    ast.Suite([]),
                    ast.Is(value, ast.Existing(ast.program.Object(None))),
                ),
                ast.Suite([]),
                ast.Suite([ast.Discard(ast.GetAttr(value, payload))]),
            ),
            ast.Return([]),
        ],
        return_name="main_ret",
    )

    cfg = build_cfg(compiler, main_code)
    adapter = build_supergraph_from_cfgs([cfg])
    result = analyze_nullness(adapter, entry_nodes=[adapter.supergraph.entry_of(cfg)])

    assert result.findings == ()


def test_nullness_propagates_nullable_arguments_and_returns():
    compiler = context.CompilerContext(None)

    param = ast.Local("param")
    helper_code, _ = make_code(
        "helper",
        [param],
        [ast.Return([param])],
        return_name="helper_ret",
    )

    value = ast.Local("value")
    out = ast.Local("out")
    payload = ast.Existing(ast.program.Object("payload"))
    main_code, _ = make_code(
        "main",
        [],
        [
            ast.Assign(ast.Existing(ast.program.Object(None)), [value]),
            ast.Assign(ast.Call(ast.Local("helper"), [value], [], None, None), [out]),
            ast.Discard(ast.GetAttr(out, payload)),
            ast.Return([]),
        ],
        return_name="main_ret",
    )

    helper_cfg = build_cfg(compiler, helper_code)
    main_cfg = build_cfg(compiler, main_code)
    adapter = build_supergraph_from_cfgs([main_cfg, helper_cfg])
    result = analyze_nullness(
        adapter,
        entry_nodes=[adapter.supergraph.entry_of(main_cfg)],
    )

    assert len(result.findings) == 1
    assert result.findings[0].expression_label == "out"


def test_nullness_reports_nullable_call_target():
    compiler = context.CompilerContext(None)

    fn = ast.Local("fn")
    main_code, _ = make_code(
        "main",
        [],
        [
            ast.Assign(ast.Existing(ast.program.Object(None)), [fn]),
            ast.Discard(ast.Call(fn, [], [], None, None)),
            ast.Return([]),
        ],
        return_name="main_ret",
    )

    cfg = build_cfg(compiler, main_code)
    adapter = build_supergraph_from_cfgs([cfg])
    result = analyze_nullness(adapter, entry_nodes=[adapter.supergraph.entry_of(cfg)])

    assert len(result.findings) == 1
    assert result.findings[0].kind == "call_target"
    assert result.findings[0].expression_label == "fn"


def test_nullness_refines_lowered_is_not_none_guard():
    compiler = context.CompilerContext(None)

    value = ast.Local("value")
    payload = ast.Existing(ast.program.Object("payload"))
    main_code, _ = make_code(
        "main",
        [],
        [
            ast.Assign(ast.Existing(ast.program.Object(None)), [value]),
            ast.Switch(
                ast.Condition(
                    ast.Suite([]),
                    ast.Call(
                        ast.Existing(ast.program.Object("interpreter__is_not__")),
                        [value, ast.Existing(ast.program.Object(None))],
                        [],
                        None,
                        None,
                    ),
                ),
                ast.Suite([ast.Discard(ast.GetAttr(value, payload))]),
                ast.Suite([]),
            ),
            ast.Return([]),
        ],
        return_name="main_ret",
    )

    cfg = build_cfg(compiler, main_code)
    adapter = build_supergraph_from_cfgs([cfg])
    result = analyze_nullness(adapter, entry_nodes=[adapter.supergraph.entry_of(cfg)])

    assert result.findings == ()


def test_nullness_propagates_default_none_parameter():
    compiler = context.CompilerContext(None)

    param = ast.Local("param")
    helper_ret = ast.Local("helper_ret")
    helper_code = ast.Code(
        "helper",
        ast.CodeParameters(
            selfparam=None,
            posonlyparams=[],
            posonlynames=[],
            params=[param],
            paramnames=["param"],
            defaults=[ast.Existing(ast.program.Object(None))],
            vparam=None,
            kparam=None,
            returnparams=[helper_ret],
            type_params=None,
        ),
        ast.Suite([ast.Return([param])]),
    )

    out = ast.Local("out")
    payload = ast.Existing(ast.program.Object("payload"))
    main_code, _ = make_code(
        "main",
        [],
        [
            ast.Assign(ast.Call(ast.Local("helper"), [], [], None, None), [out]),
            ast.Discard(ast.GetAttr(out, payload)),
            ast.Return([]),
        ],
        return_name="main_ret",
    )

    main_cfg = build_cfg(compiler, main_code)
    helper_cfg = build_cfg(compiler, helper_code)
    adapter = build_supergraph_from_cfgs([main_cfg, helper_cfg])
    result = analyze_nullness(adapter, entry_nodes=[adapter.supergraph.entry_of(main_cfg)])

    assert any(
        finding.kind == "attribute_access" and finding.expression_label == "out"
        for finding in result.findings
    )


def test_nullness_delete_kills_local_fact():
    compiler = context.CompilerContext(None)

    value = ast.Local("value")
    payload = ast.Existing(ast.program.Object("payload"))
    main_code, _ = make_code(
        "main",
        [],
        [
            ast.Assign(ast.Existing(ast.program.Object(None)), [value]),
            ast.Delete(value),
            ast.Discard(ast.GetAttr(value, payload)),
            ast.Return([]),
        ],
        return_name="main_ret",
    )

    cfg = build_cfg(compiler, main_code)
    adapter = build_supergraph_from_cfgs([cfg])
    result = analyze_nullness(adapter, entry_nodes=[adapter.supergraph.entry_of(cfg)])

    assert result.findings == ()
