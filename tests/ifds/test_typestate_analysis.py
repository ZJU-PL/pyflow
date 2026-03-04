"""Tests for the IFDS typestate analysis."""

from __future__ import annotations

from pyflow.application import context
from pyflow.analysis.ifds import (
    TypestateConfiguration,
    analyze_typestate,
    build_supergraph_from_cfgs,
)
from pyflow.language.python import ast

from tests.ifds._support import build_cfg, make_code


def test_typestate_reports_use_after_close():
    compiler = context.CompilerContext(None)

    resource = ast.Local("resource")
    main_code, _ = make_code(
        "main",
        [],
        [
            ast.Assign(ast.Call(ast.Local("open"), [], [], None, None), [resource]),
            ast.Discard(ast.Call(ast.Local("close"), [resource], [], None, None)),
            ast.Discard(ast.Call(ast.Local("read"), [resource], [], None, None)),
            ast.Return([]),
        ],
        return_name="main_ret",
    )

    cfg = build_cfg(compiler, main_code)
    adapter = build_supergraph_from_cfgs([cfg])
    result = analyze_typestate(
        adapter,
        TypestateConfiguration(),
        entry_nodes=[adapter.supergraph.entry_of(cfg)],
    )

    assert any(f.kind == "use_after_close" and f.resource_label == "resource" for f in result.findings)


def test_typestate_reports_resource_leak_at_exit():
    compiler = context.CompilerContext(None)

    resource = ast.Local("resource")
    main_code, _ = make_code(
        "main",
        [],
        [
            ast.Assign(ast.Call(ast.Local("open"), [], [], None, None), [resource]),
            ast.Return([]),
        ],
        return_name="main_ret",
    )

    cfg = build_cfg(compiler, main_code)
    adapter = build_supergraph_from_cfgs([cfg])
    result = analyze_typestate(
        adapter,
        TypestateConfiguration(),
        entry_nodes=[adapter.supergraph.entry_of(cfg)],
    )

    assert any(f.kind == "resource_leak" and f.resource_label == "resource" for f in result.findings)


def test_typestate_propagates_closed_state_through_helper():
    compiler = context.CompilerContext(None)

    param = ast.Local("param")
    helper_code, _ = make_code(
        "helper",
        [param],
        [
            ast.Discard(ast.Call(ast.Local("close"), [param], [], None, None)),
            ast.Return([]),
        ],
        return_name="helper_ret",
    )

    resource = ast.Local("resource")
    main_code, _ = make_code(
        "main",
        [],
        [
            ast.Assign(ast.Call(ast.Local("open"), [], [], None, None), [resource]),
            ast.Discard(ast.Call(ast.Local("helper"), [resource], [], None, None)),
            ast.Discard(ast.Call(ast.Local("read"), [resource], [], None, None)),
            ast.Return([]),
        ],
        return_name="main_ret",
    )

    helper_cfg = build_cfg(compiler, helper_code)
    main_cfg = build_cfg(compiler, main_code)
    adapter = build_supergraph_from_cfgs([main_cfg, helper_cfg])
    result = analyze_typestate(
        adapter,
        TypestateConfiguration(),
        entry_nodes=[adapter.supergraph.entry_of(main_cfg)],
    )

    assert any(f.kind == "use_after_close" and f.resource_label == "resource" for f in result.findings)


def test_typestate_reports_double_close():
    compiler = context.CompilerContext(None)

    resource = ast.Local("resource")
    main_code, _ = make_code(
        "main",
        [],
        [
            ast.Assign(ast.Call(ast.Local("open"), [], [], None, None), [resource]),
            ast.Discard(ast.Call(ast.Local("close"), [resource], [], None, None)),
            ast.Discard(ast.Call(ast.Local("close"), [resource], [], None, None)),
            ast.Return([]),
        ],
        return_name="main_ret",
    )

    cfg = build_cfg(compiler, main_code)
    adapter = build_supergraph_from_cfgs([cfg])
    result = analyze_typestate(
        adapter,
        TypestateConfiguration(),
        entry_nodes=[adapter.supergraph.entry_of(cfg)],
    )

    assert any(f.kind == "double_close" and f.resource_label == "resource" for f in result.findings)
