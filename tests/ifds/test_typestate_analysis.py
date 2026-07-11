"""Tests for the IFDS typestate analysis."""

from __future__ import annotations

import pytest

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

    assert any(
        f.kind == "use_after_close" and f.resource_label == "resource"
        for f in result.findings
    )


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

    assert any(
        f.kind == "resource_leak" and f.resource_label == "resource"
        for f in result.findings
    )


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

    assert any(
        f.kind == "use_after_close" and f.resource_label == "resource"
        for f in result.findings
    )


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

    assert any(
        f.kind == "double_close" and f.resource_label == "resource"
        for f in result.findings
    )


def test_typestate_tracks_resource_in_nonfirst_argument():
    compiler = context.CompilerContext(None)

    resource = ast.Local("resource")
    context_arg = ast.Local("context_arg")
    main_code, _ = make_code(
        "main",
        [],
        [
            ast.Assign(ast.Call(ast.Local("open"), [], [], None, None), [resource]),
            ast.Assign(ast.Existing(ast.program.Object(0)), [context_arg]),
            ast.Discard(ast.Call(ast.Local("close2"), [context_arg, resource], [], None, None)),
            ast.Discard(ast.Call(ast.Local("read"), [resource], [], None, None)),
            ast.Return([]),
        ],
        return_name="main_ret",
    )

    cfg = build_cfg(compiler, main_code)
    adapter = build_supergraph_from_cfgs([cfg])
    result = analyze_typestate(
        adapter,
        TypestateConfiguration(
            close_names=frozenset({"close2"}),
            resource_arg_positions=frozenset({0, 1}),
        ),
        entry_nodes=[adapter.supergraph.entry_of(cfg)],
    )

    assert any(
        finding.kind == "use_after_close" and finding.resource_label == "resource"
        for finding in result.findings
    )


def test_typestate_tracks_constant_name_getattr_setattr_field_flow():
    compiler = context.CompilerContext(None)

    obj = ast.Local("obj")
    resource = ast.Local("resource")
    payload = ast.Existing(ast.program.Object("payload"))
    payload_get = ast.Call(ast.Local("getattr"), [obj, payload], [], None, None)
    main_code, _ = make_code(
        "main",
        [obj],
        [
            ast.Assign(ast.Call(ast.Local("open"), [], [], None, None), [resource]),
            ast.Discard(
                ast.Call(
                    ast.Local("setattr"),
                    [obj, payload, resource],
                    [],
                    None,
                    None,
                )
            ),
            ast.Discard(ast.Call(ast.Local("close"), [payload_get], [], None, None)),
            ast.Discard(ast.Call(ast.Local("read"), [payload_get], [], None, None)),
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

    assert any(
        finding.kind == "use_after_close" and finding.resource_label == "obj.payload"
        for finding in result.findings
    )


def test_typestate_tracks_unknown_subscript_write_to_constant_read():
    compiler = context.CompilerContext(None)

    obj = ast.Local("obj")
    key = ast.Local("key")
    resource = ast.Local("resource")
    payload = ast.Existing(ast.program.Object("payload"))
    payload_get = ast.GetSubscript(obj, payload)
    main_code, _ = make_code(
        "main",
        [obj, key],
        [
            ast.Assign(ast.Call(ast.Local("open"), [], [], None, None), [resource]),
            ast.SetSubscript(resource, obj, key),
            ast.Discard(ast.Call(ast.Local("close"), [payload_get], [], None, None)),
            ast.Discard(ast.Call(ast.Local("read"), [payload_get], [], None, None)),
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

    assert any(
        finding.kind == "use_after_close" and finding.resource_label == "obj[*]"
        for finding in result.findings
    )


def test_typestate_tracks_lowered_interpreter_subscript_helpers():
    compiler = context.CompilerContext(None)

    items = ast.Local("items")
    resource = ast.Local("resource")
    key = ast.Existing(ast.program.Object("payload"))
    item_get = ast.Call(
        ast.Existing(ast.program.Object("interpreter_getitem")),
        [items, key],
        [],
        None,
        None,
    )
    main_code, _ = make_code(
        "main",
        [items],
        [
            ast.Assign(ast.Call(ast.Local("open"), [], [], None, None), [resource]),
            ast.Discard(
                ast.Call(
                    ast.Existing(ast.program.Object("interpreter_setitem")),
                    [items, key, resource],
                    [],
                    None,
                    None,
                )
            ),
            ast.Discard(ast.Call(ast.Local("close"), [item_get], [], None, None)),
            ast.Discard(ast.Call(ast.Local("read"), [item_get], [], None, None)),
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

    assert any(
        finding.kind == "use_after_close" and finding.resource_label == "items['payload']"
        for finding in result.findings
    )


def test_typestate_deletes_lowered_subscript_fact():
    compiler = context.CompilerContext(None)

    items = ast.Local("items")
    resource = ast.Local("resource")
    key = ast.Existing(ast.program.Object("payload"))
    item_get = ast.Call(
        ast.Existing(ast.program.Object("interpreter_getitem")),
        [items, key],
        [],
        None,
        None,
    )
    main_code, _ = make_code(
        "main",
        [items],
        [
            ast.Assign(ast.Call(ast.Local("open"), [], [], None, None), [resource]),
            ast.Discard(
                ast.Call(
                    ast.Existing(ast.program.Object("interpreter_setitem")),
                    [items, key, resource],
                    [],
                    None,
                    None,
                )
            ),
            ast.Discard(ast.Call(ast.Local("close"), [item_get], [], None, None)),
            ast.Discard(
                ast.Call(
                    ast.Existing(ast.program.Object("interpreter_delitem")),
                    [items, key],
                    [],
                    None,
                    None,
                )
            ),
            ast.Discard(ast.Call(ast.Local("read"), [item_get], [], None, None)),
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

    assert not any(finding.kind == "use_after_close" for finding in result.findings)


def test_typestate_tracks_collection_mutator_to_subscript_read():
    compiler = context.CompilerContext(None)

    items = ast.Local("items")
    resource = ast.Local("resource")
    index = ast.Existing(ast.program.Object(0))
    item_get = ast.GetSubscript(items, index)
    main_code, _ = make_code(
        "main",
        [items],
        [
            ast.Assign(ast.Call(ast.Local("open"), [], [], None, None), [resource]),
            ast.Discard(
                ast.MethodCall(
                    items,
                    ast.Local("append"),
                    [resource],
                    [],
                    None,
                    None,
                )
            ),
            ast.Discard(ast.Call(ast.Local("close"), [item_get], [], None, None)),
            ast.Discard(ast.Call(ast.Local("read"), [item_get], [], None, None)),
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

    assert any(
        finding.kind == "use_after_close" and finding.resource_label == "items[*]"
        for finding in result.findings
    )


def test_typestate_tracks_function_style_collection_mutator_to_subscript_read():
    compiler = context.CompilerContext(None)

    items = ast.Local("items")
    resource = ast.Local("resource")
    index = ast.Existing(ast.program.Object(0))
    item_get = ast.GetSubscript(items, index)
    main_code, _ = make_code(
        "main",
        [items],
        [
            ast.Assign(ast.Call(ast.Local("open"), [], [], None, None), [resource]),
            ast.Discard(
                ast.Call(
                    ast.Local("append"),
                    [items, resource],
                    [],
                    None,
                    None,
                )
            ),
            ast.Discard(ast.Call(ast.Local("close"), [item_get], [], None, None)),
            ast.Discard(ast.Call(ast.Local("read"), [item_get], [], None, None)),
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

    assert any(
        finding.kind == "use_after_close" and finding.resource_label == "items[*]"
        for finding in result.findings
    )


def test_typestate_tracks_collection_accessor_to_subscript_slot():
    compiler = context.CompilerContext(None)

    items = ast.Local("items")
    resource = ast.Local("resource")
    key = ast.Existing(ast.program.Object("payload"))
    item_get = ast.MethodCall(items, ast.Local("get"), [key], [], None, None)
    main_code, _ = make_code(
        "main",
        [items],
        [
            ast.Assign(ast.Call(ast.Local("open"), [], [], None, None), [resource]),
            ast.SetSubscript(resource, items, key),
            ast.Discard(ast.Call(ast.Local("close"), [item_get], [], None, None)),
            ast.Discard(ast.Call(ast.Local("read"), [item_get], [], None, None)),
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

    assert any(
        finding.kind == "use_after_close" and finding.resource_label == "items['payload']"
        for finding in result.findings
    )


def test_typestate_tracks_tuple_literal_element_to_subscript_read():
    compiler = context.CompilerContext(None)

    items = ast.Local("items")
    index = ast.Existing(ast.program.Object(0))
    item_get = ast.GetSubscript(items, index)
    main_code, _ = make_code(
        "main",
        [],
        [
            ast.Assign(
                ast.BuildTuple([ast.Call(ast.Local("open"), [], [], None, None)]),
                [items],
            ),
            ast.Discard(ast.Call(ast.Local("close"), [item_get], [], None, None)),
            ast.Discard(ast.Call(ast.Local("read"), [item_get], [], None, None)),
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

    assert any(
        finding.kind == "use_after_close" and finding.resource_label == "items[0]"
        for finding in result.findings
    )


def test_typestate_copies_dynamic_subscript_facts_to_alias():
    compiler = context.CompilerContext(None)

    items = ast.Local("items")
    alias = ast.Local("alias")
    resource = ast.Local("resource")
    index = ast.Existing(ast.program.Object(0))
    item_get = ast.GetSubscript(alias, index)
    main_code, _ = make_code(
        "main",
        [items],
        [
            ast.Assign(ast.Call(ast.Local("open"), [], [], None, None), [resource]),
            ast.SetSubscript(resource, items, index),
            ast.Assign(items, [alias]),
            ast.Discard(ast.Call(ast.Local("close"), [item_get], [], None, None)),
            ast.Discard(ast.Call(ast.Local("read"), [item_get], [], None, None)),
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

    assert any(
        finding.kind == "use_after_close" and finding.resource_label == "alias[0]"
        for finding in result.findings
    )


def test_typestate_delete_kills_resource_fact():
    compiler = context.CompilerContext(None)

    resource = ast.Local("resource")
    main_code, _ = make_code(
        "main",
        [],
        [
            ast.Assign(ast.Call(ast.Local("open"), [], [], None, None), [resource]),
            ast.Delete(resource),
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

    assert result.findings == ()


def test_typestate_requires_explicit_entry_nodes():
    compiler = context.CompilerContext(None)

    resource = ast.Local("resource")
    main_code, _ = make_code(
        "main",
        [],
        [
            ast.Assign(ast.Call(ast.Local("open"), [], [], None, None), [resource]),
            ast.Return([resource]),
        ],
        return_name="main_ret",
    )

    cfg = build_cfg(compiler, main_code)
    adapter = build_supergraph_from_cfgs([cfg])

    with pytest.raises(ValueError, match="explicit entry_nodes"):
        analyze_typestate(adapter, TypestateConfiguration())
