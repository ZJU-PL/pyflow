"""Tests for the IFDS typestate analysis."""

from __future__ import annotations

import pytest

from pyflow.application import context
from pyflow.analysis.ifds import (
    TypestateActionModel,
    TypestateConfiguration,
    TypestateExitObligation,
    TypestateProtocol,
    TypestateTransition,
    analyze_typestate,
    build_supergraph_from_cfgs,
)
from pyflow.analysis.ifds.clients._call_model import CallModel, CallModelRegistry
from pyflow.analysis.ifds.clients.typestate_engine import (
    ACTION_CLOSE,
    ACTION_USE,
    TypestateEngine,
    resource_lifecycle_protocol,
)
from pyflow.language.python import ast

from tests.analysis.ifds._support import build_cfg, make_code


def test_typestate_engine_models_resource_protocol_rules():
    engine = TypestateEngine(
        (
            resource_lifecycle_protocol(
                open_names={"open_resource"},
                close_names={"close_resource"},
                use_names={"use_resource"},
                resource_arg_positions=frozenset({1}),
                track_method_receiver=False,
            ),
        )
    )

    registry = engine.call_model_registry()
    close_model = registry.model_for_name("close_resource")
    use_model = registry.model_for_name("use_resource")

    assert close_model is not None
    assert close_model.typestate_actions == frozenset({ACTION_CLOSE})
    assert close_model.resource_arg_positions == frozenset({1})
    assert close_model.track_method_receiver is False
    transition = engine.transition(ACTION_CLOSE, "open")
    assert transition is not None
    assert transition.to_state == "closed"
    assert [v.kind for v in engine.violations_for(ACTION_USE, "closed")] == [
        "use_after_close"
    ]
    assert [v.kind for v in engine.exit_violations_for("resource", "open")] == [
        "resource_leak"
    ]
    assert use_model is not None


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
    finding = next(f for f in result.findings if f.kind == "use_after_close")
    assert finding.protocol == "resource"
    assert finding.state == "closed"
    assert result.resource_facts_at(finding.node)
    assert "resource" in result.states_at(finding.node)


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


def test_typestate_suppresses_leak_for_returned_resource():
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
    result = analyze_typestate(
        adapter,
        TypestateConfiguration(),
        entry_nodes=[adapter.supergraph.entry_of(cfg)],
    )

    assert not any(f.kind == "resource_leak" for f in result.findings)


def test_typestate_suppresses_leak_for_unresolved_escaped_resource():
    compiler = context.CompilerContext(None)

    resource = ast.Local("resource")
    main_code, _ = make_code(
        "main",
        [],
        [
            ast.Assign(ast.Call(ast.Local("open"), [], [], None, None), [resource]),
            ast.Discard(
                ast.Call(ast.Local("store_elsewhere"), [resource], [], None, None)
            ),
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

    assert not any(f.kind == "resource_leak" for f in result.findings)


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
            ast.Discard(
                ast.Call(ast.Local("close2"), [context_arg, resource], [], None, None)
            ),
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
        finding.kind == "use_after_close"
        and finding.resource_label == "items['payload']"
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


def test_typestate_tracks_collection_extend_source_elements():
    compiler = context.CompilerContext(None)

    src_items = ast.Local("src_items")
    dst_items = ast.Local("dst_items")
    index = ast.Existing(ast.program.Object(0))
    item_get = ast.GetSubscript(dst_items, index)
    main_code, _ = make_code(
        "main",
        [dst_items],
        [
            ast.Assign(
                ast.BuildList([ast.Call(ast.Local("open"), [], [], None, None)]),
                [src_items],
            ),
            ast.Discard(
                ast.MethodCall(
                    dst_items,
                    ast.Local("extend"),
                    [src_items],
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
        finding.kind == "use_after_close" and finding.resource_label == "dst_items[*]"
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
        finding.kind == "use_after_close"
        and finding.resource_label == "items['payload']"
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


def test_typestate_builtin_lock_reports_release_without_acquire():
    compiler = context.CompilerContext(None)

    lock = ast.Local("lock")
    main_code, _ = make_code(
        "main",
        [],
        [
            ast.Assign(
                ast.Call(ast.Local("threading.Lock"), [], [], None, None), [lock]
            ),
            ast.Discard(ast.MethodCall(lock, ast.Local("release"), [], [], None, None)),
            ast.Return([]),
        ],
        return_name="main_ret",
    )

    cfg = build_cfg(compiler, main_code)
    adapter = build_supergraph_from_cfgs([cfg])
    result = analyze_typestate(
        adapter,
        TypestateConfiguration(enabled_protocols=frozenset({"lock"})),
        entry_nodes=[adapter.supergraph.entry_of(cfg)],
    )

    assert any(
        finding.kind == "release_without_acquire"
        and finding.protocol == "lock"
        and finding.state == "unlocked"
        for finding in result.findings
    )


def test_typestate_builtin_lock_context_manager_releases_lock():
    compiler = context.CompilerContext(None)

    lock = ast.Local("lock")
    main_code, _ = make_code(
        "main",
        [],
        [
            ast.Assign(
                ast.Call(ast.Local("threading.Lock"), [], [], None, None), [lock]
            ),
            ast.Discard(
                ast.MethodCall(lock, ast.Local("__enter__"), [], [], None, None)
            ),
            ast.Discard(
                ast.MethodCall(lock, ast.Local("__exit__"), [], [], None, None)
            ),
            ast.Return([]),
        ],
        return_name="main_ret",
    )

    cfg = build_cfg(compiler, main_code)
    adapter = build_supergraph_from_cfgs([cfg])
    result = analyze_typestate(
        adapter,
        TypestateConfiguration(enabled_protocols=frozenset({"lock"})),
        entry_nodes=[adapter.supergraph.entry_of(cfg)],
    )

    assert result.findings == ()


def test_typestate_builtin_socket_reports_use_after_close():
    compiler = context.CompilerContext(None)

    sock = ast.Local("sock")
    main_code, _ = make_code(
        "main",
        [],
        [
            ast.Assign(
                ast.Call(ast.Local("socket.socket"), [], [], None, None), [sock]
            ),
            ast.Discard(ast.MethodCall(sock, ast.Local("close"), [], [], None, None)),
            ast.Discard(ast.MethodCall(sock, ast.Local("send"), [], [], None, None)),
            ast.Return([]),
        ],
        return_name="main_ret",
    )

    cfg = build_cfg(compiler, main_code)
    adapter = build_supergraph_from_cfgs([cfg])
    result = analyze_typestate(
        adapter,
        TypestateConfiguration(enabled_protocols=frozenset({"socket"})),
        entry_nodes=[adapter.supergraph.entry_of(cfg)],
    )

    assert any(
        finding.kind == "use_after_close"
        and finding.protocol == "socket"
        and finding.state == "closed"
        for finding in result.findings
    )


def test_typestate_builtin_transaction_reports_uncommitted_exit():
    compiler = context.CompilerContext(None)

    txn = ast.Local("txn")
    main_code, _ = make_code(
        "main",
        [],
        [
            ast.Assign(ast.Call(ast.Local("begin"), [], [], None, None), [txn]),
            ast.Return([]),
        ],
        return_name="main_ret",
    )

    cfg = build_cfg(compiler, main_code)
    adapter = build_supergraph_from_cfgs([cfg])
    result = analyze_typestate(
        adapter,
        TypestateConfiguration(enabled_protocols=frozenset({"transaction"})),
        entry_nodes=[adapter.supergraph.entry_of(cfg)],
    )

    assert any(
        finding.kind == "uncommitted_transaction"
        and finding.protocol == "transaction"
        and finding.state == "active"
        for finding in result.findings
    )


def test_typestate_constrained_action_only_matches_receiver_type():
    compiler = context.CompilerContext(None)

    db = ast.Local("db")
    other = ast.Local("other")
    db_protocol = TypestateProtocol(
        name="db",
        initial_state="open",
        actions=(
            TypestateActionModel(
                names=frozenset({"make_db"}),
                action="db.open",
                resource_arg_positions=frozenset(),
                track_method_receiver=False,
                creates_resource=True,
            ),
            TypestateActionModel(
                names=frozenset(),
                action="db.close",
                resource_arg_positions=frozenset(),
            ),
        ),
        transitions=(
            TypestateTransition(
                action="db.close",
                from_states=frozenset({"open"}),
                to_state="closed",
            ),
        ),
        violations=(),
        exit_obligations=(
            TypestateExitObligation(
                states=frozenset({"open"}),
                kind="db_leak",
            ),
        ),
    )
    call_models = CallModelRegistry(
        (
            CallModel(
                name="close",
                typestate_actions=frozenset({"db.close"}),
                typestate_action_protocols=frozenset({("db.close", "db")}),
                resource_arg_positions=frozenset({0}),
                track_method_receiver=False,
                receiver_types=frozenset({"make_db"}),
            ),
        )
    )
    main_code, _ = make_code(
        "main",
        [],
        [
            ast.Assign(ast.Call(ast.Local("make_db"), [], [], None, None), [db]),
            ast.Assign(ast.Call(ast.Local("make_other"), [], [], None, None), [other]),
            ast.Discard(ast.Call(ast.Local("close"), [other], [], None, None)),
            ast.Return([]),
        ],
        return_name="main_ret",
    )

    cfg = build_cfg(compiler, main_code)
    adapter = build_supergraph_from_cfgs([cfg])
    result = analyze_typestate(
        adapter,
        TypestateConfiguration(
            enabled_protocols=frozenset(),
            extra_protocols=(db_protocol,),
            call_models=call_models,
        ),
        entry_nodes=[adapter.supergraph.entry_of(cfg)],
    )

    assert any(
        finding.kind == "db_leak"
        and finding.protocol == "db"
        and finding.resource_label == "db"
        for finding in result.findings
    )


def test_typestate_constrained_action_matches_receiver_type():
    compiler = context.CompilerContext(None)

    db = ast.Local("db")
    db_protocol = TypestateProtocol(
        name="db",
        initial_state="open",
        actions=(
            TypestateActionModel(
                names=frozenset({"make_db"}),
                action="db.open",
                resource_arg_positions=frozenset(),
                track_method_receiver=False,
                creates_resource=True,
            ),
            TypestateActionModel(
                names=frozenset(),
                action="db.close",
                resource_arg_positions=frozenset(),
            ),
        ),
        transitions=(
            TypestateTransition(
                action="db.close",
                from_states=frozenset({"open"}),
                to_state="closed",
            ),
        ),
        violations=(),
        exit_obligations=(
            TypestateExitObligation(
                states=frozenset({"open"}),
                kind="db_leak",
            ),
        ),
    )
    call_models = CallModelRegistry(
        (
            CallModel(
                name="close",
                typestate_actions=frozenset({"db.close"}),
                typestate_action_protocols=frozenset({("db.close", "db")}),
                resource_arg_positions=frozenset({0}),
                track_method_receiver=False,
                receiver_types=frozenset({"make_db"}),
            ),
        )
    )
    main_code, _ = make_code(
        "main",
        [],
        [
            ast.Assign(ast.Call(ast.Local("make_db"), [], [], None, None), [db]),
            ast.Discard(ast.Call(ast.Local("close"), [db], [], None, None)),
            ast.Return([]),
        ],
        return_name="main_ret",
    )

    cfg = build_cfg(compiler, main_code)
    adapter = build_supergraph_from_cfgs([cfg])
    result = analyze_typestate(
        adapter,
        TypestateConfiguration(
            enabled_protocols=frozenset(),
            extra_protocols=(db_protocol,),
            call_models=call_models,
        ),
        entry_nodes=[adapter.supergraph.entry_of(cfg)],
    )

    assert not any(finding.kind == "db_leak" for finding in result.findings)


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
