"""Tests for the IFDS nullness analysis."""

from __future__ import annotations

import pytest

from pyflow.application import context
from pyflow.analysis.ifds import (
    NullnessConfiguration,
    analyze_nullness,
    build_supergraph_from_cfgs,
)
from pyflow.language.python import ast

from tests.analysis.ifds._support import build_cfg, make_code


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


def test_nullness_tracks_constant_name_getattr_setattr_field_flow():
    compiler = context.CompilerContext(None)

    obj = ast.Local("obj")
    out = ast.Local("out")
    payload = ast.Existing(ast.program.Object("payload"))
    attr = ast.Existing(ast.program.Object("attr"))
    main_code, _ = make_code(
        "main",
        [obj],
        [
            ast.Discard(
                ast.Call(
                    ast.Local("setattr"),
                    [obj, payload, ast.Existing(ast.program.Object(None))],
                    [],
                    None,
                    None,
                )
            ),
            ast.Assign(ast.Call(ast.Local("getattr"), [obj, payload], [], None, None), [out]),
            ast.Discard(ast.GetAttr(out, attr)),
            ast.Return([]),
        ],
        return_name="main_ret",
    )

    cfg = build_cfg(compiler, main_code)
    adapter = build_supergraph_from_cfgs([cfg])
    result = analyze_nullness(adapter, entry_nodes=[adapter.supergraph.entry_of(cfg)])

    assert len(result.findings) == 1
    assert result.findings[0].kind == "attribute_access"
    assert result.findings[0].expression_label == "out"


def test_nullness_tracks_unknown_name_setattr_to_constant_getattr():
    compiler = context.CompilerContext(None)

    obj = ast.Local("obj")
    name = ast.Local("name")
    out = ast.Local("out")
    payload = ast.Existing(ast.program.Object("payload"))
    attr = ast.Existing(ast.program.Object("attr"))
    main_code, _ = make_code(
        "main",
        [obj, name],
        [
            ast.Discard(
                ast.Call(
                    ast.Local("setattr"),
                    [obj, name, ast.Existing(ast.program.Object(None))],
                    [],
                    None,
                    None,
                )
            ),
            ast.Assign(ast.Call(ast.Local("getattr"), [obj, payload], [], None, None), [out]),
            ast.Discard(ast.GetAttr(out, attr)),
            ast.Return([]),
        ],
        return_name="main_ret",
    )

    cfg = build_cfg(compiler, main_code)
    adapter = build_supergraph_from_cfgs([cfg])
    result = analyze_nullness(adapter, entry_nodes=[adapter.supergraph.entry_of(cfg)])

    assert len(result.findings) == 1
    assert result.findings[0].kind == "attribute_access"
    assert result.findings[0].expression_label == "out"


def test_nullness_tracks_unknown_subscript_write_to_constant_read():
    compiler = context.CompilerContext(None)

    obj = ast.Local("obj")
    key = ast.Local("key")
    out = ast.Local("out")
    payload = ast.Existing(ast.program.Object("payload"))
    attr = ast.Existing(ast.program.Object("attr"))
    main_code, _ = make_code(
        "main",
        [obj, key],
        [
            ast.SetSubscript(ast.Existing(ast.program.Object(None)), obj, key),
            ast.Assign(ast.GetSubscript(obj, payload), [out]),
            ast.Discard(ast.GetAttr(out, attr)),
            ast.Return([]),
        ],
        return_name="main_ret",
    )

    cfg = build_cfg(compiler, main_code)
    adapter = build_supergraph_from_cfgs([cfg])
    result = analyze_nullness(adapter, entry_nodes=[adapter.supergraph.entry_of(cfg)])

    assert len(result.findings) == 1
    assert result.findings[0].kind == "attribute_access"
    assert result.findings[0].expression_label == "out"


def test_nullness_tracks_lowered_interpreter_subscript_helpers():
    compiler = context.CompilerContext(None)

    items = ast.Local("items")
    out = ast.Local("out")
    key = ast.Existing(ast.program.Object("payload"))
    attr = ast.Existing(ast.program.Object("attr"))
    main_code, _ = make_code(
        "main",
        [items],
        [
            ast.Discard(
                ast.Call(
                    ast.Existing(ast.program.Object("interpreter_setitem")),
                    [items, key, ast.Existing(ast.program.Object(None))],
                    [],
                    None,
                    None,
                )
            ),
            ast.Assign(
                ast.Call(
                    ast.Existing(ast.program.Object("interpreter_getitem")),
                    [items, key],
                    [],
                    None,
                    None,
                ),
                [out],
            ),
            ast.Discard(ast.GetAttr(out, attr)),
            ast.Return([]),
        ],
        return_name="main_ret",
    )

    cfg = build_cfg(compiler, main_code)
    adapter = build_supergraph_from_cfgs([cfg])
    result = analyze_nullness(adapter, entry_nodes=[adapter.supergraph.entry_of(cfg)])

    assert len(result.findings) == 1
    assert result.findings[0].kind == "attribute_access"
    assert result.findings[0].expression_label == "out"


def test_nullness_deletes_lowered_subscript_fact():
    compiler = context.CompilerContext(None)

    items = ast.Local("items")
    out = ast.Local("out")
    key = ast.Existing(ast.program.Object("payload"))
    attr = ast.Existing(ast.program.Object("attr"))
    getitem = ast.Call(
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
            ast.Discard(
                ast.Call(
                    ast.Existing(ast.program.Object("interpreter_setitem")),
                    [items, key, ast.Existing(ast.program.Object(None))],
                    [],
                    None,
                    None,
                )
            ),
            ast.Discard(
                ast.Call(
                    ast.Existing(ast.program.Object("interpreter_delitem")),
                    [items, key],
                    [],
                    None,
                    None,
                )
            ),
            ast.Assign(getitem, [out]),
            ast.Discard(ast.GetAttr(out, attr)),
            ast.Return([]),
        ],
        return_name="main_ret",
    )

    cfg = build_cfg(compiler, main_code)
    adapter = build_supergraph_from_cfgs([cfg])
    result = analyze_nullness(adapter, entry_nodes=[adapter.supergraph.entry_of(cfg)])

    assert result.findings == ()


def test_nullness_tracks_collection_mutator_to_subscript_read():
    compiler = context.CompilerContext(None)

    items = ast.Local("items")
    out = ast.Local("out")
    index = ast.Existing(ast.program.Object(0))
    attr = ast.Existing(ast.program.Object("attr"))
    main_code, _ = make_code(
        "main",
        [items],
        [
            ast.Discard(
                ast.MethodCall(
                    items,
                    ast.Local("append"),
                    [ast.Existing(ast.program.Object(None))],
                    [],
                    None,
                    None,
                )
            ),
            ast.Assign(ast.GetSubscript(items, index), [out]),
            ast.Discard(ast.GetAttr(out, attr)),
            ast.Return([]),
        ],
        return_name="main_ret",
    )

    cfg = build_cfg(compiler, main_code)
    adapter = build_supergraph_from_cfgs([cfg])
    result = analyze_nullness(adapter, entry_nodes=[adapter.supergraph.entry_of(cfg)])

    assert len(result.findings) == 1
    assert result.findings[0].kind == "attribute_access"
    assert result.findings[0].expression_label == "out"


def test_nullness_tracks_function_style_collection_mutator_to_subscript_read():
    compiler = context.CompilerContext(None)

    items = ast.Local("items")
    out = ast.Local("out")
    index = ast.Existing(ast.program.Object(0))
    attr = ast.Existing(ast.program.Object("attr"))
    main_code, _ = make_code(
        "main",
        [items],
        [
            ast.Discard(
                ast.Call(
                    ast.Local("append"),
                    [items, ast.Existing(ast.program.Object(None))],
                    [],
                    None,
                    None,
                )
            ),
            ast.Assign(ast.GetSubscript(items, index), [out]),
            ast.Discard(ast.GetAttr(out, attr)),
            ast.Return([]),
        ],
        return_name="main_ret",
    )

    cfg = build_cfg(compiler, main_code)
    adapter = build_supergraph_from_cfgs([cfg])
    result = analyze_nullness(adapter, entry_nodes=[adapter.supergraph.entry_of(cfg)])

    assert len(result.findings) == 1
    assert result.findings[0].kind == "attribute_access"
    assert result.findings[0].expression_label == "out"


def test_nullness_tracks_collection_update_source_elements():
    compiler = context.CompilerContext(None)

    src_mapping = ast.Local("src_mapping")
    dst_mapping = ast.Local("dst_mapping")
    out = ast.Local("out")
    key = ast.Existing(ast.program.Object("payload"))
    attr = ast.Existing(ast.program.Object("attr"))
    main_code, _ = make_code(
        "main",
        [dst_mapping],
        [
            ast.Assign(
                ast.BuildMap([key, ast.Existing(ast.program.Object(None))]),
                [src_mapping],
            ),
            ast.Discard(
                ast.MethodCall(
                    dst_mapping,
                    ast.Local("update"),
                    [src_mapping],
                    [],
                    None,
                    None,
                )
            ),
            ast.Assign(ast.GetSubscript(dst_mapping, key), [out]),
            ast.Discard(ast.GetAttr(out, attr)),
            ast.Return([]),
        ],
        return_name="main_ret",
    )

    cfg = build_cfg(compiler, main_code)
    adapter = build_supergraph_from_cfgs([cfg])
    result = analyze_nullness(adapter, entry_nodes=[adapter.supergraph.entry_of(cfg)])

    assert len(result.findings) == 1
    assert result.findings[0].kind == "attribute_access"
    assert result.findings[0].expression_label == "out"


def test_nullness_tracks_collection_accessor_to_subscript_slot():
    compiler = context.CompilerContext(None)

    items = ast.Local("items")
    out = ast.Local("out")
    key = ast.Existing(ast.program.Object("payload"))
    attr = ast.Existing(ast.program.Object("attr"))
    main_code, _ = make_code(
        "main",
        [items],
        [
            ast.SetSubscript(ast.Existing(ast.program.Object(None)), items, key),
            ast.Assign(ast.MethodCall(items, ast.Local("get"), [key], [], None, None), [out]),
            ast.Discard(ast.GetAttr(out, attr)),
            ast.Return([]),
        ],
        return_name="main_ret",
    )

    cfg = build_cfg(compiler, main_code)
    adapter = build_supergraph_from_cfgs([cfg])
    result = analyze_nullness(adapter, entry_nodes=[adapter.supergraph.entry_of(cfg)])

    assert len(result.findings) == 1
    assert result.findings[0].kind == "attribute_access"
    assert result.findings[0].expression_label == "out"


def test_nullness_tracks_dict_literal_value_to_collection_accessor():
    compiler = context.CompilerContext(None)

    mapping = ast.Local("mapping")
    out = ast.Local("out")
    key = ast.Existing(ast.program.Object("payload"))
    attr = ast.Existing(ast.program.Object("attr"))
    main_code, _ = make_code(
        "main",
        [],
        [
            ast.Assign(
                ast.BuildMap([key, ast.Existing(ast.program.Object(None))]),
                [mapping],
            ),
            ast.Assign(
                ast.MethodCall(mapping, ast.Local("get"), [key], [], None, None),
                [out],
            ),
            ast.Discard(ast.GetAttr(out, attr)),
            ast.Return([]),
        ],
        return_name="main_ret",
    )

    cfg = build_cfg(compiler, main_code)
    adapter = build_supergraph_from_cfgs([cfg])
    result = analyze_nullness(adapter, entry_nodes=[adapter.supergraph.entry_of(cfg)])

    assert len(result.findings) == 1
    assert result.findings[0].kind == "attribute_access"
    assert result.findings[0].expression_label == "out"


def test_nullness_copies_dynamic_attribute_facts_to_alias():
    compiler = context.CompilerContext(None)

    obj = ast.Local("obj")
    alias = ast.Local("alias")
    out = ast.Local("out")
    payload = ast.Existing(ast.program.Object("payload"))
    attr = ast.Existing(ast.program.Object("attr"))
    main_code, _ = make_code(
        "main",
        [obj],
        [
            ast.Discard(
                ast.Call(
                    ast.Local("setattr"),
                    [obj, payload, ast.Existing(ast.program.Object(None))],
                    [],
                    None,
                    None,
                )
            ),
            ast.Assign(obj, [alias]),
            ast.Assign(ast.Call(ast.Local("getattr"), [alias, payload], [], None, None), [out]),
            ast.Discard(ast.GetAttr(out, attr)),
            ast.Return([]),
        ],
        return_name="main_ret",
    )

    cfg = build_cfg(compiler, main_code)
    adapter = build_supergraph_from_cfgs([cfg])
    result = analyze_nullness(adapter, entry_nodes=[adapter.supergraph.entry_of(cfg)])

    assert len(result.findings) == 1
    assert result.findings[0].kind == "attribute_access"
    assert result.findings[0].expression_label == "out"


def test_nullness_models_nullable_return_from_unresolved_library_call():
    compiler = context.CompilerContext(None)

    out = ast.Local("out")
    payload = ast.Existing(ast.program.Object("payload"))
    main_code, _ = make_code(
        "main",
        [],
        [
            ast.Assign(ast.Call(ast.Local("maybe_none"), [], [], None, None), [out]),
            ast.Discard(ast.GetAttr(out, payload)),
            ast.Return([]),
        ],
        return_name="main_ret",
    )

    cfg = build_cfg(compiler, main_code)
    adapter = build_supergraph_from_cfgs([cfg])
    result = analyze_nullness(
        adapter,
        NullnessConfiguration(nullable_return_names=frozenset({"maybe_none"})),
        entry_nodes=[adapter.supergraph.entry_of(cfg)],
    )

    assert len(result.findings) == 1
    assert result.findings[0].kind == "attribute_access"
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


def test_nullness_respects_configuration_call_models():
    """NullnessConfiguration.call_models should merge with nullable_return_names."""
    from pyflow.analysis.ifds.clients._call_model import CallModel, CallModelRegistry

    custom_models = CallModelRegistry([
        CallModel(name="custom_lookup", nullness_nullable_return=True),
    ])
    config = NullnessConfiguration(
        nullable_return_names=frozenset({"get"}),
        call_models=custom_models,
    )
    # Verify that both sources are represented in the merged models
    merged = CallModelRegistry.from_nullness_configuration(config)
    if config.call_models is not None:
        merged = merged.merged(config.call_models)

    assert merged.model_for_name("get").nullness_nullable_return is True
    assert merged.model_for_name("custom_lookup").nullness_nullable_return is True
    assert merged.model_for_name("nonexistent") is None


def test_nullness_requires_explicit_entry_nodes():
    compiler = context.CompilerContext(None)

    value = ast.Local("value")
    main_code, _ = make_code(
        "main",
        [],
        [
            ast.Assign(ast.Existing(ast.program.Object(None)), [value]),
            ast.Return([value]),
        ],
        return_name="main_ret",
    )

    cfg = build_cfg(compiler, main_code)
    adapter = build_supergraph_from_cfgs([cfg])

    with pytest.raises(ValueError, match="explicit entry_nodes"):
        analyze_nullness(adapter)
