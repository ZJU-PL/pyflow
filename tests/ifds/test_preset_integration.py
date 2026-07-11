from __future__ import annotations

from pyflow.application import context
from pyflow.analysis.ifds import (
    NullnessConfiguration,
    TaintConfiguration,
    TypestateConfiguration,
    analyze_nullness,
    analyze_taint,
    analyze_typestate,
    build_supergraph_from_cfgs,
)
from pyflow.analysis.ifds.clients.library_presets import (
    NULLNESS_PRESETS,
    TAINT_PRESETS,
    TAINT_SANITIZER_PRESETS,
    TAINT_SINK_PRESETS,
)
from pyflow.language.python import ast

from tests.ifds._support import build_cfg, make_code


def test_preset_nullable_return_detected():
    compiler = context.CompilerContext(None)

    value = ast.Local("value")
    result = ast.Local("result")
    main_code, _ = make_code(
        "main",
        [value],
        [
            ast.Assign(
                ast.Call(ast.Local("get"), [value, ast.Local("key")], [], None, None),
                [result],
            ),
            ast.Discard(ast.GetAttr(result, ast.Existing(ast.program.Object("payload")))),
            ast.Return([]),
        ],
        return_name="main_ret",
    )

    cfg = build_cfg(compiler, main_code)
    adapter = build_supergraph_from_cfgs([cfg])

    result = analyze_nullness(
        adapter,
        NullnessConfiguration(
            nullable_return_names=NULLNESS_PRESETS.as_mapping().keys(),
        ),
        entry_nodes=[adapter.supergraph.entry_of(cfg)],
    )

    assert len(result.findings) >= 1
    assert any(f.kind == "attribute_access" for f in result.findings)


def test_preset_taint_source_sink_with_sanitizer():
    compiler = context.CompilerContext(None)

    val = ast.Local("val")
    main_code, _ = make_code(
        "main",
        [],
        [
            ast.Assign(
                ast.Call(ast.Local("input"), [], [], None, None),
                [val],
            ),
            ast.Assign(
                ast.Call(ast.Local("str.strip"), [val], [], None, None),
                [val],
            ),
            ast.Discard(
                ast.Call(
                    ast.Local("os.system"),
                    [val],
                    [],
                    None,
                    None,
                )
            ),
            ast.Return([]),
        ],
        return_name="main_ret",
    )

    cfg = build_cfg(compiler, main_code)
    adapter = build_supergraph_from_cfgs([cfg])

    config = TaintConfiguration(
        source_names=TAINT_PRESETS.as_mapping().keys(),
        sink_names=TAINT_SINK_PRESETS.as_mapping().keys(),
        sanitizer_names=TAINT_SANITIZER_PRESETS.as_mapping().keys(),
    )
    result = analyze_taint(adapter, config, entry_nodes=[adapter.supergraph.entry_of(cfg)])

    assert len(result.findings) == 0


def test_preset_taint_without_sanitizer_reports_sink():
    compiler = context.CompilerContext(None)

    val = ast.Local("val")
    main_code, _ = make_code(
        "main",
        [],
        [
            ast.Assign(
                ast.Call(ast.Local("input"), [], [], None, None),
                [val],
            ),
            ast.Discard(
                ast.Call(
                    ast.Local("os.system"),
                    [val],
                    [],
                    None,
                    None,
                )
            ),
            ast.Return([]),
        ],
        return_name="main_ret",
    )

    cfg = build_cfg(compiler, main_code)
    adapter = build_supergraph_from_cfgs([cfg])

    config = TaintConfiguration(
        source_names=TAINT_PRESETS.as_mapping().keys(),
        sink_names=TAINT_SINK_PRESETS.as_mapping().keys(),
        sanitizer_names=frozenset(),
    )
    result = analyze_taint(adapter, config, entry_nodes=[adapter.supergraph.entry_of(cfg)])

    assert len(result.findings) == 1


def test_preset_typestate_detects_double_close():
    compiler = context.CompilerContext(None)

    file_var = ast.Local("f")
    main_code, _ = make_code(
        "main",
        [],
        [
            ast.Assign(
                ast.Call(ast.Local("open"), [ast.Local("name")], [], None, None),
                [file_var],
            ),
            ast.Discard(
                ast.MethodCall(file_var, ast.Local("close"), [], [], None, None)
            ),
            ast.Discard(
                ast.MethodCall(file_var, ast.Local("close"), [], [], None, None)
            ),
            ast.Return([]),
        ],
        return_name="main_ret",
    )

    cfg = build_cfg(compiler, main_code)
    adapter = build_supergraph_from_cfgs([cfg])

    from pyflow.analysis.ifds.clients.library_presets import (
        TYPESTATE_CLOSE_PRESETS,
        TYPESTATE_OPEN_PRESETS,
        TYPESTATE_USE_PRESETS,
    )

    config = TypestateConfiguration(
        open_names=TYPESTATE_OPEN_PRESETS.as_mapping().keys(),
        close_names=TYPESTATE_CLOSE_PRESETS.as_mapping().keys(),
        use_names=TYPESTATE_USE_PRESETS.as_mapping().keys(),
    )
    result = analyze_typestate(adapter, config, entry_nodes=[adapter.supergraph.entry_of(cfg)])

    assert any(f.kind == "double_close" for f in result.findings)


def test_preset_typestate_detects_use_after_close():
    compiler = context.CompilerContext(None)

    file_var = ast.Local("f")
    main_code, _ = make_code(
        "main",
        [],
        [
            ast.Assign(
                ast.Call(ast.Local("open"), [ast.Local("name")], [], None, None),
                [file_var],
            ),
            ast.Discard(
                ast.MethodCall(file_var, ast.Local("close"), [], [], None, None)
            ),
            ast.Discard(
                ast.MethodCall(file_var, ast.Local("read"), [], [], None, None)
            ),
            ast.Return([]),
        ],
        return_name="main_ret",
    )

    cfg = build_cfg(compiler, main_code)
    adapter = build_supergraph_from_cfgs([cfg])

    from pyflow.analysis.ifds.clients.library_presets import (
        TYPESTATE_CLOSE_PRESETS,
        TYPESTATE_OPEN_PRESETS,
        TYPESTATE_USE_PRESETS,
    )

    config = TypestateConfiguration(
        open_names=TYPESTATE_OPEN_PRESETS.as_mapping().keys(),
        close_names=TYPESTATE_CLOSE_PRESETS.as_mapping().keys(),
        use_names=TYPESTATE_USE_PRESETS.as_mapping().keys(),
    )
    result = analyze_typestate(adapter, config, entry_nodes=[adapter.supergraph.entry_of(cfg)])

    assert any(f.kind == "use_after_close" for f in result.findings)
