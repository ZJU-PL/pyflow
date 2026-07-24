"""Tests for the shipped IFDS taint analysis."""

from __future__ import annotations

import pytest

from pyflow.application import context
from pyflow.application.errors import TemporaryLimitation
from pyflow.ir.cfg import transform
from pyflow.analysis.ifds import (
    HeapObjectKind,
    TaintConfiguration,
    analyze_taint,
    build_supergraph_from_cfgs,
)
from pyflow.analysis.ifds.modeling.calls import CallModel, CallModelRegistry
from pyflow.analysis.taint import TaintRule
from pyflow.language.python import ast

from tests.analysis.ifds._support import build_cfg, call_stmt, make_code


def _config(
    *,
    source_names=frozenset(),
    sink_names=frozenset(),
    sanitizer_names=frozenset(),
    **options,
):
    models = [
        *(
            CallModel(name, source_kinds=frozenset({"test.source"}))
            for name in source_names
        ),
        *(CallModel(name, sink_kinds=frozenset({"test.sink"})) for name in sink_names),
        *(
            CallModel(name, sanitizer_kinds=frozenset({"*"}))
            for name in sanitizer_names
        ),
    ]
    rules = (
        TaintRule(
            "TEST-TAINT",
            "Test taint flow",
            frozenset({"test.source"}),
            frozenset({"test.sink"}),
        ),
    )
    return TaintConfiguration(
        call_models=CallModelRegistry(models),
        rules=rules,
        **options,
    )


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
        _config(
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


def test_typed_rules_only_report_matching_source_sink_kinds():
    compiler = context.CompilerContext(None)
    source_code, _ = make_code("source", [], [], return_name="source_ret")
    sink_value = ast.Local("value")
    sink_code, _ = make_code("sink", [sink_value], [], return_name="sink_ret")
    value = ast.Local("value")
    main_code, _ = make_code(
        "main",
        [],
        [
            call_stmt(source_code, [], [value]),
            call_stmt(sink_code, [value]),
            ast.Return([]),
        ],
        return_name="main_ret",
    )
    cfgs = [build_cfg(compiler, code) for code in (main_code, source_code, sink_code)]
    adapter = build_supergraph_from_cfgs(cfgs)
    models = CallModelRegistry(
        [
            CallModel("source", source_kinds=frozenset({"network"})),
            CallModel("sink", sink_kinds=frozenset({"sql"})),
        ]
    )

    result = analyze_taint(
        adapter,
        TaintConfiguration(
            call_models=models,
            rules=(
                TaintRule(
                    "NO-MATCH",
                    "Only HTTP input is dangerous",
                    frozenset({"http"}),
                    frozenset({"sql"}),
                ),
            ),
        ),
        entry_nodes=[adapter.supergraph.entry_of(cfgs[0])],
    )
    assert result.findings == ()


def test_typed_rules_record_matched_kinds_and_rule():
    compiler = context.CompilerContext(None)
    source_code, _ = make_code("source", [], [], return_name="source_ret")
    sink_value = ast.Local("value")
    sink_code, _ = make_code("sink", [sink_value], [], return_name="sink_ret")
    value = ast.Local("value")
    main_code, _ = make_code(
        "main",
        [],
        [call_stmt(source_code, [], [value]), call_stmt(sink_code, [value])],
        return_name="main_ret",
    )
    cfgs = [build_cfg(compiler, code) for code in (main_code, source_code, sink_code)]
    adapter = build_supergraph_from_cfgs(cfgs)
    rule = TaintRule(
        "SQL-001",
        "SQL injection",
        frozenset({"http"}),
        frozenset({"sql"}),
        severity="high",
        cwe="CWE-89",
    )
    result = analyze_taint(
        adapter,
        TaintConfiguration(
            call_models=CallModelRegistry(
                [
                    CallModel("source", source_kinds=frozenset({"http"})),
                    CallModel("sink", sink_kinds=frozenset({"sql"})),
                ]
            ),
            rules=(rule,),
        ),
        entry_nodes=[adapter.supergraph.entry_of(cfgs[0])],
    )
    assert len(result.findings) == 1
    finding = result.findings[0]
    assert finding.rule == rule
    assert finding.source_kind == "http"
    assert finding.sink_kind == "sql"


def test_typed_sink_ports_ignore_taint_on_unmodeled_arguments():
    compiler = context.CompilerContext(None)
    source_code, _ = make_code("source", [], [], return_name="source_ret")
    first = ast.Local("first")
    second = ast.Local("second")
    sink_code, _ = make_code("sink", [first, second], [], return_name="sink_ret")
    tainted = ast.Local("tainted")
    clean = ast.Local("clean")
    main_code, _ = make_code(
        "main",
        [],
        [
            call_stmt(source_code, [], [tainted]),
            ast.Assign(ast.Existing(ast.program.Object(0)), [clean]),
            call_stmt(sink_code, [clean, tainted]),
        ],
        return_name="main_ret",
    )
    cfgs = [build_cfg(compiler, code) for code in (main_code, source_code, sink_code)]
    adapter = build_supergraph_from_cfgs(cfgs)
    result = analyze_taint(
        adapter,
        TaintConfiguration(
            call_models=CallModelRegistry(
                [
                    CallModel("source", source_kinds=frozenset({"http"})),
                    CallModel(
                        "sink",
                        sink_kinds=frozenset({"sql"}),
                        sink_arg_positions=frozenset({0}),
                    ),
                ]
            ),
            rules=(
                TaintRule(
                    "SQL-001",
                    "SQL injection",
                    frozenset({"http"}),
                    frozenset({"sql"}),
                ),
            ),
        ),
        entry_nodes=[adapter.supergraph.entry_of(cfgs[0])],
    )
    assert result.findings == ()


def test_kind_scoped_sanitizer_preserves_other_taint_kinds():
    compiler = context.CompilerContext(None)
    http_source, _ = make_code("http_source", [], [], return_name="http_ret")
    secret_source, _ = make_code("secret_source", [], [], return_name="secret_ret")
    parameter = ast.Local("value")
    sanitizer, _ = make_code(
        "sanitize_http", [parameter], [ast.Return([parameter])], return_name="san_ret"
    )
    sink_parameter = ast.Local("value")
    sink, _ = make_code("sink", [sink_parameter], [], return_name="sink_ret")
    http_value = ast.Local("http_value")
    safe_http = ast.Local("safe_http")
    secret_value = ast.Local("secret_value")
    preserved_secret = ast.Local("preserved_secret")
    main, _ = make_code(
        "main",
        [],
        [
            call_stmt(http_source, [], [http_value]),
            call_stmt(sanitizer, [http_value], [safe_http]),
            call_stmt(sink, [safe_http]),
            call_stmt(secret_source, [], [secret_value]),
            call_stmt(sanitizer, [secret_value], [preserved_secret]),
            call_stmt(sink, [preserved_secret]),
        ],
        return_name="main_ret",
    )
    cfgs = [
        build_cfg(compiler, code)
        for code in (main, http_source, secret_source, sanitizer, sink)
    ]
    adapter = build_supergraph_from_cfgs(cfgs)
    result = analyze_taint(
        adapter,
        TaintConfiguration(
            call_models=CallModelRegistry(
                [
                    CallModel("http_source", source_kinds=frozenset({"http"})),
                    CallModel("secret_source", source_kinds=frozenset({"secret"})),
                    CallModel("sanitize_http", sanitizer_kinds=frozenset({"http"})),
                    CallModel("sink", sink_kinds=frozenset({"sql"})),
                ]
            ),
            rules=(
                TaintRule(
                    "SQL-HTTP",
                    "HTTP to SQL",
                    frozenset({"http"}),
                    frozenset({"sql"}),
                ),
                TaintRule(
                    "SQL-SECRET",
                    "Secret to SQL",
                    frozenset({"secret"}),
                    frozenset({"sql"}),
                ),
            ),
        ),
        entry_nodes=[adapter.supergraph.entry_of(cfgs[0])],
    )
    assert [
        (finding.rule.rule_id, finding.source_kind) for finding in result.findings
    ] == [("SQL-SECRET", "secret")]


def test_interprocedural_taint_materializes_source_call_result_root():
    compiler = context.CompilerContext(None)

    source_code, _ = make_code("source", [], [], return_name="source_ret")
    sink_value = ast.Local("sink_value")
    sink_code, _ = make_code("sink", [sink_value], [], return_name="sink_ret")
    value = ast.Local("value")
    main_code, _ = make_code(
        "main",
        [],
        [
            ast.Assign(ast.Call(ast.Local("source"), [], [], None, None), [value]),
            ast.Discard(ast.Call(ast.Local("sink"), [value], [], None, None)),
            ast.Return([]),
        ],
        return_name="main_ret",
    )

    cfgs = [
        build_cfg(compiler, main_code),
        build_cfg(compiler, source_code),
        build_cfg(compiler, sink_code),
    ]
    adapter = build_supergraph_from_cfgs(cfgs)
    result = analyze_taint(
        adapter,
        _config(
            source_names=frozenset({"source"}),
            sink_names=frozenset({"sink"}),
        ),
        entry_nodes=[adapter.supergraph.entry_of(cfgs[0])],
    )

    assert len(result.findings) == 1
    fact = result.fact_for_local(result.findings[0].sink, value)
    assert fact is not None
    assert fact.location.root.kind is HeapObjectKind.CALL_RESULT
    assert result._problem.describe_location(fact.location) == "value"


def test_constructor_self_field_write_projects_to_call_result_object():
    compiler = context.CompilerContext(None)

    source_code, _ = make_code("source", [], [], return_name="source_ret")
    sink_value = ast.Local("sink_value")
    sink_code, _ = make_code("sink", [sink_value], [], return_name="sink_ret")

    self_local = ast.Local("self")
    value = ast.Local("value")
    init_ret = ast.Local("user_ret")
    payload = ast.Existing(ast.program.Object("payload"))
    user_code = ast.Code(
        "User",
        ast.CodeParameters(
            selfparam=self_local,
            posonlyparams=[],
            posonlynames=[],
            params=[value],
            paramnames=["value"],
            defaults=[],
            vparam=None,
            kparam=None,
            returnparams=[init_ret],
            type_params=None,
        ),
        ast.Suite(
            [
                ast.SetAttr(value, self_local, payload),
                ast.Return([]),
            ]
        ),
    )

    raw = ast.Local("raw")
    user = ast.Local("user")
    main_code, _ = make_code(
        "main",
        [],
        [
            ast.Assign(ast.Call(ast.Local("source"), [], [], None, None), [raw]),
            ast.Assign(ast.Call(ast.Local("User"), [raw], [], None, None), [user]),
            ast.Discard(
                ast.Call(
                    ast.Local("sink"),
                    [ast.GetAttr(user, payload)],
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
        build_cfg(compiler, user_code),
        build_cfg(compiler, sink_code),
    ]
    adapter = build_supergraph_from_cfgs(cfgs)
    result = analyze_taint(
        adapter,
        _config(
            source_names=frozenset({"source"}),
            sink_names=frozenset({"sink"}),
        ),
        entry_nodes=[adapter.supergraph.entry_of(cfgs[0])],
    )

    assert len(result.findings) == 1
    finding = result.findings[0]
    tainted_locations = {
        result._problem.describe_location(fact.location)
        for fact in result._ifds_result.facts_at(finding.sink)
        if getattr(fact, "location", None) is not None
    }
    assert "user.payload" in tainted_locations


def test_interprocedural_taint_rejects_non_annotated_cfgs():
    compiler = context.CompilerContext(None)

    source_code, _ = make_code("source", [], [], return_name="source_ret")
    sink_value = ast.Local("sink_value")
    sink_code, _ = make_code("sink", [sink_value], [], return_name="sink_ret")
    local = ast.Local("local")
    main_code, _ = make_code(
        "main",
        [],
        [
            ast.Assign(ast.Call(ast.Local("source"), [], [], None, None), [local]),
            ast.Discard(ast.Call(ast.Local("sink"), [local], [], None, None)),
            ast.Return([local]),
        ],
        return_name="main_ret",
    )

    cfgs = [
        transform.evaluate(compiler, code)
        for code in (main_code, source_code, sink_code)
    ]
    adapter = build_supergraph_from_cfgs(cfgs)

    with pytest.raises(TemporaryLimitation, match="annotation-complete programs"):
        analyze_taint(
            adapter,
            _config(
                source_names=frozenset({"source"}),
                sink_names=frozenset({"sink"}),
            ),
            entry_nodes=[adapter.supergraph.entry_of(cfgs[0])],
        )


def test_interprocedural_taint_requires_explicit_entry_nodes():
    compiler = context.CompilerContext(None)

    source_code, _ = make_code("source", [], [], return_name="source_ret")
    sink_value = ast.Local("sink_value")
    sink_code, _ = make_code("sink", [sink_value], [], return_name="sink_ret")
    value = ast.Local("value")
    main_code, _ = make_code(
        "main",
        [],
        [
            ast.Assign(ast.DirectCall(source_code, None, [], [], None, None), [value]),
            ast.Discard(ast.DirectCall(sink_code, None, [value], [], None, None)),
            ast.Return([value]),
        ],
        return_name="main_ret",
    )

    cfgs = [build_cfg(compiler, code) for code in (main_code, source_code, sink_code)]
    adapter = build_supergraph_from_cfgs(cfgs)

    with pytest.raises(ValueError, match="explicit entry_nodes"):
        analyze_taint(
            adapter,
            _config(
                source_names=frozenset({"source"}),
                sink_names=frozenset({"sink"}),
            ),
        )


def test_interprocedural_taint_handles_return_calls():
    compiler = context.CompilerContext(None)

    source_code, _ = make_code("source", [], [], return_name="source_ret")

    choose_x = ast.Local("x")
    choose_y = ast.Local("y")
    choose_code, _ = make_code(
        "choose",
        [choose_x, choose_y],
        [ast.Return([choose_x])],
        return_name="choose_ret",
    )

    choose_call = ast.Call(
        ast.Local("choose"),
        [
            ast.Call(ast.Local("source"), [], [], None, None),
            ast.Existing(ast.program.Object(0)),
        ],
        [],
        None,
        None,
    )
    wrapper_code, _ = make_code(
        "wrapper",
        [],
        [ast.Return([choose_call])],
        return_name="wrapper_ret",
    )

    sink_value = ast.Local("value")
    sink_code, _ = make_code("sink", [sink_value], [], return_name="sink_ret")

    tainted = ast.Local("tainted")
    main_code, _ = make_code(
        "main",
        [],
        [
            ast.Assign(ast.Call(ast.Local("wrapper"), [], [], None, None), [tainted]),
            ast.Discard(ast.Call(ast.Local("sink"), [tainted], [], None, None)),
            ast.Return([tainted]),
        ],
        return_name="main_ret",
    )

    cfgs = [
        build_cfg(compiler, main_code),
        build_cfg(compiler, wrapper_code),
        build_cfg(compiler, choose_code),
        build_cfg(compiler, source_code),
        build_cfg(compiler, sink_code),
    ]
    adapter = build_supergraph_from_cfgs(cfgs)
    result = analyze_taint(
        adapter,
        _config(
            source_names=frozenset({"source"}),
            sink_names=frozenset({"sink"}),
        ),
        entry_nodes=[adapter.supergraph.entry_of(cfgs[0])],
    )

    assert len(result.findings) == 1
    assert [local.name for local in result.findings[0].tainted_arguments] == ["tainted"]


def test_taint_conservatively_models_unresolved_call_side_effects_when_enabled():
    compiler = context.CompilerContext(None)

    source_code, _ = make_code("source", [], [], return_name="source_ret")
    sink_value = ast.Local("sink_value")
    sink_code, _ = make_code("sink", [sink_value], [], return_name="sink_ret")

    tainted = ast.Local("tainted")
    target = ast.Local("target")
    main_code, _ = make_code(
        "main",
        [],
        [
            ast.Assign(
                ast.DirectCall(source_code, None, [], [], None, None), [tainted]
            ),
            ast.Assign(ast.Existing(ast.program.Object(0)), [target]),
            ast.Discard(
                ast.Call(
                    ast.Local("dynamic_update"),
                    [tainted, target],
                    [],
                    None,
                    None,
                )
            ),
            ast.Discard(ast.DirectCall(sink_code, None, [target], [], None, None)),
            ast.Return([target]),
        ],
        return_name="main_ret",
    )

    cfgs = [
        build_cfg(compiler, main_code),
        build_cfg(compiler, source_code),
        build_cfg(compiler, sink_code),
    ]
    adapter = build_supergraph_from_cfgs(cfgs)
    result = analyze_taint(
        adapter,
        _config(
            source_names=frozenset({"source"}),
            sink_names=frozenset({"sink"}),
            conservative_unresolved_call_side_effects=True,
        ),
        entry_nodes=[adapter.supergraph.entry_of(cfgs[0])],
    )

    assert len(result.findings) == 1
    assert [local.name for local in result.findings[0].tainted_arguments] == ["target"]


def test_interprocedural_taint_flows_through_if_branch_merge():
    compiler = context.CompilerContext(None)

    source_code, _ = make_code("source", [], [], return_name="source_ret")
    sink_value = ast.Local("sink_value")
    sink_code, _ = make_code("sink", [sink_value], [], return_name="sink_ret")

    cond = ast.Local("cond")
    branch_value = ast.Local("branch_value")
    main_code, _ = make_code(
        "main",
        [cond],
        [
            ast.Switch(
                ast.Condition(ast.Suite([]), cond),
                ast.Suite(
                    [
                        ast.Assign(
                            ast.DirectCall(source_code, None, [], [], None, None),
                            [branch_value],
                        )
                    ]
                ),
                ast.Suite(
                    [
                        ast.Assign(
                            ast.Existing(ast.program.Object(0)),
                            [branch_value],
                        )
                    ]
                ),
            ),
            ast.Discard(
                ast.DirectCall(sink_code, None, [branch_value], [], None, None)
            ),
            ast.Return([branch_value]),
        ],
        return_name="main_ret",
    )

    cfgs = [
        build_cfg(compiler, main_code),
        build_cfg(compiler, source_code),
        build_cfg(compiler, sink_code),
    ]
    adapter = build_supergraph_from_cfgs(cfgs)
    result = analyze_taint(
        adapter,
        _config(
            source_names=frozenset({"source"}),
            sink_names=frozenset({"sink"}),
        ),
        entry_nodes=[adapter.supergraph.entry_of(cfgs[0])],
    )

    assert len(result.findings) == 1
    assert [local.name for local in result.findings[0].tainted_arguments] == [
        "branch_value"
    ]


def test_interprocedural_taint_flows_through_while_loop_body():
    compiler = context.CompilerContext(None)

    source_code, _ = make_code("source", [], [], return_name="source_ret")
    sink_value = ast.Local("sink_value")
    sink_code, _ = make_code("sink", [sink_value], [], return_name="sink_ret")

    cond = ast.Local("cond")
    loop_value = ast.Local("loop_value")
    main_code, _ = make_code(
        "main",
        [cond],
        [
            ast.Assign(ast.Existing(ast.program.Object(0)), [loop_value]),
            ast.While(
                ast.Condition(ast.Suite([]), cond),
                ast.Suite(
                    [
                        ast.Assign(
                            ast.DirectCall(source_code, None, [], [], None, None),
                            [loop_value],
                        )
                    ]
                ),
                ast.Suite([]),
            ),
            ast.Discard(ast.DirectCall(sink_code, None, [loop_value], [], None, None)),
            ast.Return([loop_value]),
        ],
        return_name="main_ret",
    )

    cfgs = [
        build_cfg(compiler, main_code),
        build_cfg(compiler, source_code),
        build_cfg(compiler, sink_code),
    ]
    adapter = build_supergraph_from_cfgs(cfgs)
    result = analyze_taint(
        adapter,
        _config(
            source_names=frozenset({"source"}),
            sink_names=frozenset({"sink"}),
        ),
        entry_nodes=[adapter.supergraph.entry_of(cfgs[0])],
    )

    assert len(result.findings) == 1
    assert [local.name for local in result.findings[0].tainted_arguments] == [
        "loop_value"
    ]


def test_interprocedural_taint_tracks_flows_through_except_handlers():
    compiler = context.CompilerContext(None)

    source_code, _ = make_code("source", [], [], return_name="source_ret")
    sink_value = ast.Local("sink_value")
    sink_code, _ = make_code("sink", [sink_value], [], return_name="sink_ret")

    handler_value = ast.Local("handler_value")
    handler = ast.ExceptionHandler(
        ast.Suite([]),
        ast.Existing(ast.program.Object(ValueError)),
        None,
        ast.Suite(
            [
                ast.Assign(
                    ast.DirectCall(source_code, None, [], [], None, None),
                    [handler_value],
                )
            ]
        ),
    )
    main_code, _ = make_code(
        "main",
        [],
        [
            ast.TryExceptFinally(
                ast.Suite(
                    [
                        ast.Raise(
                            ast.Existing(ast.program.Object(ValueError)), None, None
                        )
                    ]
                ),
                [handler],
                None,
                None,
                None,
            ),
            ast.Discard(
                ast.DirectCall(sink_code, None, [handler_value], [], None, None)
            ),
            ast.Return([handler_value]),
        ],
        return_name="main_ret",
    )

    cfgs = [
        build_cfg(compiler, main_code),
        build_cfg(compiler, source_code),
        build_cfg(compiler, sink_code),
    ]
    adapter = build_supergraph_from_cfgs(cfgs)
    result = analyze_taint(
        adapter,
        _config(
            source_names=frozenset({"source"}),
            sink_names=frozenset({"sink"}),
        ),
        entry_nodes=[adapter.supergraph.entry_of(cfgs[0])],
    )

    assert len(result.findings) == 1
    assert result.findings[0].sink_name == "sink"
    assert [local.name for local in result.findings[0].tainted_arguments] == [
        "handler_value"
    ]


def test_interprocedural_taint_delete_kills_local_fact():
    compiler = context.CompilerContext(None)

    source_code, _ = make_code("source", [], [], return_name="source_ret")
    sink_value = ast.Local("sink_value")
    sink_code, _ = make_code("sink", [sink_value], [], return_name="sink_ret")

    tainted = ast.Local("tainted")
    main_code, _ = make_code(
        "main",
        [],
        [
            call_stmt(source_code, [], [tainted]),
            ast.Delete(tainted),
            call_stmt(sink_code, [tainted]),
            ast.Return([]),
        ],
        return_name="main_ret",
    )

    cfgs = [
        build_cfg(compiler, main_code),
        build_cfg(compiler, source_code),
        build_cfg(compiler, sink_code),
    ]
    adapter = build_supergraph_from_cfgs(cfgs)
    result = analyze_taint(
        adapter,
        _config(
            source_names=frozenset({"source"}),
            sink_names=frozenset({"sink"}),
        ),
        entry_nodes=[adapter.supergraph.entry_of(cfgs[0])],
    )

    assert result.findings == ()


def test_interprocedural_taint_preserves_return_slot_mapping():
    compiler = context.CompilerContext(None)

    source_code, _ = make_code("source", [], [], return_name="source_ret")

    left_out = ast.Local("pair_left")
    right_out = ast.Local("pair_right")
    pair_code = ast.Code(
        "pair",
        ast.CodeParameters(
            selfparam=None,
            posonlyparams=[],
            posonlynames=[],
            params=[],
            paramnames=[],
            defaults=[],
            vparam=None,
            kparam=None,
            returnparams=[left_out, right_out],
            type_params=None,
        ),
        ast.Suite(
            [
                ast.Return(
                    [
                        ast.Existing(ast.program.Object(0)),
                        ast.Call(ast.Local("source"), [], [], None, None),
                    ]
                )
            ]
        ),
    )

    left = ast.Local("left")
    right = ast.Local("right")
    sink_value = ast.Local("value")
    sink_code, _ = make_code("sink", [sink_value], [], return_name="sink_ret")
    main_code, _ = make_code(
        "main",
        [],
        [
            ast.Assign(ast.Call(ast.Local("pair"), [], [], None, None), [left, right]),
            ast.Discard(ast.Call(ast.Local("sink"), [left], [], None, None)),
            ast.Discard(ast.Call(ast.Local("sink"), [right], [], None, None)),
            ast.Return([right]),
        ],
        return_name="main_ret",
    )

    cfgs = [
        build_cfg(compiler, main_code),
        build_cfg(compiler, pair_code),
        build_cfg(compiler, source_code),
        build_cfg(compiler, sink_code),
    ]
    adapter = build_supergraph_from_cfgs(cfgs)
    result = analyze_taint(
        adapter,
        _config(
            source_names=frozenset({"source"}),
            sink_names=frozenset({"sink"}),
        ),
        entry_nodes=[adapter.supergraph.entry_of(cfgs[0])],
    )

    assert len(result.findings) == 1
    assert [local.name for local in result.findings[0].tainted_arguments] == ["right"]


def test_interprocedural_taint_tracks_attribute_global_and_cell_flows():
    compiler = context.CompilerContext(None)

    source_code, _ = make_code("source", [], [], return_name="source_ret")
    sink_value = ast.Local("sink_value")
    sink_code, _ = make_code("sink", [sink_value], [], return_name="sink_ret")

    obj = ast.Local("obj")
    slot = ast.Cell("captured")
    payload_name = ast.Existing(ast.program.Object("payload"))
    global_name = ast.Existing(ast.program.Object("SHARED"))
    main_code, _ = make_code(
        "main",
        [],
        [
            ast.SetAttr(
                ast.DirectCall(source_code, None, [], [], None, None),
                obj,
                payload_name,
            ),
            ast.SetGlobal(
                global_name,
                ast.DirectCall(source_code, None, [], [], None, None),
            ),
            ast.SetCellDeref(
                ast.DirectCall(source_code, None, [], [], None, None),
                slot,
            ),
            ast.Discard(
                ast.DirectCall(
                    sink_code,
                    None,
                    [ast.GetAttr(obj, payload_name)],
                    [],
                    None,
                    None,
                )
            ),
            ast.Discard(
                ast.DirectCall(
                    sink_code,
                    None,
                    [ast.GetGlobal(global_name)],
                    [],
                    None,
                    None,
                )
            ),
            ast.Discard(
                ast.DirectCall(
                    sink_code,
                    None,
                    [ast.GetCellDeref(slot)],
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
        build_cfg(compiler, sink_code),
    ]
    adapter = build_supergraph_from_cfgs(cfgs)
    result = analyze_taint(
        adapter,
        _config(
            source_names=frozenset({"source"}),
            sink_names=frozenset({"sink"}),
        ),
        entry_nodes=[adapter.supergraph.entry_of(cfgs[0])],
    )

    assert len(result.findings) == 3
    labels = sorted(
        label
        for finding in result.findings
        for label in finding.tainted_argument_labels
    )
    assert labels == ["SHARED", "captured", "obj.payload"]


def test_interprocedural_taint_tracks_constant_name_getattr_setattr_field_flow():
    compiler = context.CompilerContext(None)

    source_code, _ = make_code("source", [], [], return_name="source_ret")
    sink_value = ast.Local("sink_value")
    sink_code, _ = make_code("sink", [sink_value], [], return_name="sink_ret")

    obj = ast.Local("obj")
    out = ast.Local("out")
    payload_name = ast.Existing(ast.program.Object("payload"))
    main_code, _ = make_code(
        "main",
        [obj],
        [
            ast.Discard(
                ast.Call(
                    ast.Local("setattr"),
                    [
                        obj,
                        payload_name,
                        ast.DirectCall(source_code, None, [], [], None, None),
                    ],
                    [],
                    None,
                    None,
                )
            ),
            ast.Assign(
                ast.Call(ast.Local("getattr"), [obj, payload_name], [], None, None),
                [out],
            ),
            ast.Discard(ast.DirectCall(sink_code, None, [out], [], None, None)),
            ast.Return([]),
        ],
        return_name="main_ret",
    )

    cfgs = [
        build_cfg(compiler, main_code),
        build_cfg(compiler, source_code),
        build_cfg(compiler, sink_code),
    ]
    adapter = build_supergraph_from_cfgs(cfgs)
    result = analyze_taint(
        adapter,
        _config(
            source_names=frozenset({"source"}),
            sink_names=frozenset({"sink"}),
        ),
        entry_nodes=[adapter.supergraph.entry_of(cfgs[0])],
    )

    assert len(result.findings) == 1
    assert [local.name for local in result.findings[0].tainted_arguments] == ["out"]


def test_interprocedural_taint_tracks_unknown_name_setattr_to_constant_getattr():
    compiler = context.CompilerContext(None)

    source_code, _ = make_code("source", [], [], return_name="source_ret")
    sink_value = ast.Local("sink_value")
    sink_code, _ = make_code("sink", [sink_value], [], return_name="sink_ret")

    obj = ast.Local("obj")
    name = ast.Local("name")
    out = ast.Local("out")
    payload_name = ast.Existing(ast.program.Object("payload"))
    main_code, _ = make_code(
        "main",
        [obj, name],
        [
            ast.Discard(
                ast.Call(
                    ast.Local("setattr"),
                    [
                        obj,
                        name,
                        ast.DirectCall(source_code, None, [], [], None, None),
                    ],
                    [],
                    None,
                    None,
                )
            ),
            ast.Assign(
                ast.Call(ast.Local("getattr"), [obj, payload_name], [], None, None),
                [out],
            ),
            ast.Discard(ast.DirectCall(sink_code, None, [out], [], None, None)),
            ast.Return([]),
        ],
        return_name="main_ret",
    )

    cfgs = [
        build_cfg(compiler, main_code),
        build_cfg(compiler, source_code),
        build_cfg(compiler, sink_code),
    ]
    adapter = build_supergraph_from_cfgs(cfgs)
    result = analyze_taint(
        adapter,
        _config(
            source_names=frozenset({"source"}),
            sink_names=frozenset({"sink"}),
        ),
        entry_nodes=[adapter.supergraph.entry_of(cfgs[0])],
    )

    assert len(result.findings) == 1
    assert [local.name for local in result.findings[0].tainted_arguments] == ["out"]


def test_interprocedural_taint_tracks_unknown_subscript_write_to_constant_read():
    compiler = context.CompilerContext(None)

    source_code, _ = make_code("source", [], [], return_name="source_ret")
    sink_value = ast.Local("sink_value")
    sink_code, _ = make_code("sink", [sink_value], [], return_name="sink_ret")

    obj = ast.Local("obj")
    key = ast.Local("key")
    out = ast.Local("out")
    payload = ast.Existing(ast.program.Object("payload"))
    main_code, _ = make_code(
        "main",
        [obj, key],
        [
            ast.SetSubscript(
                ast.DirectCall(source_code, None, [], [], None, None),
                obj,
                key,
            ),
            ast.Assign(ast.GetSubscript(obj, payload), [out]),
            ast.Discard(ast.DirectCall(sink_code, None, [out], [], None, None)),
            ast.Return([]),
        ],
        return_name="main_ret",
    )

    cfgs = [
        build_cfg(compiler, main_code),
        build_cfg(compiler, source_code),
        build_cfg(compiler, sink_code),
    ]
    adapter = build_supergraph_from_cfgs(cfgs)
    result = analyze_taint(
        adapter,
        _config(
            source_names=frozenset({"source"}),
            sink_names=frozenset({"sink"}),
        ),
        entry_nodes=[adapter.supergraph.entry_of(cfgs[0])],
    )

    assert len(result.findings) == 1
    assert [local.name for local in result.findings[0].tainted_arguments] == ["out"]


def test_interprocedural_taint_tracks_collection_mutator_to_subscript_read():
    compiler = context.CompilerContext(None)

    source_code, _ = make_code("source", [], [], return_name="source_ret")
    sink_value = ast.Local("sink_value")
    sink_code, _ = make_code("sink", [sink_value], [], return_name="sink_ret")

    items = ast.Local("items")
    out = ast.Local("out")
    index = ast.Existing(ast.program.Object(0))
    main_code, _ = make_code(
        "main",
        [items],
        [
            ast.Discard(
                ast.MethodCall(
                    items,
                    ast.Local("append"),
                    [ast.DirectCall(source_code, None, [], [], None, None)],
                    [],
                    None,
                    None,
                )
            ),
            ast.Assign(ast.GetSubscript(items, index), [out]),
            ast.Discard(ast.DirectCall(sink_code, None, [out], [], None, None)),
            ast.Return([]),
        ],
        return_name="main_ret",
    )

    cfgs = [
        build_cfg(compiler, main_code),
        build_cfg(compiler, source_code),
        build_cfg(compiler, sink_code),
    ]
    adapter = build_supergraph_from_cfgs(cfgs)
    result = analyze_taint(
        adapter,
        _config(
            source_names=frozenset({"source"}),
            sink_names=frozenset({"sink"}),
        ),
        entry_nodes=[adapter.supergraph.entry_of(cfgs[0])],
    )

    assert len(result.findings) == 1
    assert [local.name for local in result.findings[0].tainted_arguments] == ["out"]


def test_interprocedural_taint_tracks_function_style_collection_mutator_to_subscript_read():
    compiler = context.CompilerContext(None)

    source_code, _ = make_code("source", [], [], return_name="source_ret")
    sink_value = ast.Local("sink_value")
    sink_code, _ = make_code("sink", [sink_value], [], return_name="sink_ret")

    items = ast.Local("items")
    out = ast.Local("out")
    index = ast.Existing(ast.program.Object(0))
    main_code, _ = make_code(
        "main",
        [items],
        [
            ast.Discard(
                ast.Call(
                    ast.Local("append"),
                    [
                        items,
                        ast.DirectCall(source_code, None, [], [], None, None),
                    ],
                    [],
                    None,
                    None,
                )
            ),
            ast.Assign(ast.GetSubscript(items, index), [out]),
            ast.Discard(ast.DirectCall(sink_code, None, [out], [], None, None)),
            ast.Return([]),
        ],
        return_name="main_ret",
    )

    cfgs = [
        build_cfg(compiler, main_code),
        build_cfg(compiler, source_code),
        build_cfg(compiler, sink_code),
    ]
    adapter = build_supergraph_from_cfgs(cfgs)
    result = analyze_taint(
        adapter,
        _config(
            source_names=frozenset({"source"}),
            sink_names=frozenset({"sink"}),
        ),
        entry_nodes=[adapter.supergraph.entry_of(cfgs[0])],
    )

    assert len(result.findings) == 1
    assert [local.name for local in result.findings[0].tainted_arguments] == ["out"]


def test_interprocedural_taint_tracks_collection_extend_source_elements():
    compiler = context.CompilerContext(None)

    source_code, _ = make_code("source", [], [], return_name="source_ret")
    sink_value = ast.Local("sink_value")
    sink_code, _ = make_code("sink", [sink_value], [], return_name="sink_ret")

    src_items = ast.Local("src_items")
    dst_items = ast.Local("dst_items")
    out = ast.Local("out")
    index = ast.Existing(ast.program.Object(0))
    main_code, _ = make_code(
        "main",
        [dst_items],
        [
            ast.Assign(
                ast.BuildList([ast.DirectCall(source_code, None, [], [], None, None)]),
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
            ast.Assign(ast.GetSubscript(dst_items, index), [out]),
            ast.Discard(ast.DirectCall(sink_code, None, [out], [], None, None)),
            ast.Return([]),
        ],
        return_name="main_ret",
    )

    cfgs = [
        build_cfg(compiler, main_code),
        build_cfg(compiler, source_code),
        build_cfg(compiler, sink_code),
    ]
    adapter = build_supergraph_from_cfgs(cfgs)
    result = analyze_taint(
        adapter,
        _config(
            source_names=frozenset({"source"}),
            sink_names=frozenset({"sink"}),
        ),
        entry_nodes=[adapter.supergraph.entry_of(cfgs[0])],
    )

    assert len(result.findings) == 1
    assert [local.name for local in result.findings[0].tainted_arguments] == ["out"]


def test_interprocedural_taint_tracks_collection_accessor_to_subscript_slot():
    compiler = context.CompilerContext(None)

    source_code, _ = make_code("source", [], [], return_name="source_ret")
    sink_value = ast.Local("sink_value")
    sink_code, _ = make_code("sink", [sink_value], [], return_name="sink_ret")

    items = ast.Local("items")
    out = ast.Local("out")
    key = ast.Existing(ast.program.Object("payload"))
    main_code, _ = make_code(
        "main",
        [items],
        [
            ast.SetSubscript(
                ast.DirectCall(source_code, None, [], [], None, None),
                items,
                key,
            ),
            ast.Assign(
                ast.MethodCall(items, ast.Local("get"), [key], [], None, None), [out]
            ),
            ast.Discard(ast.DirectCall(sink_code, None, [out], [], None, None)),
            ast.Return([]),
        ],
        return_name="main_ret",
    )

    cfgs = [
        build_cfg(compiler, main_code),
        build_cfg(compiler, source_code),
        build_cfg(compiler, sink_code),
    ]
    adapter = build_supergraph_from_cfgs(cfgs)
    result = analyze_taint(
        adapter,
        _config(
            source_names=frozenset({"source"}),
            sink_names=frozenset({"sink"}),
        ),
        entry_nodes=[adapter.supergraph.entry_of(cfgs[0])],
    )

    assert len(result.findings) == 1
    assert [local.name for local in result.findings[0].tainted_arguments] == ["out"]


def test_interprocedural_taint_tracks_list_literal_element_to_subscript_read():
    compiler = context.CompilerContext(None)

    source_code, _ = make_code("source", [], [], return_name="source_ret")
    sink_value = ast.Local("sink_value")
    sink_code, _ = make_code("sink", [sink_value], [], return_name="sink_ret")

    items = ast.Local("items")
    out = ast.Local("out")
    index = ast.Existing(ast.program.Object(0))
    main_code, _ = make_code(
        "main",
        [],
        [
            ast.Assign(
                ast.BuildList([ast.DirectCall(source_code, None, [], [], None, None)]),
                [items],
            ),
            ast.Assign(ast.GetSubscript(items, index), [out]),
            ast.Discard(ast.DirectCall(sink_code, None, [out], [], None, None)),
            ast.Return([]),
        ],
        return_name="main_ret",
    )

    cfgs = [
        build_cfg(compiler, main_code),
        build_cfg(compiler, source_code),
        build_cfg(compiler, sink_code),
    ]
    adapter = build_supergraph_from_cfgs(cfgs)
    result = analyze_taint(
        adapter,
        _config(
            source_names=frozenset({"source"}),
            sink_names=frozenset({"sink"}),
        ),
        entry_nodes=[adapter.supergraph.entry_of(cfgs[0])],
    )

    assert len(result.findings) == 1
    assert [local.name for local in result.findings[0].tainted_arguments] == ["out"]


def test_interprocedural_taint_copies_dynamic_subscript_facts_to_alias():
    compiler = context.CompilerContext(None)

    source_code, _ = make_code("source", [], [], return_name="source_ret")
    sink_value = ast.Local("sink_value")
    sink_code, _ = make_code("sink", [sink_value], [], return_name="sink_ret")

    items = ast.Local("items")
    alias = ast.Local("alias")
    out = ast.Local("out")
    index = ast.Existing(ast.program.Object(0))
    main_code, _ = make_code(
        "main",
        [items],
        [
            ast.SetSubscript(
                ast.DirectCall(source_code, None, [], [], None, None),
                items,
                index,
            ),
            ast.Assign(items, [alias]),
            ast.Assign(ast.GetSubscript(alias, index), [out]),
            ast.Discard(ast.DirectCall(sink_code, None, [out], [], None, None)),
            ast.Return([]),
        ],
        return_name="main_ret",
    )

    cfgs = [
        build_cfg(compiler, main_code),
        build_cfg(compiler, source_code),
        build_cfg(compiler, sink_code),
    ]
    adapter = build_supergraph_from_cfgs(cfgs)
    result = analyze_taint(
        adapter,
        _config(
            source_names=frozenset({"source"}),
            sink_names=frozenset({"sink"}),
        ),
        entry_nodes=[adapter.supergraph.entry_of(cfgs[0])],
    )

    assert len(result.findings) == 1
    assert [local.name for local in result.findings[0].tainted_arguments] == ["out"]


def test_interprocedural_taint_copies_precise_container_selector_to_fresh_copy():
    compiler = context.CompilerContext(None)

    source_code, _ = make_code("source", [], [], return_name="source_ret")
    sink_value = ast.Local("sink_value")
    sink_code, _ = make_code("sink", [sink_value], [], return_name="sink_ret")

    items = ast.Local("items")
    copied = ast.Local("copied")
    out = ast.Local("out")
    key = ast.Existing(ast.program.Object("payload"))
    main_code, _ = make_code(
        "main",
        [items],
        [
            ast.SetSubscript(
                ast.DirectCall(source_code, None, [], [], None, None),
                items,
                key,
            ),
            ast.Assign(ast.Call(ast.Local("dict"), [items], [], None, None), [copied]),
            ast.Assign(ast.GetSubscript(copied, key), [out]),
            ast.Discard(ast.DirectCall(sink_code, None, [out], [], None, None)),
            ast.Return([]),
        ],
        return_name="main_ret",
    )

    cfgs = [
        build_cfg(compiler, main_code),
        build_cfg(compiler, source_code),
        build_cfg(compiler, sink_code),
    ]
    adapter = build_supergraph_from_cfgs(cfgs)
    result = analyze_taint(
        adapter,
        _config(
            source_names=frozenset({"source"}),
            sink_names=frozenset({"sink"}),
        ),
        entry_nodes=[adapter.supergraph.entry_of(cfgs[0])],
    )

    assert len(result.findings) == 1
    assert [local.name for local in result.findings[0].tainted_arguments] == ["out"]
    reached_labels = {
        result._problem.describe_location(fact.location)
        for node, facts in result._ifds_result._reached.items()
        if node.procedure.code.codeName() == "main"
        for fact in facts
        if getattr(fact, "location", None) is not None
    }
    assert "copied['payload']" in reached_labels


def test_interprocedural_taint_deletes_lowered_subscript_fact():
    compiler = context.CompilerContext(None)

    source_code, _ = make_code("source", [], [], return_name="source_ret")
    sink_value = ast.Local("sink_value")
    sink_code, _ = make_code("sink", [sink_value], [], return_name="sink_ret")

    items = ast.Local("items")
    out = ast.Local("out")
    key = ast.Existing(ast.program.Object("payload"))
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
                    [items, key, ast.DirectCall(source_code, None, [], [], None, None)],
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
            ast.Discard(ast.DirectCall(sink_code, None, [out], [], None, None)),
            ast.Return([]),
        ],
        return_name="main_ret",
    )

    cfgs = [
        build_cfg(compiler, main_code),
        build_cfg(compiler, source_code),
        build_cfg(compiler, sink_code),
    ]
    adapter = build_supergraph_from_cfgs(cfgs)
    result = analyze_taint(
        adapter,
        _config(
            source_names=frozenset({"source"}),
            sink_names=frozenset({"sink"}),
        ),
        entry_nodes=[adapter.supergraph.entry_of(cfgs[0])],
    )

    assert result.findings == ()


def test_interprocedural_taint_strong_updates_locals_and_globals():
    compiler = context.CompilerContext(None)

    source_code, _ = make_code("source", [], [], return_name="source_ret")
    sink_value = ast.Local("sink_value")
    sink_code, _ = make_code("sink", [sink_value], [], return_name="sink_ret")

    tainted = ast.Local("tainted")
    global_name = ast.Existing(ast.program.Object("SHARED"))
    main_code, _ = make_code(
        "main",
        [],
        [
            ast.Assign(ast.Call(ast.Local("source"), [], [], None, None), [tainted]),
            ast.Assign(ast.Existing(ast.program.Object(0)), [tainted]),
            ast.SetGlobal(
                global_name, ast.Call(ast.Local("source"), [], [], None, None)
            ),
            ast.SetGlobal(global_name, ast.Existing(ast.program.Object(0))),
            ast.Discard(ast.Call(ast.Local("sink"), [tainted], [], None, None)),
            ast.Discard(
                ast.Call(
                    ast.Local("sink"), [ast.GetGlobal(global_name)], [], None, None
                )
            ),
            ast.Return([tainted]),
        ],
        return_name="main_ret",
    )

    cfgs = [
        build_cfg(compiler, main_code),
        build_cfg(compiler, source_code),
        build_cfg(compiler, sink_code),
    ]
    adapter = build_supergraph_from_cfgs(cfgs)
    result = analyze_taint(
        adapter,
        _config(
            source_names=frozenset({"source"}),
            sink_names=frozenset({"sink"}),
        ),
        entry_nodes=[adapter.supergraph.entry_of(cfgs[0])],
    )

    assert result.findings == ()


def test_interprocedural_taint_uses_weak_updates_for_heap_slots():
    compiler = context.CompilerContext(None)

    source_code, _ = make_code("source", [], [], return_name="source_ret")
    sink_value = ast.Local("sink_value")
    sink_code, _ = make_code("sink", [sink_value], [], return_name="sink_ret")

    obj = ast.Local("obj")
    payload_name = ast.Existing(ast.program.Object("payload"))
    main_code, _ = make_code(
        "main",
        [],
        [
            ast.SetAttr(
                ast.Call(ast.Local("source"), [], [], None, None), obj, payload_name
            ),
            ast.SetAttr(ast.Existing(ast.program.Object(0)), obj, payload_name),
            ast.Discard(
                ast.Call(
                    ast.Local("sink"),
                    [ast.GetAttr(obj, payload_name)],
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
        build_cfg(compiler, sink_code),
    ]
    adapter = build_supergraph_from_cfgs(cfgs)
    result = analyze_taint(
        adapter,
        _config(
            source_names=frozenset({"source"}),
            sink_names=frozenset({"sink"}),
        ),
        entry_nodes=[adapter.supergraph.entry_of(cfgs[0])],
    )

    assert len(result.findings) == 1
    assert result.findings[0].tainted_argument_labels == ("obj.payload",)


def test_interprocedural_taint_keeps_outer_call_argument_facts_for_nested_calls():
    compiler = context.CompilerContext(None)

    source_code, _ = make_code("source", [], [], return_name="source_ret")
    benign_code, _ = make_code(
        "benign",
        [],
        [ast.Return([ast.Existing(ast.program.Object(0))])],
        return_name="benign_ret",
    )
    first = ast.Local("first")
    second = ast.Local("second")
    pick_code, _ = make_code(
        "pick_first",
        [first, second],
        [ast.Return([first])],
        return_name="pick_ret",
    )
    sink_value = ast.Local("sink_value")
    sink_code, _ = make_code("sink", [sink_value], [], return_name="sink_ret")

    value = ast.Local("value")
    main_code, _ = make_code(
        "main",
        [],
        [
            ast.Assign(ast.Call(ast.Local("source"), [], [], None, None), [value]),
            ast.Assign(
                ast.Call(
                    ast.Local("pick_first"),
                    [value, ast.Call(ast.Local("benign"), [], [], None, None)],
                    [],
                    None,
                    None,
                ),
                [value],
            ),
            ast.Discard(ast.Call(ast.Local("sink"), [value], [], None, None)),
            ast.Return([value]),
        ],
        return_name="main_ret",
    )

    cfgs = [
        build_cfg(compiler, main_code),
        build_cfg(compiler, source_code),
        build_cfg(compiler, benign_code),
        build_cfg(compiler, pick_code),
        build_cfg(compiler, sink_code),
    ]
    adapter = build_supergraph_from_cfgs(cfgs)
    result = analyze_taint(
        adapter,
        _config(
            source_names=frozenset({"source"}),
            sink_names=frozenset({"sink"}),
        ),
        entry_nodes=[adapter.supergraph.entry_of(cfgs[0])],
    )

    assert len(result.findings) == 1
    assert [local.name for local in result.findings[0].tainted_arguments] == ["value"]
