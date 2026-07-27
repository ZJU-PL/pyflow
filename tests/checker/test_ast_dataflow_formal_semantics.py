from __future__ import annotations

import ast

from pyflow.analysis.taint import TaintPolicy, TaintRule
from pyflow.checker.ast_dataflow.semantics import TaintSinkEvent, analyze_ast_function

POLICY = TaintPolicy(
    source_kinds_by_call={"input": frozenset({"user_input"})},
    sink_kinds_by_call={"eval": frozenset({"code_execution"})},
    sink_positions_by_call={"eval": frozenset({0})},
    sanitizer_kinds_by_call={"clean": frozenset({"*"})},
    rules=(
        TaintRule(
            "TEST-RCE",
            "Untrusted code execution",
            frozenset({"user_input"}),
            frozenset({"code_execution"}),
        ),
    ),
)


def _analyze(source: str):
    function = ast.parse(source).body[0]
    return analyze_ast_function(
        function,
        procedure=function.name,
        filename="sample.py",
        policy=POLICY,
    )


def _sink_events(result):
    return [event for event in result.events if isinstance(event, TaintSinkEvent)]


def test_formal_semantics_reports_direct_source_to_sink_flow():
    result = _analyze("""
def f():
    value = input()
    eval(value)
""")

    assert len(_sink_events(result)) == 1
    assert _sink_events(result)[0].source_kinds == frozenset({"user_input"})
    assert result.status == "complete"


def test_formal_semantics_strong_assignment_kills_scalar_taint():
    result = _analyze("""
def f():
    value = input()
    value = "safe"
    eval(value)
""")

    assert _sink_events(result) == []


def test_formal_semantics_joins_unknown_branches_without_order_dependence():
    result = _analyze("""
def f(flag):
    value = "safe"
    if flag:
        value = input()
    else:
        value = "safe"
    eval(value)
""")

    assert len(_sink_events(result)) == 1


def test_formal_semantics_prunes_constant_dead_branch():
    result = _analyze("""
def f():
    value = "safe"
    if False:
        value = input()
    eval(value)
""")

    assert _sink_events(result) == []


def test_formal_semantics_iterates_loops_and_keeps_zero_iteration_path():
    result = _analyze("""
def f(items):
    value = "safe"
    for item in items:
        value = input()
    eval(value)
""")

    assert len(_sink_events(result)) == 1


def test_formal_semantics_applies_kind_specific_sanitizer():
    policy = TaintPolicy(
        source_kinds_by_call={"source": frozenset({"html", "shell"})},
        sink_kinds_by_call={"sink": frozenset({"dangerous"})},
        sink_positions_by_call={"sink": frozenset({0})},
        sanitizer_kinds_by_call={"clean_html": frozenset({"html"})},
        rules=(),
    )
    function = ast.parse("""
def f():
    value = source()
    sink(clean_html(value))
""").body[0]

    result = analyze_ast_function(
        function, procedure="f", filename="sample.py", policy=policy
    )
    event = next(event for event in result.events if isinstance(event, TaintSinkEvent))

    assert event.source_kinds == frozenset({"shell"})


def test_formal_semantics_propagates_raised_payload_to_handler_name():
    result = _analyze("""
def f():
    try:
        raise input()
    except Exception as error:
        eval(error)
""")

    assert len(_sink_events(result)) == 1


def test_unknown_call_havocs_return_and_marks_result_partial():
    result = _analyze("""
def f():
    value = unknown_library()
    eval(value)
""")

    assert len(_sink_events(result)) == 1
    assert result.status == "partial"
    assert any(
        diagnostic.code == "unknown-call-effect" for diagnostic in result.diagnostics
    )
