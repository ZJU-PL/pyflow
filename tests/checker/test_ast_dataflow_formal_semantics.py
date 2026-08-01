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
    result = _analyze(
        """
def f():
    value = input()
    eval(value)
"""
    )

    assert len(_sink_events(result)) == 1
    assert _sink_events(result)[0].source_kinds == frozenset({"user_input"})
    assert result.status == "complete"


def test_formal_semantics_models_response_body_attribute_as_xss_sink():
    result = _analyze(
        """
def handler(resp):
    resp.text = input()
"""
    )

    event = _sink_events(result)[0]
    assert event.sink_name == "resp.text"
    assert event.sink_kinds == frozenset({"xss"})


def test_formal_semantics_respects_sanitizer_before_response_body_write():
    result = _analyze(
        """
def handler(response):
    response.body = clean(input())
"""
    )

    assert _sink_events(result) == []


def test_formal_semantics_strong_assignment_kills_scalar_taint():
    result = _analyze(
        """
def f():
    value = input()
    value = "safe"
    eval(value)
"""
    )

    assert _sink_events(result) == []


def test_formal_semantics_joins_unknown_branches_without_order_dependence():
    result = _analyze(
        """
def f(flag):
    value = "safe"
    if flag:
        value = input()
    else:
        value = "safe"
    eval(value)
"""
    )

    assert len(_sink_events(result)) == 1


def test_formal_semantics_prunes_constant_dead_branch():
    result = _analyze(
        """
def f():
    value = "safe"
    if False:
        value = input()
    eval(value)
"""
    )

    assert _sink_events(result) == []


def test_formal_semantics_iterates_loops_and_keeps_zero_iteration_path():
    result = _analyze(
        """
def f(items):
    value = "safe"
    for item in items:
        value = input()
    eval(value)
"""
    )

    assert len(_sink_events(result)) == 1


def test_formal_semantics_applies_kind_specific_sanitizer():
    policy = TaintPolicy(
        source_kinds_by_call={"source": frozenset({"html", "shell"})},
        sink_kinds_by_call={"sink": frozenset({"dangerous"})},
        sink_positions_by_call={"sink": frozenset({0})},
        sanitizer_kinds_by_call={"clean_html": frozenset({"html"})},
        rules=(),
    )
    function = ast.parse(
        """
def f():
    value = source()
    sink(clean_html(value))
"""
    ).body[0]

    result = analyze_ast_function(
        function, procedure="f", filename="sample.py", policy=policy
    )
    event = next(event for event in result.events if isinstance(event, TaintSinkEvent))

    assert event.source_kinds == frozenset({"shell"})


def test_formal_semantics_propagates_taint_through_starred_expression():
    result = _analyze(
        """
def f():
    values = [input()]
    expanded = [*values]
    eval(expanded)
"""
    )

    assert len(_sink_events(result)) == 1
    assert result.status == "complete"


def test_formal_semantics_propagates_raised_payload_to_handler_name():
    result = _analyze(
        """
def f():
    try:
        raise input()
    except Exception as error:
        eval(error)
"""
    )

    assert len(_sink_events(result)) == 1


def test_unknown_call_havocs_return_conservatively_without_partial_status():
    result = _analyze(
        """
def f():
    value = unknown_library()
    eval(value)
"""
    )

    assert len(_sink_events(result)) == 1
    assert result.status == "complete"
    diagnostic = next(
        diagnostic
        for diagnostic in result.diagnostics
        if diagnostic.code == "unknown-call-effect"
    )
    assert diagnostic.affects_completeness is False
    assert diagnostic.level.value == "conservative"


def test_equivalent_qualified_sink_models_match_short_receiver_call():
    policy = TaintPolicy(
        source_kinds_by_call={"source": frozenset({"user_input"})},
        sink_kinds_by_call={
            "sqlite3.Cursor.execute": frozenset({"sql"}),
            "psycopg2.cursor.execute": frozenset({"sql"}),
        },
        sink_positions_by_call={
            "sqlite3.Cursor.execute": frozenset({0}),
            "psycopg2.cursor.execute": frozenset({0}),
        },
        rules=(
            TaintRule(
                "TEST-SQL",
                "Untrusted SQL",
                frozenset({"user_input"}),
                frozenset({"sql"}),
            ),
        ),
    )
    function = ast.parse(
        """
def f(cursor):
    query = source()
    cursor.execute(query)
"""
    ).body[0]

    result = analyze_ast_function(
        function, procedure="f", filename="sample.py", policy=policy
    )

    assert len(_sink_events(result)) == 1


def test_identical_qualified_sink_models_match_unqualified_import_alias():
    policy = TaintPolicy(
        source_kinds_by_call={"source": frozenset({"user_input"})},
        sink_kinds_by_call={
            "framework.send_file": frozenset({"file"}),
            "framework.helpers.send_file": frozenset({"file"}),
        },
        sink_positions_by_call={
            "framework.send_file": frozenset({0}),
            "framework.helpers.send_file": frozenset({0}),
        },
        rules=(
            TaintRule(
                "TEST-FILE",
                "Untrusted file path",
                frozenset({"user_input"}),
                frozenset({"file"}),
            ),
        ),
    )
    function = ast.parse("def handler(path):\n    send_file(path)\n").body[0]

    result = analyze_ast_function(
        function,
        procedure="handler",
        filename="sample.py",
        policy=policy,
        entry_taint={"path": {"user_input"}},
    )

    assert len(_sink_events(result)) == 1
    assert _sink_events(result)[0].sink_name == "send_file"


def test_ambiguous_receiver_type_conservatively_unions_sink_models():
    policy = TaintPolicy(
        source_kinds_by_call={"source": frozenset({"user_input"})},
        sink_kinds_by_call={
            "database.Cursor.execute": frozenset({"sql"}),
            "runtime.Executor.execute": frozenset({"code_execution"}),
        },
        sink_positions_by_call={
            "database.Cursor.execute": frozenset({0}),
            "runtime.Executor.execute": frozenset({1}),
        },
        sink_cwe_by_call={
            "database.Cursor.execute": "CWE-89",
            "runtime.Executor.execute": "CWE-89",
        },
        rules=(
            TaintRule(
                "TEST-SQL",
                "Untrusted SQL",
                frozenset({"user_input"}),
                frozenset({"sql"}),
            ),
        ),
    )
    function = ast.parse(
        "def handler(cursor):\n    cursor.execute(source(), 'safe')\n"
    ).body[0]

    result = analyze_ast_function(
        function,
        procedure="handler",
        filename="sample.py",
        policy=policy,
    )

    assert len(_sink_events(result)) == 1
    assert "sql" in _sink_events(result)[0].sink_kinds
    assert policy.sink_cwe_for("cursor.execute") == "CWE-89"


def test_leaf_fallback_does_not_borrow_cwe_metadata_from_another_api():
    policy = TaintPolicy(
        sink_kinds_by_call={
            "json.loads": frozenset({"dangerous"}),
            "pickle.loads": frozenset({"deserialization"}),
        },
        sink_cwe_by_call={"pickle.loads": "CWE-502"},
    )

    assert policy.sink_kinds_for("decoder.loads") == frozenset(
        {"dangerous", "deserialization"}
    )
    assert policy.sink_cwe_for("json.loads") is None


def test_framework_attribute_source_alias_flows_to_qualified_sink():
    policy = TaintPolicy(
        source_kinds_by_call={"request.GET.get": frozenset({"user_input"})},
        sink_kinds_by_call={"django.http.HttpResponse": frozenset({"xss"})},
        sink_positions_by_call={"django.http.HttpResponse": frozenset({0})},
        rules=(
            TaintRule(
                "TEST-XSS",
                "Untrusted HTML",
                frozenset({"user_input"}),
                frozenset({"xss"}),
            ),
        ),
    )
    function = ast.parse(
        """
def get(request):
    query = request.GET.get("query", "")
    return HttpResponse(f"<p>{query}</p>")
"""
    ).body[0]

    result = analyze_ast_function(
        function, procedure="get", filename="sample.py", policy=policy
    )

    assert len(_sink_events(result)) == 1


def test_pure_path_operations_do_not_reintroduce_taint_after_sanitization():
    policy = TaintPolicy(
        source_kinds_by_call={"input": frozenset({"user_input"})},
        sink_kinds_by_call={"open": frozenset({"file"})},
        sink_positions_by_call={"open": frozenset({0})},
        sanitizer_kinds_by_call={
            "secure_filename": frozenset({"user_input"})
        },
        rules=(
            TaintRule(
                "TEST-PATH",
                "Untrusted path",
                frozenset({"user_input"}),
                frozenset({"file"}),
            ),
        ),
    )
    function = ast.parse(
        """
def handler():
    filename = secure_filename(input())
    path = os.path.join("/srv/files", filename)
    if os.path.exists(path) and os.path.isfile(path):
        open(path)
"""
    ).body[0]

    result = analyze_ast_function(
        function, procedure="handler", filename="sample.py", policy=policy
    )

    assert _sink_events(result) == []


def test_pure_path_operations_preserve_unsanitized_taint():
    policy = TaintPolicy(
        source_kinds_by_call={"input": frozenset({"user_input"})},
        sink_kinds_by_call={"open": frozenset({"file"})},
        sink_positions_by_call={"open": frozenset({0})},
        rules=(
            TaintRule(
                "TEST-PATH",
                "Untrusted path",
                frozenset({"user_input"}),
                frozenset({"file"}),
            ),
        ),
    )
    function = ast.parse(
        """
def handler():
    path = os.path.join("/srv/files", input())
    if os.path.exists(path):
        open(path)
"""
    ).body[0]

    result = analyze_ast_function(
        function, procedure="handler", filename="sample.py", policy=policy
    )

    assert len(_sink_events(result)) == 1
