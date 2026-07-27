from __future__ import annotations

import ast

from pyflow.analysis.taint import TaintPolicy
from pyflow.checker.ast_dataflow.semantics import TaintSinkEvent, analyze_ast_function

POLICY = TaintPolicy(
    source_kinds_by_call={"source": frozenset({"user_input"})},
    sink_kinds_by_call={"sink": frozenset({"dangerous"})},
    sink_positions_by_call={"sink": frozenset({0})},
)


def _events(source):
    function = ast.parse(source).body[0]
    result = analyze_ast_function(
        function, procedure=function.name, filename="shape.py", policy=POLICY
    )
    return [event for event in result.events if isinstance(event, TaintSinkEvent)]


def test_dict_literal_keeps_constant_keys_distinct():
    safe = _events("""
def f():
    payload = {"command": source(), "page": "safe"}
    sink(payload["page"])
""")
    unsafe = _events("""
def f():
    payload = {"command": source(), "page": "safe"}
    sink(payload["command"])
""")

    assert safe == []
    assert len(unsafe) == 1


def test_dynamic_dict_key_conservatively_reads_any_tainted_value():
    events = _events("""
def f(key):
    payload = {"command": source(), "page": "safe"}
    sink(payload[key])
""")

    assert len(events) == 1


def test_list_literal_keeps_constant_indices_distinct():
    safe = _events("""
def f():
    values = [source(), "safe"]
    sink(values[1])
""")
    unsafe = _events("""
def f():
    values = [source(), "safe"]
    sink(values[0])
""")

    assert safe == []
    assert len(unsafe) == 1


def test_dict_get_uses_constant_key_shape():
    events = _events("""
def f():
    payload = {"command": source(), "page": "safe"}
    sink(payload.get("page"))
""")

    assert events == []


def test_append_taints_unknown_container_element():
    events = _events("""
def f(index):
    values = []
    values.append(source())
    sink(values[index])
""")

    assert len(events) == 1
