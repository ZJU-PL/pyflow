"""Type predicates preserve taint; explicit sanitizers affect returned values."""

import pytest

from pyflow.application.cpg import build_cpg
from pyflow.checker.cpg.taint import CPGTaintEngine, MemoryLayout, TaintState
from pyflow.ir.cpg import CodePropertyGraph
from pyflow.language.python import ast as py_ast


@pytest.mark.parametrize("call_name", ["isinstance", "other_predicate"])
def test_legacy_guard_helper_does_not_clean_argument_memory(call_name):
    engine = CPGTaintEngine(CodePropertyGraph())
    memory = MemoryLayout()
    state = TaintState.user_controlled()
    memory.mark_tainted("value", state)
    call = py_ast.Call(
        py_ast.Local(call_name), [py_ast.Local("value"), py_ast.Local("str")], [], None, None
    )
    assert engine._isinstance_guard_strip(call, memory) is False
    assert memory.read("value") == state


@pytest.mark.parametrize(
    "body",
    [
        "if isinstance(value, str):\n        eval(value)",
        "if isinstance(value, str):\n        pass\n    else:\n        eval(value)",
        "alias = value\n    if isinstance(value, str):\n        eval(alias)",
        "isinstance(value, str)\n    eval(value)",
    ],
)
def test_isinstance_does_not_sanitize_source_to_sink_flow(body):
    cpg = build_cpg("def f():\n    value = input()\n    " + body + "\n")
    engine = CPGTaintEngine(cpg)
    engine.add_source("input")
    engine.add_sink("eval", cwe="CWE-95")
    findings = engine.analyze().findings
    assert len(findings) == 1
    assert findings[0].sanitizers == frozenset()


def test_guard_metadata_explicitly_distinguishes_type_checks_from_sanitizers():
    cpg = build_cpg("def f(value):\n    if isinstance(value, str):\n        return value\n")
    guards = [
        cpg.node_meta(node)
        for node in cpg.nodes("f")
        if cpg.node_meta(node).get("isinstance_guard")
    ]
    assert len(guards) == 1
    assert guards[0]["guarded_var"] == "value"
    assert guards[0]["guard_kind"] == "type_check"
    assert guards[0]["sanitizes_taint"] is False


@pytest.mark.parametrize("argument, expected_findings", [("clean(value)", 0), ("value", 1)])
def test_explicit_sanitizer_only_cleans_its_result(argument, expected_findings):
    cpg = build_cpg(
        "def f():\n    value = input()\n    if isinstance(value, str):\n"
        "        cleaned = clean(value)\n        eval(" + argument + ")\n"
    )
    engine = CPGTaintEngine(cpg)
    engine.add_source("input")
    engine.add_sink("eval", cwe="CWE-95")
    engine.add_sanitizer("clean")
    assert len(engine.analyze().findings) == expected_findings
