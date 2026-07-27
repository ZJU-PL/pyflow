from __future__ import annotations

import ast
from itertools import product

import pytest

from pyflow.analysis.taint import TaintPolicy
from pyflow.checker.ast_dataflow.semantics import TaintSinkEvent, analyze_ast_function

POLICY = TaintPolicy(
    source_kinds_by_call={"source": frozenset({"test"})},
    sink_kinds_by_call={"sink": frozenset({"test-sink"})},
    sink_positions_by_call={"sink": frozenset({0})},
    sanitizer_kinds_by_call={"clean": frozenset({"*"})},
)


def _static_may_flow(source: str) -> bool:
    function = ast.parse(source).body[0]
    result = analyze_ast_function(
        function, procedure="target", filename="oracle.py", policy=POLICY
    )
    return any(isinstance(event, TaintSinkEvent) for event in result.events)


def _concrete_may_flow(source: str, boolean_arity: int) -> bool:
    tainted = object()
    observed = []

    def source_fn():
        return tainted

    def sink_fn(value):
        observed.append(value is tainted)

    namespace = {
        "source": source_fn,
        "sink": sink_fn,
        "clean": lambda value: object(),
    }
    exec(source, namespace)
    target = namespace["target"]
    for arguments in product((False, True), repeat=boolean_arity):
        target(*arguments)
    return any(observed)


@pytest.mark.parametrize(
    ("source", "boolean_arity"),
    [
        (
            "def target(flag):\n"
            "    value = source()\n"
            "    if flag:\n"
            "        value = 'safe'\n"
            "    sink(value)\n",
            1,
        ),
        (
            "def target(flag):\n"
            "    value = 'safe'\n"
            "    if flag:\n"
            "        value = source()\n"
            "    else:\n"
            "        value = 'safe'\n"
            "    sink(value)\n",
            1,
        ),
        (
            "def target(flag):\n"
            "    payload = {'bad': source(), 'good': 'safe'}\n"
            "    sink(payload['good'])\n",
            1,
        ),
        (
            "def target(flag):\n"
            "    value = source()\n"
            "    value = clean(value)\n"
            "    sink(value)\n",
            1,
        ),
        (
            "def target(flag):\n"
            "    value = 'safe'\n"
            "    for item in ([1] if flag else []):\n"
            "        value = source()\n"
            "    sink(value)\n",
            1,
        ),
    ],
)
def test_static_may_result_matches_exhaustive_concrete_boolean_oracle(
    source, boolean_arity
):
    assert _static_may_flow(source) is _concrete_may_flow(source, boolean_arity)
