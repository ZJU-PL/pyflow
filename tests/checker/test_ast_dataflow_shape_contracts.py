from __future__ import annotations

import ast

from pyflow.analysis.taint import TaintPolicy
from pyflow.checker.ast_dataflow.modeling import sast_python3_benchmark_shapes
from pyflow.checker.ast_dataflow.semantics import TaintSinkEvent, analyze_ast_function

POLICY = TaintPolicy(
    source_kinds_by_call={"source": frozenset({"user_input"})},
    sink_kinds_by_call={"sink": frozenset({"dangerous"})},
    sink_positions_by_call={"sink": frozenset({0})},
)


def test_optional_modular_shape_contract_distinguishes_even_and_odd_indices():
    function = ast.parse("""
def f():
    values = array.array("u", source())
    sink(values[0])
    sink(values[1])
""").body[0]

    result = analyze_ast_function(
        function,
        procedure="f",
        filename="benchmark.py",
        policy=POLICY,
        shape_contracts=sast_python3_benchmark_shapes(),
    )
    events = [event for event in result.events if isinstance(event, TaintSinkEvent)]

    assert [event.line for event in events] == [4]
    assert result.status == "partial"
    assert any(
        diagnostic.code == "shape-contract-assumption"
        for diagnostic in result.diagnostics
    )
