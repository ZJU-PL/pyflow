"""Default and fallback PDG edges must follow CFG reaching definitions."""

from unittest.mock import patch

import pytest

from pyflow.ir.pdg import construct_pdg
from pyflow.ir.core.source import syntax_source_span
from tests.ir.cfg.test_reported_semantics import lower


def edges_by_line(pdg):
    result = set()
    for edge in pdg.all_edges(kind="data"):
        source = syntax_source_span(edge.source.ast_node)
        target = syntax_source_span(edge.target.ast_node)
        if source is not None and target is not None:
            result.add((source.start_line, target.start_line, edge.label))
    return result


@pytest.mark.parametrize("fallback", [False, True])
def test_future_definition_does_not_feed_a_past_use(fallback):
    _, cfg = lower("def f():\n    x=1\n    print(x)\n    x=2\n    return x\n")
    if fallback:
        with patch(
            "pyflow.ir.pdg.construction.construct_ddg", side_effect=ValueError("heap unavailable")
        ):
            pdg = construct_pdg(cfg)
        assert pdg.data_dependence_mode == "semantics"
    else:
        pdg = construct_pdg(cfg)
    edges = edges_by_line(pdg)
    assert (2, 3, "x") in edges
    assert (4, 3, "x") not in edges
    assert (4, 5, "x") in edges


def test_loop_carried_backward_edge_is_preserved():
    _, cfg = lower("def f(flag):\n    x=0\n    while flag:\n        x=x+1\n    return x\n")
    assert (4, 4, "x") in edges_by_line(construct_pdg(cfg))
