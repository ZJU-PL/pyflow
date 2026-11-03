"""Structured control excludes implicit exception chains by default."""

from pyflow.ir.cfg import graph
from pyflow.ir.cdg import construct_cdg
from tests.ir.cfg.test_reported_semantics import lower


def test_linear_raising_suites_are_not_default_controllers():
    cfg = graph.Code()
    error = graph.Merge(None)
    error.setExit("normal", cfg.errorTerminal)
    previous, label = cfg.entryTerminal, "entry"
    for _ in range(50):
        suite = graph.Suite(None)
        previous.setExit(label, suite)
        suite.setExit("error", error)
        previous, label = suite, "normal"
    previous.setExit("normal", cfg.normalTerminal)
    assert not construct_cdg(cfg).get_all_edges()
    assert construct_cdg(cfg, include_exceptional=True).get_all_edges()


def test_branch_suites_do_not_control_the_common_return():
    _, cfg = lower(
        "def f(a,b):\n    if a>0:\n        c=a+b\n    else:\n        c=a-b\n    return c\n"
    )
    cdg = construct_cdg(cfg)
    assert cdg.get_all_edges()
    assert all(isinstance(edge.source.cfg_node, graph.Switch) for edge in cdg.get_all_edges())
