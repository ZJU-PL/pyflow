"""
Smoke tests for SOTA engines: BMC, PDR (Spacer), and ICE learning.

These operate on small integer transition systems used as extracted models in the
kitchen-sink portfolio.
"""

import z3

from a3_python.barriers.int_bmc import bmc_find_counterexample
from a3_python.barriers.pdr_spacer import pdr_check_safety
from a3_python.barriers.ice import ice_learn_conjunction


def test_bmc_finds_counterexample():
    var_names = ["x"]

    def init(x):
        return x["x"] == 0

    def trans(x, x_next):
        return x_next["x"] == x["x"] + 1

    def unsafe(x):
        return x["x"] == 2

    cex = bmc_find_counterexample(
        var_names=var_names,
        init=init,
        trans=trans,
        unsafe=unsafe,
        max_depth=5,
        timeout_ms=5000,
    )
    assert cex is not None
    assert cex.depth == 2
    assert [st["x"] for st in cex.trace] == [0, 1, 2]


def test_pdr_proves_safe_when_bounded():
    var_names = ["x"]

    def init(x):
        return x["x"] == 0

    def trans(x, x_next):
        # x increments until 3, then stutters.
        return z3.Or(
            z3.And(x["x"] < 3, x_next["x"] == x["x"] + 1),
            z3.And(x["x"] >= 3, x_next["x"] == x["x"]),
        )

    def unsafe(x):
        return x["x"] > 3

    res = pdr_check_safety(
        var_names=var_names,
        init=init,
        trans=trans,
        unsafe=unsafe,
        timeout_ms=20000,
    )
    assert res.verdict == "SAFE", res.message


def test_pdr_finds_bug_when_reachable():
    var_names = ["x"]

    def init(x):
        return x["x"] == 0

    def trans(x, x_next):
        return x_next["x"] == x["x"] + 1

    def unsafe(x):
        return x["x"] == 5

    res = pdr_check_safety(
        var_names=var_names,
        init=init,
        trans=trans,
        unsafe=unsafe,
        timeout_ms=20000,
    )
    assert res.verdict in {"BUG", "UNKNOWN"}, res.message


def test_ice_learns_simple_bounds_conjunction():
    x = z3.Int("x")
    variables = {"x": x}
    candidates = {
        "x_ge0": x >= 0,
        "x_le3": x <= 3,
        "x_le2": x <= 2,
    }

    positive = [{"x": 0}, {"x": 1}, {"x": 2}, {"x": 3}]
    negative = [{"x": 4}]
    implications = [({"x": 1}, {"x": 2})]

    res = ice_learn_conjunction(
        variables=variables,
        candidate_predicates=candidates,
        positive=positive,
        negative=negative,
        implications=implications,
        timeout_ms=5000,
    )
    assert res.success, res.message
    assert "x_le3" in res.chosen_predicates
    assert "x_le2" not in res.chosen_predicates

