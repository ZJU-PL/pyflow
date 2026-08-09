import pytest

from pyflow.concolic.exploration.state_space import SolverResultCache, SolverStateSpace


z3 = pytest.importorskip("z3")


def test_state_space_caches_unsatisfiable_queries_and_checks_deferred_assumptions():
    cache = SolverResultCache()
    value = z3.Int("value")

    first = SolverStateSpace(z3, cache=cache)
    first.add(value > 0)
    first.defer_assumption("value must stay small", lambda: value < 3)
    assert first.check(value > 5).result == z3.unsat

    second = SolverStateSpace(z3, cache=cache)
    second.add(value > 0, value < 3)
    cached = second.check(value > 5)
    assert cached.result == z3.unsat
    assert cached.cache_hit


def test_state_space_supports_decisions_and_multiway_fanout():
    value = z3.Int("choice")
    space = SolverStateSpace(z3)
    space.add(value >= 0, value <= 2)

    assert space.choose_possible(value == 1)
    selected = space.fanout(
        ((value == 0, "zero"), (value == 1, "one"), (value == 2, "two")),
        description="integer choice",
    )

    assert selected == "one"
    assert space.model().eval(value).as_long() == 1
