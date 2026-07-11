"""Tests for access-path-aware fact prefix matching."""

from __future__ import annotations

from dataclasses import dataclass

from pyflow.analysis.ifds import (
    GenFlow,
    IFDSProblem,
    IFDSResult,
    IFDSSolver,
    IdentityFlow,
    TaintFact,
    Supergraph,
    ZERO,
    ZeroFact,
)
from pyflow.analysis.ifds.solver import (
    _fact_prefix_match,
    _paths_prefix_match,
)


def test_paths_prefix_empty_matches_everything():
    """Empty stored path matches any query path."""
    assert _paths_prefix_match(_PathFact(()), _PathFact(("f",)))
    assert _paths_prefix_match(_PathFact(()), _PathFact(("f", "g")))
    assert _paths_prefix_match(_PathFact(()), _PathFact(()))


def test_paths_prefix_f_matches_f_g():
    """("f",) is a prefix of ("f", "g")."""
    assert _paths_prefix_match(_PathFact(("f",)), _PathFact(("f", "g")))


def test_paths_prefix_f_g_not_match_f():
    """("f", "g") is NOT a prefix of ("f",)."""
    assert not _paths_prefix_match(_PathFact(("f", "g")), _PathFact(("f",)))


def test_paths_prefix_equal():
    """Equal paths match."""
    assert _paths_prefix_match(_PathFact(("f", "g")), _PathFact(("f", "g")))


def test_paths_prefix_single_long():
    """("f",) is a prefix of ("f",)."""
    assert _paths_prefix_match(_PathFact(("f",)), _PathFact(("f",)))


@dataclass(frozen=True)
class _PathFact:
    access_path: tuple[str, ...]


@dataclass(frozen=True)
class _LocationFact:
    location: object
    access_path: tuple[str, ...]


@dataclass(frozen=True)
class _ExprFact:
    expression: object
    procedure: object
    access_path: tuple[str, ...]


def test_fact_prefix_match_location_different():
    """Different locations: no match."""
    f1 = _LocationFact(location="a", access_path=("f",))
    f2 = _LocationFact(location="b", access_path=("f", "g"))
    assert not _fact_prefix_match(f1, f2)


def test_fact_prefix_match_location_same_prefix():
    """Same location, stored path is prefix of query path: match."""
    f1 = _LocationFact(location="a", access_path=("f",))
    f2 = _LocationFact(location="a", access_path=("f", "g"))
    assert _fact_prefix_match(f1, f2)


def test_fact_prefix_match_location_same_exact():
    """Same location, same access_path: match."""
    f1 = _LocationFact(location="a", access_path=("f", "g"))
    f2 = _LocationFact(location="a", access_path=("f", "g"))
    assert _fact_prefix_match(f1, f2)


def test_fact_prefix_match_expr_different():
    """Different expression: no match."""
    f1 = _ExprFact(expression="x", procedure="p", access_path=("f",))
    f2 = _ExprFact(expression="y", procedure="p", access_path=("f", "g"))
    assert not _fact_prefix_match(f1, f2)


def test_fact_prefix_match_expr_different_proc():
    """Different procedure: no match."""
    f1 = _ExprFact(expression="x", procedure="p1", access_path=("f",))
    f2 = _ExprFact(expression="x", procedure="p2", access_path=("f", "g"))
    assert not _fact_prefix_match(f1, f2)


def test_fact_prefix_match_expr_same_prefix():
    """Same expression and procedure, stored path is prefix of query path: match."""
    f1 = _ExprFact(expression="x", procedure="p", access_path=("f",))
    f2 = _ExprFact(expression="x", procedure="p", access_path=("f", "g"))
    assert _fact_prefix_match(f1, f2)


def test_fact_prefix_match_expr_same_exact():
    """Same expression and procedure, same access_path: match."""
    f1 = _ExprFact(expression="x", procedure="p", access_path=("f", "g"))
    f2 = _ExprFact(expression="x", procedure="p", access_path=("f", "g"))
    assert _fact_prefix_match(f1, f2)


def test_fact_prefix_match_cross_kinds():
    """Location fact does not match expression fact even if paths align."""
    f1 = _LocationFact(location="a", access_path=("f",))
    f2 = _ExprFact(expression="a", procedure="p", access_path=("f", "g"))
    assert not _fact_prefix_match(f1, f2)


def test_is_reached_prefix_exact_match():
    """is_reached_prefix returns True for an exact stored fact match."""
    graph = Supergraph[str, str]()
    graph.add_procedure("main", "main.entry", ["main.exit"])
    graph.add_node("main", "main.body")
    graph.add_normal_edge("main.entry", "main.body")
    graph.add_normal_edge("main.body", "main.exit")

    location = "my_obj"
    fact_a = TaintFact(location=location, access_path=("f",))

    class _TestProblem(IFDSProblem[str, str, TaintFact]):
        def __init__(self, supergraph):
            self._supergraph = supergraph

        @property
        def supergraph(self):
            return self._supergraph

        @property
        def zero_fact(self):
            return ZERO

        def initial_seeds(self):
            return {"main.entry": frozenset({ZERO})}

        def normal_flow(self, node, successor, fact):
            if node == "main.entry" and successor == "main.body" and fact == ZERO:
                return (ZERO, fact_a)
            if fact is not ZERO:
                return (fact,)
            return ()

    result = IFDSSolver().solve(_TestProblem(graph))

    assert result.is_reached_prefix("main.body", fact_a)
    assert result.is_reached_prefix("main.exit", fact_a)


def test_is_reached_prefix_with_prefix_path():
    """is_reached_prefix returns True when stored fact has a prefix access_path."""
    graph = Supergraph[str, str]()
    graph.add_procedure("main", "main.entry", ["main.exit"])
    graph.add_node("main", "main.body")
    graph.add_normal_edge("main.entry", "main.body")
    graph.add_normal_edge("main.body", "main.exit")

    location = "my_obj"
    fact_stored = TaintFact(location=location, access_path=("f",))
    fact_query = TaintFact(location=location, access_path=("f", "g"))

    class _TestProblem(IFDSProblem[str, str, TaintFact]):
        def __init__(self, supergraph):
            self._supergraph = supergraph

        @property
        def supergraph(self):
            return self._supergraph

        @property
        def zero_fact(self):
            return ZERO

        def initial_seeds(self):
            return {"main.entry": frozenset({ZERO})}

        def normal_flow(self, node, successor, fact):
            if node == "main.entry" and successor == "main.body" and fact == ZERO:
                return (ZERO, fact_stored)
            if fact is not ZERO:
                return (fact,)
            return ()

    result = IFDSSolver().solve(_TestProblem(graph))

    assert result.is_reached_prefix("main.body", fact_query)
    assert result.is_reached_prefix("main.exit", fact_query)


def test_is_reached_prefix_wrong_location():
    """is_reached_prefix returns False when location doesn't match."""
    graph = Supergraph[str, str]()
    graph.add_procedure("main", "main.entry", ["main.exit"])
    graph.add_node("main", "main.body")
    graph.add_normal_edge("main.entry", "main.body")
    graph.add_normal_edge("main.body", "main.exit")

    fact_stored = TaintFact(location="a", access_path=("f",))
    fact_query = TaintFact(location="b", access_path=("f", "g"))

    class _TestProblem(IFDSProblem[str, str, TaintFact]):
        def __init__(self, supergraph):
            self._supergraph = supergraph

        @property
        def supergraph(self):
            return self._supergraph

        @property
        def zero_fact(self):
            return ZERO

        def initial_seeds(self):
            return {"main.entry": frozenset({ZERO})}

        def normal_flow(self, node, successor, fact):
            if node == "main.entry" and successor == "main.body" and fact == ZERO:
                return (ZERO, fact_stored)
            if fact is not ZERO:
                return (fact,)
            return ()

    result = IFDSSolver().solve(_TestProblem(graph))

    assert not result.is_reached_prefix("main.body", fact_query)
    assert not result.is_reached_prefix("main.exit", fact_query)


def test_is_reached_prefix_not_reversed():
    """is_reached_prefix returns False when query has shorter path than stored."""
    graph = Supergraph[str, str]()
    graph.add_procedure("main", "main.entry", ["main.exit"])
    graph.add_node("main", "main.body")
    graph.add_normal_edge("main.entry", "main.body")
    graph.add_normal_edge("main.body", "main.exit")

    location = "my_obj"
    fact_stored = TaintFact(location=location, access_path=("f", "g"))
    fact_query = TaintFact(location=location, access_path=("f",))

    class _TestProblem(IFDSProblem[str, str, TaintFact]):
        def __init__(self, supergraph):
            self._supergraph = supergraph

        @property
        def supergraph(self):
            return self._supergraph

        @property
        def zero_fact(self):
            return ZERO

        def initial_seeds(self):
            return {"main.entry": frozenset({ZERO})}

        def normal_flow(self, node, successor, fact):
            if node == "main.entry" and successor == "main.body" and fact == ZERO:
                return (ZERO, fact_stored)
            if fact is not ZERO:
                return (fact,)
            return ()

    result = IFDSSolver().solve(_TestProblem(graph))

    assert not result.is_reached_prefix("main.body", fact_query)
    assert not result.is_reached_prefix("main.exit", fact_query)


def test_is_reached_prefix_nothing_stored():
    """is_reached_prefix returns False when nothing is stored at the node."""
    graph = Supergraph[str, str]()
    graph.add_procedure("main", "main.entry", ["main.exit"])
    graph.add_node("main", "main.body")
    graph.add_normal_edge("main.entry", "main.body")
    graph.add_normal_edge("main.body", "main.exit")

    fact_query = TaintFact(location="a", access_path=("f",))

    class _TestProblem(IFDSProblem[str, str, TaintFact]):
        def __init__(self, supergraph):
            self._supergraph = supergraph

        @property
        def supergraph(self):
            return self._supergraph

        @property
        def zero_fact(self):
            return ZERO

        def initial_seeds(self):
            return {"main.entry": frozenset({ZERO})}

        def normal_flow(self, node, successor, fact):
            if fact == ZERO:
                return (ZERO,)
            return ()

    result = IFDSSolver().solve(_TestProblem(graph))

    assert not result.is_reached_prefix("main.body", fact_query)
