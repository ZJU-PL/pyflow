"""Tests for demand-driven backward call-chain verification."""

from pyflow.analysis.ifds import (
    IFDSProblem,
    IFDSSolver,
    Supergraph,
    ZERO,
    verify_call_chain,
)


def _build_two_proc_layered_supergraph() -> Supergraph[str, str]:
    graph = Supergraph[str, str]()
    graph.add_procedure("main", "main.entry", ["main.exit"])
    graph.add_node("main", "main.call")
    graph.add_node("main", "main.after")
    graph.add_normal_edge("main.entry", "main.call")
    graph.add_normal_edge("main.after", "main.exit")

    graph.add_procedure("helper", "helper.entry", ["helper.exit"])
    graph.add_normal_edge("helper.entry", "helper.exit")

    graph.add_call_edge("main.call", "helper", "main.after")
    return graph


class _TwoProcPassThroughProblem(IFDSProblem[str, str, str]):
    def __init__(self, supergraph: Supergraph[str, str]) -> None:
        self._supergraph = supergraph

    @property
    def supergraph(self) -> Supergraph[str, str]:
        return self._supergraph

    @property
    def zero_fact(self) -> str:
        return ZERO

    def initial_seeds(self):
        return {"main.entry": frozenset({ZERO})}

    def normal_flow(self, node: str, successor: str, fact: str):
        if fact in {ZERO}:
            return (fact,)
        return ()

    def call_flow(self, call_node: str, callee: str, fact: str):
        if callee == "helper" and fact == ZERO:
            return (ZERO,)
        return ()

    def return_flow(
        self,
        call_node: str,
        callee: str,
        exit_node: str,
        return_site: str,
        call_fact: str,
        exit_fact: str,
    ):
        if (
            callee == "helper"
            and exit_node == "helper.exit"
            and call_fact == ZERO
            and exit_fact == ZERO
        ):
            return (ZERO,)
        return ()

    def call_to_return_flow(self, call_node: str, return_site: str, fact: str):
        if call_node == "main.call" and fact == ZERO:
            return (ZERO,)
        return ()


def test_reachable_two_procedure_chain():
    graph = _build_two_proc_layered_supergraph()
    problem = _TwoProcPassThroughProblem(graph)
    result = IFDSSolver().solve(problem)

    is_reachable, chain = verify_call_chain(result, graph, "helper.exit", ZERO)

    assert is_reachable
    assert len(chain) >= 2
    assert chain[0] in {"main.entry", "main.call"}
    assert chain[-1] == "helper.exit"


def test_unreachable_island_sink():
    graph = Supergraph[str, str]()

    graph.add_procedure("a", "a.entry", ["a.exit"])
    graph.add_node("a", "a.call")
    graph.add_node("a", "a.after")
    graph.add_normal_edge("a.entry", "a.call")
    graph.add_normal_edge("a.after", "a.exit")

    graph.add_procedure("b", "b.entry", ["b.exit"])
    graph.add_node("b", "b.call")
    graph.add_node("b", "b.after")
    graph.add_normal_edge("b.entry", "b.call")
    graph.add_normal_edge("b.after", "b.exit")

    graph.add_call_edge("a.call", "b", "a.after")
    graph.add_call_edge("b.call", "a", "b.after")

    class _MutualCycleProblem(IFDSProblem[str, str, str]):
        def __init__(self, sg: Supergraph[str, str]) -> None:
            self._sg = sg

        @property
        def supergraph(self) -> Supergraph[str, str]:
            return self._sg

        @property
        def zero_fact(self) -> str:
            return ZERO

        def initial_seeds(self):
            return {"a.entry": frozenset({ZERO})}

        def normal_flow(self, node: str, successor: str, fact: str):
            if fact == ZERO:
                return (ZERO,)
            return ()

        def call_flow(self, call_node: str, callee: str, fact: str):
            if fact == ZERO:
                return (ZERO,)
            return ()

        def return_flow(self, call_node, callee, exit_node, return_site, call_fact, exit_fact):
            if call_fact == ZERO and exit_fact == ZERO:
                return (ZERO,)
            return ()

        def call_to_return_flow(self, call_node: str, return_site: str, fact: str):
            if fact == ZERO:
                return (ZERO,)
            return ()

    result = IFDSSolver().solve(_MutualCycleProblem(graph))
    is_reachable, chain = verify_call_chain(result, graph, "a.exit", ZERO)
    assert is_reachable is False
    assert chain == ()


def test_source_node_specified():
    graph = _build_two_proc_layered_supergraph()
    result = IFDSSolver().solve(_TwoProcPassThroughProblem(graph))

    is_reachable, chain = verify_call_chain(
        result, graph, "helper.exit", ZERO, source_node="main.call"
    )

    assert is_reachable
    assert len(chain) >= 2
    assert chain[0] == "main.call"
    assert chain[-1] == "helper.exit"


def test_wrong_source_node():
    graph = _build_two_proc_layered_supergraph()
    result = IFDSSolver().solve(_TwoProcPassThroughProblem(graph))

    is_reachable, chain = verify_call_chain(
        result, graph, "helper.exit", ZERO, source_node="nonexistent"
    )

    assert is_reachable is False
    assert chain == ()


def _build_five_proc_chain_supergraph() -> Supergraph[str, str]:
    graph = Supergraph[str, str]()

    def _add_call_proc(name, entry, exit_node, call_node, after_node):
        graph.add_procedure(name, entry, [exit_node])
        graph.add_node(name, call_node)
        graph.add_node(name, after_node)
        graph.add_normal_edge(entry, call_node)
        graph.add_normal_edge(after_node, exit_node)

    _add_call_proc("main", "main.entry", "main.exit", "main.call", "main.after")
    _add_call_proc("h1", "h1.entry", "h1.exit", "h1.call", "h1.after")
    _add_call_proc("h2", "h2.entry", "h2.exit", "h2.call", "h2.after")
    _add_call_proc("h3", "h3.entry", "h3.exit", "h3.call", "h3.after")
    _add_call_proc("h4", "h4.entry", "h4.exit", "h4.call", "h4.after")
    _add_call_proc("h5", "h5.entry", "h5.exit", "h5.call", "h5.after")

    graph.add_call_edge("main.call", "h1", "main.after")
    graph.add_call_edge("h1.call", "h2", "h1.after")
    graph.add_call_edge("h2.call", "h3", "h2.after")
    graph.add_call_edge("h3.call", "h4", "h3.after")
    graph.add_call_edge("h4.call", "h5", "h4.after")

    return graph


class _MultiCallPassThroughProblem(IFDSProblem[str, str, str]):
    def __init__(self, supergraph: Supergraph[str, str]) -> None:
        self._supergraph = supergraph

    @property
    def supergraph(self) -> Supergraph[str, str]:
        return self._supergraph

    @property
    def zero_fact(self) -> str:
        return ZERO

    def initial_seeds(self):
        return {"main.entry": frozenset({ZERO})}

    def normal_flow(self, node: str, successor: str, fact: str):
        if fact == ZERO:
            return (ZERO,)
        return ()

    def call_flow(self, call_node: str, callee: str, fact: str):
        if fact == ZERO:
            return (ZERO,)
        return ()

    def return_flow(self, call_node, callee, exit_node, return_site, call_fact, exit_fact):
        if call_fact == ZERO and exit_fact == ZERO:
            return (ZERO,)
        return ()

    def call_to_return_flow(self, call_node: str, return_site: str, fact: str):
        if fact == ZERO:
            return (ZERO,)
        return ()


def test_max_depth_limit():
    graph = _build_five_proc_chain_supergraph()
    result = IFDSSolver().solve(_MultiCallPassThroughProblem(graph))

    is_reachable, chain = verify_call_chain(
        result, graph, "h5.exit", ZERO, max_depth=2
    )

    assert is_reachable is False
    assert chain == ()


def test_intraprocedural_no_calls():
    graph = Supergraph[str, str]()
    graph.add_procedure("main", "main.entry", ["main.exit"])
    graph.add_node("main", "main.body")
    graph.add_normal_edge("main.entry", "main.body")
    graph.add_normal_edge("main.body", "main.exit")

    class _IntraProblem(IFDSProblem[str, str, str]):
        def __init__(self, sg: Supergraph[str, str]) -> None:
            self._sg = sg

        @property
        def supergraph(self) -> Supergraph[str, str]:
            return self._sg

        @property
        def zero_fact(self) -> str:
            return ZERO

        def initial_seeds(self):
            return {"main.entry": frozenset({ZERO})}

        def normal_flow(self, node: str, successor: str, fact: str):
            if fact == ZERO:
                return (ZERO,)
            return ()

    result = IFDSSolver().solve(_IntraProblem(graph))

    is_reachable, chain = verify_call_chain(result, graph, "main.exit", ZERO)

    assert is_reachable
    assert len(chain) >= 1
    assert chain[-1] == "main.exit"
