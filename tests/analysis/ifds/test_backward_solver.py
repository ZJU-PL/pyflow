from __future__ import annotations

from pyflow.analysis.ifds.backward_solver import (
    BackwardIFDSProblem,
    BackwardIFDSSolver,
)
from pyflow.analysis.ifds import AnalysisStatus, SolverOptions, Supergraph

ZERO = "ZERO"


class LinearBackwardProblem(BackwardIFDSProblem[str, str, str]):
    def __init__(self, supergraph: Supergraph[str, str]) -> None:
        self._supergraph = supergraph

    @property
    def supergraph(self) -> Supergraph[str, str]:
        return self._supergraph

    @property
    def zero_fact(self) -> str:
        return ZERO

    def initial_seeds(self):
        return {"main.exit": frozenset({ZERO, "tainted"})}

    def normal_flow(self, predecessor: str, successor: str, fact: str):
        if predecessor == "main.entry" and successor == "main.body" and fact == ZERO:
            return (ZERO,)
        if fact in {ZERO, "tainted"}:
            return (fact,)
        return ()


def build_linear_supergraph() -> Supergraph[str, str]:
    graph = Supergraph[str, str]()
    graph.add_procedure("main", "main.entry", ["main.exit"])
    graph.add_node("main", "main.body")
    graph.add_normal_edge("main.entry", "main.body")
    graph.add_normal_edge("main.body", "main.exit")
    return graph


def test_backward_ifds_linear_intra_procedural():
    result = BackwardIFDSSolver().solve(
        LinearBackwardProblem(build_linear_supergraph())
    )

    assert result.is_reached("main.entry", ZERO)
    assert result.is_reached("main.entry", "tainted")
    assert result.is_reached("main.body", "tainted")


def test_backward_ifds_honors_solver_budgets():
    result = BackwardIFDSSolver(
        options=SolverOptions(max_propagated_path_edges=1)
    ).solve(LinearBackwardProblem(build_linear_supergraph()))

    assert result.status is AnalysisStatus.PARTIAL
    assert "max_propagated_path_edges=1" in result.termination_reason


class CallReturnBackwardProblem(BackwardIFDSProblem[str, str, str]):
    def __init__(self, supergraph: Supergraph[str, str]) -> None:
        self._supergraph = supergraph

    @property
    def supergraph(self) -> Supergraph[str, str]:
        return self._supergraph

    @property
    def zero_fact(self) -> str:
        return ZERO

    def initial_seeds(self):
        return {"main.exit": frozenset({ZERO, "sink_fact"})}

    def normal_flow(self, predecessor: str, successor: str, fact: str):
        if predecessor == "main.entry" and successor == "main.call" and fact == ZERO:
            return (ZERO,)
        if (
            predecessor == "main.after"
            and successor == "main.exit"
            and fact in {ZERO, "sink_fact"}
        ):
            return (fact,)
        if (
            predecessor == "helper.entry"
            and successor == "helper.exit"
            and fact == ZERO
        ):
            return (ZERO, "source_fact")
        return ()

    def call_flow(self, return_site: str, callee: str, fact: str):
        if return_site == "main.after" and callee == "helper":
            if fact == ZERO:
                return (ZERO,)
            if fact == "sink_fact":
                return ("sink_fact",)
        return ()

    def return_flow(
        self, return_site: str, callee: str, callee_entry: str, call_fact: str
    ):
        if (
            return_site == "main.after"
            and callee == "helper"
            and callee_entry == "helper.entry"
        ):
            if call_fact == "sink_fact":
                return ("sink_fact",)
        return ()

    def call_to_return_flow(self, return_site: str, call_site: str, fact: str):
        if return_site == "main.after" and call_site == "main.call" and fact == ZERO:
            return (ZERO,)
        if (
            return_site == "main.after"
            and call_site == "main.call"
            and fact == "sink_fact"
        ):
            return ("sink_fact",)
        return ()


def build_call_supergraph() -> Supergraph[str, str]:
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


def test_backward_ifds_propagates_facts_reverse_through_call_and_return():
    result = BackwardIFDSSolver().solve(
        CallReturnBackwardProblem(build_call_supergraph())
    )

    assert result.is_reached("main.after", "sink_fact")
    assert result.is_reached("main.call", "sink_fact")
    assert result.is_reached("main.entry", ZERO)
