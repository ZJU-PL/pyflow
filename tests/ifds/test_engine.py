"""Tests for the IFDS/IDE interprocedural dataflow engine."""

from __future__ import annotations

from dataclasses import dataclass

from pyflow.analysis.ifds import (
    EdgeFunction,
    FactTransition,
    IDEProblem,
    IDESolver,
    IFDSProblem,
    IFDSSolver,
    IdentityEdgeFunction,
    PathEdge,
    SolverLimitExceeded,
    Supergraph,
    ValueTransition,
)


ZERO = "ZERO"


class LinearIFDSProblem(IFDSProblem[str, str, str]):
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
        if node == "main.entry" and successor == "main.body" and fact == ZERO:
            return (ZERO, "x")
        if fact in {ZERO, "x"}:
            return (fact,)
        return ()


class CallReturnIFDSProblem(IFDSProblem[str, str, str]):
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
        if node == "main.entry" and successor == "main.call" and fact == ZERO:
            return (ZERO, "taint")
        if fact in {ZERO, "taint", "param"}:
            return (fact,)
        return ()

    def call_flow(self, call_node: str, callee: str, fact: str):
        if call_node == "main.call" and callee == "helper":
            if fact == ZERO:
                return (ZERO,)
            if fact == "taint":
                return ("param",)
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
            call_node == "main.call"
            and callee == "helper"
            and exit_node == "helper.exit"
            and return_site == "main.after"
        ):
            if call_fact == ZERO and exit_fact == ZERO:
                return (ZERO,)
            if call_fact == "taint" and exit_fact == "param":
                return ("taint",)
        return ()

    def call_to_return_flow(self, call_node: str, return_site: str, fact: str):
        if call_node == "main.call" and return_site == "main.after" and fact == ZERO:
            return (ZERO,)
        return ()


class RecursiveIFDSProblem(IFDSProblem[str, str, str]):
    def __init__(self, supergraph: Supergraph[str, str]) -> None:
        self._supergraph = supergraph

    @property
    def supergraph(self) -> Supergraph[str, str]:
        return self._supergraph

    @property
    def zero_fact(self) -> str:
        return ZERO

    def initial_seeds(self):
        return {"rec.entry": frozenset({ZERO})}

    def normal_flow(self, node: str, successor: str, fact: str):
        if node == "rec.entry" and successor == "rec.call" and fact == ZERO:
            return (ZERO, "loop")
        if fact in {ZERO, "loop"}:
            return (fact,)
        return ()

    def call_flow(self, call_node: str, callee: str, fact: str):
        if call_node == "rec.call" and callee == "rec" and fact == "loop":
            return ("loop",)
        if call_node == "rec.call" and callee == "rec" and fact == ZERO:
            return (ZERO,)
        return ()

    def call_to_return_flow(self, call_node: str, return_site: str, fact: str):
        if call_node == "rec.call" and return_site == "rec.after":
            return (fact,)
        return ()


@dataclass(frozen=True)
class AddLabels(EdgeFunction[frozenset[str]]):
    labels: frozenset[str]

    def compute(self, value: frozenset[str]) -> frozenset[str]:
        return value | self.labels

    def is_idempotent(self) -> bool:
        return True


class SplitCallIDEProblem(IDEProblem[str, str, str, frozenset[str]]):
    def __init__(self, supergraph: Supergraph[str, str]) -> None:
        self._supergraph = supergraph

    @property
    def supergraph(self) -> Supergraph[str, str]:
        return self._supergraph

    @property
    def zero_fact(self) -> str:
        return ZERO

    @property
    def bottom_value(self) -> frozenset[str]:
        return frozenset()

    def join_values(
        self, left: frozenset[str], right: frozenset[str]
    ) -> frozenset[str]:
        return left | right

    def initial_seed_values(self):
        return {("main.entry", ZERO): frozenset()}

    def normal_flow(self, node: str, successor: str, fact: str):
        if node == "main.entry" and successor in {"main.call1", "main.call2"} and fact == ZERO:
            return (ValueTransition("d", IdentityEdgeFunction()),)
        if node in {"main.ret1", "main.ret2"} and successor == "main.exit" and fact == "d":
            return (ValueTransition("d", IdentityEdgeFunction()),)
        if node == "callee.entry" and successor == "callee.exit" and fact == "p":
            return (ValueTransition("p", AddLabels(frozenset({"summary"}))),)
        return ()

    def call_flow(self, call_node: str, callee: str, fact: str):
        if callee != "callee" or fact != "d":
            return ()
        if call_node == "main.call1":
            return (ValueTransition("p", AddLabels(frozenset({"one"}))),)
        if call_node == "main.call2":
            return (ValueTransition("p", AddLabels(frozenset({"two"}))),)
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
            callee == "callee"
            and exit_node == "callee.exit"
            and call_fact == "d"
            and exit_fact == "p"
            and return_site in {"main.ret1", "main.ret2"}
        ):
            return (ValueTransition("d", IdentityEdgeFunction()),)
        return ()

    def call_to_return_flow(self, call_node: str, return_site: str, fact: str):
        if fact == ZERO:
            return (ValueTransition(ZERO, IdentityEdgeFunction()),)
        return ()


class RecursiveIDEProblem(IDEProblem[str, str, str, frozenset[str]]):
    def __init__(self, supergraph: Supergraph[str, str]) -> None:
        self._supergraph = supergraph

    @property
    def supergraph(self) -> Supergraph[str, str]:
        return self._supergraph

    @property
    def zero_fact(self) -> str:
        return ZERO

    @property
    def bottom_value(self) -> frozenset[str]:
        return frozenset()

    def join_values(
        self, left: frozenset[str], right: frozenset[str]
    ) -> frozenset[str]:
        return left | right

    def initial_seed_values(self):
        return {("rec.entry", ZERO): frozenset()}

    def normal_flow(self, node: str, successor: str, fact: str):
        if node == "rec.entry" and successor == "rec.call" and fact == ZERO:
            return (
                ValueTransition(ZERO, IdentityEdgeFunction()),
                ValueTransition("d", IdentityEdgeFunction()),
            )
        if node == "rec.entry" and successor == "rec.call" and fact == "d":
            return (ValueTransition("d", IdentityEdgeFunction()),)
        if node == "rec.after" and successor == "rec.exit" and fact in {ZERO, "d"}:
            return (ValueTransition(fact, IdentityEdgeFunction()),)
        return ()

    def call_flow(self, call_node: str, callee: str, fact: str):
        if call_node != "rec.call" or callee != "rec":
            return ()
        if fact == ZERO:
            return (ValueTransition(ZERO, IdentityEdgeFunction()),)
        if fact == "d":
            return (ValueTransition("d", AddLabels(frozenset({"recur"}))),)
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
            call_node == "rec.call"
            and callee == "rec"
            and exit_node == "rec.exit"
            and return_site == "rec.after"
        ):
            if call_fact == ZERO and exit_fact == ZERO:
                return (ValueTransition(ZERO, IdentityEdgeFunction()),)
            if call_fact == "d" and exit_fact == "d":
                return (ValueTransition("d", IdentityEdgeFunction()),)
        return ()

    def call_to_return_flow(self, call_node: str, return_site: str, fact: str):
        if call_node == "rec.call" and return_site == "rec.after":
            return (ValueTransition(fact, IdentityEdgeFunction()),)
        return ()


class RecursiveSourceValueIDEProblem(IDEProblem[str, str, str, frozenset[str]]):
    """Exercise source-value fixed-point resolution with a self-cycle."""

    def __init__(self, supergraph: Supergraph[str, str]) -> None:
        self._supergraph = supergraph

    @property
    def supergraph(self) -> Supergraph[str, str]:
        return self._supergraph

    @property
    def zero_fact(self) -> str:
        return ZERO

    @property
    def bottom_value(self) -> frozenset[str]:
        return frozenset()

    def join_values(
        self, left: frozenset[str], right: frozenset[str]
    ) -> frozenset[str]:
        return left | right

    def initial_seed_values(self):
        return {("main.entry", ZERO): frozenset()}

    def normal_flow(self, node: str, successor: str, fact: str):
        if node == "main.entry" and successor == "main.call" and fact == ZERO:
            return (
                ValueTransition(ZERO, IdentityEdgeFunction()),
                ValueTransition("d", IdentityEdgeFunction()),
            )
        if node == "rec.entry" and successor == "rec.call" and fact == "d":
            return (ValueTransition("d", IdentityEdgeFunction()),)
        if node == "rec.ret" and successor == "rec.exit" and fact in {ZERO, "d"}:
            return (ValueTransition(fact, IdentityEdgeFunction()),)
        if node == "main.ret" and successor == "main.exit" and fact in {ZERO, "d"}:
            return (ValueTransition(fact, IdentityEdgeFunction()),)
        return ()

    def call_flow(self, call_node: str, callee: str, fact: str):
        if callee != "rec" or fact != "d":
            return ()
        if call_node == "main.call":
            return (ValueTransition("d", AddLabels(frozenset({"A"}))),)
        if call_node == "rec.call":
            return (ValueTransition("d", AddLabels(frozenset({"B"}))),)
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
        if callee == "rec" and exit_node == "rec.exit" and return_site in {"main.ret", "rec.ret"}:
            if call_fact == ZERO and exit_fact == ZERO:
                return (ValueTransition(ZERO, IdentityEdgeFunction()),)
            if call_fact == "d" and exit_fact == "d":
                return (ValueTransition("d", IdentityEdgeFunction()),)
        return ()

    def call_to_return_flow(self, call_node: str, return_site: str, fact: str):
        if fact == ZERO and (call_node, return_site) in {
            ("main.call", "main.ret"),
            ("rec.call", "rec.ret"),
        }:
            return (ValueTransition(ZERO, IdentityEdgeFunction()),)
        return ()


def build_linear_supergraph() -> Supergraph[str, str]:
    graph = Supergraph[str, str]()
    graph.add_procedure("main", "main.entry", ["main.exit"])
    graph.add_node("main", "main.body")
    graph.add_normal_edge("main.entry", "main.body")
    graph.add_normal_edge("main.body", "main.exit")
    return graph


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


def build_recursive_supergraph() -> Supergraph[str, str]:
    graph = Supergraph[str, str]()
    graph.add_procedure("rec", "rec.entry", ["rec.exit"])
    graph.add_node("rec", "rec.call")
    graph.add_node("rec", "rec.after")
    graph.add_normal_edge("rec.entry", "rec.call")
    graph.add_normal_edge("rec.after", "rec.exit")
    graph.add_call_edge("rec.call", "rec", "rec.after")
    return graph


def build_recursive_source_value_supergraph() -> Supergraph[str, str]:
    graph = Supergraph[str, str]()

    graph.add_procedure("main", "main.entry", ["main.exit"])
    graph.add_node("main", "main.call")
    graph.add_node("main", "main.ret")
    graph.add_normal_edge("main.entry", "main.call")
    graph.add_normal_edge("main.ret", "main.exit")

    graph.add_procedure("rec", "rec.entry", ["rec.exit"])
    graph.add_node("rec", "rec.call")
    graph.add_node("rec", "rec.ret")
    graph.add_normal_edge("rec.entry", "rec.call")
    graph.add_normal_edge("rec.ret", "rec.exit")

    graph.add_call_edge("main.call", "rec", "main.ret")
    graph.add_call_edge("rec.call", "rec", "rec.ret")
    return graph


def build_split_call_supergraph() -> Supergraph[str, str]:
    graph = Supergraph[str, str]()
    graph.add_procedure("main", "main.entry", ["main.exit"])
    for node in ("main.call1", "main.call2", "main.ret1", "main.ret2"):
        graph.add_node("main", node)
    graph.add_normal_edge("main.entry", "main.call1")
    graph.add_normal_edge("main.entry", "main.call2")
    graph.add_normal_edge("main.ret1", "main.exit")
    graph.add_normal_edge("main.ret2", "main.exit")

    graph.add_procedure("callee", "callee.entry", ["callee.exit"])
    graph.add_call_edge("main.call1", "callee", "main.ret1")
    graph.add_call_edge("main.call2", "callee", "main.ret2")
    graph.add_normal_edge("callee.entry", "callee.exit")
    return graph


def test_ifds_handles_linear_intra_procedural_flow():
    result = IFDSSolver().solve(LinearIFDSProblem(build_linear_supergraph()))

    assert result.is_reached("main.exit", ZERO)
    assert result.is_reached("main.exit", "x")


def test_ifds_propagates_facts_through_call_and_return():
    result = IFDSSolver(record_traces=True).solve(
        CallReturnIFDSProblem(build_call_supergraph())
    )

    assert result.is_reached("main.after", ZERO)
    assert result.is_reached("main.after", "taint")
    assert result.is_reached("main.exit", "taint")
    assert result.statistics.summary_updates >= 1
    explanation = result.explain_fact("main.after", "taint")
    assert explanation
    assert any(
        any(step.kind.startswith("return_flow") for step in traces)
        for traces in explanation.values()
    )


def test_ifds_terminates_on_recursive_call_graph():
    result = IFDSSolver().solve(RecursiveIFDSProblem(build_recursive_supergraph()))

    assert result.is_reached("rec.after", "loop")
    assert result.is_reached("rec.exit", "loop")


def test_ide_preserves_per_callsite_values_via_jump_functions():
    result = IDESolver(record_traces=True).solve(
        SplitCallIDEProblem(build_split_call_supergraph())
    )

    assert result.value_at("callee.entry", "p") == frozenset({"one", "two"})
    assert result.value_at("callee.exit", "p") == frozenset({"one", "two", "summary"})
    assert result.value_at("main.ret1", "d") == frozenset({"one", "summary"})
    assert result.value_at("main.ret2", "d") == frozenset({"two", "summary"})
    assert result.value_at("main.exit", "d") == frozenset({"one", "two", "summary"})
    edge = PathEdge("callee.entry", "p", "callee.exit", "p")
    assert result.traces_for(edge)


def test_solvers_do_not_record_traces_unless_requested():
    ifds_result = IFDSSolver().solve(CallReturnIFDSProblem(build_call_supergraph()))
    ide_result = IDESolver().solve(SplitCallIDEProblem(build_split_call_supergraph()))

    assert not ifds_result.explain_fact("main.after", "taint")
    edge = PathEdge("callee.entry", "p", "callee.exit", "p")
    assert not ide_result.traces_for(edge)


class DuplicatePropagationIFDSProblem(LinearIFDSProblem):
    def normal_flow(self, node: str, successor: str, fact: str):
        if node == "main.entry" and successor == "main.body" and fact == ZERO:
            return (ZERO, ZERO)
        return super().normal_flow(node, successor, fact)


class WrappedTransitionIFDSProblem(LinearIFDSProblem):
    def normal_flow(self, node: str, successor: str, fact: str):
        if node == "main.entry" and successor == "main.body" and fact == ZERO:
            return (FactTransition(ZERO), FactTransition("x"))
        if fact in {ZERO, "x"}:
            return (FactTransition(fact),)
        return ()


class DuplicatePropagationIDEProblem(SplitCallIDEProblem):
    def normal_flow(self, node: str, successor: str, fact: str):
        transitions = list(super().normal_flow(node, successor, fact))
        if node == "main.entry" and successor == "main.call1" and fact == ZERO:
            transitions.append(ValueTransition("d", IdentityEdgeFunction()))
        return tuple(transitions)

    def call_to_return_flow(self, call_node: str, return_site: str, fact: str):
        transitions = list(super().call_to_return_flow(call_node, return_site, fact))
        if fact == ZERO:
            transitions.append(ValueTransition(ZERO, IdentityEdgeFunction()))
        return tuple(transitions)


def test_solvers_only_record_traces_for_new_information():
    ifds_result = IFDSSolver(record_traces=True).solve(
        DuplicatePropagationIFDSProblem(build_linear_supergraph())
    )
    ide_result = IDESolver(record_traces=True).solve(
        DuplicatePropagationIDEProblem(build_split_call_supergraph())
    )

    ifds_edge = PathEdge("main.entry", ZERO, "main.body", ZERO)
    assert len(ifds_result.traces_for(ifds_edge)) == 1

    ide_edge = PathEdge("main.entry", ZERO, "main.call1", "d")
    assert len(ide_result.traces_for(ide_edge)) == 1


def test_ifds_accepts_explicit_fact_transitions():
    result = IFDSSolver().solve(WrappedTransitionIFDSProblem(build_linear_supergraph()))

    assert result.is_reached("main.exit", ZERO)
    assert result.is_reached("main.exit", "x")


def test_edge_function_join_is_idempotent_for_duplicate_terms():
    first = AddLabels(frozenset({"one"}))
    second = AddLabels(frozenset({"two"}))
    join_values = lambda left, right: left | right

    joined = first.join(second, join_values)
    rejoined = joined.join(first, join_values)

    assert rejoined == joined
    assert rejoined(frozenset()) == frozenset({"one", "two"})


def test_ide_terminates_on_recursive_idempotent_edge_functions():
    result = IDESolver().solve(RecursiveIDEProblem(build_recursive_supergraph()))

    assert result.value_at("rec.after", "d") == frozenset({"recur"})
    assert result.value_at("rec.exit", "d") == frozenset({"recur"})


def test_ide_resolves_recursive_source_values_to_fixed_point():
    result = IDESolver().solve(
        RecursiveSourceValueIDEProblem(build_recursive_source_value_supergraph())
    )

    assert result.value_at("rec.entry", "d") == frozenset({"A", "B"})


def test_ifds_honors_max_propagation_limit():
    solver = IFDSSolver(max_propagated_path_edges=1)

    try:
        solver.solve(LinearIFDSProblem(build_linear_supergraph()))
    except SolverLimitExceeded as exc:
        assert "max_propagated_path_edges=1" in str(exc)
    else:
        raise AssertionError("Expected SolverLimitExceeded")


def test_ide_honors_max_propagation_limit():
    solver = IDESolver(max_propagated_path_edges=1)

    try:
        solver.solve(SplitCallIDEProblem(build_split_call_supergraph()))
    except SolverLimitExceeded as exc:
        assert "max_propagated_path_edges=1" in str(exc)
    else:
        raise AssertionError("Expected SolverLimitExceeded")
