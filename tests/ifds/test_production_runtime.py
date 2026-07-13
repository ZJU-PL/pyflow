from __future__ import annotations

import random
import json
from types import SimpleNamespace
import pytest

from pyflow.analysis.ifds import (
    AnalysisStatus,
    CancellationToken,
    IFDSProblem,
    IFDSSolver,
    SolverOptions,
    Supergraph,
)
from pyflow.cli.security import run_security
from pyflow.analysis.ifds.clients.registry import (
    validate_registry,
    validate_rule_pack_data,
)
from pyflow.analysis.ifds.preparation import PreparationMode, prepare_program_for_ifds

from tests.ifds.reference_solver import solve_reference


class _GeneratedProblem(IFDSProblem[str, str, str]):
    def __init__(self, graph, transitions):
        self._graph = graph
        self.transitions = transitions

    @property
    def supergraph(self):
        return self._graph

    @property
    def zero_fact(self):
        return "0"

    def initial_seeds(self):
        return {"n0": frozenset({"0"})}

    def normal_flow(self, node, successor, fact):
        return self.transitions.get((node, successor, fact), (fact,))


def _linear_problem(length=8):
    graph = Supergraph[str, str]()
    graph.add_procedure("main", "n0", [f"n{length - 1}"])
    for index in range(1, length):
        graph.add_node("main", f"n{index}")
        graph.add_normal_edge(f"n{index - 1}", f"n{index}")
    return _GeneratedProblem(graph, {})


def test_solver_options_return_partial_result_instead_of_raising():
    result = IFDSSolver(
        options=SolverOptions(max_propagated_path_edges=2)
    ).solve(_linear_problem())

    assert result.status is AnalysisStatus.PARTIAL
    assert "max_propagated_path_edges=2" in result.termination_reason
    assert result.statistics.propagated_path_edges == 3


def test_solver_cancellation_returns_cancelled_result():
    token = CancellationToken()
    token.cancel("test cancellation")
    result = IFDSSolver(
        options=SolverOptions(cancellation_token=token, budget_check_interval=1)
    ).solve(_linear_problem())

    assert result.status is AnalysisStatus.CANCELLED
    assert result.termination_reason == "test cancellation"


def test_supergraph_assigns_compact_stable_ids_and_order():
    problem = _linear_problem(5)
    graph = problem.supergraph

    assert [graph.node_id(node) for node in graph.ordered_nodes()] == list(range(5))
    assert graph.procedure_id("main") == 0
    assert graph.ordered_normal_successors("n2") == ("n3",)
    result = IFDSSolver().solve(problem)
    assert result.fact_id("0") == 0
    assert result.facts_with_ids_at("n4") == ((0, "0"),)


def test_random_intraprocedural_problems_match_reference_solver():
    for seed in range(25):
        rng = random.Random(seed)
        graph = Supergraph[str, str]()
        graph.add_procedure("main", "n0", ["n7"])
        for index in range(1, 8):
            graph.add_node("main", f"n{index}")
        for source in range(7):
            graph.add_normal_edge(f"n{source}", f"n{source + 1}")
            if source + 2 < 8 and rng.random() < 0.5:
                graph.add_normal_edge(f"n{source}", f"n{source + 2}")

        transitions = {}
        facts = ("0", "a", "b")
        for node in graph.ordered_nodes():
            for successor in graph.ordered_normal_successors(node):
                for fact in facts:
                    outputs = {fact}
                    if rng.random() < 0.25:
                        outputs.add(rng.choice(facts))
                    transitions[(node, successor, fact)] = tuple(sorted(outputs))

        problem = _GeneratedProblem(graph, transitions)
        expected = solve_reference(problem)
        actual = IFDSSolver().solve(problem)
        assert {
            node: actual.facts_at(node) for node in graph.ordered_nodes()
        } == {node: expected.get(node, frozenset()) for node in graph.ordered_nodes()}


def test_ifds_sarif_contains_location_and_code_flow(tmp_path, capsys):
    target = tmp_path / "flow.py"
    target.write_text(
        """
def source():
    return 1

def sink(value):
    return value

def main():
    value = source()
    sink(value)
"""
    )
    args = SimpleNamespace(
        function="main",
        analysis="taint",
        engine="ifds",
        targets=[target],
        sources=["source"],
        sinks=["sink"],
        sanitizers=[],
        format="sarif",
        recursive=False,
        dependency_strategy="auto",
        verbose=False,
    )

    assert run_security(args) == 1
    payload = json.loads(capsys.readouterr().out)
    result = payload["runs"][0]["results"][0]
    region = result["locations"][0]["physicalLocation"]["region"]
    assert region["startLine"] > 0
    assert region["endLine"] >= region["startLine"]
    assert region["endColumn"] > region["startColumn"]
    assert result["partialFingerprints"]["pyflow/v1"]
    assert result["codeFlows"][0]["threadFlows"][0]["locations"]


def test_shipped_registry_is_schema_valid():
    assert validate_registry() == ()


def test_registry_validation_rejects_invalid_argument_positions():
    issues = validate_rule_pack_data(
        {
            "schema_version": 1,
            "framework": "demo",
            "version": "1.0",
            "models": [{"call": "demo.sink", "sink_arg_positions": [-1]}],
        }
    )
    assert any("non-negative integers" in issue.message for issue in issues)


def test_strict_preparation_propagates_pipeline_failure():
    program = SimpleNamespace(liveCode=set())

    with pytest.raises(RuntimeError, match="pipeline failed"):
        prepare_program_for_ifds(
            None,
            program,
            get_cfg=lambda code: code,
            describe_code=str,
            run_pipeline=lambda: (_ for _ in ()).throw(
                RuntimeError("pipeline failed")
            ),
            mode=PreparationMode.STRICT,
        )


def test_cli_uses_distinct_invalid_and_partial_exit_codes(tmp_path, capsys):
    target = tmp_path / "flow.py"
    target.write_text(
        """
def source(): return 1
def sink(value): return value
def main(): sink(source())
"""
    )
    base = dict(
        function="main",
        analysis="taint",
        engine="ifds",
        targets=[target],
        sources=[],
        sinks=[],
        sanitizers=[],
        format="json",
        recursive=False,
        dependency_strategy="auto",
        verbose=False,
    )
    assert run_security(SimpleNamespace(**base)) == 2
    capsys.readouterr()

    limited = {
        **base,
        "sources": ["source"],
        "sinks": ["sink"],
        "ifds_max_path_edges": 1,
    }
    assert run_security(SimpleNamespace(**limited)) == 3
    payload = json.loads(capsys.readouterr().out)
    assert payload["status"] == "partial"
