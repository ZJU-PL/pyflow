from __future__ import annotations

import random
import json
import os
import subprocess
import sys
import textwrap
from types import SimpleNamespace
import pytest

import pyflow.analysis.ifds.core.solver as solver_module
from pyflow.analysis.ifds import (
    AnalysisStatus,
    AnalysisFinding,
    CancellationToken,
    IDEProblem,
    IDESolver,
    IdentityEdgeFunction,
    IFDSProblem,
    IFDSSolver,
    SolverOptions,
    SolverLimitExceeded,
    Supergraph,
    SourceSpan,
    ValueTransition,
)
from pyflow.cli.security import run_security
from pyflow.analysis.ifds.modeling.registry import (
    validate_registry,
    validate_rule_pack_data,
)
from pyflow.analysis.ifds.frontend.preparation import PreparationMode, prepare_program_for_ifds

from tests.analysis.ifds.reference_solver import solve_reference


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


class _GeneratedInterproceduralProblem(IFDSProblem[str, str, str]):
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
        return {"main.entry": frozenset({"0"})}

    def normal_flow(self, node, successor, fact):
        return self.transitions.get(("normal", node, successor, fact), ())

    def call_flow(self, call_node, callee, fact):
        return self.transitions.get(("call", call_node, callee, fact), ())

    def return_flow(
        self, call_node, callee, exit_node, return_site, call_fact, exit_fact
    ):
        return self.transitions.get(
            (
                "return",
                call_node,
                callee,
                exit_node,
                return_site,
                call_fact,
                exit_fact,
            ),
            (),
        )

    def call_to_return_flow(self, call_node, return_site, fact):
        return self.transitions.get(("bypass", call_node, return_site, fact), ())


class _GeneratedIDEProblem(IDEProblem[str, str, str, int]):
    def __init__(self, graph):
        self._graph = graph

    @property
    def supergraph(self):
        return self._graph

    @property
    def zero_fact(self):
        return "0"

    @property
    def bottom_value(self):
        return 0

    def join_values(self, left, right):
        return max(left, right)

    def initial_seed_values(self):
        return {("n0", "0"): 1}

    def normal_flow(self, node, successor, fact):
        del node, successor
        identity = IdentityEdgeFunction()
        return (
            ValueTransition(fact, identity),
            ValueTransition("generated", identity),
        )


def _linear_problem(length=8):
    graph = Supergraph[str, str]()
    graph.add_procedure("main", "n0", [f"n{length - 1}"])
    for index in range(1, length):
        graph.add_node("main", f"n{index}")
        graph.add_normal_edge(f"n{index - 1}", f"n{index}")
    return _GeneratedProblem(graph, {})


def test_solver_options_return_partial_result_instead_of_raising():
    result = IFDSSolver(options=SolverOptions(max_propagated_path_edges=2)).solve(
        _linear_problem()
    )

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


@pytest.mark.parametrize(
    ("options", "reason"),
    [
        (SolverOptions(max_queue_size=1), "max_queue_size=1"),
        (SolverOptions(max_facts_per_node=1), "max_facts_per_node=1"),
        (
            SolverOptions(max_memory_bytes=1, budget_check_interval=1),
            "max_memory_bytes=1",
        ),
    ],
)
def test_solver_enforces_resource_budgets(options, reason):
    problem = _linear_problem(3)
    problem.transitions[("n0", "n1", "0")] = ("0", "a", "b")
    result = IFDSSolver(options=options).solve(problem)

    assert result.status is AnalysisStatus.PARTIAL
    assert reason in result.termination_reason


def test_solver_enforces_sub_resolution_time_budget(monkeypatch):
    clock_reading = 10_000_000.0
    assert clock_reading + 1e-12 == clock_reading
    monkeypatch.setattr(
        solver_module,
        "time",
        SimpleNamespace(monotonic=lambda: clock_reading),
    )

    result = IFDSSolver(
        options=SolverOptions(max_seconds=1e-12, budget_check_interval=1)
    ).solve(_linear_problem())

    assert result.status is AnalysisStatus.PARTIAL
    assert "max_seconds=1e-12" in result.termination_reason


def test_solver_can_raise_on_budget_exhaustion():
    with pytest.raises(SolverLimitExceeded, match="max_queue_size=1"):
        problem = _linear_problem(3)
        problem.transitions[("n0", "n1", "0")] = ("0", "a", "b")
        IFDSSolver(
            options=SolverOptions(max_queue_size=1, limit_behavior="raise")
        ).solve(problem)


def test_ide_solver_honors_shared_solver_budgets():
    base = _linear_problem(3)
    result = IDESolver(options=SolverOptions(max_facts_per_node=1)).solve(
        _GeneratedIDEProblem(base.supergraph)
    )

    assert result.status is AnalysisStatus.PARTIAL
    assert "max_facts_per_node=1" in result.termination_reason


def test_supergraph_assigns_compact_stable_ids_and_order():
    problem = _linear_problem(5)
    graph = problem.supergraph

    assert [graph.node_id(node) for node in graph.ordered_nodes()] == list(range(5))
    assert graph.procedure_id("main") == 0
    assert graph.ordered_normal_successors("n2") == ("n3",)
    result = IFDSSolver().solve(problem)
    assert result.fact_id("0") == 0
    assert result.facts_with_ids_at("n4") == ((0, "0"),)


def test_finding_fingerprint_uses_source_identity_over_transient_node_id():
    fields = dict(
        rule_id="RULE-1",
        kind="taint",
        severity="high",
        confidence="high",
        message="source reaches sink",
        primary_location=SourceSpan("app.py", 12, 4, 12, 18),
        procedure="main",
    )
    first = AnalysisFinding(node_id=10, **fields)
    second = AnalysisFinding(node_id=999, **fields)

    assert first.fingerprint == second.fingerprint


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
        assert {node: actual.facts_at(node) for node in graph.ordered_nodes()} == {
            node: expected.get(node, frozenset()) for node in graph.ordered_nodes()
        }


def test_random_interprocedural_problems_match_reference_solver():
    facts = ("0", "a", "b")
    for seed in range(25):
        rng = random.Random(seed)
        graph = Supergraph[str, str]()
        graph.add_procedure("main", "main.entry", ["main.exit"])
        graph.add_node("main", "main.call")
        graph.add_node("main", "main.return")
        graph.add_normal_edge("main.entry", "main.call")
        graph.add_normal_edge("main.return", "main.exit")
        graph.add_procedure("helper", "helper.entry", ["helper.exit"])
        graph.add_node("helper", "helper.body")
        graph.add_normal_edge("helper.entry", "helper.body")
        graph.add_normal_edge("helper.body", "helper.exit")
        graph.add_call_edge("main.call", "helper", "main.return")

        transitions = {}

        def outputs(fact):
            result = {fact}
            if rng.random() < 0.45:
                result.add(rng.choice(facts))
            return tuple(sorted(result))

        for fact in facts:
            transitions[("normal", "main.entry", "main.call", fact)] = outputs(fact)
            transitions[("call", "main.call", "helper", fact)] = outputs(fact)
            transitions[("bypass", "main.call", "main.return", fact)] = outputs(fact)
            transitions[("normal", "helper.entry", "helper.body", fact)] = outputs(fact)
            transitions[("normal", "helper.body", "helper.exit", fact)] = outputs(fact)
            transitions[("normal", "main.return", "main.exit", fact)] = outputs(fact)
            for call_fact in facts:
                transitions[
                    (
                        "return",
                        "main.call",
                        "helper",
                        "helper.exit",
                        "main.return",
                        call_fact,
                        fact,
                    )
                ] = outputs(fact)

        problem = _GeneratedInterproceduralProblem(graph, transitions)
        expected = solve_reference(problem)
        actual = IFDSSolver().solve(problem)
        assert {node: actual.facts_at(node) for node in graph.ordered_nodes()} == {
            node: expected.get(node, frozenset()) for node in graph.ordered_nodes()
        }


def test_solver_serialization_is_independent_of_python_hash_seed():
    script = textwrap.dedent("""
        import json
        from pyflow.analysis.ifds import IFDSProblem, IFDSSolver, Supergraph

        class Problem(IFDSProblem):
            def __init__(self):
                self.graph = Supergraph()
                self.graph.add_procedure("main", "entry", ["exit"])
                self.graph.add_node("main", "body")
                self.graph.add_normal_edge("entry", "body")
                self.graph.add_normal_edge("body", "exit")
            @property
            def supergraph(self): return self.graph
            @property
            def zero_fact(self): return "zero"
            def initial_seeds(self): return {"entry": frozenset({"zero"})}
            def normal_flow(self, node, successor, fact):
                return {fact, "alpha", "omega", "middle"}

        problem = Problem()
        result = IFDSSolver().solve(problem)
        print(json.dumps([
            [node, result.facts_with_ids_at(node)]
            for node in problem.graph.ordered_nodes()
        ]))
        """)
    outputs = []
    for seed in ("1", "777"):
        environment = {**os.environ, "PYTHONHASHSEED": seed}
        outputs.append(
            subprocess.run(
                [sys.executable, "-c", script],
                check=True,
                capture_output=True,
                text=True,
                env=environment,
            ).stdout
        )
    assert outputs[0] == outputs[1]


def test_ifds_sarif_contains_location_and_code_flow(tmp_path, capsys):
    target = tmp_path / "flow.py"
    target.write_text("""
def source():
    return 1

def sink(value):
    return value

def main():
    value = source()
    sink(value)
""")
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
            run_pipeline=lambda: (_ for _ in ()).throw(RuntimeError("pipeline failed")),
            mode=PreparationMode.STRICT,
        )


def test_cli_uses_distinct_invalid_and_partial_exit_codes(tmp_path, capsys):
    target = tmp_path / "flow.py"
    target.write_text("""
def source(): return 1
def sink(value): return value
def main(): sink(source())
""")
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
