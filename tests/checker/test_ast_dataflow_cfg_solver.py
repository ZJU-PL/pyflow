from __future__ import annotations

from pyflow.checker.ast_dataflow.domain import TaintLocation, TaintOrigin, TaintState
from pyflow.checker.ast_dataflow.solver import (
    CFGEdge,
    ControlFlowGraph,
    EdgeKind,
    MonotoneCFGDataflowSolver,
    TransferResult,
)

ORIGIN = TaintOrigin("user_input", "sample.py", 1)
X = TaintLocation("x")
Y = TaintLocation("y")


def test_cfg_solver_joins_independent_branch_states():
    true_edge = CFGEdge("branch", "join", EdgeKind.TRUE)
    false_edge = CFGEdge("branch", "join", EdgeKind.FALSE)
    graph = ControlFlowGraph(
        entry="branch",
        nodes=frozenset({"branch", "join"}),
        edges=(true_edge, false_edge),
    )
    initial = TaintState().introduce(X, {"user_input"}, ORIGIN)

    def transfer(node, state, edges):
        if node == "branch":
            cleaned = state.kill(X)
            return TransferResult(((true_edge, cleaned), (false_edge, state)))
        return TransferResult.identity(edges, state)

    result = MonotoneCFGDataflowSolver().solve(graph, initial, transfer)

    assert result.in_states["join"].is_tainted(X)
    assert result.status == "complete"


def test_cfg_solver_iterates_loop_to_fixed_point():
    entry = CFGEdge("entry", "loop")
    back = CFGEdge("loop", "loop", EdgeKind.CONTINUE)
    exit_edge = CFGEdge("loop", "exit", EdgeKind.FALSE)
    graph = ControlFlowGraph(
        entry="entry",
        nodes=frozenset({"entry", "loop", "exit"}),
        edges=(entry, back, exit_edge),
    )
    initial = TaintState().introduce(X, {"user_input"}, ORIGIN)

    def transfer(node, state, edges):
        if node == "loop":
            copied = state.write(Y, state.facts_at(X), strong=True)
            return TransferResult(tuple((edge, copied) for edge in edges))
        return TransferResult.identity(edges, state)

    result = MonotoneCFGDataflowSolver().solve(graph, initial, transfer)

    assert result.in_states["exit"].is_tainted(Y)
    assert result.steps >= 3


def test_cfg_solver_marks_nonconvergence_partial():
    edge = CFGEdge("loop", "loop", EdgeKind.CONTINUE)
    graph = ControlFlowGraph("loop", frozenset({"loop"}), (edge,))

    counter = 0

    def transfer(node, state, edges):
        nonlocal counter
        counter += 1
        location = TaintLocation(f"generated_{counter}")
        growing = state.introduce(location, {"dynamic"}, ORIGIN)
        return TransferResult.identity(edges, growing)

    from pyflow.checker.ast_dataflow.solver import SolverOptions

    result = MonotoneCFGDataflowSolver(SolverOptions(max_steps=4)).solve(
        graph, TaintState(), transfer
    )

    assert result.status == "partial"
    assert result.diagnostics[0].code == "ast-dataflow-step-limit"
