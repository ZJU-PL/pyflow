"""Coverage, outcomes, statistics, and search-policy regression tests."""

from pyflow.concolic import explore_file

from .helpers import target_file as _target


def test_exploration_reports_ast_node_and_branch_coverage(tmp_path):
    target = _target(
        tmp_path,
        "def main(value):\n" "    if value > 0:\n" "        return 1\n" "    return 0\n",
    )

    result = explore_file(target, initial_inputs=[0])

    if_edges = [edge for edge in result.coverage.branches if edge.kind == "if"]
    assert {edge.taken for edge in if_edges} == {False, True}
    assert {edge.location.line for edge in if_edges if edge.location} == {2}
    assert {node.node_kind for node in result.coverage.nodes} >= {
        "If",
        "Compare",
        "Return",
    }
    assert all(run.coverage.nodes for run in result.runs)
    serialized = result.to_dict()
    assert serialized["coverage"]["node_count"] == len(result.coverage.nodes)
    assert serialized["coverage"]["branch_count"] == len(result.coverage.branches)


def test_exploration_records_structured_nonreturning_outcomes(tmp_path):
    unsupported = explore_file(
        _target(tmp_path, "def main():\n    return 1j\n"),
        initial_inputs=[],
    )
    raised = explore_file(
        _target(
            tmp_path,
            "def main():\n    raise ValueError('bad')\n",
        ),
        initial_inputs=[],
    )
    limited = explore_file(
        _target(
            tmp_path,
            "def main():\n    while True:\n        pass\n",
        ),
        initial_inputs=[],
        max_loop_iterations=2,
    )

    assert unsupported.runs[0].outcome.kind.value == "unsupported"
    assert unsupported.statistics.unsupported == 1
    assert raised.runs[0].outcome.kind.value == "target_exception"
    assert raised.runs[0].outcome.exception_type == "ValueError"
    assert limited.runs[0].outcome.kind.value == "resource_limit"
    assert limited.statistics.resource_limits == 1


def test_statistics_report_solver_and_search_activity(tmp_path):
    result = explore_file(
        _target(
            tmp_path,
            "def main(value):\n" "    if value == 4:\n" "        return 1\n" "    return 0\n",
        ),
        initial_inputs=[0],
    )

    statistics = result.statistics
    assert statistics.executions == len(result.runs)
    assert statistics.returned == len(result.runs)
    assert statistics.solver_calls >= 1
    assert statistics.satisfiable_queries >= 1
    assert statistics.states_enqueued >= 2
    assert statistics.coverage_discoveries >= 1
    assert statistics.stop_reason == "exhausted"


def test_coverage_search_prioritizes_a_new_edge_over_a_stale_state(tmp_path):
    target = _target(
        tmp_path,
        "def main(value):\n"
        "    if value > 0:\n"
        "        if value > 10:\n"
        "            return 3\n"
        "    if value != 0:\n"
        "        return 2\n"
        "    return 0\n",
    )

    coverage = explore_file(
        target,
        initial_inputs=[0],
        max_iterations=3,
        search_strategy="coverage",
    )
    fifo = explore_file(
        target,
        initial_inputs=[0],
        max_iterations=3,
        search_strategy="fifo",
    )

    assert [run.result for run in coverage.runs] == [0, 2, 3]
    assert [run.result for run in fifo.runs] == [0, 2, 2]


def test_search_stops_after_a_coverage_plateau(tmp_path):
    target = _target(
        tmp_path,
        "import asyncio\n"
        "async def child(value):\n"
        "    await asyncio.sleep(0)\n"
        "    return value\n"
        "async def main(value):\n"
        "    first = asyncio.create_task(child(value))\n"
        "    second = asyncio.create_task(child(value + 1))\n"
        "    return await first + await second\n",
    )

    result = explore_file(
        target,
        initial_inputs=[0],
        scheduler="nondeterministic",
        max_iterations=20,
        max_uninteresting_iterations=1,
    )

    assert result.statistics.stop_reason == "max_uninteresting_iterations"
    assert result.statistics.iterations_without_discovery == 1
