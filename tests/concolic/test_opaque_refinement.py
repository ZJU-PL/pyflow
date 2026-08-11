from dataclasses import replace

from pyflow.concolic import ReplayStatus, explore_file, replay_runs

from .helpers import assert_matches_cpython, target_file as _target


def test_opaque_boolean_relation_guides_branch_discovery(tmp_path):
    target = _target(
        tmp_path,
        "import math\n"
        "\n"
        "def main(value):\n"
        "    if math.isclose(value, 7, abs_tol=0.0):\n"
        "        return 1\n"
        "    return 0\n",
    )

    result = explore_file(
        target,
        initial_inputs=[0],
        max_iterations=6,
        refine_opaque_calls=True,
    )

    assert {run.result for run in result.runs} == {0, 1}
    assert (7,) in {run.inputs for run in result.runs}
    assert result.statistics.opaque_observations >= 2
    assert result.statistics.opaque_refinements >= 2
    assert all(run.operations for run in result.runs)
    assert all(operation.name == "isclose" for run in result.runs for operation in run.operations)
    assert all(
        replay.status is ReplayStatus.MATCHED for replay in replay_runs(target, "main", result.runs)
    )
    assert_matches_cpython(target, result)


def test_opaque_exception_samples_refine_toward_normal_execution(tmp_path):
    target = _target(
        tmp_path,
        "import math\n" "\n" "def main(value):\n" "    return math.acosh(value)\n",
    )

    result = explore_file(
        target,
        initial_inputs=[-1],
        max_iterations=8,
        refine_opaque_calls=True,
    )

    assert any(run.outcome.exception_type == "ValueError" for run in result.runs)
    assert any(run.outcome.kind.value == "returned" for run in result.runs)
    assert result.statistics.opaque_refinements >= 2
    assert_matches_cpython(target, result)


def test_opaque_refinement_is_opt_in(tmp_path):
    target = _target(
        tmp_path,
        "import math\n"
        "\n"
        "def main(value):\n"
        "    if math.isclose(value, 3, abs_tol=0.0):\n"
        "        return 1\n"
        "    return 0\n",
    )

    result = explore_file(target, initial_inputs=[0])

    assert result.runs[0].outcome.kind.value == "unsupported"
    assert result.statistics.opaque_observations == 0


def test_opaque_refinement_budget_is_explicit(tmp_path):
    target = _target(
        tmp_path,
        "import math\n"
        "\n"
        "def main(value):\n"
        "    if math.isclose(value, 3, abs_tol=0.0):\n"
        "        return 1\n"
        "    return 0\n",
    )

    result = explore_file(
        target,
        initial_inputs=[0],
        max_iterations=4,
        refine_opaque_calls=True,
        max_opaque_refinements=1,
    )

    assert result.statistics.opaque_refinements == 1
    assert any(run.outcome.kind.value == "resource_limit" for run in result.runs)


def test_opaque_integer_relation_guides_branch_discovery(tmp_path):
    target = _target(
        tmp_path,
        "import operator\n"
        "\n"
        "def main(value):\n"
        "    if operator.neg(value) == 5:\n"
        "        return 1\n"
        "    return 0\n",
    )

    result = explore_file(
        target,
        initial_inputs=[0],
        max_iterations=6,
        refine_opaque_calls=True,
    )

    assert {run.result for run in result.runs} == {0, 1}
    assert (-5,) in {run.inputs for run in result.runs}
    assert_matches_cpython(target, result)


def test_opaque_string_relation_guides_branch_discovery(tmp_path):
    target = _target(
        tmp_path,
        "import operator\n"
        "\n"
        "def main(value):\n"
        '    if operator.concat(value, "!") == "go!":\n'
        "        return 1\n"
        "    return 0\n",
    )

    result = explore_file(
        target,
        initial_inputs=[""],
        max_iterations=6,
        refine_opaque_calls=True,
    )

    assert {run.result for run in result.runs} == {0, 1}
    assert ("go",) in {run.inputs for run in result.runs}
    assert_matches_cpython(target, result)


def test_opaque_mutation_updates_runtime_state_and_replay(tmp_path):
    target = _target(
        tmp_path,
        "import operator\n"
        "\n"
        "def main(values):\n"
        "    operator.setitem(values, 0, 7)\n"
        "    return values[0]\n",
    )

    result = explore_file(
        target,
        initial_inputs=[[1]],
        max_iterations=1,
        refine_opaque_calls=True,
    )

    run = result.runs[0]
    assert run.result == 7
    assert run.post_inputs == ([7],)
    assert run.operations[0].post_arguments == ([7], 0, 7)
    assert run.operations[0].precision == "opaque"
    assert replay_runs(target, "main", result.runs)[0].status is ReplayStatus.MATCHED
    assert_matches_cpython(target, result)


def test_opaque_mutation_preserves_symbolic_value_flow(tmp_path):
    target = _target(
        tmp_path,
        "import operator\n"
        "\n"
        "def main(values, value):\n"
        "    if not values:\n"
        "        return -1\n"
        "    operator.setitem(values, 0, value)\n"
        "    if values[0] == 7:\n"
        "        return 1\n"
        "    return 0\n",
    )

    result = explore_file(
        target,
        initial_inputs=[[1], 0],
        max_iterations=5,
        refine_opaque_calls=True,
    )

    assert {0, 1} <= {run.result for run in result.runs}
    assert any(run.inputs[0] and run.inputs[1] == 7 for run in result.runs)
    assert_matches_cpython(target, result)


def test_opaque_container_result_can_flow_through_program(tmp_path):
    target = _target(
        tmp_path,
        "from urllib.parse import parse_qsl\n"
        "\n"
        "def main(value):\n"
        "    pairs = parse_qsl(value, keep_blank_values=True)\n"
        "    return len(pairs)\n",
    )

    result = explore_file(
        target,
        initial_inputs=["a=1&b=2"],
        max_iterations=1,
        refine_opaque_calls=True,
    )

    assert result.runs[0].result == 2
    assert result.runs[0].operations[0].result == [("a", "1"), ("b", "2")]
    assert_matches_cpython(target, result)


def test_replay_localizes_opaque_operation_divergence(tmp_path):
    target = _target(
        tmp_path,
        "import operator\n" "\n" "def main(value):\n" "    return operator.neg(value)\n",
    )
    result = explore_file(
        target,
        initial_inputs=[2],
        max_iterations=1,
        refine_opaque_calls=True,
    )
    run = result.runs[0]
    incorrect_operation = replace(run.operations[0], result=999)
    incorrect_run = replace(run, operations=(incorrect_operation,))

    replay = replay_runs(target, "main", [incorrect_run])[0]

    assert replay.status is ReplayStatus.MISMATCHED
    assert any(
        difference.startswith("operation 1 operator.neg: result:")
        for difference in replay.differences
    )
