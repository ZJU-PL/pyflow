from pyflow.concolic import explore_file

from .helpers import assert_matches_cpython, target_file as _target


def test_empty_list_seed_discovers_nonempty_length_branch(tmp_path):
    target = _target(
        tmp_path,
        "def main(values):\n"
        "    if len(values) > 0:\n"
        "        return values[0] + 1\n"
        "    return 0\n",
    )

    result = explore_file(target, initial_inputs=[[]])

    assert {tuple(run.inputs[0]) for run in result.runs} >= {(), (0,)}
    assert {run.result for run in result.runs} == {0, 1}
    assert_matches_cpython(target, result)


def test_list_length_respects_configured_symbolic_bound(tmp_path):
    target = _target(
        tmp_path,
        "def main(values):\n"
        "    if len(values) == 2:\n"
        "        return len(values)\n"
        "    return 0\n",
    )

    result = explore_file(
        target,
        initial_inputs=[[]],
        max_symbolic_container_size=2,
    )

    assert any(len(run.inputs[0]) == 2 for run in result.runs)
    assert_matches_cpython(target, result)


def test_dictionary_membership_can_add_and_remove_candidate_keys(tmp_path):
    target = _target(
        tmp_path,
        "def main(values):\n"
        "    if 'enabled' in values:\n"
        "        return values['enabled'] + 1\n"
        "    return 0\n",
    )

    result = explore_file(target, initial_inputs=[{}])

    assert {} in [run.inputs[0] for run in result.runs]
    assert {"enabled": 0} in [run.inputs[0] for run in result.runs]
    assert {run.result for run in result.runs} == {0, 1}
    assert_matches_cpython(target, result)


def test_set_membership_can_synthesize_candidate_elements(tmp_path):
    target = _target(
        tmp_path,
        "def main(values):\n"
        "    if 7 in values:\n"
        "        values.discard(7)\n"
        "        return len(values)\n"
        "    values.add(7)\n"
        "    return len(values)\n",
    )

    result = explore_file(target, initial_inputs=[set()])

    assert set() in [run.inputs[0] for run in result.runs]
    assert {7} in [run.inputs[0] for run in result.runs]
    assert_matches_cpython(target, result)
