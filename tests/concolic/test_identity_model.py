from pyflow.concolic import IdentityToken, ReplayStatus, explore_file, replay_runs

from .helpers import assert_matches_cpython, target_file as _target


def test_id_model_preserves_alias_and_distinct_object_identity(tmp_path):
    target = _target(
        tmp_path,
        "def main(first, second):\n"
        "    alias = first\n"
        "    return id(first) == id(alias) and id(first) != id(second)\n",
    )

    result = explore_file(target, initial_inputs=[[1], [1]], max_iterations=1)

    assert result.runs[0].result is True
    assert_matches_cpython(target, result)


def test_id_result_is_treated_as_process_local_identity(tmp_path):
    target = _target(tmp_path, "def main(value):\n    return id(value)\n")

    result = explore_file(target, initial_inputs=[[1]], max_iterations=1)
    replay = replay_runs(target, result.entry, result.runs)[0]

    assert isinstance(result.runs[0].result, IdentityToken)
    assert replay.status is ReplayStatus.NOT_COMPARABLE
    assert replay.differences == ("result contains process-local object identity",)
