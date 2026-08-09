from pyflow.concolic import explore_file

from .helpers import assert_matches_cpython, target_file as _target


def test_aliased_input_lists_share_symbolic_heap_identity(tmp_path):
    target = _target(
        tmp_path,
        "def main(first, second):\n" "    first.append(3)\n" "    return len(second)\n",
    )
    shared = [1]

    result = explore_file(target, initial_inputs=[shared, shared], max_iterations=1)

    run = result.runs[0]
    assert run.result == 2
    assert run.post_inputs[0] is run.post_inputs[1]
    assert_matches_cpython(target, result)
