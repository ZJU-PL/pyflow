"""Corpus minimization, CPython replay, and pytest generation tests."""

from dataclasses import replace

from pyflow.concolic.corpus import minimize_runs
from pyflow.concolic.engine import explore_file
from pyflow.concolic.pytestgen import generate_pytest
from pyflow.concolic.replay import ReplayStatus, replay_runs
from pyflow.concolic.runtime import (
    BranchCoverage,
    CoverageSnapshot,
    ExecutionOutcome,
    OutcomeKind,
    RunRecord,
    SourceLocation,
)

from .helpers import target_file as _target


def test_minimize_runs_preserves_coverage_and_distinct_failures():
    location = SourceLocation("target.py", 1, 0, 1, 1, "If")
    first = BranchCoverage(location, "if", False)
    second = BranchCoverage(location, "if", True)
    node = frozenset({location})
    runs = (
        RunRecord((0,), 0, 1, coverage=CoverageSnapshot(node, frozenset({first}))),
        RunRecord((1,), 1, 1, coverage=CoverageSnapshot(node, frozenset({second}))),
        RunRecord(
            (2,),
            2,
            2,
            coverage=CoverageSnapshot(node, frozenset({first, second})),
        ),
        RunRecord(
            (3,),
            None,
            0,
            outcome=ExecutionOutcome(
                OutcomeKind.TARGET_EXCEPTION, "ValueError", "bad"
            ),
        ),
    )

    selected = minimize_runs(runs)

    assert [run.inputs for run in selected] == [(2,), (3,)]
    assert set().union(*(run.coverage.branches for run in selected)) == {
        first,
        second,
    }


def test_replay_compares_returns_exceptions_and_post_arguments(tmp_path):
    target = _target(
        tmp_path,
        "def main(value):\n"
        "    if value == 1:\n"
        "        raise ValueError('bad')\n"
        "    return value * 2\n",
    )
    result = explore_file(target, initial_inputs=[0])

    replays = replay_runs(target, "main", result.runs)

    assert {replay.status for replay in replays} == {ReplayStatus.MATCHED}
    assert {replay.actual_outcome.kind for replay in replays} == {
        OutcomeKind.RETURNED,
        OutcomeKind.TARGET_EXCEPTION,
    }


def test_replay_detects_result_mismatches(tmp_path):
    target = _target(tmp_path, "def main(value):\n    return value + 1\n")
    result = explore_file(target, initial_inputs=[2])
    incorrect = replace(result.runs[0], result=999)

    replay = replay_runs(target, "main", [incorrect])[0]

    assert replay.status is ReplayStatus.MISMATCHED
    assert replay.differences[0].startswith("result:")


def test_replay_tracks_mutated_arguments(tmp_path):
    target = _target(
        tmp_path,
        "def main(values):\n"
        "    values.append(3)\n"
        "    return len(values)\n",
    )
    result = explore_file(target, initial_inputs=[[1]])

    run = result.runs[0]
    replay = replay_runs(target, "main", [run])[0]

    assert run.post_inputs == ([1, 3],)
    assert replay.actual_post_inputs == ([1, 3],)
    assert replay.status is ReplayStatus.MATCHED


def test_replay_drives_async_entrypoints(tmp_path):
    target = _target(
        tmp_path,
        "import asyncio\n"
        "async def main(value):\n"
        "    await asyncio.sleep(0)\n"
        "    return value + 1\n",
    )
    result = explore_file(target, initial_inputs=[2])

    replay = replay_runs(target, "main", result.runs)[0]

    assert replay.status is ReplayStatus.MATCHED
    assert replay.actual_result == 3


def test_generated_pytest_executes_replay_confirmed_cases(tmp_path):
    target = _target(
        tmp_path,
        "def main(value):\n"
        "    if value == 1:\n"
        "        raise ValueError('bad')\n"
        "    return value * 2\n",
    )
    result = explore_file(target, initial_inputs=[0])

    generated = generate_pytest(target, result)
    namespace = {}
    exec(compile(generated.source, "generated_test.py", "exec"), namespace)
    tests = [namespace[name] for name in sorted(namespace) if name.startswith("test_")]
    for test in tests:
        test()

    assert len(generated.selected_runs) == 2
    assert len(generated.emitted_runs) == 2
    assert not generated.skipped


def test_generated_pytest_asserts_mutated_arguments(tmp_path):
    target = _target(
        tmp_path,
        "def main(values):\n"
        "    values.append(3)\n"
        "    return len(values)\n",
    )
    result = explore_file(target, initial_inputs=[[1]])

    generated = generate_pytest(target, result)
    namespace = {}
    exec(compile(generated.source, "generated_test.py", "exec"), namespace)
    namespace["test_main_001"]()

    assert "assert arguments == ([1, 3],)" in generated.source


def test_generation_skips_replay_mismatches(tmp_path):
    target = _target(tmp_path, "def main(value):\n    return value + 1\n")
    result = explore_file(target, initial_inputs=[2])
    incorrect = replace(result.runs[0], result=999)
    incorrect_result = replace(result, runs=(incorrect,))

    generated = generate_pytest(target, incorrect_result)

    assert not generated.emitted_runs
    assert "replay mismatched" in generated.skipped[0]
