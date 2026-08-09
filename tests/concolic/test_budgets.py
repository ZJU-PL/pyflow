"""Resource-budget and timing regression tests for concolic exploration."""

import z3

from pyflow.concolic import explore_file

from .helpers import target_file as _target


def test_total_timeout_stops_before_starting_an_execution(tmp_path):
    result = explore_file(
        _target(tmp_path, "def main(value):\n    return value\n"),
        initial_inputs=[0],
        total_timeout=1e-12,
    )

    assert result.statistics.stop_reason == "total_timeout"
    assert result.statistics.executions == 0
    assert result.statistics.total_seconds > 0


def test_per_run_timeout_is_a_structured_resource_outcome(tmp_path):
    result = explore_file(
        _target(tmp_path, "def main(value):\n    return value\n"),
        initial_inputs=[0],
        per_run_timeout=1e-12,
    )

    assert result.runs[0].outcome.kind.value == "resource_limit"
    assert result.runs[0].outcome.message == "per_run_timeout"
    assert result.statistics.per_run_timeouts == 1
    assert result.statistics.stop_reason == "exhausted"


def test_solver_call_budget_has_an_explicit_stop_reason(tmp_path):
    result = explore_file(
        _target(
            tmp_path,
            "def main(value):\n"
            "    if value == 1:\n"
            "        return 1\n"
            "    if value == 2:\n"
            "        return 2\n"
            "    return 0\n",
        ),
        initial_inputs=[0],
        max_solver_calls=1,
    )

    assert result.statistics.solver_calls == 1
    assert result.statistics.stop_reason == "max_solver_calls"


def test_pending_state_budget_bounds_the_queue_and_reports_drops(tmp_path):
    result = explore_file(
        _target(
            tmp_path,
            "def main(value):\n"
            "    if value == 1:\n"
            "        return 1\n"
            "    if value == 2:\n"
            "        return 2\n"
            "    return 0\n",
        ),
        initial_inputs=[0],
        max_pending_states=1,
    )

    assert result.statistics.maximum_queue_size == 1
    assert result.statistics.states_dropped >= 1
    assert result.statistics.stop_reason == "max_pending_states"


def test_solver_timeout_is_reported_separately(monkeypatch, tmp_path):
    class _TimeoutSolver:
        def set(self, **_options):
            pass

        def add(self, *_constraints):
            pass

        def check(self):
            return z3.unknown

        def reason_unknown(self):
            return "timeout"

    monkeypatch.setattr(z3, "Solver", _TimeoutSolver)
    result = explore_file(
        _target(
            tmp_path,
            "def main(value):\n" "    if value:\n" "        return 1\n" "    return 0\n",
        ),
        initial_inputs=[0],
        solver_timeout=0.1,
    )

    assert result.statistics.solver_timeouts == 1
    assert result.statistics.stop_reason == "solver_timeout"


def test_timing_statistics_are_json_serializable(tmp_path):
    result = explore_file(
        _target(
            tmp_path,
            "def main(value):\n" "    if value == 1:\n" "        return 1\n" "    return 0\n",
        ),
        initial_inputs=[0],
    )

    timing = result.to_dict()["statistics"]["timing"]
    assert timing["total_seconds"] >= timing["execution_seconds"] >= 0
    assert timing["solver_seconds"] >= 0


def test_budget_options_must_be_positive(tmp_path):
    target = _target(tmp_path, "def main():\n    return 0\n")

    for option in (
        {"total_timeout": 0},
        {"per_run_timeout": 0},
        {"solver_timeout": 0},
        {"max_solver_calls": 0},
        {"max_pending_states": 0},
    ):
        try:
            explore_file(target, initial_inputs=[], **option)
        except ValueError:
            pass
        else:
            raise AssertionError(f"option should have been rejected: {option}")
