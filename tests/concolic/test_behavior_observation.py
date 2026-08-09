from pyflow.concolic import (
    BehaviorObservation,
    ExecutionOutcome,
    OutcomeKind,
    behavior_equal,
    compare_observations,
)


def test_behavior_equal_handles_nested_nan_values():
    assert behavior_equal({"values": [float("nan")]}, {"values": [float("nan")]})


def test_compare_observations_reports_result_and_post_argument_differences():
    returned = ExecutionOutcome(OutcomeKind.RETURNED)
    expected = BehaviorObservation(returned, 3, ([1, 2],))
    actual = BehaviorObservation(returned, 4, ([1, 3],))

    differences = compare_observations(expected, actual)

    assert differences[0].startswith("result:")
    assert differences[1].startswith("post inputs:")


def test_compare_observations_can_ignore_exception_messages():
    expected = BehaviorObservation(
        ExecutionOutcome(OutcomeKind.TARGET_EXCEPTION, "ValueError", "first")
    )
    actual = BehaviorObservation(
        ExecutionOutcome(OutcomeKind.TARGET_EXCEPTION, "ValueError", "second")
    )

    assert compare_observations(expected, actual, compare_exception_messages=False) == ()
