"""Capture and compare observable callable behavior."""

from __future__ import annotations

import math
from collections.abc import Collection, Iterator, Mapping, Set
from dataclasses import dataclass
from typing import Any

from ..core.runtime import ExecutionOutcome, OutcomeKind, RunRecord


@dataclass(frozen=True)
class BehaviorObservation:
    """The externally visible result of one callable execution."""

    outcome: ExecutionOutcome
    result: Any = None
    post_arguments: tuple[Any, ...] | None = None

    @classmethod
    def from_run(cls, run: RunRecord) -> "BehaviorObservation":
        return cls(run.outcome, run.result, run.post_inputs)


def compare_observations(
    expected: BehaviorObservation,
    actual: BehaviorObservation,
    *,
    compare_exception_messages: bool = True,
) -> tuple[str, ...]:
    """Return human-readable differences between two observations."""

    differences: list[str] = []
    if actual.outcome.kind is not expected.outcome.kind:
        differences.append(
            f"outcome: expected {expected.outcome.kind.value}, " f"got {actual.outcome.kind.value}"
        )
    elif expected.outcome.kind is OutcomeKind.RETURNED:
        if not behavior_equal(expected.result, actual.result):
            differences.append(f"result: expected {expected.result!r}, got {actual.result!r}")
    elif expected.outcome.kind is OutcomeKind.TARGET_EXCEPTION:
        if actual.outcome.exception_type != expected.outcome.exception_type:
            differences.append(
                f"exception type: expected {expected.outcome.exception_type!r}, "
                f"got {actual.outcome.exception_type!r}"
            )
        if compare_exception_messages and actual.outcome.message != expected.outcome.message:
            differences.append(
                f"exception message: expected {expected.outcome.message!r}, "
                f"got {actual.outcome.message!r}"
            )
    if expected.post_arguments is not None and not behavior_equal(
        expected.post_arguments, actual.post_arguments
    ):
        differences.append(
            f"post inputs: expected {expected.post_arguments!r}, " f"got {actual.post_arguments!r}"
        )
    return tuple(differences)


def behavior_equal(left: Any, right: Any) -> bool:
    """Compare values by stable user-visible behavior instead of identity."""

    if left is right:
        return True
    if _is_nan(left) and _is_nan(right):
        return True
    if isinstance(left, Iterator) and isinstance(right, Iterator):
        left, right = tuple(left), tuple(right)
    if type(left) is not type(right):
        return False
    if isinstance(left, Mapping):
        if left.keys() != right.keys():
            return False
        return all(behavior_equal(value, right[key]) for key, value in left.items())
    if isinstance(left, Set) and not isinstance(left, (str, bytes, bytearray)):
        return left == right
    if isinstance(left, Collection) and not isinstance(left, (str, bytes, bytearray)):
        if len(left) != len(right):
            return False
        return all(behavior_equal(a, b) for a, b in zip(left, right))
    if type(left).__eq__ is object.__eq__:
        return type(left) is type(right)
    try:
        return bool(left == right)
    except Exception:
        return False


def _is_nan(value: Any) -> bool:
    return isinstance(value, float) and math.isnan(value)
