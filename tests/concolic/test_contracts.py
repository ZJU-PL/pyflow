"""Contract-checking coverage for concolic exploration."""

from __future__ import annotations

import pytest

from pyflow.concolic import ConcolicError, explore_file

from .helpers import target_file


def test_explorer_finds_a_postcondition_counterexample(tmp_path):
    target = target_file(
        tmp_path,
        "def main(value):\n" '    """post: __return__ >= 0"""\n' "    return value\n",
    )

    result = explore_file(target, initial_inputs=[0], check_contracts=True)

    assert len(result.counterexamples) == 1
    counterexample = result.counterexamples[0]
    assert counterexample.clause == "__return__ >= 0"
    assert counterexample.inputs[0] < 0
    assert counterexample.result < 0
    assert result.to_dict()["counterexamples"][0]["inputs"] == list(counterexample.inputs)


def test_explorer_accepts_a_satisfied_postcondition(tmp_path):
    target = target_file(
        tmp_path,
        "def main(value):\n" '    """post: __return__ == value + 1"""\n' "    return value + 1\n",
    )

    result = explore_file(target, initial_inputs=[0], check_contracts=True)

    assert result.counterexamples == ()


def test_explorer_rejects_invalid_postcondition_syntax(tmp_path):
    target = target_file(
        tmp_path,
        "def main(value):\n" '    """post: __return__ = value"""\n' "    return value\n",
    )

    with pytest.raises(ConcolicError, match="invalid postcondition"):
        explore_file(target, initial_inputs=[0], check_contracts=True)
