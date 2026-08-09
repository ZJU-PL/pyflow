"""Contract-checking coverage for concolic exploration."""

from __future__ import annotations

import pytest

from pyflow.concolic import (
    ConcolicError,
    OutcomeKind,
    clear_registered_contracts,
    explore_file,
    register_contract,
)

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


def test_postconditions_can_compare_mutated_arguments_with_old_snapshots(tmp_path):
    target = target_file(
        tmp_path,
        "def main(values):\n"
        '    """post[values]: len(values) == len(__old__.values) + 1"""\n'
        "    values.append(3)\n"
        "    return len(values)\n",
    )

    result = explore_file(target, initial_inputs=[[1]], check_contracts=True)

    assert result.counterexamples == ()


def test_old_snapshot_finds_mutation_contract_counterexample(tmp_path):
    target = target_file(
        tmp_path,
        "def main(values):\n"
        '    """post[values]: len(values) == len(__old__.values)"""\n'
        "    values.append(3)\n"
        "    return len(values)\n",
    )

    result = explore_file(target, initial_inputs=[[1]], check_contracts=True)

    assert len(result.counterexamples) == 1


def test_precondition_rejection_is_explored_until_a_valid_input_is_found(tmp_path):
    target = target_file(
        tmp_path,
        "def main(value):\n"
        '    """pre: value > 0\n    post: __return__ > 0"""\n'
        "    return value\n",
    )

    result = explore_file(target, initial_inputs=[0], check_contracts=True)

    assert result.runs[0].outcome.kind is OutcomeKind.PRECONDITION_REJECTED
    assert any(run.outcome.kind is OutcomeKind.RETURNED for run in result.runs)
    assert result.statistics.precondition_rejected == 1


def test_raises_contract_reports_unexpected_exception_types(tmp_path):
    target = target_file(
        tmp_path,
        "def main(value):\n" '    """raises: ValueError"""\n' "    raise KeyError(value)\n",
    )

    result = explore_file(target, initial_inputs=[1], check_contracts=True)

    assert result.counterexamples[0].clause == "raises: ValueError"


def test_multiline_contract_sections_are_supported(tmp_path):
    target = target_file(
        tmp_path,
        "def main(value):\n"
        '    """pre:\n'
        "        value >= 0\n"
        "    post:\n"
        "        __return__ == value + 1\n"
        '    """\n'
        "    return value + 1\n",
    )

    result = explore_file(target, initial_inputs=[0], check_contracts=True)

    assert result.counterexamples == ()


def test_inherited_class_invariant_is_checked_after_method_entry(tmp_path):
    target = target_file(
        tmp_path,
        "class Base:\n"
        '    """inv: self.value >= 0"""\n'
        "    def __init__(self):\n"
        "        self.value = 0\n"
        "\n"
        "class Child(Base):\n"
        "    def lower(self, amount):\n"
        "        self.value -= amount\n"
        "        return self.value\n",
    )

    result = explore_file(
        target,
        entry="Child.lower",
        initial_inputs=[1],
        max_iterations=1,
        check_contracts=True,
    )

    assert result.counterexamples[0].clause == "self.value >= 0"


def test_contract_decorators_are_parsed_without_runtime_dependency(tmp_path):
    target = target_file(
        tmp_path,
        "import icontract\n"
        "@icontract.require(lambda value: value > 0)\n"
        "@icontract.ensure(lambda result, value: result == value + 1)\n"
        "def main(value):\n"
        "    return value + 1\n",
    )

    result = explore_file(target, initial_inputs=[0], check_contracts=True)

    assert result.runs[0].outcome.kind is OutcomeKind.PRECONDITION_REJECTED
    assert result.counterexamples == ()


def test_registered_contracts_overlay_source_contracts(tmp_path):
    target = target_file(tmp_path, "def main(value):\n    return value\n")
    register_contract("main", post="__return__ >= 0")
    try:
        result = explore_file(target, initial_inputs=[0], check_contracts=True)
    finally:
        clear_registered_contracts()

    assert len(result.counterexamples) == 1
    assert result.counterexamples[0].clause == "__return__ >= 0"
