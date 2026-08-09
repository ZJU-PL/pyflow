"""Performance-oriented smoke tests for concolic task scheduling."""

from __future__ import annotations

import pytest

from pyflow.concolic.engine import explore_file

from .helpers import target_file as _target


def test_schedule_state_budget_bounds_high_fanout_exploration(tmp_path):
    target = _target(
        tmp_path,
        "import asyncio\n"
        "\n"
        "async def worker(label, state):\n"
        "    await asyncio.sleep(0)\n"
        "    state.append(label)\n"
        "\n"
        "async def main(value):\n"
        "    state = []\n"
        "    tasks = [\n"
        "        asyncio.create_task(worker(1, state)),\n"
        "        asyncio.create_task(worker(2, state)),\n"
        "        asyncio.create_task(worker(3, state)),\n"
        "        asyncio.create_task(worker(4, state)),\n"
        "    ]\n"
        "    await asyncio.gather(*tasks)\n"
        "    result = 0\n"
        "    for item in state:\n"
        "        result = result * 10 + item\n"
        "    return result + value * 0\n",
    )

    result = explore_file(
        target,
        initial_inputs=[0],
        scheduler="nondeterministic",
        max_iterations=100,
        max_schedule_states=24,
    )

    assert 1 < len(result.runs) <= 24
    assert len(result.runs) == len({run.schedule for run in result.runs})
    assert len({run.result for run in result.runs}) > 1


def test_schedule_state_budget_must_be_positive(tmp_path):
    target = _target(tmp_path, "def main(value):\n    return value\n")

    with pytest.raises(ValueError, match="max_schedule_states"):
        explore_file(target, initial_inputs=[0], max_schedule_states=0)
