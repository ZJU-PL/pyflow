from __future__ import annotations

import ast

from pyflow.concolic import explore_file
from pyflow.concolic.resumable import _ResumableCFG
from pyflow.concolic.core.runtime import (
    _ResumeKind,
    _ResumeOperation,
    _Returned,
    _SequenceIteratorValue,
    _Yielded,
)

from .helpers import target_file as _target


def test_sequence_iterator_implements_incremental_resume_protocol():
    iterator = _SequenceIteratorValue((1, 2))
    executor = object()

    first = iterator.resume(executor, _ResumeOperation(_ResumeKind.NEXT))
    second = iterator.resume(executor, _ResumeOperation(_ResumeKind.NEXT))
    exhausted = iterator.resume(executor, _ResumeOperation(_ResumeKind.NEXT))

    assert isinstance(first, _Yielded) and first.value == 1
    assert isinstance(second, _Yielded) and second.value == 2
    assert isinstance(exhausted, _Returned)


def test_resumable_cfg_records_suspension_and_resume_edges():
    function = ast.parse(
        "def values(value):\n" "    if value:\n" "        yield value\n" "    return value + 1\n"
    ).body[0]
    cfg = _ResumableCFG.from_function(function)

    yield_node = next(node for node in ast.walk(function) if isinstance(node, ast.Yield))
    point = cfg.point_for(yield_node)

    assert point is not None
    assert any(source == point and label == "resume" for source, _, label in cfg.edges)
    assert any(label == "true" for _, _, label in cfg.edges)


def test_resumable_chained_comparison_short_circuits_awaited_rhs(tmp_path):
    target = _target(
        tmp_path,
        "async def boom(state):\n"
        "    state.append(1)\n"
        "    return 2\n"
        "\n"
        "async def main(value):\n"
        "    state = []\n"
        "    result = 0 > 1 < await boom(state)\n"
        "    return (len(state), result)\n",
    )

    result = explore_file(target, initial_inputs=[0], max_iterations=1)

    assert result.runs[0].result == (0, False)


def test_resumable_rich_comparison_preserves_return_value(tmp_path):
    target = _target(
        tmp_path,
        "class Token:\n"
        "    def __eq__(self, other):\n"
        "        return [42]\n"
        "\n"
        "async def identity(value):\n"
        "    return value\n"
        "\n"
        "async def main(value):\n"
        "    return Token() == await identity(value)\n",
    )

    result = explore_file(target, initial_inputs=[0], max_iterations=1)

    assert result.runs[0].result == [42]


def test_generators_are_lazy_and_delay_post_yield_exceptions(tmp_path):
    target = _target(
        tmp_path,
        "def values(value, state):\n"
        "    state.append(1)\n"
        "    yield value\n"
        "    state.append(2)\n"
        "    raise ValueError('after yield')\n"
        "\n"
        "def main(value):\n"
        "    state = []\n"
        "    iterator = values(value, state)\n"
        "    if len(state) != 0:\n"
        "        return -1\n"
        "    result = next(iterator)\n"
        "    if len(state) != 1:\n"
        "        return -2\n"
        "    try:\n"
        "        next(iterator)\n"
        "    except ValueError:\n"
        "        return result * 10 + len(state)\n"
        "    return -3\n",
    )

    result = explore_file(target, initial_inputs=[3])

    assert result.runs[0].result == 32


def test_generator_send_throw_and_close(tmp_path):
    target = _target(
        tmp_path,
        "def values(value, state):\n"
        "    try:\n"
        "        received = yield value\n"
        "        yield received\n"
        "    except ValueError:\n"
        "        yield value + 2\n"
        "    finally:\n"
        "        state.append(1)\n"
        "\n"
        "def main(value):\n"
        "    state = []\n"
        "    sent = values(value, state)\n"
        "    first = next(sent)\n"
        "    second = sent.send(value + 1)\n"
        "    sent.close()\n"
        "    thrown = values(value, state)\n"
        "    next(thrown)\n"
        "    third = thrown.throw(ValueError('boom'))\n"
        "    thrown.close()\n"
        "    return first * 100 + second * 10 + third + len(state)\n",
    )

    result = explore_file(target, initial_inputs=[3])

    assert result.runs[0].result == 347


def test_yield_from_forwards_send_and_returns_delegate_value(tmp_path):
    target = _target(
        tmp_path,
        "def child(value):\n"
        "    received = yield value\n"
        "    yield received\n"
        "    return value + 2\n"
        "\n"
        "def parent(value):\n"
        "    result = yield from child(value)\n"
        "    yield result\n"
        "\n"
        "def main(value):\n"
        "    iterator = parent(value)\n"
        "    first = next(iterator)\n"
        "    second = iterator.send(value + 1)\n"
        "    third = next(iterator)\n"
        "    return first * 100 + second * 10 + third\n",
    )

    result = explore_file(target, initial_inputs=[3])

    assert result.runs[0].result == 345


def test_yield_from_forwards_throw_and_close(tmp_path):
    target = _target(
        tmp_path,
        "def child(value, state):\n"
        "    try:\n"
        "        yield value\n"
        "    except ValueError:\n"
        "        yield value + 1\n"
        "    finally:\n"
        "        state.append(1)\n"
        "\n"
        "def parent(value, state):\n"
        "    yield from child(value, state)\n"
        "\n"
        "def main(value):\n"
        "    state = []\n"
        "    iterator = parent(value, state)\n"
        "    first = next(iterator)\n"
        "    second = iterator.throw(ValueError('recover'))\n"
        "    iterator.close()\n"
        "    return first * 100 + second * 10 + len(state)\n",
    )

    result = explore_file(target, initial_inputs=[3])

    assert result.runs[0].result == 341


def test_generator_context_manager_resumes_cleanup_and_suppresses(tmp_path):
    target = _target(
        tmp_path,
        "from contextlib import contextmanager\n"
        "\n"
        "@contextmanager\n"
        "def guard(state):\n"
        "    state.append(1)\n"
        "    try:\n"
        "        yield\n"
        "    except ValueError:\n"
        "        state.append(2)\n"
        "    finally:\n"
        "        state.append(3)\n"
        "\n"
        "def main(value):\n"
        "    state = []\n"
        "    with guard(state):\n"
        "        if len(state) != 1:\n"
        "            return -1\n"
        "        raise ValueError('handled')\n"
        "    return len(state)\n",
    )

    result = explore_file(target, initial_inputs=[0])

    assert result.runs[0].result == 3


def test_short_circuit_and_islice_do_not_exhaust_infinite_generators(tmp_path):
    target = _target(
        tmp_path,
        "from itertools import islice\n"
        "\n"
        "def values(value, state):\n"
        "    yield value\n"
        "    state.append(1)\n"
        "    while True:\n"
        "        yield value + 1\n"
        "\n"
        "def main(value):\n"
        "    state = []\n"
        "    if not any(values(value, state)):\n"
        "        return -1\n"
        "    if len(state) != 0:\n"
        "        return -2\n"
        "    sample = list(islice(values(value, state), 3))\n"
        "    return len(sample) * 10 + len(state)\n",
    )

    result = explore_file(target, initial_inputs=[2])

    assert result.runs[0].result == 31


def test_generator_expressions_map_filter_and_zip_are_lazy(tmp_path):
    target = _target(
        tmp_path,
        "def mark(value, state):\n"
        "    state.append(value)\n"
        "    return value\n"
        "\n"
        "def main(value):\n"
        "    state = []\n"
        "    generated = (mark(item, state) for item in [value, value + 1])\n"
        "    mapped = map(lambda item: item * 2, generated)\n"
        "    filtered = filter(lambda item: item > 0, mapped)\n"
        "    rows = zip(filtered, [10, 20])\n"
        "    if len(state) != 0:\n"
        "        return -1\n"
        "    first = next(rows)\n"
        "    if len(state) != 1:\n"
        "        return -2\n"
        "    return first[0] + first[1]\n",
    )

    result = explore_file(target, initial_inputs=[3])

    assert result.runs[0].result == 16


def test_coroutines_async_iteration_and_async_context_are_resumable(tmp_path):
    target = _target(
        tmp_path,
        "import asyncio\n"
        "from contextlib import asynccontextmanager\n"
        "\n"
        "class Counter:\n"
        "    def __init__(self, stop):\n"
        "        self.current = 0\n"
        "        self.stop = stop\n"
        "    def __aiter__(self):\n"
        "        return self\n"
        "    async def __anext__(self):\n"
        "        if self.current >= self.stop:\n"
        "            raise StopAsyncIteration\n"
        "        result = self.current\n"
        "        self.current += 1\n"
        "        return result\n"
        "\n"
        "async def generated(value):\n"
        "    yield value\n"
        "    await asyncio.sleep(0)\n"
        "    yield value + 1\n"
        "\n"
        "@asynccontextmanager\n"
        "async def guard(state):\n"
        "    await asyncio.sleep(0)\n"
        "    state.append(1)\n"
        "    try:\n"
        "        yield\n"
        "    finally:\n"
        "        await asyncio.sleep(0)\n"
        "        state.append(2)\n"
        "\n"
        "async def main(value):\n"
        "    state = []\n"
        "    pending = guard(state)\n"
        "    if len(state) != 0:\n"
        "        return -1\n"
        "    total = 0\n"
        "    async with pending:\n"
        "        async for item in Counter(value):\n"
        "            total += item\n"
        "        async for item in generated(value):\n"
        "            total += item\n"
        "    return total * 10 + len(state)\n",
    )

    result = explore_file(target, initial_inputs=[3])

    assert result.runs[0].result == 102


def test_nondeterministic_scheduler_explores_task_order_separately(tmp_path):
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
        "    first = asyncio.create_task(worker(1, state))\n"
        "    second = asyncio.create_task(worker(2, state))\n"
        "    await asyncio.gather(first, second)\n"
        "    return state[0] * 10 + state[1]\n",
    )

    result = explore_file(
        target,
        initial_inputs=[0],
        scheduler="nondeterministic",
        max_iterations=12,
    )

    assert {run.result for run in result.runs} == {12, 21}
    assert all(run.schedule for run in result.runs)
    assert len(result.runs) == len({run.schedule for run in result.runs})
