from __future__ import annotations

import asyncio
import inspect
from typing import Any

import pytest

from pyflow.concolic import explore_file

from .helpers import target_file as _target


def _cpython_result(source: str, inputs: tuple[Any, ...]) -> Any:
    namespace: dict[str, Any] = {}
    exec(compile(source, "<concolic-differential>", "exec"), namespace)
    result = namespace["main"](*inputs)
    return asyncio.run(result) if inspect.isawaitable(result) else result


def _assert_matches_cpython(tmp_path, source: str, inputs: tuple[Any, ...]) -> None:
    expected = _cpython_result(source, inputs)
    target = _target(tmp_path, source)
    explored = explore_file(target, initial_inputs=inputs, max_iterations=1)

    assert explored.runs[0].result == expected


@pytest.mark.parametrize(
    "source, inputs",
    [
        (
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
            (3,),
        ),
        (
            "def child(value, state):\n"
            "    try:\n"
            "        received = yield value\n"
            "        yield received\n"
            "    except ValueError:\n"
            "        yield value + 2\n"
            "    finally:\n"
            "        state.append(1)\n"
            "    return value + 4\n"
            "\n"
            "def parent(value, state):\n"
            "    delegated = yield from child(value, state)\n"
            "    yield delegated\n"
            "\n"
            "def main(value):\n"
            "    state = []\n"
            "    iterator = parent(value, state)\n"
            "    first = next(iterator)\n"
            "    second = iterator.throw(ValueError('recover'))\n"
            "    third = next(iterator)\n"
            "    iterator.close()\n"
            "    return first * 1000 + second * 100 + third * 10 + len(state)\n",
            (2,),
        ),
        (
            "from contextlib import contextmanager\n"
            "\n"
            "@contextmanager\n"
            "def guard(state, suppress):\n"
            "    state.append(1)\n"
            "    try:\n"
            "        yield len(state)\n"
            "    except ValueError:\n"
            "        state.append(2)\n"
            "        if not suppress:\n"
            "            raise\n"
            "    finally:\n"
            "        state.append(3)\n"
            "\n"
            "def main(value):\n"
            "    state = []\n"
            "    try:\n"
            "        with guard(state, value > 0) as entered:\n"
            "            raise ValueError('failure')\n"
            "    except ValueError:\n"
            "        return entered * 100 + len(state) * 10\n"
            "    return entered * 100 + len(state)\n",
            (1,),
        ),
        (
            "from contextlib import contextmanager\n"
            "\n"
            "@contextmanager\n"
            "def guard(state):\n"
            "    try:\n"
            "        yield\n"
            "    finally:\n"
            "        state.append(1)\n"
            "\n"
            "def main(value):\n"
            "    state = []\n"
            "    try:\n"
            "        with guard(state):\n"
            "            raise KeyError('failure')\n"
            "    except KeyError:\n"
            "        return value * 10 + len(state)\n"
            "    return -1\n",
            (4,),
        ),
        (
            "def values():\n"
            "    try:\n"
            "        yield 1\n"
            "    finally:\n"
            "        yield 2\n"
            "\n"
            "def main(value):\n"
            "    iterator = values()\n"
            "    next(iterator)\n"
            "    try:\n"
            "        iterator.close()\n"
            "    except RuntimeError:\n"
            "        return value + 1\n"
            "    return -1\n",
            (5,),
        ),
        (
            "def main(value):\n"
            "    try:\n"
            "        raise ValueError('specific')\n"
            "    except RuntimeError:\n"
            "        return -1\n"
            "    except ValueError:\n"
            "        return value + 3\n",
            (5,),
        ),
        (
            "from contextlib import contextmanager\n"
            "\n"
            "@contextmanager\n"
            "def invalid():\n"
            "    yield 1\n"
            "    yield 2\n"
            "\n"
            "def main(value):\n"
            "    try:\n"
            "        with invalid():\n"
            "            pass\n"
            "    except RuntimeError:\n"
            "        return value + 2\n"
            "    return -1\n",
            (5,),
        ),
    ],
)
def test_generator_and_context_semantics_match_cpython(
    tmp_path, source: str, inputs: tuple[Any, ...]
):
    _assert_matches_cpython(tmp_path, source, inputs)


@pytest.mark.parametrize(
    "source, inputs",
    [
        (
            "import asyncio\n"
            "from contextlib import asynccontextmanager\n"
            "\n"
            "async def generated(value):\n"
            "    yield value\n"
            "    await asyncio.sleep(0)\n"
            "    yield value + 1\n"
            "\n"
            "@asynccontextmanager\n"
            "async def guard(state):\n"
            "    state.append(1)\n"
            "    try:\n"
            "        yield len(state)\n"
            "    finally:\n"
            "        await asyncio.sleep(0)\n"
            "        state.append(2)\n"
            "\n"
            "async def main(value):\n"
            "    state = []\n"
            "    total = 0\n"
            "    async with guard(state) as entered:\n"
            "        async for item in generated(value):\n"
            "            total += item\n"
            "    return total * 10 + entered + len(state)\n",
            (3,),
        ),
        (
            "import asyncio\n"
            "\n"
            "async def good(value):\n"
            "    await asyncio.sleep(0)\n"
            "    return value + 1\n"
            "\n"
            "async def bad():\n"
            "    await asyncio.sleep(0)\n"
            "    raise ValueError('failure')\n"
            "\n"
            "async def main(value):\n"
            "    try:\n"
            "        await asyncio.gather(good(value), bad())\n"
            "    except ValueError:\n"
            "        return value * 10 + 1\n"
            "    return -1\n",
            (5,),
        ),
        (
            "import asyncio\n"
            "\n"
            "async def worker():\n"
            "    await asyncio.sleep(0)\n"
            "\n"
            "async def main(value):\n"
            "    task = asyncio.create_task(worker())\n"
            "    task.cancel()\n"
            "    try:\n"
            "        await task\n"
            "    except BaseException:\n"
            "        pass\n"
            "    try:\n"
            "        task.exception()\n"
            "    except BaseException:\n"
            "        return value * 10 + (1 if task.cancelled() else 0)\n"
            "    return -1\n",
            (6,),
        ),
        (
            "import asyncio\n"
            "from contextlib import asynccontextmanager\n"
            "\n"
            "@asynccontextmanager\n"
            "async def guard(state):\n"
            "    state.append(1)\n"
            "    try:\n"
            "        yield\n"
            "    finally:\n"
            "        await asyncio.sleep(0)\n"
            "        state.append(2)\n"
            "\n"
            "async def worker(state):\n"
            "    async with guard(state):\n"
            "        await asyncio.sleep(0)\n"
            "\n"
            "async def main(value):\n"
            "    state = []\n"
            "    task = asyncio.create_task(worker(state))\n"
            "    await asyncio.sleep(0)\n"
            "    task.cancel()\n"
            "    try:\n"
            "        await task\n"
            "    except BaseException:\n"
            "        return value * 10 + len(state)\n"
            "    return -1\n",
            (7,),
        ),
        (
            "from contextlib import asynccontextmanager\n"
            "\n"
            "@asynccontextmanager\n"
            "async def invalid():\n"
            "    yield 1\n"
            "    yield 2\n"
            "\n"
            "async def main(value):\n"
            "    try:\n"
            "        async with invalid():\n"
            "            pass\n"
            "    except RuntimeError:\n"
            "        return value + 1\n"
            "    return -1\n",
            (7,),
        ),
        (
            "import asyncio\n"
            "\n"
            "async def good(value):\n"
            "    await asyncio.sleep(0)\n"
            "    return value + 1\n"
            "\n"
            "async def bad():\n"
            "    await asyncio.sleep(0)\n"
            "    raise ValueError('failure')\n"
            "\n"
            "async def main(value):\n"
            "    results = await asyncio.gather(\n"
            "        good(value), bad(), return_exceptions=True\n"
            "    )\n"
            "    return results[0] + (10 if results[1] is not None else 0)\n",
            (6,),
        ),
        (
            "import asyncio\n"
            "\n"
            "async def worker(value):\n"
            "    await asyncio.sleep(0)\n"
            "    return value\n"
            "\n"
            "async def main(value):\n"
            "    task = asyncio.create_task(worker(value))\n"
            "    cancelled = task.cancel()\n"
            "    done_before_await = task.done()\n"
            "    try:\n"
            "        await task\n"
            "    except BaseException:\n"
            "        return (100 if cancelled else 0) + (\n"
            "            10 if done_before_await else 0\n"
            "        ) + (1 if task.done() else 0)\n"
            "    return -1\n",
            (8,),
        ),
        (
            "import asyncio\n"
            "\n"
            "async def worker():\n"
            "    await asyncio.sleep(0)\n"
            "\n"
            "async def main(value):\n"
            "    task = asyncio.create_task(worker())\n"
            "    task.cancel()\n"
            "    try:\n"
            "        await task\n"
            "    except Exception:\n"
            "        return -1\n"
            "    except BaseException:\n"
            "        return value + 1\n"
            "    return -2\n",
            (8,),
        ),
        (
            "import asyncio\n"
            "\n"
            "async def worker(state):\n"
            "    state.append(1)\n"
            "    try:\n"
            "        await asyncio.sleep(0)\n"
            "        state.append(2)\n"
            "    finally:\n"
            "        state.append(3)\n"
            "\n"
            "async def main(value):\n"
            "    state = []\n"
            "    task = asyncio.create_task(worker(state))\n"
            "    await asyncio.sleep(0)\n"
            "    task.cancel()\n"
            "    try:\n"
            "        await task\n"
            "    except BaseException:\n"
            "        return value * 10 + len(state)\n"
            "    return -1\n",
            (4,),
        ),
        (
            "import asyncio\n"
            "\n"
            "async def inner(state):\n"
            "    try:\n"
            "        await asyncio.sleep(0)\n"
            "    finally:\n"
            "        state.append(1)\n"
            "\n"
            "async def outer(state):\n"
            "    await inner(state)\n"
            "\n"
            "async def main(value):\n"
            "    state = []\n"
            "    task = asyncio.create_task(outer(state))\n"
            "    await asyncio.sleep(0)\n"
            "    task.cancel()\n"
            "    try:\n"
            "        await task\n"
            "    except BaseException:\n"
            "        return value * 10 + len(state)\n"
            "    return -1\n",
            (5,),
        ),
        (
            "import asyncio\n"
            "\n"
            "async def worker(value):\n"
            "    await asyncio.sleep(0)\n"
            "    return value + 2\n"
            "\n"
            "async def main(value):\n"
            "    task = asyncio.create_task(worker(value))\n"
            "    await asyncio.gather(task)\n"
            "    return task.result() * 10 + (1 if task.done() else 0)\n",
            (7,),
        ),
    ],
)
def test_async_semantics_match_cpython(tmp_path, source: str, inputs: tuple[Any, ...]):
    _assert_matches_cpython(tmp_path, source, inputs)
