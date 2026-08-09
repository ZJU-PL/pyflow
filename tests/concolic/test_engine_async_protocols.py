"""CPython differential coverage for advanced async protocols."""

from __future__ import annotations

from typing import Any

import pytest

from .test_engine_differential import _assert_matches_cpython


@pytest.mark.parametrize(
    "source, inputs",
    [
        (
            "import asyncio\n"
            "\n"
            "async def values(value, state):\n"
            "    received = yield value\n"
            "    try:\n"
            "        yield received\n"
            "    except ValueError:\n"
            "        yield value + 4\n"
            "    finally:\n"
            "        await asyncio.sleep(0)\n"
            "        state.append(1)\n"
            "\n"
            "async def main(value):\n"
            "    state = []\n"
            "    iterator = values(value, state)\n"
            "    first = await iterator.__anext__()\n"
            "    second = await iterator.asend(value + 2)\n"
            "    third = await iterator.athrow(ValueError('recover'))\n"
            "    await iterator.aclose()\n"
            "    return first * 1000 + second * 100 + third * 10 + len(state)\n",
            (3,),
        ),
        (
            "class Immediate:\n"
            "    def __init__(self, value):\n"
            "        self.value = value\n"
            "\n"
            "    def __await__(self):\n"
            "        yield\n"
            "        return self.value + 1\n"
            "\n"
            "async def main(value):\n"
            "    return await Immediate(value)\n",
            (7,),
        ),
        (
            "import asyncio\n"
            "\n"
            "class CleanupAwaitable:\n"
            "    def __init__(self, state):\n"
            "        self.state = state\n"
            "\n"
            "    def __await__(self):\n"
            "        try:\n"
            "            yield\n"
            "        finally:\n"
            "            self.state.append(1)\n"
            "\n"
            "async def worker(state):\n"
            "    await CleanupAwaitable(state)\n"
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
            "async def child(state):\n"
            "    try:\n"
            "        await asyncio.sleep(0)\n"
            "    finally:\n"
            "        state.append(1)\n"
            "\n"
            "async def parent(task):\n"
            "    await task\n"
            "\n"
            "async def main(value):\n"
            "    state = []\n"
            "    child_task = asyncio.create_task(child(state))\n"
            "    parent_task = asyncio.create_task(parent(child_task))\n"
            "    await asyncio.sleep(0)\n"
            "    parent_task.cancel()\n"
            "    try:\n"
            "        await parent_task\n"
            "    except BaseException:\n"
            "        return value * 100 + len(state) * 10 + (\n"
            "            1 if child_task.cancelled() else 0\n"
            "        )\n"
            "    return -1\n",
            (5,),
        ),
    ],
)
def test_advanced_async_protocols_match_cpython(tmp_path, source: str, inputs: tuple[Any, ...]):
    _assert_matches_cpython(tmp_path, source, inputs)
