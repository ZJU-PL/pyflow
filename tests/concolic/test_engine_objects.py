from __future__ import annotations

from pyflow.concolic.engine import explore_file

from .helpers import target_file as _target


def test_explorer_resolves_package_initializers_and_relative_imports(tmp_path):
    package = tmp_path / "helpers"
    package.mkdir()
    (package / "__init__.py").write_text(
        "from .maths import offset\n",
        encoding="utf-8",
    )
    (package / "maths.py").write_text(
        "def offset(value):\n"
        "    return value + 2\n"
        "\n"
        "def scale(value):\n"
        "    return value * 3\n",
        encoding="utf-8",
    )
    target = _target(
        tmp_path,
        "from helpers import offset\n"
        "from helpers.maths import scale\n"
        "\n"
        "def main(value):\n"
        "    return scale(offset(value))\n",
    )

    result = explore_file(target, initial_inputs=[2])

    assert result.runs[0].result == 12


def test_explorer_resolves_dotted_package_imports_and_aliases(tmp_path):
    package = tmp_path / "helpers"
    package.mkdir()
    (package / "__init__.py").write_text("", encoding="utf-8")
    (package / "maths.py").write_text(
        "def offset(value):\n"
        "    return value + 1\n"
        "\n"
        "def scale(value):\n"
        "    return value * 2 + 1\n"
        "\n"
        "def bias(value):\n"
        "    return value - 1\n",
        encoding="utf-8",
    )
    target = _target(
        tmp_path,
        "import helpers.maths\n"
        "import helpers.maths as maths_alias\n"
        "from helpers import maths as maths_from\n"
        "\n"
        "def main(value):\n"
        "    return (helpers.maths.offset(value) + maths_alias.scale(value)\n"
        "            + maths_from.bias(value))\n",
    )

    result = explore_file(target, initial_inputs=[1])

    assert result.runs[0].result == 5


def test_explorer_supports_inheritance_mro_super_and_method_decorators(tmp_path):
    target = _target(
        tmp_path,
        "class Root:\n"
        "    def __init__(self, value):\n"
        "        self.value = value\n"
        "\n"
        "    def amount(self):\n"
        "        return self.value\n"
        "\n"
        "class Base(Root):\n"
        "    def amount(self):\n"
        "        return super().amount() + 1\n"
        "\n"
        "class Side:\n"
        "    def side(self):\n"
        "        return 2\n"
        "\n"
        "class Child(Base, Side):\n"
        "    @staticmethod\n"
        "    def scale(value):\n"
        "        return value * 2\n"
        "\n"
        "    @classmethod\n"
        "    def create(cls, value):\n"
        "        return cls(value)\n"
        "\n"
        "    @property\n"
        "    def result(self):\n"
        "        return self.amount() + self.side()\n"
        "\n"
        "def main(value):\n"
        "    child = Child.create(value)\n"
        "    return child.result + Child.scale(value)\n",
    )

    result = explore_file(target, initial_inputs=[3])

    assert result.runs[0].result == 12


def test_explorer_constructs_basic_dataclasses(tmp_path):
    target = _target(
        tmp_path,
        "from dataclasses import dataclass\n"
        "\n"
        "@dataclass\n"
        "class Point:\n"
        "    x: int\n"
        "    y: int = 2\n"
        "\n"
        "    @property\n"
        "    def total(self):\n"
        "        return self.x + self.y\n"
        "\n"
        "def main(value):\n"
        "    return Point(value, y=3).total\n",
    )

    result = explore_file(target, initial_inputs=[4])

    assert result.runs[0].result == 7


def test_explorer_constructs_configured_dataclasses(tmp_path):
    target = _target(
        tmp_path,
        "from dataclasses import dataclass\n"
        "\n"
        "@dataclass(frozen=True, slots=True)\n"
        "class Setting:\n"
        "    value: int\n"
        "    offset: int = 2\n"
        "\n"
        "def main(value):\n"
        "    setting = Setting(value)\n"
        "    return setting.value + setting.offset\n",
    )

    result = explore_file(target, initial_inputs=[4])

    assert result.runs[0].result == 6


def test_explorer_supports_simple_enum_members(tmp_path):
    target = _target(
        tmp_path,
        "from enum import Enum\n"
        "\n"
        "class Status(Enum):\n"
        "    READY = 'ready'\n"
        "    FAILED = 'failed'\n"
        "\n"
        "def main(value):\n"
        "    status = Status('ready') if value > 0 else Status.FAILED\n"
        "    if status == Status.READY:\n"
        "        return status.name + ':' + status.value\n"
        "    return status.name + ':' + status.value\n",
    )

    result = explore_file(target, initial_inputs=[1])

    assert {run.result for run in result.runs} == {"READY:ready", "FAILED:failed"}


def test_explorer_supports_intenum_and_strenum_scalar_behavior(tmp_path):
    target = _target(
        tmp_path,
        "from enum import IntEnum, StrEnum\n"
        "\n"
        "class Priority(IntEnum):\n"
        "    LOW = 1\n"
        "    HIGH = 4\n"
        "\n"
        "class Kind(StrEnum):\n"
        "    READY = 'ready'\n"
        "\n"
        "def main(value):\n"
        "    if Kind.READY == 'ready' and Priority.HIGH > Priority.LOW:\n"
        "        return Priority.HIGH + value\n"
        "    return 0\n",
    )

    result = explore_file(target, initial_inputs=[3])

    assert result.runs[0].result == 7


def test_explorer_uses_dataclass_conversion_and_replacement_helpers(tmp_path):
    target = _target(
        tmp_path,
        "from dataclasses import asdict, astuple, dataclass, replace\n"
        "\n"
        "@dataclass\n"
        "class Setting:\n"
        "    value: int\n"
        "    offset: int = 2\n"
        "\n"
        "def main(value):\n"
        "    setting = replace(Setting(value), offset=4)\n"
        "    mapping = asdict(setting)\n"
        "    return mapping['value'] + mapping['offset'] + astuple(setting)[1]\n",
    )

    result = explore_file(target, initial_inputs=[3])

    assert result.runs[0].result == 11


def test_explorer_supports_context_managers_and_exception_suppression(tmp_path):
    target = _target(
        tmp_path,
        "class Guard:\n"
        "    def __init__(self, value):\n"
        "        self.value = value\n"
        "\n"
        "    def __enter__(self):\n"
        "        return self.value\n"
        "\n"
        "    def __exit__(self, kind, message, traceback):\n"
        "        return kind == 'ValueError'\n"
        "\n"
        "def main(value):\n"
        "    with Guard(value) as entered:\n"
        "        if entered < 0:\n"
        "            raise ValueError('negative')\n"
        "        return entered + 1\n"
        "    return 0\n",
    )

    result = explore_file(target, initial_inputs=[0])

    assert {run.result for run in result.runs} == {0, 1}


def test_explorer_supports_contextlib_nullcontext(tmp_path):
    target = _target(
        tmp_path,
        "from contextlib import nullcontext\n"
        "\n"
        "def main(value):\n"
        "    with nullcontext(value + 1) as item:\n"
        "        return item * 2\n",
    )

    result = explore_file(target, initial_inputs=[3])

    assert result.runs[0].result == 8


def test_explorer_supports_contextmanager_decorators(tmp_path):
    target = _target(
        tmp_path,
        "from contextlib import asynccontextmanager, contextmanager\n"
        "\n"
        "@contextmanager\n"
        "def doubled(value):\n"
        "    yield value * 2\n"
        "\n"
        "@asynccontextmanager\n"
        "async def shifted(value):\n"
        "    yield value + 1\n"
        "\n"
        "async def main(value):\n"
        "    with doubled(value) as first:\n"
        "        async with shifted(value) as second:\n"
        "            return first + second\n",
    )

    result = explore_file(target, initial_inputs=[3])

    assert result.runs[0].result == 10


def test_explorer_supports_contextlib_suppress(tmp_path):
    target = _target(
        tmp_path,
        "from contextlib import suppress\n"
        "\n"
        "def main(value):\n"
        "    result = 0\n"
        "    with suppress(Exception):\n"
        "        if value > 0:\n"
        "            raise ValueError('invalid')\n"
        "        result = 3\n"
        "    return result\n",
    )

    result = explore_file(target, initial_inputs=[1])

    assert {run.result for run in result.runs} == {0, 3}


def test_explorer_supports_stepped_slices_for_reads_updates_and_deletion(tmp_path):
    target = _target(
        tmp_path,
        "def main(value):\n"
        "    data = [value, 2, 3, 4, 5]\n"
        "    data[::2] = [7, 8, 9]\n"
        "    selected = data[::-2]\n"
        "    del data[1::2]\n"
        "    return sum(selected) + sum(data)\n",
    )

    result = explore_file(target, initial_inputs=[1])

    assert result.runs[0].result == 48


def test_explorer_uses_structured_math_library_summaries(tmp_path):
    target = _target(
        tmp_path,
        "import math\n"
        "from math import gcd\n"
        "\n"
        "def main(value):\n"
        "    root = math.floor(math.sqrt(value * value))\n"
        "    if math.isfinite(root):\n"
        "        return root + gcd(8, 6)\n"
        "    return 0\n",
    )

    result = explore_file(target, initial_inputs=[3])

    assert result.runs[0].result == 5


def test_explorer_uses_structured_json_library_summaries(tmp_path):
    target = _target(
        tmp_path,
        "from json import dumps\n"
        "import json\n"
        "\n"
        "def main(value):\n"
        "    payload = json.loads('{\"offset\": 2, \"items\": [3]}')\n"
        "    encoded = dumps({'value': value, 'offset': payload['offset']})\n"
        "    if 'offset' in encoded:\n"
        "        return payload['items'][0] + payload['offset']\n"
        "    return 0\n",
    )

    result = explore_file(target, initial_inputs=[4])

    assert result.runs[0].result == 5


def test_explorer_supports_common_json_dump_options(tmp_path):
    target = _target(
        tmp_path,
        "import json\n"
        "\n"
        "def main(value):\n"
        "    return json.dumps({'b': value, 'a': 'é'}, sort_keys=True,\n"
        "                      ensure_ascii=False, separators=(',', ':'))\n",
    )

    result = explore_file(target, initial_inputs=[3])

    assert result.runs[0].result == '{"a":"é","b":3}'


def test_explorer_supports_basic_async_functions_await_and_async_for(tmp_path):
    target = _target(
        tmp_path,
        "async def offset(value):\n"
        "    return value + 2\n"
        "\n"
        "async def main(value):\n"
        "    total = 0\n"
        "    async for item in [value, await offset(value)]:\n"
        "        total += item\n"
        "    return total\n",
    )

    result = explore_file(target, initial_inputs=[3])

    assert result.runs[0].result == 8


def test_explorer_supports_eager_async_comprehensions(tmp_path):
    target = _target(
        tmp_path,
        "async def doubled(value):\n"
        "    return value * 2\n"
        "\n"
        "async def main(value):\n"
        "    return [await doubled(item) async for item in [value, 2]]\n",
    )

    result = explore_file(target, initial_inputs=[3])

    assert result.runs[0].result == [6, 4]


def test_explorer_supports_eager_async_context_managers(tmp_path):
    target = _target(
        tmp_path,
        "class Guard:\n"
        "    def __init__(self, value):\n"
        "        self.value = value\n"
        "\n"
        "    async def __aenter__(self):\n"
        "        return self.value\n"
        "\n"
        "    async def __aexit__(self, kind, message, traceback):\n"
        "        return False\n"
        "\n"
        "async def main(value):\n"
        "    async with Guard(value) as entered:\n"
        "        return entered + 1\n",
    )

    result = explore_file(target, initial_inputs=[3])

    assert result.runs[0].result == 4


def test_explorer_realizes_generator_helpers_and_yield_from(tmp_path):
    target = _target(
        tmp_path,
        "def first(value):\n"
        "    for item in range(value):\n"
        "        yield item\n"
        "\n"
        "def values(value):\n"
        "    yield from first(value)\n"
        "    yield value\n"
        "\n"
        "def main(value):\n"
        "    return sum(values(value))\n",
    )

    result = explore_file(target, initial_inputs=[3])

    assert result.runs[0].result == 6


def test_explorer_generators_advance_across_repeated_next_calls(tmp_path):
    target = _target(
        tmp_path,
        "def values(value):\n"
        "    yield value\n"
        "    yield value + 1\n"
        "\n"
        "def main(value):\n"
        "    iterator = values(value)\n"
        "    return next(iterator) * 10 + next(iterator)\n",
    )

    result = explore_file(target, initial_inputs=[4])

    assert result.runs[0].result == 45
