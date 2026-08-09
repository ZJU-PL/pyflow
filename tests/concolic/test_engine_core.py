from __future__ import annotations

import json

from pyflow.concolic import explore_file

from .helpers import target_file as _target


def test_explorer_flips_nested_integer_branches(tmp_path):
    target = _target(
        tmp_path,
        "def main(value):\n"
        "    if value > 0:\n"
        "        if value == 5:\n"
        "            return 10\n"
        "        return 1\n"
        "    return -1\n",
    )

    result = explore_file(target, initial_inputs=[0])

    assert {run.inputs for run in result.runs} >= {(0,), (1,), (5,)}
    assert next(run.result for run in result.runs if run.inputs == (5,)) == 10
    assert result.parameter_names == ("value",)
    assert json.loads(json.dumps(result.to_dict()))["generated_inputs"]


def test_explorer_solves_loop_exit_path(tmp_path):
    target = _target(
        tmp_path,
        "def main(value):\n"
        "    count = 0\n"
        "    while value > 0:\n"
        "        count += 1\n"
        "        value -= 1\n"
        "    return count\n",
    )

    result = explore_file(target, initial_inputs=[0], max_iterations=5)

    assert (1,) in result.generated_inputs
    assert next(run.result for run in result.runs if run.inputs == (1,)) == 1


def test_explorer_supports_variadic_entry_parameters(tmp_path):
    target = _target(
        tmp_path,
        "def main(*values):\n" "    return len(values)\n",
    )

    result = explore_file(target, initial_inputs=[])

    assert result.runs[0].result == 0


def test_explorer_generates_string_membership_input(tmp_path):
    target = _target(
        tmp_path,
        "def main(value):\n" "    if 'abc' in value:\n" "        return 1\n" "    return 0\n",
    )

    result = explore_file(target, initial_inputs=["x"])

    assert {run.result for run in result.runs} == {0, 1}
    assert any("abc" in run.inputs[0] for run in result.runs)


def test_explorer_supports_collections_builtins_and_helper_calls(tmp_path):
    target = _target(
        tmp_path,
        "def parse(value):\n"
        "    return int(value)\n"
        "\n"
        "def main(number, text):\n"
        "    values = [number, 2]\n"
        "    values.append(3)\n"
        "    table = {number: values[0:2][1], 'parsed': parse('7')}\n"
        "    total = sum(values) + table.get(number)\n"
        "    if 'ok' in text:\n"
        "        return total\n"
        "    return max(total, table['parsed'])\n",
    )

    result = explore_file(target, initial_inputs=[1, "no"])

    assert any("ok" in run.inputs[1] for run in result.runs)
    assert next(run.result for run in result.runs if run.inputs == (1, "no")) == 8


def test_explorer_supports_conditional_expressions_and_range_loops(tmp_path):
    target = _target(
        tmp_path,
        "def main(limit):\n"
        "    start = 1 if limit > 0 else 0\n"
        "    total = 0\n"
        "    for value in range(start, 4):\n"
        "        total += value\n"
        "    return total\n",
    )

    result = explore_file(target, initial_inputs=[0])

    assert {run.inputs for run in result.runs} >= {(0,), (1,)}
    assert next(run.result for run in result.runs if run.inputs == (1,)) == 6


def test_explorer_preserves_python_and_or_operand_values(tmp_path):
    target = _target(
        tmp_path,
        "def main(value):\n" "    return (value and value + 1) or 9\n",
    )

    result = explore_file(target, initial_inputs=[0])

    assert {run.result for run in result.runs} == {2, 9}


def test_explorer_supports_list_parameters_and_integer_division(tmp_path):
    target = _target(
        tmp_path,
        "def main(values, divisor):\n"
        "    result = []\n"
        "    for value in values:\n"
        "        if value % divisor == 0:\n"
        "            result.append(int(value / divisor))\n"
        "    return result\n",
    )

    result = explore_file(target, initial_inputs=[[2, 3], 2], max_iterations=3)

    assert result.runs[0].result == [1]
    assert isinstance(result.runs[0].inputs[0], list)


def test_explorer_supports_local_classes_and_instance_methods(tmp_path):
    target = _target(
        tmp_path,
        "class Counter:\n"
        "    def __init__(self, value):\n"
        "        self.value = value\n"
        "\n"
        "    def exceeds(self, limit):\n"
        "        return self.value > limit\n"
        "\n"
        "def main(value):\n"
        "    counter = Counter(value)\n"
        "    if counter.exceeds(2):\n"
        "        return counter.value\n"
        "    return 0\n",
    )

    result = explore_file(target, initial_inputs=[0])

    assert {run.result for run in result.runs} == {0, 3}


def test_explorer_supports_computed_module_constants(tmp_path):
    target = _target(
        tmp_path,
        "BASE = 2\n"
        "OFFSET = BASE * 3\n"
        "LABEL = 'v' + '1'\n"
        "VALUES = (BASE, OFFSET)\n"
        "TABLE = {'offset': OFFSET}\n"
        "\n"
        "def main(value):\n"
        "    return value + TABLE['offset'] + len(LABEL) + sum(VALUES)\n",
    )

    result = explore_file(target, initial_inputs=[4])

    assert result.runs[0].result == 20


def test_explorer_ignores_uninitialized_local_annotations(tmp_path):
    target = _target(
        tmp_path,
        "def main(value):\n" "    result: int\n" "    label: str\n" "    return value + 1\n",
    )

    result = explore_file(target, initial_inputs=[4])

    assert result.runs[0].result == 5


def test_explorer_replays_pyconbyte_num_decodings_benchmark(tmp_path):
    target = _target(
        tmp_path,
        "def numDecodings(text):\n"
        "    length = len(text)\n"
        "    if length == 0:\n"
        "        return 0\n"
        "    dp = [0] * length\n"
        "    for index in range(length):\n"
        "        if (index >= 1 and int(text[index - 1:index + 1]) < 27\n"
        "                and int(text[index - 1:index + 1]) >= 10):\n"
        "            if index == 1:\n"
        "                dp[index] = 1\n"
        "            else:\n"
        "                dp[index] += dp[index - 2]\n"
        "        if int(text[index]) != 0:\n"
        "            if index == 0:\n"
        "                dp[index] = 1\n"
        "            else:\n"
        "                dp[index] += dp[index - 1]\n"
        "    return dp[length - 1]\n",
    )

    result = explore_file(target, entry="numDecodings", initial_inputs=["226"])

    assert result.runs[0].result == 3


def test_explorer_supports_builtin_type_checks(tmp_path):
    target = _target(
        tmp_path,
        "def main(value):\n"
        "    values = [value, 'value']\n"
        "    if (isinstance(value, int) and isinstance(values, list)\n"
        "            and type(values[1]) is str):\n"
        "        return 1\n"
        "    return 0\n",
    )

    result = explore_file(target, initial_inputs=[3])

    assert result.runs[0].result == 1


def test_explorer_supports_function_local_class_declarations(tmp_path):
    target = _target(
        tmp_path,
        "def main(value):\n"
        "    class Box:\n"
        "        def __init__(self, item):\n"
        "            self.item = item\n"
        "\n"
        "        def doubled(self):\n"
        "            return self.item * 2\n"
        "\n"
        "    return Box(value).doubled()\n",
    )

    result = explore_file(target, initial_inputs=[3])

    assert result.runs[0].result == 6


def test_explorer_supports_inherited_class_attributes(tmp_path):
    target = _target(
        tmp_path,
        "class Base:\n"
        "    OFFSET = 2\n"
        "\n"
        "class Child(Base):\n"
        "    FACTOR: int = Base.OFFSET + 1\n"
        "\n"
        "    def apply(self, value):\n"
        "        return value * self.FACTOR + self.OFFSET\n"
        "\n"
        "def main(value):\n"
        "    Child.FACTOR += value\n"
        "    return Child().apply(value) + Child.FACTOR\n",
    )

    result = explore_file(target, initial_inputs=[4])

    assert result.runs[0].result == 37


def test_explorer_supports_dynamic_class_attribute_updates(tmp_path):
    target = _target(
        tmp_path,
        "class Config:\n"
        "    threshold = 2\n"
        "\n"
        "def main(value):\n"
        "    setattr(Config, 'threshold', value)\n"
        "    threshold = getattr(Config, 'threshold')\n"
        "    delattr(Config, 'threshold')\n"
        "    return threshold if not hasattr(Config, 'threshold') else 0\n",
    )

    result = explore_file(target, initial_inputs=[4])

    assert result.runs[0].result == 4


def test_explorer_supports_getattr_protocol_fallback(tmp_path):
    target = _target(
        tmp_path,
        "class Config:\n"
        "    def __init__(self, value):\n"
        "        self.value = value\n"
        "\n"
        "    def __getattr__(self, name):\n"
        "        if name == 'doubled':\n"
        "            return self.value * 2\n"
        "        raise AttributeError(name)\n"
        "\n"
        "def main(value):\n"
        "    config = Config(value)\n"
        "    return config.doubled if hasattr(config, 'doubled') else 0\n",
    )

    result = explore_file(target, initial_inputs=[4])

    assert result.runs[0].result == 8


def test_explorer_applies_supported_class_decorators(tmp_path):
    target = _target(
        tmp_path,
        "def tagged(class_value):\n"
        "    class_value.factor = 2\n"
        "    return class_value\n"
        "\n"
        "@tagged\n"
        "class Scale:\n"
        "    pass\n"
        "\n"
        "def main(value):\n"
        "    return Scale.factor * value\n",
    )

    result = explore_file(target, initial_inputs=[4])

    assert result.runs[0].result == 8


def test_explorer_supports_exception_chaining_and_simple_except_star(tmp_path):
    target = _target(
        tmp_path,
        "def main(value):\n"
        "    result = 0\n"
        "    try:\n"
        "        try:\n"
        "            if value < 0:\n"
        "                raise ValueError('negative')\n"
        "        except ValueError as error:\n"
        "            raise RuntimeError('invalid') from error\n"
        "    except* RuntimeError:\n"
        "        result = 1\n"
        "    return result\n",
    )

    result = explore_file(target, initial_inputs=[-1])

    assert result.runs[0].result == 1


def test_explorer_supports_common_itertools_iterators(tmp_path):
    target = _target(
        tmp_path,
        "from itertools import accumulate, pairwise, zip_longest\n"
        "\n"
        "def main(value):\n"
        "    totals = list(accumulate([value, 2, 3], initial=1))\n"
        "    pairs = list(pairwise(totals))\n"
        "    rows = list(zip_longest('ab', [value], fillvalue='x'))\n"
        "    return totals[-1] + pairs[0][1] + len(rows[1][1])\n",
    )

    result = explore_file(target, initial_inputs=[4])

    assert result.runs[0].result == 16


def test_explorer_supports_operator_higher_order_helpers(tmp_path):
    target = _target(
        tmp_path,
        "from operator import add, attrgetter, itemgetter, methodcaller\n"
        "\n"
        "class Row:\n"
        "    def __init__(self, rank, label):\n"
        "        self.rank = rank\n"
        "        self.label = label\n"
        "\n"
        "def main(value):\n"
        "    rows = [Row(3, 'cc'), Row(value, 'ab')]\n"
        "    rows.sort(key=attrgetter('rank'))\n"
        "    rank = itemgetter('rank')({'rank': rows[0].rank})\n"
        "    label = methodcaller('upper')(rows[0].label)\n"
        "    return add(rank, len(label))\n",
    )

    result = explore_file(target, initial_inputs=[2])

    assert result.runs[0].result == 4


def test_explorer_supports_bisect_search_and_insertion(tmp_path):
    target = _target(
        tmp_path,
        "from bisect import bisect_left, bisect_right, insort\n"
        "\n"
        "def main(value):\n"
        "    values = [1, 3, 3, 5]\n"
        "    left = bisect_left(values, value)\n"
        "    right = bisect_right(values, value)\n"
        "    insort(values, value)\n"
        "    return left + right + len(values)\n",
    )

    result = explore_file(target, initial_inputs=[3])

    assert result.runs[0].result == 9


def test_explorer_supports_heapq_priority_queue_operations(tmp_path):
    target = _target(
        tmp_path,
        "from heapq import heapify, heappop, heappush, nlargest\n"
        "\n"
        "def main(value):\n"
        "    heap = [4, value, 2]\n"
        "    heapify(heap)\n"
        "    heappush(heap, 1)\n"
        "    smallest = heappop(heap)\n"
        "    return smallest + nlargest(1, heap)[0] + len(heap)\n",
    )

    result = explore_file(target, initial_inputs=[3])

    assert result.runs[0].result == 8


def test_explorer_supports_shallow_and_deep_copy_summaries(tmp_path):
    target = _target(
        tmp_path,
        "from copy import copy, deepcopy\n"
        "\n"
        "def main(value):\n"
        "    original = [[value], {'value': value}]\n"
        "    shallow = copy(original)\n"
        "    deep = deepcopy(original)\n"
        "    shallow[0].append(1)\n"
        "    deep[1]['value'] = 9\n"
        "    return len(original[0]) * 10 + original[1]['value'] + len(deep[0])\n",
    )

    result = explore_file(target, initial_inputs=[4])

    assert result.runs[0].result == 25


def test_explorer_applies_function_local_decorators(tmp_path):
    target = _target(
        tmp_path,
        "def offset_by(offset):\n"
        "    def decorate(function):\n"
        "        def wrapped(value):\n"
        "            return function(value) + offset\n"
        "        return wrapped\n"
        "    return decorate\n"
        "\n"
        "def main(value):\n"
        "    @offset_by(2)\n"
        "    def double(number):\n"
        "        return number * 2\n"
        "\n"
        "    return double(value)\n",
    )

    result = explore_file(target, initial_inputs=[3])

    assert result.runs[0].result == 8


def test_explorer_supports_transparent_functools_decorators(tmp_path):
    target = _target(
        tmp_path,
        "from functools import lru_cache, wraps\n"
        "\n"
        "def main(value):\n"
        "    @lru_cache(maxsize=4)\n"
        "    def double(number):\n"
        "        return number * 2\n"
        "\n"
        "    def identity(function):\n"
        "        @wraps(function)\n"
        "        def wrapped(number):\n"
        "            return function(number)\n"
        "        return wrapped\n"
        "\n"
        "    @identity\n"
        "    @lru_cache\n"
        "    def increment(number):\n"
        "        return number + 1\n"
        "\n"
        "    return double(value) + increment(value)\n",
    )

    result = explore_file(target, initial_inputs=[3])

    assert result.runs[0].result == 10


def test_explorer_applies_top_level_decorators(tmp_path):
    target = _target(
        tmp_path,
        "def offset_by(offset):\n"
        "    def decorate(function):\n"
        "        def wrapped(value):\n"
        "            return function(value) + offset\n"
        "        return wrapped\n"
        "    return decorate\n"
        "\n"
        "@offset_by(2)\n"
        "def double(value):\n"
        "    return value * 2\n"
        "\n"
        "def main(value):\n"
        "    return double(value)\n",
    )

    result = explore_file(target, initial_inputs=[3])

    assert result.runs[0].result == 8


def test_explorer_supports_local_imported_functions_classes_and_globals(tmp_path):
    (tmp_path / "helper.py").write_text(
        "GLOBAL = 2\n"
        "\n"
        "def increase(value):\n"
        "    return value + 1\n"
        "\n"
        "class Box:\n"
        "    def __init__(self, value):\n"
        "        self.value = value\n"
        "\n"
        "    def exceeds(self, limit):\n"
        "        return self.value > limit\n",
        encoding="utf-8",
    )
    target = _target(
        tmp_path,
        "import helper\n"
        "\n"
        "def main(value):\n"
        "    box = helper.Box(helper.increase(value))\n"
        "    if box.exceeds(3):\n"
        "        return box.value\n"
        "    return helper.GLOBAL\n",
    )

    result = explore_file(target, initial_inputs=[0])

    assert {run.result for run in result.runs} == {2, 4}


def test_explorer_preserves_the_defining_module_scope_for_imported_methods(tmp_path):
    (tmp_path / "constants.py").write_text("OFFSET = 4\n", encoding="utf-8")
    (tmp_path / "helper.py").write_text(
        "import constants\n"
        "\n"
        "class Box:\n"
        "    def __init__(self, value):\n"
        "        self.value = value + constants.OFFSET\n",
        encoding="utf-8",
    )
    target = _target(
        tmp_path,
        "import helper\n" "\n" "def main(value):\n" "    return helper.Box(value).value\n",
    )

    result = explore_file(target, initial_inputs=[2])

    assert result.runs[0].result == 6


def test_explorer_supports_the_re_compile_match_group_workflow(tmp_path):
    target = _target(
        tmp_path,
        "import re\n"
        "\n"
        "def main(value):\n"
        "    match = re.compile(r'^(\\d+)').match(value)\n"
        "    if match:\n"
        "        return match.group()\n"
        "    return 'none'\n",
    )

    result = explore_file(target, initial_inputs=["007 James Bond"])

    assert result.runs[0].result == "007"


def test_explorer_supports_deletion_slice_updates_and_integer_shifts(tmp_path):
    target = _target(
        tmp_path,
        "def main(value):\n"
        "    data = [value, 2, 3, 4]\n"
        "    data[1:3] = [7]\n"
        "    del data[0]\n"
        "    data.append(value)\n"
        "    table = {}\n"
        "    table.setdefault('items', data)\n"
        "    table.update({'scale': 2})\n"
        "    return (table['items'][0] << table['scale']) + (value >> 1)\n",
    )

    result = explore_file(target, initial_inputs=[6])

    assert result.runs[0].result == 31


def test_explorer_supports_try_except_finally_and_explicit_raise(tmp_path):
    target = _target(
        tmp_path,
        "def main(value):\n"
        "    result = 0\n"
        "    try:\n"
        "        if value < 0:\n"
        "            raise ValueError('negative')\n"
        "        result = int('not-a-number')\n"
        "    except (ValueError, IndexError) as error:\n"
        "        result = 5\n"
        "    finally:\n"
        "        result += 1\n"
        "    return result\n",
    )

    result = explore_file(target, initial_inputs=[0])

    assert [run.result for run in result.runs] == [6, 6]


def test_explorer_binds_default_and_keyword_arguments_for_functions_and_classes(
    tmp_path,
):
    target = _target(
        tmp_path,
        "def adjust(value, amount=2):\n"
        "    return value + amount\n"
        "\n"
        "class Box:\n"
        "    def __init__(self, value, amount=1):\n"
        "        self.value = adjust(value, amount=amount)\n"
        "\n"
        "    def result(self, offset=0):\n"
        "        return self.value + offset\n"
        "\n"
        "def main(value):\n"
        "    box = Box(value, amount=3)\n"
        "    return box.result(offset=4)\n",
    )

    result = explore_file(target, initial_inputs=[1])

    assert result.runs[0].result == 8


def test_explorer_supports_comprehensions_and_iterable_builtins(tmp_path):
    target = _target(
        tmp_path,
        "def main(values):\n"
        "    doubled = [value * 2 for value in values if value > 1]\n"
        "    table = {index: value for index, value in enumerate(doubled)}\n"
        "    unique = set(value for value in table.values())\n"
        "    pairs = list(zip(sorted(unique), range(10, 20)))\n"
        "    if (all(left > 0 for left, right in pairs)\n"
        "            and any(right == 10 for left, right in pairs)):\n"
        "        return sum(left for left, right in pairs)\n"
        "    return 0\n",
    )

    result = explore_file(target, initial_inputs=[[1, 2, 2, 3]])

    assert result.runs[0].result == 10


def test_explorer_supports_variadic_keyword_only_lambda_and_global_calls(tmp_path):
    target = _target(
        tmp_path,
        "COUNTER = 1\n"
        "\n"
        "def combine(first, /, second=2, *rest, scale, **extra):\n"
        "    return (first + second + rest[0] + extra['bonus']) * scale\n"
        "\n"
        "def increment():\n"
        "    global COUNTER\n"
        "    COUNTER += 1\n"
        "    return COUNTER\n"
        "\n"
        "def main(value):\n"
        "    transform = lambda number: number + increment()\n"
        "    args = (3, 4)\n"
        "    extra = {'bonus': 5}\n"
        "    return transform(combine(value, *args, scale=2, **extra))\n",
    )

    result = explore_file(target, initial_inputs=[1])

    assert result.runs[0].result == 28


def test_explorer_supports_nested_closures_and_nonlocal_mutation(tmp_path):
    target = _target(
        tmp_path,
        "def main(value):\n"
        "    total = value\n"
        "    def increment(amount):\n"
        "        nonlocal total\n"
        "        total += amount\n"
        "        return total\n"
        "    increment(2)\n"
        "    return increment(3)\n",
    )

    result = explore_file(target, initial_inputs=[1])

    assert result.runs[0].result == 6
