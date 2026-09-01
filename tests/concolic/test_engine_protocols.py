from __future__ import annotations

import pytest

from pyflow.concolic import explore_file

from .helpers import target_file as _target


def test_chained_comparison_short_circuits_comparator_evaluation(tmp_path):
    target = _target(
        tmp_path,
        "def boom(state):\n"
        "    state.append('called')\n"
        "    return 2\n"
        "\n"
        "def main(value):\n"
        "    state = []\n"
        "    result = 0 > 1 < boom(state)\n"
        "    return (len(state), result)\n",
    )

    result = explore_file(target, initial_inputs=[0], max_iterations=1)

    assert result.runs[0].result == (0, False)


def test_rich_comparison_preserves_non_boolean_return_value(tmp_path):
    target = _target(
        tmp_path,
        "class Token:\n"
        "    def __eq__(self, other):\n"
        "        return [42]\n"
        "\n"
        "def main(value):\n"
        "    return Token() == value\n",
    )

    result = explore_file(target, initial_inputs=[0], max_iterations=1)

    assert result.runs[0].result == [42]


@pytest.mark.parametrize(
    ("method", "return_value", "exception_type"),
    [
        ("__bool__", "123", "TypeError"),
        ("__len__", "-1", "ValueError"),
    ],
)
def test_truthiness_protocol_rejects_invalid_results(
    tmp_path, method, return_value, exception_type
):
    target = _target(
        tmp_path,
        "class Invalid:\n"
        f"    def {method}(self):\n"
        f"        return {return_value}\n"
        "\n"
        "def main(value):\n"
        "    return bool(Invalid())\n",
    )

    result = explore_file(target, initial_inputs=[0], max_iterations=1)

    assert result.runs[0].outcome.kind.value == "target_exception"
    assert result.runs[0].outcome.exception_type == exception_type


def test_explorer_supports_iter_and_next_consumption(tmp_path):
    target = _target(
        tmp_path,
        "def main(value):\n"
        "    iterator = iter([value, 2])\n"
        "    first = next(iterator)\n"
        "    second = next(iterator)\n"
        "    return first + second + next(iterator, 3)\n",
    )

    result = explore_file(target, initial_inputs=[4])

    assert result.runs[0].result == 9


def test_explorer_supports_list_sort_key_and_reverse_keywords(tmp_path):
    target = _target(
        tmp_path,
        "def main(value):\n"
        "    values = [value, 3, 1]\n"
        "    values.sort(key=lambda item: abs(item - 2), reverse=True)\n"
        "    return values[0]\n",
    )

    result = explore_file(target, initial_inputs=[2])

    assert result.runs[0].result == 3


def test_explorer_uses_custom_equality_and_hash_protocols(tmp_path):
    target = _target(
        tmp_path,
        "class Token:\n"
        "    def __init__(self, value):\n"
        "        self.value = value\n"
        "\n"
        "    def __eq__(self, other):\n"
        "        return self.value == other.value\n"
        "\n"
        "    def __hash__(self):\n"
        "        return self.value + 10\n"
        "\n"
        "def main(value):\n"
        "    token = Token(value)\n"
        "    if token == Token(value):\n"
        "        return hash(token)\n"
        "    return 0\n",
    )

    result = explore_file(target, initial_inputs=[2])

    assert result.runs[0].result == 12


def test_explorer_supports_symbolic_float_arithmetic_and_comparisons(tmp_path):
    target = _target(
        tmp_path,
        "def main(value):\n"
        "    scaled = value / 2.0\n"
        "    if scaled > 1.5:\n"
        "        return scaled + 0.5\n"
        "    return 0.0\n",
    )

    result = explore_file(target, initial_inputs=[0.0])

    assert {run.result for run in result.runs} == {0.0, 2.5}


def test_explorer_supports_float_aggregate_builtins_and_sum_start(tmp_path):
    target = _target(
        tmp_path,
        "def main(value):\n"
        "    values = [value / 2.0, 1.5]\n"
        "    total = sum(values, 1.0)\n"
        "    return total + max(values) - min(values)\n",
    )

    result = explore_file(target, initial_inputs=[4])

    assert result.runs[0].result == 5.0


def test_explorer_supports_function_local_imports(tmp_path):
    (tmp_path / "helper.py").write_text(
        "OFFSET = 1\n" "def increment(value):\n" "    return value + OFFSET\n",
        encoding="utf-8",
    )
    target = _target(
        tmp_path,
        "def main(value):\n"
        "    import math\n"
        "    from helper import increment\n"
        "    from os import path\n"
        "    return increment(math.floor(value / 2.0)) + len(path.basename('/x.py'))\n",
    )

    result = explore_file(target, initial_inputs=[5])

    assert result.runs[0].result == 7


def test_explorer_retains_globals_of_top_level_imported_helpers(tmp_path):
    (tmp_path / "helper.py").write_text(
        "OFFSET = 2\n" "def increment(value):\n" "    return value + OFFSET\n",
        encoding="utf-8",
    )
    target = _target(
        tmp_path,
        "from helper import increment\n" "\n" "def main(value):\n" "    return increment(value)\n",
    )

    result = explore_file(target, initial_inputs=[5])

    assert result.runs[0].result == 7


def test_explorer_supports_byte_strings_and_byte_slices(tmp_path):
    target = _target(
        tmp_path,
        "def main(value):\n"
        "    payload = bytes([65, value, 67, 68])\n"
        "    if payload.startswith(b'A'):\n"
        "        return payload[::2].decode()\n"
        "    return 'none'\n",
    )

    result = explore_file(target, initial_inputs=[66])

    assert result.runs[0].result == "AC"


def test_explorer_supports_common_byte_string_methods(tmp_path):
    target = _target(
        tmp_path,
        "def main(value):\n"
        "    payload = b'  a,b,c  '.strip().replace(b',', b':', value)\n"
        "    return payload.split(b':')[1].decode()\n",
    )

    result = explore_file(target, initial_inputs=[1])

    assert result.runs[0].result == "b,c"


def test_explorer_supports_fstrings_named_expressions_and_assertions(tmp_path):
    target = _target(
        tmp_path,
        "def main(value):\n"
        "    if (number := value + 1) > 2:\n"
        "        assert number < 5, f'out of range: {number}'\n"
        "        return f'value={number}'\n"
        "    return f'value={number}'\n",
    )

    result = explore_file(target, initial_inputs=[2])

    assert result.runs[0].result == "value=3"


def test_explorer_supports_sequence_mapping_and_guarded_match_cases(tmp_path):
    target = _target(
        tmp_path,
        "def main(value):\n"
        "    match value:\n"
        "        case [0, *rest] if len(rest) > 1:\n"
        "            return sum(rest)\n"
        "        case {'kind': 'point', 'x': coordinate, **extra}:\n"
        "            return coordinate + len(extra)\n"
        "        case 1 | 2:\n"
        "            return 7\n"
        "        case _:\n"
        "            return 0\n",
    )

    sequence_result = explore_file(target, initial_inputs=[[0, 3, 4]])
    mapping_result = explore_file(target, initial_inputs=[{"kind": "point", "x": 5, "y": 9}])

    assert sequence_result.runs[0].result == 7
    assert mapping_result.runs[0].result == 6


def test_explorer_uses_itertools_and_collections_summaries(tmp_path):
    target = _target(
        tmp_path,
        "from collections import Counter\n"
        "from itertools import chain, islice, product\n"
        "\n"
        "def main(value):\n"
        "    values = list(chain([value, 2], [2, 3]))\n"
        "    counts = Counter(values)\n"
        "    pairs = list(product(islice(values, 1, 3), [0, 1]))\n"
        "    return counts[2] + len(pairs)\n",
    )

    result = explore_file(target, initial_inputs=[1])

    assert result.runs[0].result == 6


def test_explorer_supports_itertools_combinations_and_permutations(tmp_path):
    target = _target(
        tmp_path,
        "from itertools import combinations, permutations\n"
        "\n"
        "def main(value):\n"
        "    pairs = list(combinations([value, 2, 3], 2))\n"
        "    orderings = list(permutations([1, 2], 2))\n"
        "    return sum(pairs[0]) + sum(orderings[1])\n",
    )

    result = explore_file(target, initial_inputs=[3])

    assert result.runs[0].result == 8


def test_explorer_supports_regex_split_and_escape(tmp_path):
    target = _target(
        tmp_path,
        "import re\n"
        "\n"
        "def main(value):\n"
        "    parts = re.split('[-:]', 'left-middle:right', value)\n"
        "    return parts[1] + ':' + re.escape('a+b')\n",
    )

    result = explore_file(target, initial_inputs=[1])

    assert result.runs[0].result == "middle:right:a\\+b"


def test_explorer_models_counter_missing_keys_as_zero(tmp_path):
    target = _target(
        tmp_path,
        "from collections import Counter\n"
        "\n"
        "def main(value):\n"
        "    counts = Counter([value])\n"
        "    missing = value + 1\n"
        "    counts[missing] += 2\n"
        "    return counts[missing]\n",
    )

    result = explore_file(target, initial_inputs=[3])

    assert result.runs[0].result == 2


def test_explorer_supports_counter_updates_and_most_common(tmp_path):
    target = _target(
        tmp_path,
        "from collections import Counter\n"
        "\n"
        "def main(value):\n"
        "    counts = Counter([value, 2])\n"
        "    counts.update([value, 2, 2])\n"
        "    key, count = counts.most_common(1)[0]\n"
        "    return key + count\n",
    )

    result = explore_file(target, initial_inputs=[3])

    assert result.runs[0].result == 5


def test_explorer_uses_functools_partial_summary(tmp_path):
    target = _target(
        tmp_path,
        "from functools import partial\n"
        "\n"
        "def add(left, right, offset=0):\n"
        "    return left + right + offset\n"
        "\n"
        "def main(value):\n"
        "    callback = partial(add, 2, offset=1)\n"
        "    return callback(value)\n",
    )

    result = explore_file(target, initial_inputs=[4])

    assert result.runs[0].result == 7


def test_explorer_uses_collections_namedtuple_summary(tmp_path):
    target = _target(
        tmp_path,
        "from collections import namedtuple\n"
        "\n"
        "Point = namedtuple('Point', 'x y')\n"
        "\n"
        "def main(value):\n"
        "    point = Point(value, y=2)\n"
        "    updated = point._replace(y=4)\n"
        "    return updated.x + updated[1] + updated._asdict()['y']\n",
    )

    result = explore_file(target, initial_inputs=[3])

    assert result.runs[0].result == 11


def test_explorer_supports_keyword_class_match_patterns(tmp_path):
    target = _target(
        tmp_path,
        "from dataclasses import dataclass\n"
        "\n"
        "@dataclass\n"
        "class Point:\n"
        "    x: int\n"
        "    y: int\n"
        "\n"
        "def main(value):\n"
        "    point = Point(value, 2)\n"
        "    match point:\n"
        "        case Point(x=coordinate, y=2):\n"
        "            return coordinate\n"
        "        case _:\n"
        "            return 0\n",
    )

    result = explore_file(target, initial_inputs=[8])

    assert result.runs[0].result == 8


def test_explorer_supports_dataclass_positional_class_match_patterns(tmp_path):
    target = _target(
        tmp_path,
        "from dataclasses import dataclass\n"
        "\n"
        "@dataclass\n"
        "class Point:\n"
        "    x: int\n"
        "    y: int\n"
        "\n"
        "def main(value):\n"
        "    match Point(value, 2):\n"
        "        case Point(coordinate, 2):\n"
        "            return coordinate\n"
        "        case _:\n"
        "            return 0\n",
    )

    result = explore_file(target, initial_inputs=[8])

    assert result.runs[0].result == 8


def test_explorer_flips_literal_match_case_paths(tmp_path):
    target = _target(
        tmp_path,
        "def main(value):\n"
        "    match value:\n"
        "        case 0:\n"
        "            return 'zero'\n"
        "        case 1:\n"
        "            return 'one'\n"
        "        case _:\n"
        "            return 'other'\n",
    )

    result = explore_file(target, initial_inputs=[0])

    assert {run.result for run in result.runs} == {"zero", "one", "other"}


def test_explorer_supports_explicit_match_args(tmp_path):
    target = _target(
        tmp_path,
        "class Point:\n"
        "    __match_args__ = ('x',)\n"
        "\n"
        "    def __init__(self, x, y):\n"
        "        self.x = x\n"
        "        self.y = y\n"
        "\n"
        "def main(value):\n"
        "    match Point(value, 2):\n"
        "        case Point(coordinate):\n"
        "            return coordinate\n"
        "        case _:\n"
        "            return 0\n",
    )

    result = explore_file(target, initial_inputs=[8])

    assert result.runs[0].result == 8


def test_explorer_supports_dynamic_object_introspection_builtins(tmp_path):
    target = _target(
        tmp_path,
        "class Base:\n"
        "    pass\n"
        "\n"
        "class Child(Base):\n"
        "    pass\n"
        "\n"
        "def main(value):\n"
        "    child = Child()\n"
        "    setattr(child, 'value', value)\n"
        "    if (isinstance(child, Base) and hasattr(child, 'value')\n"
        "            and type(child) is Child):\n"
        "        return getattr(child, 'value') + getattr(child, 'missing', 2)\n"
        "    return 0\n",
    )

    result = explore_file(target, initial_inputs=[4])

    assert result.runs[0].result == 6


def test_explorer_supports_collection_and_dictionary_unpacking(tmp_path):
    target = _target(
        tmp_path,
        "def main(value):\n"
        "    prefix = [1, 2]\n"
        "    values = [0, *prefix, value]\n"
        "    base = {'left': 3}\n"
        "    table = {**base, 'right': value}\n"
        "    extra = dict(table, scale=2)\n"
        "    return sum(values) + extra['left'] + extra['right'] * extra['scale']\n",
    )

    result = explore_file(target, initial_inputs=[4])

    assert result.runs[0].result == 18


def test_explorer_supports_dict_update_with_pairs_and_keywords(tmp_path):
    target = _target(
        tmp_path,
        "def main(value):\n"
        "    table = {'input': value}\n"
        "    table.update([('left', 2)], right=3)\n"
        "    return table['input'] + table['left'] + table['right']\n",
    )

    result = explore_file(target, initial_inputs=[4])

    assert result.runs[0].result == 9


def test_explorer_supports_mutating_set_methods(tmp_path):
    target = _target(
        tmp_path,
        "def main(value):\n"
        "    values = {1}\n"
        "    values.add(value)\n"
        "    values.update([2, value + 1])\n"
        "    values.discard(1)\n"
        "    return sum(values)\n",
    )

    result = explore_file(target, initial_inputs=[3])

    assert result.runs[0].result == 9


def test_explorer_supports_starred_assignment_targets(tmp_path):
    target = _target(
        tmp_path,
        "def main(values):\n"
        "    head, *middle, tail = values\n"
        "    return head + 10 * sum(middle) + tail\n",
    )

    result = explore_file(target, initial_inputs=[[1, 2, 3, 4]])

    assert result.runs[0].result == 55


def test_explorer_supports_bare_reraise_in_exception_handlers(tmp_path):
    target = _target(
        tmp_path,
        "def main(value):\n"
        "    try:\n"
        "        try:\n"
        "            if value > 0:\n"
        "                raise ValueError('bad value')\n"
        "        except ValueError:\n"
        "            raise\n"
        "    except ValueError:\n"
        "        return 1\n"
        "    return 0\n",
    )

    result = explore_file(target, initial_inputs=[1])

    assert result.runs[0].result == 1


def test_explorer_resolves_local_importlib_import_module_calls(tmp_path):
    (tmp_path / "helper.py").write_text(
        "def offset(value):\n" "    return value + 5\n",
        encoding="utf-8",
    )
    target = _target(
        tmp_path,
        "import importlib\n"
        "\n"
        "def main(value):\n"
        "    helper = importlib.import_module('helper')\n"
        "    return helper.offset(value)\n",
    )

    result = explore_file(target, initial_inputs=[2])

    assert result.runs[0].result == 7


def test_explorer_resolves_direct_importlib_import_module_calls(tmp_path):
    (tmp_path / "helper.py").write_text(
        "def offset(value):\n" "    return value + 6\n",
        encoding="utf-8",
    )
    target = _target(
        tmp_path,
        "from importlib import import_module\n"
        "\n"
        "def main(value):\n"
        "    return import_module('helper').offset(value)\n",
    )

    result = explore_file(target, initial_inputs=[2])

    assert result.runs[0].result == 8


def test_explorer_supports_property_setters(tmp_path):
    target = _target(
        tmp_path,
        "class Score:\n"
        "    def __init__(self, value):\n"
        "        self._value = value\n"
        "\n"
        "    @property\n"
        "    def value(self):\n"
        "        return self._value\n"
        "\n"
        "    @value.setter\n"
        "    def value(self, value):\n"
        "        self._value = value + 1\n"
        "\n"
        "def main(value):\n"
        "    score = Score(value)\n"
        "    score.value = 4\n"
        "    setattr(score, 'value', 5)\n"
        "    return score.value\n",
    )

    result = explore_file(target, initial_inputs=[2])

    assert result.runs[0].result == 6


def test_explorer_supports_cached_properties(tmp_path):
    target = _target(
        tmp_path,
        "import functools\n"
        "\n"
        "class Score:\n"
        "    def __init__(self, value):\n"
        "        self.value = value\n"
        "        self.calls = 0\n"
        "\n"
        "    @functools.cached_property\n"
        "    def doubled(self):\n"
        "        self.calls += 1\n"
        "        return self.value * 2\n"
        "\n"
        "def main(value):\n"
        "    score = Score(value)\n"
        "    return score.doubled + score.doubled + score.calls\n",
    )

    result = explore_file(target, initial_inputs=[4])

    assert result.runs[0].result == 17
