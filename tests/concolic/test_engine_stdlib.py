from __future__ import annotations

from pyflow.concolic import explore_file

from .helpers import assert_matches_cpython, target_file as _target


def test_explorer_supports_display_protocols_and_fstring_formats(tmp_path):
    target = _target(
        tmp_path,
        "class Label:\n"
        "    def __init__(self, value):\n"
        "        self.value = value\n"
        "\n"
        "    def __str__(self):\n"
        "        return '#' + str(self.value)\n"
        "\n"
        "    def __repr__(self):\n"
        "        return 'Label(' + str(self.value) + ')'\n"
        "\n"
        "    def __format__(self, specification):\n"
        "        return str(self.value) + specification\n"
        "\n"
        "def main(value):\n"
        "    label = Label(value)\n"
        "    return str(label) + '|' + repr(label) + '|' + f'{label:!}'\n",
    )

    result = explore_file(target, initial_inputs=[4])

    assert_matches_cpython(target, result)
    assert result.runs[0].result == "#4|Label(4)|4!"


def test_explorer_uses_os_path_library_summaries(tmp_path):
    target = _target(
        tmp_path,
        "import os.path\n"
        "from os.path import join\n"
        "\n"
        "def main(value):\n"
        "    path = join('src', f'item{value}.py')\n"
        "    stem, suffix = os.path.splitext(path)\n"
        "    return path + '|' + os.path.basename(path) + '|' + stem + '|' + suffix\n",
    )

    result = explore_file(target, initial_inputs=[2])

    assert_matches_cpython(target, result)
    assert result.runs[0].result == "src/item2.py|item2.py|src/item2|.py"


def test_explorer_uses_custom_iteration_length_and_boolean_protocols(tmp_path):
    target = _target(
        tmp_path,
        "class Numbers:\n"
        "    def __init__(self, values):\n"
        "        self.values = values\n"
        "\n"
        "    def __iter__(self):\n"
        "        yield from self.values\n"
        "\n"
        "    def __len__(self):\n"
        "        return len(self.values)\n"
        "\n"
        "    def __bool__(self):\n"
        "        return len(self) > 0\n"
        "\n"
        "def main(value):\n"
        "    numbers = Numbers([value, 2])\n"
        "    if numbers:\n"
        "        return sum(numbers) + len(numbers)\n"
        "    return 0\n",
    )

    result = explore_file(target, initial_inputs=[3])

    assert_matches_cpython(target, result)
    assert result.runs[0].result == 7


def test_explorer_uses_container_and_arithmetic_dunder_protocols(tmp_path):
    target = _target(
        tmp_path,
        "class Box:\n"
        "    def __init__(self, values):\n"
        "        self.values = values\n"
        "\n"
        "    def __getitem__(self, index):\n"
        "        return self.values[index]\n"
        "\n"
        "    def __setitem__(self, index, value):\n"
        "        self.values[index] = value\n"
        "\n"
        "    def __contains__(self, value):\n"
        "        return value in self.values\n"
        "\n"
        "    def __add__(self, value):\n"
        "        return self.values[0] + value\n"
        "\n"
        "def main(value):\n"
        "    box = Box([value, 2])\n"
        "    box[1] = 3\n"
        "    if 3 in box:\n"
        "        return box[0] + (box + 4)\n"
        "    return 0\n",
    )

    result = explore_file(target, initial_inputs=[2])

    assert_matches_cpython(target, result)
    assert result.runs[0].result == 8


def test_explorer_uses_rich_comparison_dunder_protocols(tmp_path):
    target = _target(
        tmp_path,
        "class Version:\n"
        "    def __init__(self, number):\n"
        "        self.number = number\n"
        "\n"
        "    def __lt__(self, other):\n"
        "        return self.number < other.number\n"
        "\n"
        "    def __eq__(self, other):\n"
        "        return self.number == other.number\n"
        "\n"
        "def main(value):\n"
        "    current = Version(value)\n"
        "    if current < Version(5) and current != Version(3):\n"
        "        return 1\n"
        "    return 0\n",
    )

    result = explore_file(target, initial_inputs=[2])

    assert_matches_cpython(target, result)
    assert result.runs[0].result == 1


def test_explorer_uses_functools_reduce_with_callable_values(tmp_path):
    target = _target(
        tmp_path,
        "from functools import reduce\n"
        "\n"
        "def multiply(left, right):\n"
        "    return left * right\n"
        "\n"
        "def main(value):\n"
        "    first = reduce(multiply, [value, 2])\n"
        "    return reduce(lambda left, right: left + right, [first, 3], 1)\n",
    )

    result = explore_file(target, initial_inputs=[4])

    assert_matches_cpython(target, result)
    assert result.runs[0].result == 12


def test_explorer_uses_map_filter_and_keyed_sorted(tmp_path):
    target = _target(
        tmp_path,
        "def negate(value):\n"
        "    return -value\n"
        "\n"
        "def is_positive(value):\n"
        "    return value > 0\n"
        "\n"
        "def main(value):\n"
        "    values = list(map(negate, [value, -2, 3]))\n"
        "    positive = list(filter(is_positive, values))\n"
        "    return sorted(positive, key=negate, reverse=True)[0]\n",
    )

    result = explore_file(target, initial_inputs=[-4])

    assert_matches_cpython(target, result)
    assert result.runs[0].result == 2


def test_explorer_supports_fstring_format_specs_and_conversions(tmp_path):
    target = _target(
        tmp_path,
        "def main(value):\n" '    return f\'{value:03d}|{value / 2:.1f}|{"x"!r}|{"é"!a}\'\n',
    )

    result = explore_file(target, initial_inputs=[4])

    assert_matches_cpython(target, result)
    assert result.runs[0].result == "004|2.0|'x'|'\\xe9'"


def test_explorer_supports_str_format_with_positional_and_named_fields(tmp_path):
    target = _target(
        tmp_path,
        "def main(value):\n" "    return '{name}:{0:02d}'.format(value, name='item')\n",
    )

    result = explore_file(target, initial_inputs=[4])

    assert_matches_cpython(target, result)
    assert result.runs[0].result == "item:04"


def test_explorer_supports_inherited_dataclass_fields_and_default_factories(tmp_path):
    target = _target(
        tmp_path,
        "from dataclasses import dataclass, field\n"
        "\n"
        "@dataclass\n"
        "class Base:\n"
        "    value: int\n"
        "\n"
        "@dataclass\n"
        "class Child(Base):\n"
        "    tags: list = field(default_factory=list)\n"
        "    scale: int = 2\n"
        "\n"
        "def main(value):\n"
        "    child = Child(value)\n"
        "    child.tags.append(3)\n"
        "    return child.value * child.scale + child.tags[0]\n",
    )

    result = explore_file(target, initial_inputs=[4])

    assert_matches_cpython(target, result)
    assert result.runs[0].result == 11


def test_explorer_uses_collections_defaultdict_with_callable_factories(tmp_path):
    target = _target(
        tmp_path,
        "from collections import defaultdict\n"
        "\n"
        "def main(value):\n"
        "    buckets = defaultdict(list)\n"
        "    buckets['values'].append(value)\n"
        "    buckets['values'].append(2)\n"
        "    return sum(buckets['values'])\n",
    )

    result = explore_file(target, initial_inputs=[4])

    assert_matches_cpython(target, result)
    assert result.runs[0].result == 6


def test_explorer_uses_collections_deque_queue_operations(tmp_path):
    target = _target(
        tmp_path,
        "from collections import deque\n"
        "\n"
        "def main(value):\n"
        "    values = deque([value, 2, 3])\n"
        "    values.appendleft(1)\n"
        "    first = values.popleft()\n"
        "    values.rotate(1)\n"
        "    return first + values.pop() + values[0]\n",
    )

    result = explore_file(target, initial_inputs=[4])

    assert_matches_cpython(target, result)
    assert result.runs[0].result == 6


def test_explorer_supports_text_and_bytes_encoding_workflows(tmp_path):
    target = _target(
        tmp_path,
        "def main(value):\n"
        "    payload = f'item{value}'.encode('utf-8')\n"
        "    if payload.hex().startswith('6974'):\n"
        "        return payload.decode('utf-8')\n"
        "    return 'none'\n",
    )

    result = explore_file(target, initial_inputs=[2])

    assert_matches_cpython(target, result)
    assert result.runs[0].result == "item2"


def test_explorer_supports_extended_regular_expression_workflows(tmp_path):
    target = _target(
        tmp_path,
        "import re\n"
        "\n"
        "def main(value):\n"
        "    text = f'item{value} item2'\n"
        "    if re.fullmatch(r'ITEM\\d+ ITEM2', text, re.I):\n"
        "        matches = re.findall(r'\\d+', text)\n"
        "        return re.sub(r'item', 'value', text) + ':' + matches[0]\n"
        "    return 'none'\n",
    )

    result = explore_file(target, initial_inputs=[4])

    assert_matches_cpython(target, result)
    assert result.runs[0].result == "value4 value2:4"


def test_explorer_supports_named_regular_expression_match_groups(tmp_path):
    target = _target(
        tmp_path,
        "import re\n"
        "\n"
        "def main(value):\n"
        "    match = re.match(r'(?P<word>[a-z]+)-(?P<number>\\d+)', f'item-{value}')\n"
        "    groups = match.groups()\n"
        "    fields = match.groupdict()\n"
        "    return match.group('word') + fields['number'] + groups[1]\n",
    )

    result = explore_file(target, initial_inputs=[5])

    assert_matches_cpython(target, result)
    assert result.runs[0].result == "item55"


def test_explorer_supports_extended_string_processing_methods(tmp_path):
    target = _target(
        tmp_path,
        "def main(value):\n"
        "    prefix, separator, suffix = 'item-value'.partition('-')\n"
        "    text = prefix.title().removeprefix('Item').casefold()\n"
        "    if separator.isspace() or not suffix.isalpha():\n"
        "        return 'none'\n"
        "    return text.zfill(3) + suffix.rjust(value, '_')\n",
    )

    result = explore_file(target, initial_inputs=[7])

    assert_matches_cpython(target, result)
    assert result.runs[0].result == "000__value"


def test_explorer_supports_percent_string_formatting(tmp_path):
    target = _target(
        tmp_path,
        "def main(value):\n" "    return 'item-%04d:%s' % (value, 'ready')\n",
    )

    result = explore_file(target, initial_inputs=[6])

    assert_matches_cpython(target, result)
    assert result.runs[0].result == "item-0006:ready"


def test_explorer_supports_common_numeric_and_character_builtins(tmp_path):
    target = _target(
        tmp_path,
        "def main(value):\n"
        "    quotient, remainder = divmod(value, 2)\n"
        "    letter = chr(ord('A') + remainder)\n"
        "    return (letter + ':' + str(float(quotient))\n"
        "            + ':' + str(pow(2, remainder)))\n",
    )

    result = explore_file(target, initial_inputs=[3])

    assert_matches_cpython(target, result)
    assert result.runs[0].result == "B:1.0:2"


def test_explorer_supports_common_representation_builtins(tmp_path):
    target = _target(
        tmp_path,
        "def main(value):\n"
        "    return repr(value) + ':' + ascii('é') + ':' + format(value, '04d')\n",
    )

    result = explore_file(target, initial_inputs=[7])

    assert_matches_cpython(target, result)
    assert result.runs[0].result == "7:'\\xe9':0007"


def test_explorer_supports_floating_point_abs_and_round(tmp_path):
    target = _target(
        tmp_path,
        "def main(value):\n" "    return round(abs(float(value) - 2.5), 1)\n",
    )

    result = explore_file(target, initial_inputs=[1])

    assert_matches_cpython(target, result)
    assert result.runs[0].result == 1.5


def test_explorer_supports_extended_math_summaries(tmp_path):
    target = _target(
        tmp_path,
        "import math\n"
        "\n"
        "def main(value):\n"
        "    if math.isclose(math.log(math.e), 1.0):\n"
        "        return math.factorial(value) + math.comb(4, 2) + int(math.pi)\n"
        "    return 0\n",
    )

    result = explore_file(target, initial_inputs=[3])

    assert_matches_cpython(target, result)
    assert result.runs[0].result == 15


def test_explorer_uses_custom_equality_in_collection_operations(tmp_path):
    target = _target(
        tmp_path,
        "class Token:\n"
        "    def __init__(self, value):\n"
        "        self.value = value\n"
        "\n"
        "    def __eq__(self, other):\n"
        "        return self.value == other.value\n"
        "\n"
        "def main(value):\n"
        "    tokens = [Token(value), Token(2)]\n"
        "    if Token(value) in tokens:\n"
        "        tokens.remove(Token(value))\n"
        "    return len(tokens) + tokens.count(Token(2))\n",
    )

    result = explore_file(target, initial_inputs=[4])

    assert_matches_cpython(target, result)
    assert result.runs[0].result == 2


def test_explorer_supports_dictionary_union_and_set_algebra(tmp_path):
    target = _target(
        tmp_path,
        "def main(value):\n"
        "    merged = {'value': value, 'shared': 1} | {'shared': 3, 'end': 4}\n"
        "    values = ({value, 2, 3} & {2, value}) | {4}\n"
        "    return merged['value'] + merged['shared'] + merged['end'] + len(values)\n",
    )

    result = explore_file(target, initial_inputs=[6])

    assert_matches_cpython(target, result)
    assert result.runs[0].result == 16


def test_explorer_preserves_aliases_for_in_place_collection_operators(tmp_path):
    target = _target(
        tmp_path,
        "def main(value):\n"
        "    values = {'value': value}\n"
        "    alias = values\n"
        "    values |= {'offset': 2}\n"
        "    numbers = {value, 2, 3}\n"
        "    numbers &= {value, 2}\n"
        "    return alias['value'] + alias['offset'] + len(numbers)\n",
    )

    result = explore_file(target, initial_inputs=[6])

    assert_matches_cpython(target, result)
    assert result.runs[0].result == 10


def test_explorer_uses_base64_library_summaries(tmp_path):
    target = _target(
        tmp_path,
        "import base64\n"
        "\n"
        "def main(value):\n"
        "    encoded = base64.b64encode(f'item{value}'.encode())\n"
        "    return base64.b64decode(encoded).decode()\n",
    )

    result = explore_file(target, initial_inputs=[6])

    assert_matches_cpython(target, result)
    assert result.runs[0].result == "item6"


def test_explorer_uses_pure_pathlib_path_summary(tmp_path):
    target = _target(
        tmp_path,
        "from pathlib import Path\n"
        "\n"
        "def main(value):\n"
        "    path = Path('reports') / f'item{value}.json'\n"
        "    return path.parent.as_posix() + ':' + path.stem + path.suffix\n",
    )

    result = explore_file(target, initial_inputs=[6])

    assert_matches_cpython(target, result)
    assert result.runs[0].result == "reports:item6.json"


def test_explorer_uses_hashlib_digest_summary(tmp_path):
    target = _target(
        tmp_path,
        "import hashlib\n"
        "\n"
        "def main(value):\n"
        "    digest = hashlib.sha256(f'item{value}'.encode())\n"
        "    return digest.hexdigest()[:8]\n",
    )

    result = explore_file(target, initial_inputs=[6])

    assert_matches_cpython(target, result)
    assert result.runs[0].result == "597b4124"


def test_explorer_uses_urllib_parse_summaries(tmp_path):
    target = _target(
        tmp_path,
        "import urllib.parse\n"
        "from urllib.parse import parse_qs, quote, urlencode\n"
        "\n"
        "def main(value):\n"
        "    encoded = urlencode({'item': value, 'tag': 'a b'})\n"
        "    parsed = parse_qs(encoded)\n"
        "    path = quote(parsed['item'][0]) + '-' + quote(parsed['tag'][0])\n"
        "    return urllib.parse.urljoin('https://example.test/api/', path)\n",
    )

    result = explore_file(target, initial_inputs=[6])

    assert_matches_cpython(target, result)
    assert result.runs[0].result == "https://example.test/api/6-a%20b"


def test_explorer_supports_structured_urllib_parse_results(tmp_path):
    target = _target(
        tmp_path,
        "from urllib.parse import parse_qsl, urlparse\n"
        "\n"
        "def main(value):\n"
        "    parsed = urlparse('https://user:pass@example.com:8443/a?x=1&y=2#part')\n"
        "    pairs = parse_qsl(parsed.query)\n"
        "    return parsed.hostname + ':' + str(parsed.port) + ':' + pairs[value][1]\n",
    )

    result = explore_file(target, initial_inputs=[1])

    assert_matches_cpython(target, result)
    assert result.runs[0].result == "example.com:8443:2"


def test_explorer_uses_deterministic_datetime_summaries(tmp_path):
    target = _target(
        tmp_path,
        "from datetime import date, datetime, timedelta\n"
        "\n"
        "def main(value):\n"
        "    start = date.fromisoformat('2024-01-01')\n"
        "    end = start + timedelta(days=value)\n"
        "    stamp = datetime.fromisoformat('2024-02-03T12:45:00')\n"
        "    return (end.isoformat() + ':' + stamp.date().strftime('%Y-%m-%d')\n"
        "            + ':' + str(stamp.hour))\n",
    )

    result = explore_file(target, initial_inputs=[6])

    assert_matches_cpython(target, result)
    assert result.runs[0].result == "2024-01-07:2024-02-03:12"


def test_explorer_uses_statistics_library_summaries(tmp_path):
    target = _target(
        tmp_path,
        "from statistics import fmean, median\n"
        "\n"
        "def main(value):\n"
        "    values = [value, 2, 9]\n"
        "    return fmean(values) + median(values)\n",
    )

    result = explore_file(target, initial_inputs=[4])

    assert_matches_cpython(target, result)
    assert result.runs[0].result == 9.0


def test_explorer_uses_fnmatch_library_summaries(tmp_path):
    target = _target(
        tmp_path,
        "from fnmatch import filter, fnmatch, fnmatchcase\n"
        "def main(value):\n"
        "    names = [f'item{value}.py', 'notes.txt']\n"
        "    selected = filter(names, '*.py')\n"
        "    return (fnmatch(selected[0], 'item?.py') and "
        "fnmatchcase(selected[0], 'item?.py'))\n",
    )

    result = explore_file(target, initial_inputs=[4])

    assert_matches_cpython(target, result)
    assert result.runs[0].result is True


def test_explorer_uses_binary_codec_library_summaries(tmp_path):
    target = _target(
        tmp_path,
        "import binascii\n"
        "import codecs\n"
        "import zlib\n"
        "def main(value):\n"
        "    payload = codecs.encode(f'item{value}', 'utf-8')\n"
        "    encoded = binascii.hexlify(payload)\n"
        "    restored = zlib.decompress(zlib.compress(binascii.unhexlify(encoded)))\n"
        "    return codecs.decode(restored, 'utf-8') + ':' + str(zlib.crc32(restored))\n",
    )

    result = explore_file(target, initial_inputs=[4])

    assert_matches_cpython(target, result)
    assert result.runs[0].result.startswith("item4:")


def test_explorer_uses_struct_library_summaries(tmp_path):
    target = _target(
        tmp_path,
        "import struct\n"
        "def main(value):\n"
        "    payload = struct.pack('>h', value)\n"
        "    unpacked = struct.unpack('>h', payload)\n"
        "    return unpacked[0] + struct.calcsize('>h')\n",
    )

    result = explore_file(target, initial_inputs=[7])

    assert_matches_cpython(target, result)
    assert result.runs[0].result == 9


def test_explorer_uses_unicode_and_html_library_summaries(tmp_path):
    target = _target(
        tmp_path,
        "import html\n"
        "import unicodedata\n"
        "def main(value):\n"
        "    text = unicodedata.normalize('NFC', 'e\\u0301')\n"
        "    escaped = html.escape('<' + text + str(value) + '>')\n"
        "    return html.unescape(escaped) + ':' + unicodedata.category(text[0])\n",
    )

    result = explore_file(target, initial_inputs=[2])

    assert_matches_cpython(target, result)
    assert result.runs[0].result == "<é2>:Ll"
