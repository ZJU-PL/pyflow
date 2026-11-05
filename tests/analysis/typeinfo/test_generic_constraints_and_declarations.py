"""Generic constraint solving, declarative class checks, and match patterns."""

from __future__ import annotations

from pyflow.analysis.typeinfo import StaticTypeInferenceEngine


def _infer(source: str):
    return StaticTypeInferenceEngine().infer_source("m", source)


def _codes(result, code: str) -> list[str]:
    return [item.message for item in result.diagnostics if item.code == code]


def test_typeshed_protocol_elements_bind_method_type_vars() -> None:
    result = _infer(
        "import random\n"
        "one = random.choice([1, 2])\n"
        "text = random.choice(['a'])\n"
        "many = random.choices([1, 2], k=2)\n"
        "sample = random.sample([1, 2], 1)\n"
    )

    assert str(result.type_of("one")) == "int"
    assert str(result.type_of("text")) == "str"
    assert str(result.type_of("many")) == "list[int]"
    assert str(result.type_of("sample")) == "list[int]"


def test_constrained_type_vars_bind_to_matching_arguments() -> None:
    result = _infer(
        "from typing import TypeVar\n"
        "T = TypeVar('T', int, str)\n"
        "def identity(value: T) -> T:\n"
        "    return value\n"
        "number = identity(1)\n"
        "text = identity('x')\n"
    )

    assert str(result.type_of("number")) == "int"
    assert str(result.type_of("text")) == "str"


def test_typeddict_rejects_unknown_and_required_key_operations() -> None:
    result = _infer(
        "from typing import TypedDict\n"
        "class Record(TypedDict):\n"
        "    name: str\n"
        "    count: int\n"
        "record: Record = {'name': 'a', 'count': 1}\n"
        "bad_read = record['missing']\n"
        "record['missing'] = 2\n"
        "del record['name']\n"
        "Record(name='a')\n"
        "Record(name='a', count=1, extra=2)\n"
    )

    messages = _codes(result, "typed-dict-key")
    assert any("has no key 'missing'" in message for message in messages)
    assert any("Cannot delete required TypedDict key 'name'" in message for message in messages)
    assert any("unexpected keys" in message for message in messages)
    assert any(
        "Missing required TypedDict keys" in message
        for message in _codes(result, "call-arity-mismatch")
    )


def test_namedtuple_rejects_extra_positional_and_unknown_keywords() -> None:
    result = _infer(
        "from typing import NamedTuple\n"
        "class Point(NamedTuple):\n"
        "    x: int\n"
        "    y: str\n"
        "Point(1, 'a', 2)\n"
        "Point(x=1, z=2)\n"
    )

    messages = _codes(result, "call-arity-mismatch")
    assert any("Too many positional arguments" in message for message in messages)
    assert any("Unexpected keyword arguments" in message for message in messages)


def test_mapping_sequence_and_or_patterns_bind_types() -> None:
    result = _infer(
        "def mapping(value: dict[str, int]) -> int:\n"
        "    match value:\n"
        "        case {'a': item}:\n"
        "            return item\n"
        "    return 0\n"
        "def sequence(value: list[int]) -> int:\n"
        "    match value:\n"
        "        case [first, *rest]:\n"
        "            return first\n"
        "    return 0\n"
        "def alternative(value: int | str) -> str:\n"
        "    match value:\n"
        "        case int() | str():\n"
        "            return str(value)\n"
        "    return ''\n"
    )

    assert str(result.functions["m.mapping"].return_type) == "int"
    assert str(result.functions["m.sequence"].return_type) == "int"
    assert str(result.functions["m.alternative"].return_type) == "str"


def test_match_negative_narrowing_excludes_earlier_patterns() -> None:
    result = _infer(
        "def optional(value: int | None) -> int:\n"
        "    match value:\n"
        "        case None:\n"
        "            return 0\n"
        "        case _:\n"
        "            return value\n"
        "def typed(value: int | str) -> str:\n"
        "    match value:\n"
        "        case int():\n"
        "            return ''\n"
        "        case item:\n"
        "            return item\n"
    )

    assert str(result.functions["m.optional"].return_type) == "int"
    assert str(result.functions["m.typed"].return_type) == "str"
    assert not [item for item in result.diagnostics if item.code == "annotation-mismatch"]


def test_enum_aliases_members_and_values() -> None:
    result = _infer(
        "import enum\n"
        "class Color(enum.Enum):\n"
        "    RED = 1\n"
        "    CRIMSON = 1\n"
        "    BLUE = 2\n"
        "    def label(self) -> str:\n"
        "        return self.name\n"
        "alias = Color.CRIMSON\n"
        "value = alias.value\n"
        "name = alias.name\n"
        "label = alias.label()\n"
        "members = list(Color)\n"
    )

    assert str(result.type_of("alias")) == "m.Color"
    assert str(result.type_of("value")) == "int"
    assert str(result.type_of("name")) == "str"
    assert str(result.type_of("label")) == "str"
    assert str(result.type_of("members")) == "list[m.Color]"
