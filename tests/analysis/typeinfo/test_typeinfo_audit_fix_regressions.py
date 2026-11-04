"""Regressions for typeinfo crashes and missing runtime models."""

from __future__ import annotations

from pyflow.analysis.typeinfo import StaticTypeInferenceEngine, TypeInfoService
from pyflow.language.modules.project_resolution import ProjectContext


def _infer(source: str):
    return StaticTypeInferenceEngine().infer_source("m", source)


def _diagnostic_codes(result) -> list[str]:
    return [diagnostic.code for diagnostic in result.diagnostics]


def test_path_walk_is_modeled_without_crashing() -> None:
    source = """
from pathlib import Path

for root, dirs, files in Path(".").walk():
    pass

walk = Path(".").walk()
"""
    result = _infer(source)

    assert _diagnostic_codes(result) == []
    assert str(result.type_of("root")) == "pathlib.Path"
    assert str(result.type_of("dirs")) == "list[str]"
    assert str(result.type_of("files")) == "list[str]"
    assert "Iterator[tuple[pathlib.Path, list[str], list[str]]]" in str(result.type_of("walk"))


def test_io_base_read_does_not_narrow_to_text() -> None:
    source = """
import io

def read_all(fp: io.IOBase) -> bytes:
    return fp.read()

def read_line(fp: io.IOBase) -> bytes:
    return fp.readline()
"""
    result = _infer(source)

    assert "annotation-mismatch" not in _diagnostic_codes(result)
    assert str(result.functions["m.read_all"].return_type) == "bytes"
    assert str(result.functions["m.read_line"].return_type) == "bytes"
    # The base ``read`` signature is unconstrained in typeshed.
    assert str(_infer("import io\nx = io.IOBase().read()\n").type_of("x")) == "Any"


def test_file_objects_iterate_as_text_lines() -> None:
    source = """
f = open("x")
for line in f:
    result = line
"""
    result = _infer(source)

    assert str(result.type_of("line")) == "str"
    assert str(result.type_of("result")) == "str"


def test_named_temporary_file_respects_mode() -> None:
    text_source = """
import tempfile

with tempfile.NamedTemporaryFile(mode="w+") as fh:
    data = fh.read()
"""
    binary_source = """
import tempfile

with tempfile.NamedTemporaryFile() as fh:
    data = fh.read()
"""
    assert str(_infer(text_source).type_of("data")) == "str"
    assert str(_infer(binary_source).type_of("data")) == "bytes"


def test_nested_typing_unions_do_not_emit_unsupported_expression() -> None:
    source = """
from typing import Callable, Union

alias = dict[str, Union[int, str]]
callback = Callable[[Union[str, int]], int]
"""
    result = _infer(source)

    assert "unsupported-expression" not in _diagnostic_codes(result)
    assert str(result.type_of("alias")) == "type[dict[str, int | str]]"
    assert str(result.type_of("callback")) == "Callable[[int | str], int]"


def test_abstract_stub_returns_unknown_instead_of_none() -> None:
    source = """
import abc

class Handler(abc.ABC):
    def send(self) -> int:
        return self._send()

    @abc.abstractmethod
    def _send(self):
        ...
"""
    result = _infer(source)

    assert "annotation-mismatch" not in _diagnostic_codes(result)
    assert result.functions["m.Handler._send"].return_value.runtime_type() is None


def test_match_args_controls_positional_class_patterns() -> None:
    source = """
class Point:
    __match_args__ = ("y", "x")

    def __init__(self, x: int, y: str):
        self.x = x
        self.y = y

point = Point(1, "a")
match point:
    case Point(first, second):
        first_value = first
        second_value = second
"""
    result = _infer(source)

    assert str(result.type_of("first_value")) == "str"
    assert str(result.type_of("second_value")) == "int"


def test_service_keeps_property_getter_type_when_setter_is_present() -> None:
    source = """
class Client:
    @property
    def name(self) -> str:
        return "client"

    @name.setter
    def name(self, value: str) -> None:
        pass
"""
    service = TypeInfoService(ProjectContext(None))
    service.collect_module("pkg.mod", source=source)

    members = service.members_of("pkg.mod.Client")
    assert str(members["name"].typ) == "str"
    assert members["name"].kind == "property"
    assert str(service.type_of("pkg.mod", "Client.name")) == "str"


def test_match_fields_keep_private_dataclass_fields() -> None:
    source = """
import dataclasses

@dataclasses.dataclass
class Record:
    _key: int
    value: str

record = Record(1, "v")
match record:
    case Record(first, second):
        first_value = first
        second_value = second
"""
    result = _infer(source)

    assert str(result.type_of("first_value")) == "int"
    assert str(result.type_of("second_value")) == "str"


def test_io_open_uses_the_builtin_file_model() -> None:
    source = """
import io

def read_text() -> str:
    with io.open("x", "r") as handle:
        return handle.read()

def read_bytes() -> bytes:
    with io.open("x", "rb") as handle:
        return handle.read()
"""
    result = _infer(source)

    assert result.diagnostics == []
