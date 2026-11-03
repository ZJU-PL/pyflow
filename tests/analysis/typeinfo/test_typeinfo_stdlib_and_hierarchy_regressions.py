"""Regressions found while scanning the top-100 Python corpus (2026-11).

Each test pins behaviour that used to be wrong: stdlib module resolution,
stdlib class objects inside containers, builtin ancestry for source classes,
protocol checks over unresolved bases, and nested collection literal widening.
"""

from __future__ import annotations

from pyflow.analysis.typeinfo import StaticTypeInferenceEngine
from pyflow.analysis.typeinfo.core.typesystem import Instance, TypeType, UnionType
from pyflow.analysis.typeinfo.inference.engine import InferenceOptions


def _infer(source: str, *, strict: bool = False):
    return StaticTypeInferenceEngine(
        options=InferenceOptions(strict_annotations=strict)
    ).infer_source("sample", source)


def _mismatches(result):
    return [item.message for item in result.diagnostics if item.code == "annotation-mismatch"]


def test_import_time_binds_module_not_datetime_time_class() -> None:
    result = _infer("""
import time

module = time
stamp = time.time()
tick = time.monotonic()
paused = time.sleep(0)
formatted = time.strftime("%Y")
""")

    # ``time`` is a module; the bare-name annotation alias ``time`` ->
    # ``datetime.time`` must not leak into value resolution.
    assert result.type_of("module") is None
    assert str(result.type_of("stamp")) == "float"
    assert str(result.type_of("tick")) == "float"
    assert str(result.type_of("paused")) == "None"
    assert str(result.type_of("formatted")) == "str"


def test_from_imported_stdlib_globals_are_modelled() -> None:
    result = _infer("""
from math import pi
from os import environ
from sys import argv

ratio = pi
arguments = argv
environment = environ
""")

    assert str(result.type_of("ratio")) == "float"
    assert str(result.type_of("arguments")) == "list[str]"
    assert str(result.type_of("environment")) == "dict[str, str]"


def test_datetime_annotations_still_resolve_without_import_prefix() -> None:
    result = _infer("""
import datetime

today = datetime.date.today()
now = datetime.datetime.now()
""")

    assert str(result.type_of("today")) == "datetime.date"
    assert str(result.type_of("now")) == "datetime.datetime"


def test_stdlib_class_objects_in_container_literals_keep_type_projection() -> None:
    result = _infer("""
import datetime
import uuid

modules = [datetime.date, uuid.UUID]
pair = (datetime.date, uuid.UUID)
""")

    modules = result.type_of("modules")
    assert isinstance(modules, Instance)
    assert modules.type.raw_type is list
    element = modules.args[0]
    element_types = element.items if isinstance(element, UnionType) else (element,)
    assert len(element_types) == 2
    assert all(isinstance(item, TypeType) for item in element_types)

    pair = result.type_of("pair")
    assert all(isinstance(item, TypeType) for item in pair.args)


def test_stdlib_class_registry_matches_type_any_annotation() -> None:
    result = _infer(
        """
import datetime
from typing import Any, Callable

REGISTRY: dict[type[Any], Callable[[Any], Any]] = {
    datetime.date: str,
    datetime.time: str,
    list: list,
}
""",
        strict=True,
    )

    assert not _mismatches(result)


def test_re_split_and_findall_follow_typeshed_precision() -> None:
    result = _infer("""
import re

parts = re.split(":", "a:b", maxsplit=1)
matches = re.findall("(a)?", "b")
compiled = re.compile(":").split("a:b")
""")

    assert str(result.type_of("parts")) == "list[Any]"
    assert str(result.type_of("matches")) == "list[Any]"
    assert str(result.type_of("compiled")) == "list[Any]"


def test_re_split_result_is_not_flagged_as_str_argument() -> None:
    result = _infer(
        """
import re

def prepare(path: str) -> str:
    return path

def load(spec: str) -> None:
    path, _name = (re.split(":", spec, maxsplit=1) + [None])[:2]
    prepare(path)
""",
        strict=True,
    )

    assert not _mismatches(result)


def test_source_exception_is_a_builtin_exception_subtype() -> None:
    result = _infer("""
class ParseError(ValueError):
    pass

def collect(errors: list[Exception]) -> None: ...
def collect_all(errors: list[BaseException]) -> None: ...
def lookup(errors: list[LookupError]) -> None: ...

collect([ParseError()])
collect_all([ParseError()])
""")

    assert not _mismatches(result)


def test_source_dict_subclass_satisfies_mapping() -> None:
    result = _infer("""
from typing import Mapping

class Registry(dict):
    pass

def consume(values: Mapping[str, int]) -> None: ...

consume(Registry())
""")

    assert not _mismatches(result)


def test_subtype_checks_still_reject_unrelated_builtins() -> None:
    result = _infer(
        """
class ParseError(ValueError):
    pass

def consume(errors: list[KeyError]) -> None: ...

consume([ParseError()])
""",
        strict=True,
    )

    assert _mismatches(result)


def test_protocol_ignores_members_inherited_from_unknown_base() -> None:
    result = _infer(
        """
from typing import Protocol
from starlette.routing import Route

class HasPath(Protocol):
    path: str

class RouteImpl(Route):
    pass

def consume(route: HasPath) -> None: ...

consume(RouteImpl())
""",
        strict=True,
    )

    assert not _mismatches(result)


def test_protocol_still_rejects_missing_members_on_known_hierarchy() -> None:
    result = _infer(
        """
from typing import Protocol

class HasPath(Protocol):
    path: str

class NoPath:
    pass

def consume(route: HasPath) -> None: ...

consume(NoPath())
""",
        strict=True,
    )

    assert _mismatches(result)


def test_class_with_third_party_base_is_not_reported_as_incompatible() -> None:
    # scrapy passes ``InvalidNegotiatedProtocol`` (an ``h2`` exception) to a
    # ``list[BaseException]`` parameter; the hierarchy below the third-party
    # base is unknowable, so no diagnostic may be produced.
    result = _infer(
        """
from h2.exceptions import H2Error

class InvalidNegotiatedProtocol(H2Error):
    pass

def lose(errors: list[BaseException]) -> None: ...

lose([InvalidNegotiatedProtocol()])
""",
        strict=True,
    )

    assert not _mismatches(result)


def test_nested_collection_literals_widen_to_annotation() -> None:
    result = _infer(
        """
values: list[list[str | None]] = [[None], ["a"]]
mapping: dict[str, list[int]] = {"a": []}

def consume(rows: list[list[str | None]]) -> None: ...

consume([[None]])
""",
        strict=True,
    )

    assert not _mismatches(result)


def test_nested_collection_literals_still_reject_incompatible_elements() -> None:
    result = _infer(
        """
values: list[list[int]] = [["a"]]
""",
        strict=True,
    )

    assert _mismatches(result)


def test_common_stdlib_globals_are_modelled() -> None:
    result = _infer("""
import math
import os
import sys

arguments = sys.argv
platform = sys.platform
environment = os.environ
pi = math.pi
""")

    assert str(result.type_of("arguments")) == "list[str]"
    assert str(result.type_of("platform")) == "str"
    assert str(result.type_of("environment")) == "dict[str, str]"
    assert str(result.type_of("pi")) == "float"
