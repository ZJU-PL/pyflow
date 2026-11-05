"""Regressions found by the mypy differential corpus harness.

Each test pins a gap where PyFlow disagreed with mypy on real corpus code:
receiver binding for classmethods, missing builtin/stdlib member signatures,
generic substitution into stub members, and protocol-driven overload binding.
"""

from __future__ import annotations

from pathlib import Path

from pyflow.analysis.typeinfo import (
    ProjectTypeInferenceEngine,
    StaticTypeInferenceEngine,
)
from pyflow.language.modules.project_resolution import ProjectContext


def infer(source: str):
    return StaticTypeInferenceEngine().infer_source("m", source)


def test_stdlib_classmethod_is_bound_on_class_and_instance() -> None:
    result = infer("""
import pathlib
import datetime

class_access = pathlib.Path.cwd
instance_access = pathlib.Path(".").cwd
now = datetime.datetime.now
""")

    assert str(result.type_of("class_access")) == "Callable[[], pathlib.Path]"
    assert str(result.type_of("instance_access")) == "Callable[[], pathlib.Path]"
    assert str(result.type_of("now")) == "Callable[[None | datetime.tzinfo], datetime.datetime]"


def test_instance_method_accessed_through_class_keeps_self() -> None:
    result = infer("""
import pathlib

unbound = pathlib.Path.exists
""")

    assert str(result.type_of("unbound")) == "Callable[[Any, bool], bool]"


def test_builtin_container_methods_keep_typeshed_signatures() -> None:
    result = infer("""
values: list[int] = []
append = values.append
lookup = {"a": 1}.get
split = "a,b".split
keys = dict.fromkeys
""")

    assert str(result.type_of("append")) == "Callable[[int], None]"
    assert str(result.type_of("lookup")) == "Callable[[str, None], None | int]"
    assert str(result.type_of("split")) == "Callable[[None | str, typing.SupportsIndex], list[str]]"
    assert str(result.type_of("keys")) == "Callable[[collections.abc.Iterable[_T], None], dict]"


def test_typing_alias_subscript_uses_value_type() -> None:
    result = infer("""
from typing import Dict, List

table: Dict[str, int] = {}
values: List[int] = []
first = table["a"]
second = values[0]
""")

    assert str(result.type_of("first")) == "int"
    assert str(result.type_of("second")) == "int"


def test_protocol_overload_binds_type_variable_from_member() -> None:
    result = infer("""
import math

up = math.ceil(1.5)
down = math.floor(2)
best = max([1, 2])
""")

    assert str(result.type_of("up")) == "int"
    assert str(result.type_of("down")) == "int"
    assert str(result.type_of("best")) == "int"


def test_cross_module_classmethod_is_bound(tmp_path: Path) -> None:
    package = tmp_path / "pkg"
    package.mkdir()
    (package / "__init__.py").write_text("", encoding="utf-8")
    (package / "core.py").write_text(
        """
class Builder:
    @classmethod
    def create(cls, size: int) -> "Builder":
        return cls()
""",
        encoding="utf-8",
    )
    (package / "use.py").write_text(
        """
from pkg.core import Builder

factory = Builder.create
""",
        encoding="utf-8",
    )

    result = ProjectTypeInferenceEngine(ProjectContext(tmp_path)).infer_project(["pkg.use"])

    assert str(result.modules["pkg.use"].type_of("factory")) == "Callable[[int], pkg.core.Builder]"
