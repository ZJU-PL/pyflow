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
from pyflow.analysis.typeinfo.core.typesystem import CallableType, Instance
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


def test_missing_dependency_is_gradual_not_partial() -> None:
    result = infer("""
from external_package import Base

def consume(value: Base) -> Base:
    return value
""")

    assert result.status == "complete"
    codes = {item.code for item in result.diagnostics}
    assert "missing-external-type" in codes
    assert "unresolved-annotation" not in codes
    assert all(
        not item.affects_completeness
        for item in result.diagnostics
        if item.code == "missing-external-type"
    )
    assert str(result.type_of("m.consume")) == "Callable[[Any], Any]"


def test_project_internal_resolution_failure_stays_partial(tmp_path: Path) -> None:
    package = tmp_path / "pkg"
    package.mkdir()
    (package / "__init__.py").write_text("", encoding="utf-8")
    (package / "core.py").write_text("class Present:\n    pass\n", encoding="utf-8")
    (package / "use.py").write_text(
        "from pkg.core import Missing\n\ndef consume(value: Missing) -> None:\n    pass\n",
        encoding="utf-8",
    )

    result = ProjectTypeInferenceEngine(ProjectContext(tmp_path)).infer_project(["pkg.use"])
    module = result.modules["pkg.use"]

    assert module.status == "partial"
    assert any(
        item.code == "unresolved-annotation" and item.affects_completeness
        for item in module.diagnostics
    )


def test_newtype_keeps_nominal_identity_and_accepts_base_values() -> None:
    result = infer("""
from typing import NewType

UserId = NewType("UserId", int)

def consume(value: UserId) -> int:
    return value

def build(value: int) -> UserId:
    return UserId(value)

bad = consume(1)
""")

    ident = result.type_of("m.UserId")
    assert isinstance(ident, Instance) and ident.type.full_name == "m.UserId"
    built = result.type_of("m.build")
    assert isinstance(built, CallableType)
    assert str(built.return_type) == "m.UserId"
    assert built.arg_types is not None and str(built.arg_types[0]) == "int"
    mismatches = [item.message for item in result.diagnostics if item.code == "annotation-mismatch"]
    assert any("argument value of m.consume" in message for message in mismatches)


def test_decorator_keeps_wrapped_signature() -> None:
    result = infer("""
from typing import Callable, TypeVar, ParamSpec

P = ParamSpec("P")
R = TypeVar("R")

def typed(f: Callable[P, R]) -> Callable[P, R]:
    return f

@typed
def endpoint(value: int) -> str:
    return str(value)
""")

    assert str(result.type_of("m.endpoint")) == "Callable[[int], str]"


def test_type_variable_renders_by_name_only() -> None:
    result = infer("""
from typing import Callable, TypeVar

Decorated = TypeVar("Decorated", bound=Callable[..., object])

def make(handler: Decorated) -> Decorated:
    return handler
""")

    assert str(result.type_of("m.make")) == "Callable[[Decorated], Decorated]"


def test_new_on_class_returns_instance_without_false_positive() -> None:
    result = infer("""
class Options:
    def __init__(self) -> None:
        self.width = 1

def copy() -> Options:
    options: Options = Options.__new__(Options)
    return options
""")

    assert str(result.type_of("m.copy")) == "Callable[[], m.Options]"
    assert not [item for item in result.diagnostics if item.code == "annotation-mismatch"]


def test_inherited_member_uses_base_type_arguments() -> None:
    from pyflow.analysis.typeinfo import TypeInfoService

    service = TypeInfoService()
    service.collect_module(
        "sample",
        source="from collections import OrderedDict\nclass M(OrderedDict[str, int]):\n    pass\n",
        path="/tmp/sample.py",
    )

    keys = service.members_of("sample.M")["keys"].typ
    assert keys is not None
    rendered = str(keys)
    assert "_KT" not in rendered and "_VT" not in rendered
    assert "str" in rendered and "int" in rendered
