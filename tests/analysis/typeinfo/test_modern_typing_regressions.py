"""Typing and scalability regressions found while analysing real projects."""

import ast
import re
from pathlib import Path
from typing import Protocol

import pytest

from pyflow.analysis.typeinfo import ProjectTypeInferenceEngine, StaticTypeInferenceEngine
from pyflow.analysis.typeinfo.core.typesystem import (
    EmailString,
    Instance,
    TupleType,
    UnionType,
    TypeSystem,
)
from pyflow.analysis.typeinfo.inference.engine import InferenceOptions
from pyflow.analysis.typeinfo.inference.string_patterns import RegexBuilder
from pyflow.analysis.typeinfo.resolution.annotations import BuiltinTypeLookup, resolve_annotation
from pyflow.language.modules.project_resolution import ProjectContext


def raw_types(typ):
    if isinstance(typ, Instance):
        return {typ.type.raw_type}
    if isinstance(typ, UnionType):
        return set().union(*(raw_types(item) for item in typ.items))
    return set()


def infer(source, **options):
    return StaticTypeInferenceEngine(options=InferenceOptions(**options)).infer_source(
        "sample", source
    )


def test_project_discovery_excludes_external_imports_but_allows_explicit_entries(tmp_path):
    project = tmp_path / "project"
    external = tmp_path / "external"
    project.mkdir()
    external.mkdir()
    (project / "app.py").write_text("import os\nimport dependency\nimport local\n")
    (project / "local.py").write_text("number = 42\n")
    (external / "dependency.py").write_text("import pathlib\nvalue = 'external'\n")
    context = ProjectContext(project, added_sys_path=[str(external)])
    engine = ProjectTypeInferenceEngine(context)
    assert set(engine.infer_project(["app"]).modules) == {"app", "local"}
    assert set(engine.infer_project(["app", "dependency"]).modules) == {
        "app",
        "local",
        "dependency",
    }


def test_project_discovery_respects_symlink_boundaries(tmp_path):
    project = tmp_path / "project"
    project.mkdir()
    external = tmp_path / "external.py"
    external.write_text("value = 1\n")
    (project / "dependency.py").symlink_to(external)
    (project / "app.py").write_text("import dependency\n")
    result = ProjectTypeInferenceEngine(ProjectContext(project)).infer_project(["app"])
    assert set(result.modules) == {"app"}


def test_parameterized_generic_constructors_and_methods():
    result = infer("""
from typing import Generic, TypeVar
T = TypeVar("T")
class Box(Generic[T]):
    def __init__(self, value: T): self.value = value
    def get(self) -> T: return self.value
integer = Box[int](1)
text = Box[str]("hello")
a = integer.get()
b = text.get()
""")
    assert isinstance(result.type_of("integer"), Instance)
    assert raw_types(result.type_of("integer").args[0]) == {int}
    assert raw_types(result.type_of("a")) == {int}
    assert raw_types(result.type_of("b")) == {str}
    assert not [d for d in result.diagnostics if d.code == "annotation-mismatch"]


def test_advanced_typing_fixture_specializes_calculators():
    fixture = Path(__file__).parents[2] / "fixtures/analysis_inputs/advanced_typing.py"
    result = infer(fixture.read_text())
    for name, expected in (
        ("int_calc", int),
        ("int_result", int),
        ("float_calc", float),
        ("float_result", float),
    ):
        typ = result.type_of(name)
        assert isinstance(typ, Instance)
        assert typ.type.full_name == "sample.Calculator"
        assert raw_types(typ.args[0]) == {expected}


def test_newtype_and_cast_support_import_aliases_and_annotations():
    result = infer("""
import typing as t
from typing import NewType as NT, cast as narrow
UserId = NT("UserId", int)
uid: UserId = UserId(42)
other = UserId(7)
text = narrow(str, unknown)
number = t.cast(int, unknown)
""")
    assert raw_types(result.type_of("uid")) == {int}
    assert raw_types(result.type_of("other")) == {int}
    assert raw_types(result.type_of("text")) == {str}
    assert raw_types(result.type_of("number")) == {int}
    assert not result.diagnostics


def test_cast_respects_local_shadowing():
    result = infer("""
from typing import cast
def local(typ, value): return 42
cast = local
value = cast(str, "hello")
""")
    assert raw_types(result.type_of("value")) == {int}


def test_typed_dict_assignment_projection_and_optional_keys():
    result = infer("""
from typing import TypedDict, NotRequired, Required
class User(TypedDict):
    name: str
    age: int
    nickname: NotRequired[str]
class Extra(User, total=False):
    active: Required[bool]
    info: str
user: User = {"name": "Alice", "age": 30}
extra: Extra = {"name": "Alice", "age": 30, "active": True}
name = user["name"]
age = user["age"]
active = extra["active"]
""")
    assert raw_types(result.type_of("name")) == {str}
    assert raw_types(result.type_of("age")) == {int}
    assert raw_types(result.type_of("active")) == {bool}
    assert not result.diagnostics


@pytest.mark.parametrize("literal", ["{}", '{"name": 42}', '{"name": "ok", "extra": 1}'])
def test_typed_dict_invalid_literals_are_reported(literal):
    result = infer(
        f"""
from typing import TypedDict
class User(TypedDict):
    name: str
user: User = {literal}
""",
        strict_annotations=True,
    )
    assert any(
        d.code == "annotation-mismatch" and d.severity == "error" for d in result.diagnostics
    )


def test_protocol_structural_method_checks_and_runtime_branch():
    result = infer("""
from typing import Protocol, runtime_checkable
@runtime_checkable
class Greeter(Protocol):
    def greet(self) -> str: ...
class Person:
    def greet(self) -> str: return "hi"
class Wrong:
    def greet(self) -> int: return 1
good: Greeter = Person()
bad: Greeter = Wrong()
def greeting(person: Person):
    if isinstance(person, Greeter): return person.greet()
    return None
""")
    mismatches = [d for d in result.diagnostics if d.code == "annotation-mismatch"]
    assert len(mismatches) == 1
    assert "Wrong" in mismatches[0].message
    assert raw_types(result.functions["sample.greeting"].return_type) == {str}


def test_self_binds_to_receiver_including_subclasses():
    result = infer("""
from typing import Self
class Builder:
    def clone(self) -> Self: return self
class Special(Builder): pass
base = Builder().clone()
child = Special().clone()
""")
    assert result.type_of("base").type.full_name == "sample.Builder"
    assert result.type_of("child").type.full_name == "sample.Special"
    assert not result.diagnostics


def test_runtime_descriptors_check_protocol_members_and_signatures():
    class Greeter(Protocol):
        def greet(self) -> "str": ...

    class Person:
        def greet(self) -> "str":
            return "hi"

    class Wrong:
        def greet(self) -> "int":
            return 1

    class Missing:
        pass

    system = TypeSystem()
    expected = Instance(system.to_class_descriptor(Greeter))
    assert system.is_subtype(Instance(system.to_class_descriptor(Person)), expected)
    assert not system.is_subtype(Instance(system.to_class_descriptor(Wrong)), expected)
    assert not system.is_subtype(Instance(system.to_class_descriptor(Missing)), expected)


@pytest.mark.skipif(not hasattr(ast, "TypeAlias"), reason="requires Python 3.12 parser")
def test_pep695_aliases_and_scoped_function_and_class_type_parameters():
    result = infer("""
type Number = int | float
value: Number = 1
def identity[T](value: T) -> T: return value
def text[T: str](value: T) -> T: return value
class Box[T]:
    def __init__(self, value: T): self.value = value
    def get(self) -> T: return self.value
integer = identity(1)
word = text("hi")
boxed = Box[int](1).get()
""")
    assert raw_types(result.type_of("value")) == {int, float}
    assert raw_types(result.type_of("integer")) == {int}
    assert raw_types(result.type_of("word")) == {str}
    assert raw_types(result.type_of("boxed")) == {int}
    assert not result.diagnostics


@pytest.mark.skipif(not hasattr(ast, "TypeAlias"), reason="requires Python 3.12 parser")
def test_pep695_nested_alias_substitution_and_local_generic_annotations():
    result = infer("""
type Pair[T] = tuple[T, T]
type Nested[T] = list[list[T]]
type Reversed[T, U] = tuple[U, T]
pair: Pair[int] = (1, 2)
nested: Nested[str] = [["hello"]]
reverse: Reversed[int, str] = ("hello", 1)
def identity[T](value: T) -> T:
    local: T = value
    return local
answer = identity(42)
""")
    pair = result.type_of("pair")
    assert isinstance(pair, TupleType)
    assert all(raw_types(item) == {int} for item in pair.args)
    assert raw_types(result.type_of("nested").args[0].args[0]) == {str}
    reverse = result.type_of("reverse")
    assert raw_types(reverse.args[0]) == {str}
    assert raw_types(reverse.args[1]) == {int}
    assert raw_types(result.type_of("answer")) == {int}
    assert not result.diagnostics


@pytest.mark.parametrize("asynchronous", [False, True])
def test_contextmanager_decorator_binds_yield_type(asynchronous):
    prefix = "async " if asynchronous else ""
    decorator = "asynccontextmanager" if asynchronous else "contextmanager"
    result = infer(f"""
from contextlib import {decorator} as managed
@managed
{prefix}def transaction():
    yield "connection"
{prefix}def use():
    {prefix}with transaction() as connection:
        return connection
""")
    assert raw_types(result.functions["sample.use"].return_type) == {str}
    assert not result.diagnostics


def test_call_annotations_check_positional_keyword_and_variadic_arguments():
    result = infer(
        """
def calculate(value: int) -> int: return value
def variadic(*values: int, **labels: str) -> bool: return True
bad = calculate("invalid")
also_bad = calculate(value="invalid")
good = calculate(42)
variadic(1, "wrong", label=123)
variadic(1, 2, label="right")
""",
        strict_annotations=True,
    )
    assert raw_types(result.type_of("bad")) == {int}
    assert raw_types(result.type_of("good")) == {int}
    diagnostics = [d for d in result.diagnostics if d.code == "annotation-mismatch"]
    assert len(diagnostics) == 4
    assert all(d.severity == "error" for d in diagnostics)
    assert {d.span.lineno for d in diagnostics} == {4, 5, 7}


def test_numeric_return_unions_preserve_runtime_alternatives():
    result = infer("""
def f(value: int | list[int]):
    if isinstance(value, (int, str)): return value
    return 99.9
""")
    assert raw_types(result.functions["sample.f"].return_type) == {int, float}


@pytest.mark.parametrize("annotation", ["tuple[()]", "Tuple[()]", "typing.Tuple[()]"])
def test_empty_tuple_annotations_are_fixed_length(annotation):
    typ = resolve_annotation(annotation, BuiltinTypeLookup())
    assert isinstance(typ, TupleType)
    assert typ.args == ()
    assert not typ.unknown_size


def test_class_assignments_and_enum_members():
    result = infer("""
from enum import Enum
class Config:
    HOST = "localhost"
    PORT = 8080
    ALIAS = HOST
class Child(Config): pass
class Color(Enum):
    RED = 1
host = Child.HOST
alias = Config.ALIAS
port = Config.PORT
red = Color.RED
""")
    assert raw_types(result.type_of("host")) == {str}
    assert raw_types(result.type_of("alias")) == {str}
    assert raw_types(result.type_of("port")) == {int}
    assert result.type_of("red").type.full_name == "sample.Color"


def test_named_tuple_keeps_nominal_attributes_and_sequence_fields():
    result = infer("""
from typing import NamedTuple
class Point(NamedTuple):
    x: int
    label: str
p = Point(1, "two")
a, b = p
first = p[0]
last = p[-1]
label = p.label
""")
    assert result.type_of("p").type.full_name == "sample.Point"
    for name in ("a", "first"):
        assert raw_types(result.type_of(name)) == {int}
    for name in ("b", "last", "label"):
        assert raw_types(result.type_of(name)) == {str}


def test_async_generators_and_annotated_async_iterables():
    result = infer("""
from typing import AsyncIterable
async def agen(): yield 42
async def consume():
    async for item in agen(): return item
async def annotated(values: AsyncIterable[str]):
    async for item in values: return item
""")
    assert raw_types(result.functions["sample.consume"].return_type) == {int}
    assert raw_types(result.functions["sample.annotated"].return_type) == {str}


def test_regex_prefix_and_suffix_observations_form_alternatives():
    builder = RegexBuilder()
    builder.handle_startswith("foo", "bar")
    builder.handle_startswith("baz.")
    builder.handle_endswith("end", "done")
    builder.handle_endswith("last")
    pattern = re.compile(builder.build())
    assert all(pattern.fullmatch(value) for value in ("foo-end", "bar-done", "baz.last"))
    assert not pattern.fullmatch("bazXlast")
    assert not pattern.fullmatch("other-end")


def test_string_subtype_annotations_are_registered():
    result = infer("email: EmailString\n")
    assert isinstance(result.type_of("email"), EmailString)
    assert not result.diagnostics
