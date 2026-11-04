"""Regression tests for the third typeinfo corpus pass."""

from __future__ import annotations

import tempfile
from pathlib import Path

from pyflow.analysis.typeinfo import (
    InferenceOptions,
    ProjectTypeInferenceEngine,
    StaticTypeInferenceEngine,
)
from pyflow.analysis.typeinfo.core.typesystem import (
    Instance,
    LiteralType,
    TypeSystem,
    UnionType,
)
from pyflow.language.modules.project_resolution import ProjectContext


def _infer(source: str, *, strict: bool = True):
    return StaticTypeInferenceEngine(
        options=InferenceOptions(strict_annotations=strict)
    ).infer_source("sample", source)


def test_bound_method_with_keyword_only_parameters_keeps_its_arity() -> None:
    result = _infer("""
from typing import Optional

class Sender:
    def _send(self, content: str, *, timeout_seconds: Optional[float] = None) -> bool:
        return True

    def _chunks(
        self,
        chunks: list[str],
        send_once,
        *,
        timeout_seconds: Optional[float] = None,
    ) -> bool:
        ok = False
        for chunk in chunks:
            if send_once(chunk, timeout_seconds=timeout_seconds):
                ok = True
        return ok

    def go(self) -> bool:
        return self._chunks(["a"], self._send)
""")

    assert not [d for d in result.diagnostics if d.code == "call-arity-mismatch"]


def test_bound_method_with_keyword_only_parameters_stays_callable() -> None:
    result = _infer("""
class Sender:
    def _send(self, content: str, *, retries: int = 1) -> bool:
        return True

    def go(self) -> bool:
        callback = self._send
        return callback("payload")
""")

    assert not [d for d in result.diagnostics if d.code == "call-arity-mismatch"]
    summary = result.functions["sample.Sender.go"]
    assert summary is not None
    assert str(summary.return_type) == "bool"


def test_generic_properties_substitute_the_receiver_type() -> None:
    result = _infer("""
from functools import cached_property
from typing import Generic, TypeVar

T = TypeVar("T")

class Box(Generic[T]):
    def __init__(self, value: T) -> None:
        self.value = value

    @property
    def item(self) -> T:
        return self.value

    @cached_property
    def cached_item(self) -> T:
        return self.value

def read_number() -> int:
    return Box(1).item

def read_text() -> str:
    return Box("s").cached_item
""")

    assert str(result.functions["sample.read_number"].return_type) == "int"
    assert str(result.functions["sample.read_text"].return_type) == "str"


def test_generic_property_access_uses_instance_arguments() -> None:
    result = _infer("""
from typing import Generic, TypeVar

T = TypeVar("T")

class Box(Generic[T]):
    def __init__(self, value: T) -> None:
        self.value = value

    @property
    def item(self) -> T:
        return self.value

def read(box: Box[int]) -> int:
    return box.item

def read_text(box: Box[str]) -> str:
    return box.item
""")

    assert str(result.functions["sample.read"].return_type) == "int"
    assert str(result.functions["sample.read_text"].return_type) == "str"


def test_asyncio_task_group_returns_task_types() -> None:
    result = _infer("""
import asyncio

async def work() -> int:
    return 1

async def main():
    async with asyncio.TaskGroup() as group:
        task = group.create_task(work())
    return await task
""")

    assert not [d for d in result.diagnostics if d.code == "unmodeled-context-manager"]
    assert str(result.functions["sample.main"].return_type) == "int"


def test_reexported_typing_names_resolve_as_typing_constructs() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        root.joinpath("types_mod.py").write_text(
            "from typing import Union, List, Iterable, Pattern\n",
            encoding="utf-8",
        )
        root.joinpath("app.py").write_text(
            "from types_mod import Union, List, Iterable, Pattern\n"
            "\n"
            "def pick(flag: bool) -> Union[int, str]:\n"
            "    return 1 if flag else 's'\n"
            "\n"
            "def items() -> List[int]:\n"
            "    return [1]\n"
            "\n"
            "def count(xs: Iterable[int]) -> int:\n"
            "    return 0\n"
            "\n"
            "def match(pattern: Pattern) -> None: ...\n",
            encoding="utf-8",
        )
        result = ProjectTypeInferenceEngine(
            ProjectContext(root, added_sys_path=[str(root)]),
            options=InferenceOptions(strict_annotations=True),
        ).infer_project(["app"])
        module = result.modules["app"]

        assert str(module.functions["app.pick"].return_type) == "int | str"
        assert str(module.functions["app.items"].return_type) == "list[int]"
        assert not [d for d in module.diagnostics if d.code == "unresolved-annotation"]


def test_reexported_overload_decorator_selects_the_right_overload() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        root.joinpath("types_mod.py").write_text(
            "from typing import Literal, Union, overload\n",
            encoding="utf-8",
        )
        root.joinpath("app.py").write_text(
            "from types_mod import Literal, Union, overload\n"
            "\n"
            "class Text:\n"
            "    @overload\n"
            "    def re(self, value: str, *, check: Literal[True]) -> bool: ...\n"
            "    @overload\n"
            "    def re(self, value: str, check: Literal[False] = False) -> int: ...\n"
            "    def re(self, value: str, check: bool = False) -> Union[int, bool]:\n"
            "        return True if check else 1\n"
            "\n"
            "class Selector:\n"
            "    def text(self) -> Text:\n"
            "        return Text()\n"
            "\n"
            "    def matches(self) -> int:\n"
            "        return self.text().re('x')\n",
            encoding="utf-8",
        )
        result = ProjectTypeInferenceEngine(
            ProjectContext(root, added_sys_path=[str(root)]),
            options=InferenceOptions(strict_annotations=True),
        ).infer_project(["app"])
        module = result.modules["app"]

        assert str(module.functions["app.Selector.matches"].return_type) == "int"
        assert not [d for d in module.diagnostics if d.code == "annotation-mismatch"]


def test_generic_context_managers_substitute_the_yield_type() -> None:
    result = _infer("""
import contextlib
from typing import AsyncIterator, Iterator, TypeVar

T = TypeVar("T")

@contextlib.contextmanager
def managed(value: T) -> Iterator[T]:
    yield value

@contextlib.asynccontextmanager
async def async_managed(value: T) -> AsyncIterator[T]:
    yield value

def read_number() -> int:
    with managed(1) as value:
        return value

def read_text() -> str:
    with managed("s") as value:
        return value

async def read_async() -> int:
    async with async_managed(1) as value:
        return value
""")

    assert str(result.functions["sample.read_number"].return_type) == "int"
    assert str(result.functions["sample.read_text"].return_type) == "str"
    assert str(result.functions["sample.read_async"].return_type) == "int"


def test_self_properties_use_the_receiver_type() -> None:
    result = _infer("""
from typing import Self

class Base:
    @property
    def clone(self) -> Self: ...

class Child(Base): ...

def read(child: Child) -> Child:
    return child.clone
""")

    assert str(result.functions["sample.read"].return_type) == "sample.Child"


def test_generic_iterables_substitute_the_element_type() -> None:
    result = _infer("""
from typing import Generic, Iterator, TypeVar

T = TypeVar("T")

class Bag(Generic[T]):
    def __init__(self, items: list[T]) -> None:
        self.items = items

    def __iter__(self) -> Iterator[T]:
        return iter(self.items)

def read() -> list[int]:
    return list(Bag([1, 2]))

def total() -> int:
    return sum(Bag([1, 2]))
""")

    assert str(result.functions["sample.read"].return_type) == "list[int]"
    assert str(result.functions["sample.total"].return_type) == "int"


def test_asyncio_timeout_is_a_context_manager() -> None:
    result = _infer("""
import asyncio

async def run() -> int:
    async with asyncio.timeout(1) as timeout:
        return 1
""")

    assert not [d for d in result.diagnostics if d.code == "unmodeled-context-manager"]
    assert str(result.functions["sample.run"].return_type) == "int"


def test_assert_never_terminates_the_branch() -> None:
    result = _infer("""
from typing import Literal, assert_never

def choose(value: Literal[1, 2]) -> int:
    if value == 1:
        return 1
    elif value == 2:
        return 2
    else:
        assert_never(value)
""")

    assert not [d for d in result.diagnostics if d.code == "annotation-mismatch"]
    assert str(result.functions["sample.choose"].return_type) == "int"


def test_protocol_self_member_accepts_the_implementing_type() -> None:
    result = _infer("""
from typing import Protocol, Self

class Cloneable(Protocol):
    def clone(self) -> Self: ...

class Item:
    def clone(self) -> "Item":
        return self

class Wrong:
    def clone(self) -> int:
        return 1

def use(value: Cloneable) -> Cloneable:
    return value.clone()

good = use(Item())
bad = use(Wrong())
""")

    messages = [d.message for d in result.diagnostics if d.code == "annotation-mismatch"]
    assert len(messages) == 1
    assert "Wrong" in messages[0]


def test_super_in_namedtuple_subclass_does_not_crash() -> None:
    result = _infer("""
from collections import namedtuple

Requirement = namedtuple("Requirement", "name version")

class RoleRequirement(Requirement):
    def __init__(self, *args, **kwargs):
        super(RoleRequirement, self).__init__()

requirement = RoleRequirement("a", "1.0")
""")

    assert str(result.type_of("requirement")) == "sample.RoleRequirement"


def test_recursive_function_reaches_a_fixed_point() -> None:
    result = _infer("""
from typing import Any

def hash_params(params: Any):
    if isinstance(params, dict):
        try:
            return frozenset(params.items())
        except TypeError:
            return frozenset(hash_params(value) for value in params.values())
    return frozenset((params,))
""")

    assert result.converged
    assert result.iterations <= 10


def test_protocol_instances_are_reflexive() -> None:
    engine = StaticTypeInferenceEngine()
    result = engine.infer_source(
        "sample",
        """
from typing import Optional, Protocol

class Provider(Protocol):
    def handle(self, value: int) -> "Provider": ...

current: Optional[Provider] = None
""",
    )

    provider = result.type_of("current")
    assert provider is not None
    assert engine.type_system.is_subtype(provider, provider)


def test_literal_member_is_a_subtype_of_its_literal_union() -> None:
    system = TypeSystem()
    string = Instance(system.to_class_descriptor(str))
    user = LiteralType("user", string)
    assistant = LiteralType("assistant", string)

    assert system.is_subtype(user, UnionType((user, assistant)))
    assert system.is_subtype(
        UnionType((user, assistant)),
        UnionType((LiteralType("user", string), LiteralType("assistant", string))),
    )


def test_typeddict_with_literal_union_is_a_subtype_of_itself() -> None:
    result = _infer(
        """
from typing import Literal, TypedDict

class Message(TypedDict):
    role: Literal["user", "assistant", "system", "tool"]
    content: str

message: Message = {"role": "user", "content": "hi"}
""",
        strict=True,
    )

    assert not [d for d in result.diagnostics if d.code == "annotation-mismatch"]
