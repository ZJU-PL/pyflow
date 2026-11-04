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


def test_explicit_super_class_starts_after_that_class() -> None:
    result = _infer(
        """
class Base:
    def __init__(self, value: int, *, extra: int = 0) -> None: ...

class Middle(Base):
    def __init__(self, value: int) -> None:
        super().__init__(value)

class Child(Middle):
    def __init__(self) -> None:
        super(Middle, self).__init__(1, extra=2)
""",
        strict=True,
    )

    assert not [d for d in result.diagnostics if d.code == "call-arity-mismatch"]


def test_itertools_product_honours_repeat_and_starmap() -> None:
    result = _infer(
        """
import itertools
import string

pairs = list(itertools.product(string.ascii_lowercase, repeat=2))
joined = list(itertools.starmap(lambda a, b: a + b, itertools.product("ab", repeat=2)))
""",
        strict=True,
    )

    assert str(result.type_of("pairs")) == "list[tuple[str, str]]"
    assert str(result.type_of("joined")) == "list[str]"
    assert not [d for d in result.diagnostics if d.code == "call-arity-mismatch"]


def test_unannotated_iter_satisfies_the_iterable_protocol() -> None:
    result = _infer(
        """
from collections.abc import Iterable

class Bag:
    def __iter__(self):
        return iter([1])

def total(values: Iterable[int]) -> int:
    return sum(values)

value = total(Bag())
""",
        strict=True,
    )

    assert not [d for d in result.diagnostics if d.code == "annotation-mismatch"]


def test_singledispatchmethod_dispatches_on_argument_types() -> None:
    result = _infer("""
from functools import singledispatchmethod

class Handler:
    @singledispatchmethod
    def handle(self, value: object) -> int:
        return 0

    @handle.register
    def _(self, value: int) -> str:
        return "int"

    @handle.register
    def _(self, value: str) -> float:
        return 1.0

handler = Handler()
as_int = handler.handle(1)
as_str = handler.handle("s")
as_float = handler.handle(1.5)
""")

    assert str(result.type_of("as_int")) == "str"
    assert str(result.type_of("as_str")) == "float"
    assert str(result.type_of("as_float")) == "int"


def test_executor_context_manager_and_submit_results() -> None:
    result = _infer("""
import concurrent.futures

def work() -> int:
    return 1

with concurrent.futures.ThreadPoolExecutor() as executor:
    future = executor.submit(work)
    outcome = future.result()

standalone = concurrent.futures.ThreadPoolExecutor().submit(work).result()
""")

    assert str(result.type_of("outcome")) == "int"
    assert str(result.type_of("standalone")) == "int"


def test_flag_bitwise_operators_keep_the_enum_class() -> None:
    result = _infer("""
import enum

class Permission(enum.Flag):
    READ = enum.auto()
    WRITE = enum.auto()

class Mask(enum.IntFlag):
    A = 1
    B = 2

combined = Permission.READ | Permission.WRITE
intersection = Permission.READ & Permission.WRITE
masked = Mask.A | Mask.B
arithmetic = Mask.A + 1
""")

    assert str(result.type_of("combined")) == "sample.Permission"
    assert str(result.type_of("intersection")) == "sample.Permission"
    assert str(result.type_of("masked")) == "sample.Mask"
    assert str(result.type_of("arithmetic")) == "int"


def test_functools_partial_of_classes_and_builtins() -> None:
    result = _infer("""
import functools

class Item:
    def __init__(self, name: str, count: int) -> None: ...

make_item = functools.partial(Item, "x")
item = make_item(1)

parse_binary = functools.partial(int, base=2)
number = parse_binary("10")

to_text = functools.partial(str)
text = to_text(1)
""")

    assert str(result.type_of("item")) == "sample.Item"
    assert str(result.type_of("number")) == "int"
    assert str(result.type_of("text")) == "str"


def test_flag_unary_operators() -> None:
    result = _infer("""
import enum

class Flag(enum.Flag):
    A = enum.auto()

class IntFlag(enum.IntFlag):
    X = 1

inverted_flag = ~Flag.A
inverted_int_flag = ~IntFlag.X
negated = -IntFlag.X
positive = +IntFlag.X
""")

    assert str(result.type_of("inverted_flag")) == "sample.Flag"
    assert str(result.type_of("inverted_int_flag")) == "sample.IntFlag"
    assert str(result.type_of("negated")) == "int"
    assert str(result.type_of("positive")) == "int"


def test_weakref_ref_and_proxy_types() -> None:
    result = _infer("""
import weakref

class Item: ...

item = Item()
reference = weakref.ref(item)
dereferenced = reference()
proxy = weakref.proxy(item)
""")

    assert str(result.type_of("reference")) == "weakref.ReferenceType[sample.Item]"
    assert str(result.type_of("dereferenced")) == "None | sample.Item"
    assert str(result.type_of("proxy")) == "sample.Item"


def test_asyncio_as_completed_keeps_the_awaited_type() -> None:
    result = _infer("""
import asyncio

async def work() -> int:
    return 1

async def collect() -> int:
    total = 0
    for future in asyncio.as_completed([work(), work()]):
        total += await future
    return total
""")

    assert str(result.functions["sample.collect"].return_type) == "int"


def test_logging_adapter_methods_and_logger_attribute() -> None:
    result = _infer("""
import logging

logger = logging.getLogger(__name__)
adapter = logging.LoggerAdapter(logger, {})
emitted = adapter.info("hello")
enabled = adapter.isEnabledFor(20)
underlying = adapter.logger
""")

    assert str(result.type_of("emitted")) == "None"
    assert str(result.type_of("enabled")) == "bool"
    assert str(result.type_of("underlying")) == "logging.Logger"


def test_os_stat_result_attributes_are_ints() -> None:
    result = _infer("""
import os

stat = os.stat("x")
size = stat.st_size
modified = stat.st_mtime
""")

    assert str(result.type_of("size")) == "int"
    assert str(result.type_of("modified")) == "int"


def test_zipfile_and_csv_models() -> None:
    result = _infer("""
import csv
import zipfile

with zipfile.ZipFile("x.zip") as archive:
    names = archive.namelist()
    payload = archive.read("a.txt")

with open("x.csv") as handle:
    for row in csv.DictReader(handle):
        value = row["a"]
""")

    assert str(result.type_of("names")) == "list[str]"
    assert str(result.type_of("payload")) == "bytes"
    assert str(result.type_of("value")) == "str"


def test_staticmethod_self_binds_to_the_declaring_class() -> None:
    result = _infer("""
from typing import Self

class Factory:
    @staticmethod
    def make() -> Self: ...

class Child(Factory): ...

direct = Factory.make()
inherited = Child.make()
""")

    assert str(result.type_of("direct")) == "sample.Factory"
    assert str(result.type_of("inherited")) == "sample.Factory"


def test_dataclasses_fields_and_typing_helpers() -> None:
    result = _infer("""
import typing
from dataclasses import dataclass, fields

@dataclass
class Item:
    name: str
    count: int

defined = fields(Item)
first_name = defined[0].name
hints = typing.get_type_hints(Item)
origin = typing.get_origin(list[int])
arguments = typing.get_args(dict[str, int])
""")

    assert str(result.type_of("defined")) == "tuple[dataclasses.Field, ...]"
    assert str(result.type_of("first_name")) == "str"
    assert str(result.type_of("hints")) == "dict[str, Any]"
    assert str(result.type_of("arguments")) == "tuple[Any, ...]"


def test_except_star_handlers_bind_exception_types() -> None:
    result = _infer("""
def handle():
    try:
        raise ValueError("x")
    except* ValueError as error:
        return error
    except* TypeError as error:
        return error
""")

    assert not [d for d in result.diagnostics if d.code == "unsupported-statement"]
    assert str(result.functions["sample.handle"].return_type) == "TypeError | ValueError"


def test_mutually_recursive_functions_are_detected() -> None:
    engine = StaticTypeInferenceEngine()
    result = engine.infer_source(
        "sample",
        """
def first(value):
    return second(value)

def second(value):
    return first(value)
""",
    )

    assert result.converged
    assert engine._is_recursive_function(engine._functions["sample.first"])
    assert engine._is_recursive_function(engine._functions["sample.second"])


def test_nested_mutual_recursion_converges() -> None:
    result = _infer("""
def outer(value):
    def inner_a(item):
        return inner_b(item)

    def inner_b(item):
        return inner_a(item)

    return inner_a(value)
""")

    assert result.converged
    assert result.iterations <= 10


def test_typeddict_update_checks_keys_and_values() -> None:
    valid = _infer(
        """
from typing import TypedDict

class Item(TypedDict):
    name: str
    count: int

item: Item = {"name": "a", "count": 1}
item.update({"count": 2})
item.update(name="b")
""",
        strict=True,
    )
    assert not [d for d in valid.diagnostics if d.code == "annotation-mismatch"]

    invalid = _infer(
        """
from typing import TypedDict

class Item(TypedDict):
    name: str
    count: int

item: Item = {"name": "a", "count": 1}
item.update({"count": "bad"})
item.update(missing=1)
""",
        strict=True,
    )
    messages = [d.message for d in invalid.diagnostics if d.code == "annotation-mismatch"]
    assert any("TypedDict key count" in message for message in messages)
    assert any("unexpected key 'missing'" in message for message in messages)


def test_instance_getattr_is_not_invoked_on_class_objects() -> None:
    result = _infer(
        """
class Dynamic:
    def __getattr__(self, name):
        return self._helper(name)

    def _helper(self, name: str) -> int:
        return 1

value = Dynamic.missing
""",
        strict=True,
    )

    assert not [d for d in result.diagnostics if d.code == "call-arity-mismatch"]


def test_generic_alias_values_are_class_objects() -> None:
    result = _infer(
        """
def register(item_type: type) -> None: ...

item_type = list[int]
register(item_type)
register(list[int])
tuple_type = tuple[int, str]
register(tuple_type)
register(tuple[int, str, bool])
""",
        strict=True,
    )

    assert not [d for d in result.diagnostics if d.code == "annotation-mismatch"]


def test_function_satisfies_callable_protocol() -> None:
    valid = _infer(
        """
from typing import Protocol

class Notify(Protocol):
    def __call__(self, progress: float | None, text: list[str] | None) -> None: ...

def use(callback: Notify) -> None: ...

def handler(progress: float | None, text: list[str] | None) -> None: ...

use(handler)
""",
        strict=True,
    )
    assert not [d for d in valid.diagnostics if d.code == "annotation-mismatch"]

    invalid = _infer(
        """
from typing import Protocol

class Notify(Protocol):
    def __call__(self, progress: float | None) -> None: ...

def use(callback: Notify) -> None: ...

def wrong(progress: str) -> None: ...

use(wrong)
""",
        strict=True,
    )
    assert [d for d in invalid.diagnostics if d.code == "annotation-mismatch"]


def test_numeric_methods_have_result_types() -> None:
    result = _infer("""
bits = (5).bit_length()
payload = (5).to_bytes(2, "big")
integral = (1.5).is_integer()
encoded = (1.5).hex()
ratio = (5).as_integer_ratio()
""")

    assert str(result.type_of("bits")) == "int"
    assert str(result.type_of("payload")) == "bytes"
    assert str(result.type_of("integral")) == "bool"
    assert str(result.type_of("encoded")) == "str"
    assert str(result.type_of("ratio")) == "tuple[int, int]"
