"""Regression tests for the second typeinfo audit pass over the top-100 corpus."""

from __future__ import annotations

import tempfile
from pathlib import Path

from pyflow.analysis.typeinfo import (
    InferenceOptions,
    StaticTypeInferenceEngine,
    TypeInfoService,
)
from pyflow.language.modules.project_resolution import ProjectContext


def _infer(source: str, *, strict: bool = False):
    return StaticTypeInferenceEngine(
        options=InferenceOptions(strict_annotations=strict)
    ).infer_source("sample", source)


def _name(typ) -> str:
    return "<null>" if typ is None else str(typ)


def test_asyncio_gather_preserves_positional_result_types() -> None:
    result = _infer(
        """
import asyncio

async def f() -> int:
    return 1

async def g() -> str:
    return "s"

def need(x: int) -> None: ...

async def h() -> None:
    res = await asyncio.gather(f(), g())
    first, second = res
    need(first)
    need(res[0])
""",
        strict=True,
    )

    assert not [d for d in result.diagnostics if d.code == "annotation-mismatch"]
    summary = result.functions["sample.h"]
    assert summary is not None and summary.return_value.is_complete


def test_type_var_binds_from_class_object_callable_argument() -> None:
    result = _infer("""
from typing import Callable, TypeVar

T = TypeVar("T")

def apply(f: Callable[[int], T]) -> T: ...

converted = apply(str)
as_int = apply(int)
""")

    assert _name(result.type_of("converted")) == "str"
    assert _name(result.type_of("as_int")) == "int"


def test_sequence_type_var_binds_from_tuple_argument() -> None:
    result = _infer("""
from typing import Sequence, TypeVar

T = TypeVar("T")

def first(xs: Sequence[T]) -> T: ...

from_tuple = first((1, 2))
from_list = first([1, 2])
""")

    assert _name(result.type_of("from_tuple")) == "int"
    assert _name(result.type_of("from_list")) == "int"


def test_generic_builtin_subclass_substitutes_type_arguments() -> None:
    result = _infer("""
from typing import TypeVar

T = TypeVar("T")

class MyList(list[T]): ...

explicit = MyList[int]()[0]
""")

    assert _name(result.type_of("explicit")) == "int"


def test_service_resolves_forward_references_in_class_body() -> None:
    service = TypeInfoService(ProjectContext(None))
    service.collect_module(
        "sample",
        source=(
            "from __future__ import annotations\n"
            "class Node:\n"
            "    next: Node | None\n"
            "    def link(self, other: Node) -> Node: ...\n"
        ),
    )

    members = service.members_of("sample.Node")
    assert _name(members["next"].typ) == "None | sample.Node"
    signature = service.signature_of("sample", "Node.link")
    assert signature is not None
    assert _name(signature.params["other"]) == "sample.Node"
    assert _name(signature.returns) == "sample.Node"


def test_service_follows_reexported_class_members_and_functions() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        root.joinpath("core.py").write_text(
            "class Thing:\n"
            "    value: int\n"
            "    def get(self) -> int:\n"
            "        return 1\n"
            "\n"
            "def helper(x: int) -> str:\n"
            "    return str(x)\n",
            encoding="utf-8",
        )
        root.joinpath("pkg.py").write_text(
            "from core import Thing, helper\n",
            encoding="utf-8",
        )
        service = TypeInfoService(ProjectContext(root))

        members = service.members_of("pkg.Thing")
        assert set(members) >= {"value", "get"}
        assert _name(members["value"].typ) == "int"

        signature = service.signature_of("pkg", "helper")
        assert signature is not None
        assert _name(signature.returns) == "str"

        method = service.signature_of("pkg", "Thing.get")
        assert method is not None
        assert _name(method.returns) == "int"


def test_functional_typed_dict_honours_not_required() -> None:
    result = _infer("""
from typing import NotRequired, TypedDict

TD = TypedDict("TD", {"k": int, "j": NotRequired[str]})
valid: TD = {"k": 1}
""")

    assert not [d for d in result.diagnostics if d.code == "annotation-mismatch"]


def test_functional_typed_dict_keeps_required_in_total_false() -> None:
    result = _infer("""
from typing import Required, TypedDict

TD = TypedDict("TD", {"k": Required[int], "j": str}, total=False)
missing: TD = {}
""")

    messages = [d.message for d in result.diagnostics if d.code == "annotation-mismatch"]
    assert messages
    assert "missing keys ['k']" in messages[0]


def test_async_exit_stack_is_a_context_manager() -> None:
    result = _infer("""
import contextlib

async def run():
    async with contextlib.AsyncExitStack() as stack:
        return stack
""")

    assert not [d for d in result.diagnostics if d.code == "unmodeled-context-manager"]
    summary = result.functions["sample.run"]
    assert summary is not None
    assert _name(summary.return_type) == "contextlib.AsyncExitStack"


def test_builtin_exception_attributes_are_typed() -> None:
    result = _infer("""
error = ValueError("boom")
arguments = error.args
cause = error.__cause__
os_error = OSError("boom")
number = os_error.errno
path = os_error.filename
""")

    assert _name(result.type_of("arguments")) == "tuple[Any, ...]"
    assert _name(result.type_of("cause")) == "BaseException | None"
    assert _name(result.type_of("number")) == "None | int"
    assert _name(result.type_of("path")) == "None | str"


def test_int_enum_and_str_enum_operator_results() -> None:
    result = _infer("""
import enum

class Level(enum.IntEnum):
    LOW = 1
    HIGH = 2

class Flag(enum.IntFlag):
    READ = 1
    WRITE = 2

class Text(enum.StrEnum):
    WORD = "w"

added = Level.LOW + 1
combined = Flag.READ | Flag.WRITE
joined = Text.WORD + "s"
upper = Text.WORD.upper()
""")

    assert _name(result.type_of("added")) == "int"
    assert _name(result.type_of("combined")) == "int"
    assert _name(result.type_of("joined")) == "str"
    assert _name(result.type_of("upper")) == "str"


def test_builtin_functions_are_first_class_values() -> None:
    result = _infer("""
length = len
size = length([1, 2])
printer = print
printed = printer("x")
""")

    assert _name(result.type_of("size")) == "int"
    assert _name(result.type_of("printed")) == "None"


def test_functools_wraps_decorator_preserves_signature() -> None:
    result = _infer("""
import functools

def deco(fn):
    @functools.wraps(fn)
    def wrapper(*args, **kwargs):
        return fn(*args, **kwargs)
    return wrapper

@deco
def render(count: int) -> str:
    return str(count)

text = render(1)
""")

    assert _name(result.type_of("text")) == "str"
    assert "Callable[[int], str]" in _name(result.type_of("render"))


def test_pathlib_types_use_the_public_module_name() -> None:
    result = _infer("""
import pathlib

root = pathlib.Path("x")
parent = root.parent
pure = pathlib.PurePath("y")
""")

    assert _name(result.type_of("root")) == "pathlib.Path"
    assert _name(result.type_of("parent")) == "pathlib.Path"
    assert _name(result.type_of("pure")) == "pathlib.PurePath"
