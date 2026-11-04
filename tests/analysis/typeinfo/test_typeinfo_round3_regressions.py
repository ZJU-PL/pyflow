"""Regression tests for the third typeinfo corpus pass."""

from __future__ import annotations

import tempfile
from pathlib import Path

from pyflow.analysis.typeinfo import (
    InferenceOptions,
    ProjectTypeInferenceEngine,
    StaticTypeInferenceEngine,
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
