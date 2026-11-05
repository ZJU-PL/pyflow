"""Variance, protocol, and generic-expansion checks."""

from __future__ import annotations

from pyflow.analysis.typeinfo import StaticTypeInferenceEngine


def _infer(source: str):
    return StaticTypeInferenceEngine().infer_source("m", source)


def test_callable_protocol_and_variance() -> None:
    result = _infer(
        "from typing import Protocol, Callable\n"
        "class Handler(Protocol):\n"
        "    def __call__(self, value: int) -> str: ...\n"
        "class Concrete:\n"
        "    def __call__(self, value: int) -> str:\n"
        "        return ''\n"
        "def accepts(handler: Handler) -> str:\n"
        "    return handler(1)\n"
        "accepts(Concrete())\n"
        "def wants(cb: Callable[[object], int]) -> int:\n"
        "    return cb(1)\n"
        "def broad(value: object) -> int:\n"
        "    return 1\n"
        "wants(broad)\n"
    )

    assert not [item for item in result.diagnostics if item.code == "annotation-mismatch"]


def test_generic_invariance_and_covariant_sequence() -> None:
    result = _infer(
        "from typing import Generic, Sequence, TypeVar\n"
        "T = TypeVar('T')\n"
        "class Box(Generic[T]):\n"
        "    def __init__(self, value: T) -> None:\n"
        "        self.value = value\n"
        "def takes_int(box: Box[int]) -> None: ...\n"
        "takes_int(Box('bad'))\n"
        "def takes_sequence(values: Sequence[object]) -> None: ...\n"
        "takes_sequence([1, 2])\n"
        "takes_sequence(['a'])\n"
    )

    messages = [item.message for item in result.diagnostics if item.code == "annotation-mismatch"]
    assert any("m.Box[str]" in message and "m.Box[int]" in message for message in messages)
    assert len(messages) == 1
