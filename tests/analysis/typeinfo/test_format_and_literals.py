"""Literal narrowing and printf-style format checks."""

from __future__ import annotations

from pyflow.analysis.typeinfo import StaticTypeInferenceEngine


def _infer(source: str):
    return StaticTypeInferenceEngine().infer_source("m", source)


def test_percent_format_checks_conversion_types_and_arity() -> None:
    result = _infer(
        "bad_type = '%d' % 'value'\n"
        "bad_arity = '%d %d' % (1,)\n"
        "good = '%s %d' % ('value', 1)\n"
    )

    messages = [
        item.message for item in result.diagnostics if item.code == "format-string-mismatch"
    ]
    assert any("incompatible with str" in message for message in messages)
    assert any("2 conversion(s) but 1 argument(s)" in message for message in messages)
    assert len(messages) == 2


def test_literal_equality_narrows_to_the_concrete_value() -> None:
    result = _infer(
        "def f(value: str) -> str:\n"
        "    if value == 'ready':\n"
        "        return value\n"
        "    return 'other'\n"
        "def g(value: int | None) -> int:\n"
        "    if value is not None:\n"
        "        return value\n"
        "    return 0\n"
    )

    assert str(result.functions["m.f"].return_type) == "str"
    assert str(result.functions["m.g"].return_type) == "int"
    assert not [item for item in result.diagnostics if item.code == "annotation-mismatch"]
