"""Shared conversion, exception, and input helpers."""

from __future__ import annotations

import ast
from typing import Any, Iterable

from .runtime import _TargetException


def _concrete(value: Any) -> Any:
    return value.concrete if value is not None and hasattr(value, "concrete") else value


def _unique_values(values: Iterable[Any]) -> list[Any]:
    result: list[Any] = []
    seen: set[Any] = set()
    for value in values:
        concrete = _concrete(value)
        if concrete not in seen:
            seen.add(concrete)
            result.append(value)
    return result


def _exception_name(error: Exception) -> str:
    if isinstance(error, _TargetException):
        return error.name
    if isinstance(error, IndexError):
        return "IndexError"
    if isinstance(error, KeyError):
        return "KeyError"
    if isinstance(error, ValueError):
        return "ValueError"
    message = str(error)
    if "division by zero" in message:
        return "ZeroDivisionError"
    if "invalid literal for int" in message:
        return "ValueError"
    return "RuntimeError"


def _handler_matches(node: ast.expr | None, error_name: str) -> bool:
    if node is None:
        return True
    if isinstance(node, ast.Name):
        if node.id == "BaseException":
            return True
        if node.id == "Exception":
            return error_name not in {
                "CancelledError",
                "GeneratorExit",
                "KeyboardInterrupt",
                "SystemExit",
            }
        return node.id == error_name
    if isinstance(node, ast.Attribute):
        return node.attr == error_name
    if isinstance(node, ast.Tuple):
        return any(_handler_matches(element, error_name) for element in node.elts)
    return False


def _valid_input(value: Any) -> bool:
    return isinstance(value, (int, float, str, bool)) or (
        isinstance(value, list) and all(_valid_input(item) for item in value)
    ) or (
        isinstance(value, dict)
        and all(
            isinstance(key, (int, str, bool)) and _valid_input(item)
            for key, item in value.items()
        )
    )


def _input_key(value: Any) -> Any:
    if isinstance(value, list):
        return tuple(_input_key(item) for item in value)
    if isinstance(value, tuple):
        return tuple(_input_key(item) for item in value)
    if isinstance(value, dict):
        return tuple(
            sorted((key, _input_key(item)) for key, item in value.items())
        )
    return value
