"""Deterministic, annotation-guided initial input synthesis."""

from __future__ import annotations

import ast
from dataclasses import dataclass
from typing import Any, Callable, Mapping

from .catalog import FunctionTarget, ParameterTarget

InputFactory = Callable[[FunctionTarget, ParameterTarget, int], Any]


@dataclass(frozen=True)
class InputSynthesisResult:
    inputs: tuple[Any, ...] | None
    reasons: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return {
            "inputs": list(self.inputs) if self.inputs is not None else None,
            "reasons": list(self.reasons),
        }


class InputSynthesizer:
    """Generate small inputs with per-parameter override support."""

    def __init__(self, overrides: Mapping[str, InputFactory | Any] | None = None):
        self._overrides = dict(overrides or {})

    def synthesize(self, target: FunctionTarget, complexity: int = 0) -> InputSynthesisResult:
        if complexity < 0:
            raise ValueError("complexity must be non-negative")
        values: list[Any] = []
        reasons: list[str] = []
        for parameter in target.parameters:
            if not parameter.required:
                break
            key = f"{target.identifier}.{parameter.name}"
            override = self._overrides.get(key)
            if override is not None:
                value = override(target, parameter, complexity) if callable(override) else override
            else:
                try:
                    value = _annotation_value(parameter, complexity)
                except ValueError as error:
                    reasons.append(f"{parameter.name}: {error}")
                    continue
            values.append(value)
        if reasons:
            return InputSynthesisResult(None, tuple(reasons))
        return InputSynthesisResult(tuple(values))


def _annotation_value(parameter: ParameterTarget, complexity: int) -> Any:
    annotation = parameter.annotation
    if annotation is None or annotation in {"Any", "typing.Any", "object"}:
        return _tiered_int(complexity)
    try:
        node = ast.parse(annotation, mode="eval").body
    except SyntaxError as error:
        raise ValueError(f"invalid annotation {annotation!r}") from error
    value = _value_for_node(node, complexity)
    if value is _UNSUPPORTED:
        raise ValueError(f"unsupported annotation {annotation!r}")
    return value


_UNSUPPORTED = object()


def _value_for_node(node: ast.expr, complexity: int) -> Any:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        try:
            nested = ast.parse(node.value, mode="eval").body
        except SyntaxError:
            return _UNSUPPORTED
        return _value_for_node(nested, complexity)
    name = _annotation_name(node)
    if name in {"int", "builtins.int"}:
        return _tiered_int(complexity)
    if name in {"float", "builtins.float"}:
        return float(_tiered_int(complexity))
    if name in {"str", "builtins.str"}:
        return ("", "a", "pyflow", "a/b c")[min(complexity, 3)]
    if name in {"bytes", "builtins.bytes"}:
        return (b"", b"a", b"pyflow", b"a/b c")[min(complexity, 3)]
    if name in {"bool", "builtins.bool"}:
        return bool(complexity % 2)
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.BitOr):
        candidates = _flatten_union(node)
        supported = [
            value
            for candidate in candidates
            if (value := _value_for_node(candidate, complexity)) is not _UNSUPPORTED
            and value is not None
        ]
        return supported[complexity % len(supported)] if supported else _UNSUPPORTED
    if isinstance(node, ast.Subscript):
        base = _annotation_name(node.value)
        arguments = _subscript_arguments(node.slice)
        if base in {"Literal", "typing.Literal"}:
            literals = [_literal(argument) for argument in arguments]
            literals = [value for value in literals if value is not _UNSUPPORTED]
            return literals[complexity % len(literals)] if literals else _UNSUPPORTED
        if base in {"Optional", "typing.Optional"} and arguments:
            return None if complexity % 2 == 0 else _value_for_node(arguments[0], complexity)
        if base in {"Union", "typing.Union"}:
            values = [_value_for_node(argument, complexity) for argument in arguments]
            values = [value for value in values if value is not _UNSUPPORTED]
            return values[complexity % len(values)] if values else _UNSUPPORTED
        if base in {"Annotated", "typing.Annotated"} and arguments:
            return _value_for_node(arguments[0], complexity)
        if base in {"list", "typing.List", "Sequence", "typing.Sequence"}:
            element = _value_for_node(arguments[0], max(0, complexity - 1)) if arguments else 0
            if element is _UNSUPPORTED:
                return _UNSUPPORTED
            return [element] * min(complexity, 3)
        if base in {
            "set",
            "typing.Set",
            "frozenset",
            "typing.FrozenSet",
            "AbstractSet",
            "typing.AbstractSet",
        }:
            element = _value_for_node(arguments[0], max(0, complexity - 1)) if arguments else 0
            if element is _UNSUPPORTED:
                return _UNSUPPORTED
            values = set() if complexity == 0 else {element}
            return frozenset(values) if "Frozen" in (base or "") or base == "frozenset" else values
        if base in {"dict", "typing.Dict", "Mapping", "typing.Mapping"}:
            if len(arguments) < 2:
                return {}
            key = _value_for_node(arguments[0], max(0, complexity - 1))
            value = _value_for_node(arguments[1], max(0, complexity - 1))
            if (
                key is _UNSUPPORTED
                or value is _UNSUPPORTED
                or not isinstance(key, (int, str, bool))
            ):
                return _UNSUPPORTED
            return {} if complexity == 0 else {key: value}
        if base in {"tuple", "typing.Tuple"}:
            if not arguments:
                return ()
            if len(arguments) == 2 and _annotation_name(arguments[1]) == "Ellipsis":
                element = _value_for_node(arguments[0], max(0, complexity - 1))
                return (
                    tuple(element for _ in range(min(complexity, 3)))
                    if element is not _UNSUPPORTED
                    else _UNSUPPORTED
                )
            values = tuple(
                _value_for_node(argument, max(0, complexity - 1)) for argument in arguments
            )
            return _UNSUPPORTED if _UNSUPPORTED in values else values
    if name in {"None", "NoneType", "types.NoneType"}:
        return None
    return _UNSUPPORTED


def _tiered_int(complexity: int) -> int:
    return (0, 1, -1, 100)[min(complexity, 3)]


def _annotation_name(node: ast.expr) -> str | None:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        prefix = _annotation_name(node.value)
        return f"{prefix}.{node.attr}" if prefix else node.attr
    if isinstance(node, ast.Constant) and node.value is None:
        return "None"
    if isinstance(node, ast.Constant) and node.value is Ellipsis:
        return "Ellipsis"
    return None


def _flatten_union(node: ast.expr) -> list[ast.expr]:
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.BitOr):
        return [*_flatten_union(node.left), *_flatten_union(node.right)]
    return [node]


def _subscript_arguments(node: ast.expr) -> tuple[ast.expr, ...]:
    return tuple(node.elts) if isinstance(node, ast.Tuple) else (node,)


def _literal(node: ast.expr) -> Any:
    try:
        value = ast.literal_eval(node)
    except (ValueError, TypeError):
        return _UNSUPPORTED
    return value if isinstance(value, (int, float, str, bool)) else _UNSUPPORTED
