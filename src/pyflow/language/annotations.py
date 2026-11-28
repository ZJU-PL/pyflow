"""Shared AST type-annotation syntax parser and normalized descriptors.

Provides a lightweight, IR-independent, ``TypeSystem``-independent parser for
Python PEP 484 / 563 / 585 / 604 / 646 type annotation expressions.  Consumed
by ``callgraph``, ``frontend``, and ``typeinfo`` helpers so annotation wrapper
unwrapping, string forward references, ``Optional``/``Union``/``|`` splitting,
``type[T]`` recognition, and ``Literal`` extraction behave consistently.
"""

from __future__ import annotations

import ast
from collections.abc import Iterator, Mapping
from dataclasses import dataclass
from functools import lru_cache
from typing import Union

_WRAPPER_FORMS = frozenset(
    {
        "Annotated",
        "ClassVar",
        "Final",
        "InitVar",
        "NotRequired",
        "ReadOnly",
        "Required",
    }
)

_TYPING_PREFIXES = (
    "typing.",
    "typing_extensions.",
    "collections.abc.",
    "dataclasses.",
    "builtins.",
)

_MAX_PARSE_DEPTH = 24


@dataclass(frozen=True, slots=True)
class NameAnnotation:
    name: str


@dataclass(frozen=True, slots=True)
class NoneAnnotation:
    pass


@dataclass(frozen=True, slots=True)
class EllipsisAnnotation:
    pass


@dataclass(frozen=True, slots=True)
class UnionAnnotation:
    items: tuple["AnnotationExpr", ...]


@dataclass(frozen=True, slots=True)
class GenericAnnotation:
    base: str
    args: tuple["AnnotationExpr", ...]


@dataclass(frozen=True, slots=True)
class CallableAnnotation:
    params: tuple["AnnotationExpr", ...] | None
    returns: "AnnotationExpr"


@dataclass(frozen=True, slots=True)
class TypeObjectAnnotation:
    inner: "AnnotationExpr | None" = None


@dataclass(frozen=True, slots=True)
class LiteralAnnotation:
    values: tuple[object, ...]


@dataclass(frozen=True, slots=True)
class WrappedAnnotation:
    wrapper: str
    inner: "AnnotationExpr"
    metadata: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class UnpackedAnnotation:
    inner: "AnnotationExpr"


@dataclass(frozen=True, slots=True)
class UnknownAnnotation:
    raw: str


AnnotationExpr = Union[
    NameAnnotation,
    NoneAnnotation,
    EllipsisAnnotation,
    UnionAnnotation,
    GenericAnnotation,
    CallableAnnotation,
    TypeObjectAnnotation,
    LiteralAnnotation,
    WrappedAnnotation,
    UnpackedAnnotation,
    UnknownAnnotation,
]

_NONE_ANNOTATION = NoneAnnotation()
_ELLIPSIS_ANNOTATION = EllipsisAnnotation()


def _dotted_name(expr: ast.AST) -> str | None:
    if isinstance(expr, ast.Name):
        return expr.id
    if isinstance(expr, ast.Attribute):
        base = _dotted_name(expr.value)
        if base:
            return f"{base}.{expr.attr}"
    return None


def _qualify_name(name: str, aliases: Mapping[str, str] | None) -> str:
    if not aliases:
        return name
    head, sep, tail = name.partition(".")
    mapped = aliases.get(head)
    if not mapped:
        return name
    return f"{mapped}{sep}{tail}" if sep else mapped


def _canonical_special_form(name: str) -> str:
    for prefix in _TYPING_PREFIXES:
        if name.startswith(prefix):
            return name[len(prefix) :]
    return name


def _slice_items(node: ast.AST) -> list[ast.AST]:
    if isinstance(node, ast.Tuple):
        return list(node.elts)
    return [node]


def _flatten_union(items: list[AnnotationExpr]) -> AnnotationExpr:
    flattened: list[AnnotationExpr] = []
    seen: set[AnnotationExpr] = set()
    for item in items:
        subitems = item.items if isinstance(item, UnionAnnotation) else (item,)
        for sub in subitems:
            if sub not in seen:
                seen.add(sub)
                flattened.append(sub)
    if not flattened:
        return UnknownAnnotation("")
    if len(flattened) == 1:
        return flattened[0]
    return UnionAnnotation(tuple(flattened))


def _extract_literal_constant(node: ast.AST) -> tuple[bool, object]:
    if isinstance(node, ast.Constant):
        return True, node.value
    if (
        isinstance(node, ast.UnaryOp)
        and isinstance(node.op, ast.USub)
        and isinstance(node.operand, ast.Constant)
        and isinstance(node.operand.value, (int, float))
        and not isinstance(node.operand.value, bool)
    ):
        return True, -node.operand.value
    if isinstance(node, ast.Name) and node.id == "None":
        return True, None
    return False, None


@lru_cache(maxsize=2048)
def _parse_eval_expression(text: str) -> ast.expr | None:
    try:
        parsed = ast.parse(text.strip(), mode="eval")
    except SyntaxError:
        return None
    return parsed.body


def parse_annotation_ast(
    expr: ast.AST | None,
    *,
    aliases: Mapping[str, str] | None = None,
    _depth: int = 0,
) -> AnnotationExpr | None:
    """Parse a Python AST type annotation expression into a normalized tree."""
    if expr is None or _depth > _MAX_PARSE_DEPTH:
        return None

    if isinstance(expr, ast.Constant):
        if expr.value is None:
            return _NONE_ANNOTATION
        if expr.value is Ellipsis:
            return _ELLIPSIS_ANNOTATION
        if isinstance(expr.value, str):
            text = expr.value.strip()
            if not text:
                return None
            parsed = _parse_eval_expression(text)
            if parsed is None:
                return UnknownAnnotation(text)
            return parse_annotation_ast(parsed, aliases=aliases, _depth=_depth + 1)
        return LiteralAnnotation((expr.value,))

    if isinstance(expr, ast.BinOp) and isinstance(expr.op, ast.BitOr):
        left = parse_annotation_ast(expr.left, aliases=aliases, _depth=_depth + 1)
        right = parse_annotation_ast(expr.right, aliases=aliases, _depth=_depth + 1)
        items = [item for item in (left, right) if item is not None]
        return _flatten_union(items) if items else None

    if isinstance(expr, ast.Starred):
        inner = parse_annotation_ast(expr.value, aliases=aliases, _depth=_depth + 1)
        return UnpackedAnnotation(inner) if inner is not None else None

    if isinstance(expr, (ast.Name, ast.Attribute)):
        raw_name = _dotted_name(expr)
        if not raw_name:
            return UnknownAnnotation(ast.unparse(expr))
        if raw_name == "None":
            return _NONE_ANNOTATION
        qualified = _qualify_name(raw_name, aliases)
        short = _canonical_special_form(qualified)
        if short in {"type", "Type"} and qualified in {
            "type",
            "builtins.type",
            "Type",
            "typing.Type",
            "typing_extensions.Type",
        }:
            return TypeObjectAnnotation(None)
        return NameAnnotation(qualified)

    if isinstance(expr, ast.Subscript):
        raw_base = _dotted_name(expr.value)
        if not raw_base:
            return UnknownAnnotation(ast.unparse(expr))
        qualified_base = _qualify_name(raw_base, aliases)
        short_base = _canonical_special_form(qualified_base)
        raw_args = _slice_items(expr.slice)

        if short_base == "Optional":
            parsed_args = [
                arg
                for item in raw_args
                if (arg := parse_annotation_ast(item, aliases=aliases, _depth=_depth + 1))
                is not None
            ]
            parsed_args.append(_NONE_ANNOTATION)
            return _flatten_union(parsed_args)

        if short_base == "Union":
            parsed_args = [
                arg
                for item in raw_args
                if (arg := parse_annotation_ast(item, aliases=aliases, _depth=_depth + 1))
                is not None
            ]
            return _flatten_union(parsed_args) if parsed_args else None

        if short_base in {"Type", "type"}:
            inner = (
                parse_annotation_ast(raw_args[0], aliases=aliases, _depth=_depth + 1)
                if raw_args
                else None
            )
            return TypeObjectAnnotation(inner)

        if short_base == "Literal":
            values: list[object] = []
            for item in raw_args:
                ok, value = _extract_literal_constant(item)
                if ok:
                    values.append(value)
                else:
                    # Nested Literal[...] or Enum member name fallback
                    nested = parse_annotation_ast(item, aliases=aliases, _depth=_depth + 1)
                    if isinstance(nested, LiteralAnnotation):
                        values.extend(nested.values)
            return LiteralAnnotation(tuple(values))

        if short_base in _WRAPPER_FORMS and raw_args:
            inner = parse_annotation_ast(raw_args[0], aliases=aliases, _depth=_depth + 1)
            if inner is None:
                return None
            metadata = tuple(ast.unparse(meta) for meta in raw_args[1:])
            return WrappedAnnotation(short_base, inner, metadata)

        if short_base == "Unpack" and raw_args:
            inner = parse_annotation_ast(raw_args[0], aliases=aliases, _depth=_depth + 1)
            return UnpackedAnnotation(inner) if inner is not None else None

        if short_base == "Callable" and len(raw_args) == 2:
            params_node, return_node = raw_args
            returns = parse_annotation_ast(return_node, aliases=aliases, _depth=_depth + 1)
            if returns is None:
                returns = UnknownAnnotation(ast.unparse(return_node))
            if isinstance(params_node, ast.Constant) and params_node.value is Ellipsis:
                return CallableAnnotation(None, returns)
            if isinstance(params_node, ast.List):
                params = tuple(
                    arg
                    for elt in params_node.elts
                    if (arg := parse_annotation_ast(elt, aliases=aliases, _depth=_depth + 1))
                    is not None
                )
                return CallableAnnotation(params, returns)
            return CallableAnnotation(None, returns)

        generic_args = tuple(
            arg
            for item in raw_args
            if (arg := parse_annotation_ast(item, aliases=aliases, _depth=_depth + 1)) is not None
        )
        return GenericAnnotation(qualified_base, generic_args)

    if isinstance(expr, ast.Tuple):
        items = [
            arg
            for elt in expr.elts
            if (arg := parse_annotation_ast(elt, aliases=aliases, _depth=_depth + 1)) is not None
        ]
        return _flatten_union(items) if items else None

    try:
        return UnknownAnnotation(ast.unparse(expr))
    except Exception:
        return UnknownAnnotation("")


def parse_annotation_str(
    text: str | None,
    *,
    aliases: Mapping[str, str] | None = None,
) -> AnnotationExpr | None:
    """Parse a string type annotation into a normalized :class:`AnnotationExpr`."""
    if not text or not text.strip():
        return None
    parsed = _parse_eval_expression(text)
    if parsed is None:
        return UnknownAnnotation(text.strip())
    return parse_annotation_ast(parsed, aliases=aliases)


def unwrap_annotation_wrappers(ann: AnnotationExpr) -> AnnotationExpr:
    """Strip ``Annotated``/``Final``/``ClassVar``/``Required``/... wrappers."""
    current = ann
    while isinstance(current, WrappedAnnotation):
        current = current.inner
    return current


def is_optional_annotation(ann: AnnotationExpr | None) -> bool:
    """Return whether *ann* explicitly allows ``None``."""
    if ann is None:
        return False
    current = unwrap_annotation_wrappers(ann)
    if isinstance(current, NoneAnnotation):
        return True
    if isinstance(current, UnionAnnotation):
        return any(is_optional_annotation(item) for item in current.items)
    if isinstance(current, LiteralAnnotation):
        return any(val is None for val in current.values)
    return False


def is_type_object_annotation(ann: AnnotationExpr | None) -> bool:
    """Return whether *ann* denotes a class object (e.g. ``type[T]`` or ``type[T] | None``)."""
    if ann is None:
        return False
    current = unwrap_annotation_wrappers(ann)
    if isinstance(current, TypeObjectAnnotation):
        return True
    if isinstance(current, UnionAnnotation):
        non_none = [
            unwrap_annotation_wrappers(item)
            for item in current.items
            if not isinstance(unwrap_annotation_wrappers(item), NoneAnnotation)
        ]
        return bool(non_none) and all(isinstance(item, TypeObjectAnnotation) for item in non_none)
    return False


def iter_referenced_type_names(
    ann: AnnotationExpr | None,
    *,
    include_generic_args: bool = True,
) -> Iterator[str]:
    """Yield every named type referenced by *ann* in stable traversal order."""
    if ann is None:
        return
    current = unwrap_annotation_wrappers(ann)
    if isinstance(current, NameAnnotation):
        yield current.name
    elif isinstance(current, UnionAnnotation):
        for item in current.items:
            yield from iter_referenced_type_names(item, include_generic_args=include_generic_args)
    elif isinstance(current, TypeObjectAnnotation):
        if current.inner is not None:
            yield from iter_referenced_type_names(
                current.inner, include_generic_args=include_generic_args
            )
    elif isinstance(current, GenericAnnotation):
        yield current.base
        if include_generic_args:
            for arg in current.args:
                yield from iter_referenced_type_names(
                    arg, include_generic_args=include_generic_args
                )
    elif isinstance(current, CallableAnnotation):
        if include_generic_args:
            if current.params is not None:
                for param in current.params:
                    yield from iter_referenced_type_names(
                        param, include_generic_args=include_generic_args
                    )
            yield from iter_referenced_type_names(
                current.returns, include_generic_args=include_generic_args
            )
    elif isinstance(current, UnpackedAnnotation):
        yield from iter_referenced_type_names(
            current.inner, include_generic_args=include_generic_args
        )


def extract_element_annotations(ann: AnnotationExpr | None) -> tuple[AnnotationExpr, ...]:
    """Return element/value type argument annotations for subscripted containers."""
    if ann is None:
        return ()
    current = unwrap_annotation_wrappers(ann)
    if isinstance(current, GenericAnnotation):
        return tuple(arg for arg in current.args if not isinstance(arg, EllipsisAnnotation))
    if isinstance(current, UnionAnnotation):
        collected: list[AnnotationExpr] = []
        for item in current.items:
            collected.extend(extract_element_annotations(item))
        return tuple(collected)
    return ()


def extract_literal_values(ann: AnnotationExpr | None) -> tuple[object, ...]:
    """Return literal values embedded in a ``Literal[...]`` (or union of literals)."""
    if ann is None:
        return ()
    current = unwrap_annotation_wrappers(ann)
    if isinstance(current, LiteralAnnotation):
        return current.values
    if isinstance(current, UnionAnnotation):
        out: list[object] = []
        for item in current.items:
            out.extend(extract_literal_values(item))
        return tuple(out)
    return ()


__all__ = [
    "AnnotationExpr",
    "CallableAnnotation",
    "EllipsisAnnotation",
    "GenericAnnotation",
    "LiteralAnnotation",
    "NameAnnotation",
    "NoneAnnotation",
    "TypeObjectAnnotation",
    "UnionAnnotation",
    "UnknownAnnotation",
    "UnpackedAnnotation",
    "WrappedAnnotation",
    "extract_element_annotations",
    "extract_literal_values",
    "is_optional_annotation",
    "is_type_object_annotation",
    "iter_referenced_type_names",
    "parse_annotation_ast",
    "parse_annotation_str",
    "unwrap_annotation_wrappers",
]
