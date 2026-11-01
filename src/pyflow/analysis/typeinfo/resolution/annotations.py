"""Resolve PEP 484 type annotations into PyFlow :class:`ProperType` objects.

Handles the full range of ``typing`` module constructs:

* Simple types: ``int``, ``str``, ``MyClass``
* Generic aliases: ``List[int]``, ``Dict[str, int]``
* Special forms: ``Optional[T]``, ``Union[X, Y]``, ``Callable[[A], R]``
* Tuples: ``Tuple[T, ...]`` (variable), ``Tuple[X, Y]`` (fixed)
* Type variables: ``T``, ``T = TypeVar('T', bound=...)``
* Forward references: ``"MyClass"`` (string annotations)
* Wrapper forms: ``ClassVar[T]``, ``Final[T]``, ``Annotated[T, ...]``

The special-form resolution logic is adapted from Jedi's
``jedi.inference.gradual.typing`` (https://github.com/davidhalter/jedi).

SPDX-FileCopyrightText: 2025 David Halter and contributors
SPDX-FileCopyrightText: 2026 PyFlow Contributors
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import ast
import builtins
import collections
import contextvars
import datetime
import functools
import io
import itertools
import os
import pathlib
import re
import types
import uuid
from typing import TYPE_CHECKING, Protocol, Mapping

from pyflow.analysis.typeinfo.resolution.typing_syntax import (
    IGNORE_ANNOTATION_PARTS,
    resolve_type_alias,
)

# Resolve a fixed set of annotation namespaces without importing analysed code.
_STDLIB_TYPES = {
    module.__name__: module
    for module in (
        collections,
        contextvars,
        datetime,
        functools,
        io,
        itertools,
        os,
        pathlib,
        re,
        types,
        uuid,
    )
}

_COMMON_STDLIB_TYPES = {
    "Path": "pathlib.Path",
    "PurePath": "pathlib.PurePath",
    "Pattern": "re.Pattern",
    "Match": "re.Match",
    "UUID": "uuid.UUID",
    "datetime": "datetime.datetime",
    "date": "datetime.date",
    "time": "datetime.time",
    "timedelta": "datetime.timedelta",
    "ContextVar": "contextvars.ContextVar",
}

if TYPE_CHECKING:
    from pyflow.analysis.typeinfo.core.typesystem import ProperType


# ---------------------------------------------------------------------------
# Type lookup protocol
# ---------------------------------------------------------------------------


class TypeLookup(Protocol):
    """Protocol for resolving qualified type names to :class:`ProperType` objects.

    Implementations should return ``None`` for unknown names.
    """

    def __call__(self, qualified_name: str) -> ProperType | None: ...


class _AliasedTypeLookup:
    def __init__(self, lookup, aliases, type_parameters=None):
        self.lookup = lookup
        self.type_parameters = type_parameters or {}
        self.aliases = {name: target for name, target in aliases.items()}

    def qualify(self, name):
        head, separator, tail = name.partition(".")
        target = self.aliases.get(head, head)
        if name == target or name.startswith(f"{target}."):
            return name
        return target + (separator + tail if separator else "")

    def __call__(self, name):
        return self.lookup(self.qualify(name))


class BuiltinTypeLookup:
    """Resolve built-in type names, optionally delegating unknown names."""

    def __init__(self, fallback: TypeLookup | None = None) -> None:
        self._fallback = fallback

    def __call__(self, qualified_name: str) -> ProperType | None:
        from pyflow.analysis.typeinfo.core.typesystem import (
            ANY,
            NEVER,
            NONE_TYPE,
            Instance,
            TupleType,
            ClassDescriptor,
        )

        if qualified_name in {"Any", "typing.Any"}:
            return ANY
        from pyflow.analysis.typeinfo.core import typesystem

        if "." not in qualified_name or qualified_name.startswith("pyflow.analysis.typeinfo."):
            subtype = getattr(typesystem, qualified_name.rsplit(".", 1)[-1], None)
            if (
                isinstance(subtype, type)
                and issubclass(subtype, typesystem.StringSubtype)
                and subtype is not typesystem.StringSubtype
            ):
                return subtype()
        if qualified_name in {"None", "NoneType", "types.NoneType"}:
            return NONE_TYPE
        if qualified_name in {
            "Never",
            "NoReturn",
            "typing.Never",
            "typing.NoReturn",
            "typing_extensions.Never",
            "typing_extensions.NoReturn",
        }:
            return NEVER
        if qualified_name in {
            "tuple",
            "builtins.tuple",
            "typing.Tuple",
            "typing_extensions.Tuple",
        }:
            return TupleType((ANY,), unknown_size=True)
        if qualified_name.startswith(("typing.", "typing_extensions.", "collections.abc.")):
            import typing
            import collections.abc

            name = qualified_name.rsplit(".", 1)[-1]
            alias = (
                getattr(collections.abc, name, None)
                if qualified_name.startswith("collections.abc.")
                else getattr(typing, name, None)
            )
            origin = typing.get_origin(alias) or alias
            if isinstance(origin, type):
                descriptor = ClassDescriptor(origin)
                arity = descriptor.num_hardcoded_generic_parameters
                return Instance(descriptor, () if arity is None else (ANY,) * arity)
        if qualified_name.startswith("builtins."):
            qualified_name = qualified_name.rsplit(".", 1)[-1]
        qualified_name = _COMMON_STDLIB_TYPES.get(qualified_name, qualified_name)
        module, separator, member = qualified_name.rpartition(".")
        if separator and module in _STDLIB_TYPES:
            raw = getattr(_STDLIB_TYPES[module], member, None)
            if isinstance(raw, type):
                descriptor = ClassDescriptor(raw)
                arity = descriptor.num_hardcoded_generic_parameters
                return Instance(descriptor, () if arity is None else (ANY,) * arity)
        raw = getattr(builtins, qualified_name, None)
        if isinstance(raw, type):
            descriptor = ClassDescriptor(raw)
            arity = descriptor.num_hardcoded_generic_parameters
            return Instance(descriptor, () if arity is None else (ANY,) * arity)
        if self._fallback is not None:
            return self._fallback(qualified_name)
        return None


# ---------------------------------------------------------------------------
# Forward-reference resolution
# ---------------------------------------------------------------------------


def resolve_forward_reference(
    ref: str,
    lookup: TypeLookup,
) -> ProperType | None:
    """Parse and resolve a forward-reference (string) annotation.

    Forward references appear in type annotations as string literals,
    e.g. ``foo: "MyClass"`` or ``def foo() -> "int"``.

    Args:
        ref: The string annotation to resolve.
        lookup: A callable that maps qualified names to ``ProperType``.

    Returns:
        The resolved type, or ``None`` if the string cannot be parsed
        or the name cannot be resolved.
    """
    try:
        tree = ast.parse(ref.strip(), mode="eval")
    except SyntaxError:
        return None
    return _resolve_expr(tree.body, lookup)


# ---------------------------------------------------------------------------
# Main annotation resolution
# ---------------------------------------------------------------------------


def resolve_annotation(
    annotation: str,
    lookup: TypeLookup,
    *,
    aliases: Mapping[str, str] | None = None,
    type_parameters: Mapping[str, tuple[str, ...]] | None = None,
) -> ProperType | None:
    """Resolve a PEP 484 type annotation string to a :class:`ProperType`.

    Parses the annotation as a Python expression and resolves all names
    via *lookup*.  Handles all ``typing`` special forms (``Optional``,
    ``Union``, ``Callable``, ``Tuple``, ``List``, etc.), generic
    subscriptions, and forward references.

    Args:
        annotation: A type annotation string (e.g. ``"Optional[List[int]]"``).
        lookup: A callable that maps qualified names to ``ProperType``.

    Returns:
        The resolved :class:`ProperType`, or ``None`` if resolution fails.
    """
    annotation = annotation.strip()
    if not annotation:
        return None
    if aliases or type_parameters:
        lookup = _AliasedTypeLookup(lookup, aliases or {}, type_parameters)

    # Forward reference: quoted string
    if annotation.startswith(('"', "'")) and annotation.endswith(('"', "'")):
        inner = annotation[1:-1]
        return resolve_forward_reference(inner, lookup)

    try:
        tree = ast.parse(annotation, mode="eval")
    except SyntaxError:
        return None

    return _resolve_expr(tree.body, lookup)


# ---------------------------------------------------------------------------
# AST expression resolution
# ---------------------------------------------------------------------------


def _resolve_expr(
    node: ast.expr,
    lookup: TypeLookup,
) -> ProperType | None:
    """Resolve an AST expression node to a :class:`ProperType`."""
    if isinstance(node, ast.Name):
        return _resolve_name(node.id, lookup)

    if isinstance(node, ast.Subscript):
        return _resolve_subscript(node, lookup)

    if isinstance(node, ast.Constant):
        if node.value is None:
            from pyflow.analysis.typeinfo.core.typesystem import NONE_TYPE

            return NONE_TYPE
        if isinstance(node.value, str):
            return resolve_forward_reference(node.value, lookup)
        return None

    if isinstance(node, ast.Attribute):
        qualified_name = _get_qualified_name(node)
        if qualified_name:
            normalized = _normalize_typing_name(qualified_name, lookup)
            if normalized != qualified_name:
                special = _resolve_name(qualified_name, lookup)
                if special is not None:
                    return special
            direct = lookup(qualified_name)
            if direct is not None:
                return direct
        base = _resolve_expr(node.value, lookup)
        if base is not None:
            return lookup(f"{_get_qualified_name(node.value)}.{node.attr}")
        return None

    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.BitOr):
        return _resolve_union_binop(node, lookup)

    # Tuple[T, ...] or (int, str) as annotation
    if isinstance(node, ast.Tuple):
        return _resolve_tuple_literal(node, lookup)

    return None


def _resolve_name(name: str, lookup: TypeLookup) -> ProperType | None:
    """Resolve a bare name to a type via the lookup function."""
    from pyflow.analysis.typeinfo.core.typesystem import (
        ANY,
        NEVER,
        NONE_TYPE,
        CallableType,
        TupleType,
    )

    original_name = name
    qualified = lookup.qualify(name) if isinstance(lookup, _AliasedTypeLookup) else name
    name = _normalize_typing_name(name, lookup)

    if name == "None":
        return NONE_TYPE
    if name == "Any":
        return ANY
    if name in {"Never", "NoReturn"}:
        return NEVER
    if qualified in {"typing.Callable", "typing_extensions.Callable", "collections.abc.Callable"}:
        return CallableType(None, ANY)
    if qualified in {"typing.Tuple", "typing_extensions.Tuple"}:
        return TupleType((ANY,), unknown_size=True)
    if isinstance(lookup, _AliasedTypeLookup):
        direct = lookup.lookup(original_name)
        if direct is not None:
            return direct
        return lookup.lookup(qualified)
    return lookup(qualified)


def _resolve_subscript(
    node: ast.Subscript,
    lookup: TypeLookup,
) -> ProperType | None:
    """Resolve a subscript annotation like ``List[int]`` or ``Optional[str]``."""
    base_name = _normalize_typing_name(_get_qualified_name(node.value), lookup)

    # Extract subscript arguments
    args = _extract_subscript_args(node.slice)

    # Aliases can contain type variables inside a nested type expression.
    # Substitute those variables instead of replacing the outer arguments.
    base_type = lookup(_get_qualified_name(node.value))
    if base_type is not None:
        from pyflow.analysis.typeinfo.resolution.typing_syntax import (
            collect_type_vars,
            substitute_type_vars,
        )
        from pyflow.analysis.typeinfo.core.typesystem import ANY

        parameters = (
            lookup.type_parameters.get(_get_qualified_name(node.value))
            if isinstance(lookup, _AliasedTypeLookup)
            else None
        )
        if parameters is None:
            parameters = tuple(variable.name for variable in collect_type_vars(base_type))
        if parameters:
            return substitute_type_vars(
                base_type,
                {
                    parameter: _resolve_expr(argument, lookup) or ANY
                    for parameter, argument in zip(parameters, args)
                },
            )

    # Resolve type alias (List → builtins.list, etc.)
    alias = resolve_type_alias(base_name)
    if alias is not None:
        return _build_generic_instance(alias, args, lookup)

    # Handle special forms
    resolved = _resolve_special_form(base_name, args, lookup)
    if resolved is None and "." in _get_qualified_name(node.value):
        return _build_generic_instance(_get_qualified_name(node.value), args, lookup)
    return resolved


def _resolve_special_form(
    name: str,
    args: list[ast.expr],
    lookup: TypeLookup,
) -> ProperType | None:
    """Resolve a typing special form to a :class:`ProperType`.

    Handles: ``Optional``, ``Union``, ``Callable``, ``Tuple``, ``Type``,
    ``ClassVar``, ``Final``, ``Annotated``, ``Generic``, ``Protocol``.
    """
    from pyflow.analysis.typeinfo.core.typesystem import ANY, NEVER, NONE_TYPE, TypeType

    # Wrapper forms: pass through to inner type
    if name in IGNORE_ANNOTATION_PARTS and args:
        return _resolve_expr(args[0], lookup)

    if name == "Optional" and args:
        inner = _resolve_expr(args[0], lookup) or ANY
        return _make_union([inner, NONE_TYPE])

    if name == "Union" and args:
        return _make_union([_resolve_expr(a, lookup) or ANY for a in args])

    if name == "Literal" and args:
        return _resolve_literal(args, lookup)

    if name == "Any":
        return ANY

    if name in {"Never", "NoReturn"}:
        return NEVER

    if name in {"Type", "type", "builtins.type"} and args:
        return TypeType(_resolve_expr(args[0], lookup) or ANY)

    if name in {"Tuple", "tuple", "builtins.tuple"}:
        return _resolve_tuple(args, lookup)

    if name == "Callable" and len(args) >= 1:
        return _resolve_callable(args, lookup)

    # Generic[T], Protocol[T]: resolve base, strip type vars
    if name in ("Generic", "Protocol"):
        return _resolve_expr(args[0], lookup) if args else None

    # Otherwise, try to resolve the base name as a concrete type
    base_type = lookup(name)
    if base_type is not None and args:
        return _build_generic_instance_from_type(base_type, args, lookup)
    return base_type


def _resolve_tuple(
    args: list[ast.expr],
    lookup: TypeLookup,
) -> ProperType | None:
    """Resolve ``Tuple[T, ...]`` or ``Tuple[X, Y]``."""
    from pyflow.analysis.typeinfo.core.typesystem import ANY, TupleType

    if not args:
        return TupleType(())

    # Tuple[T, ...] — variable-length
    if len(args) == 2:
        second = args[1]
        if isinstance(second, ast.Constant) and second.value is Ellipsis:
            elem = _resolve_expr(args[0], lookup) or ANY
            return TupleType((elem,), unknown_size=True)

    # Tuple[X, Y, Z] — fixed-length
    resolved = [_resolve_expr(arg, lookup) or ANY for arg in args]
    return TupleType(tuple(resolved), unknown_size=False)


def _resolve_callable(
    args: list[ast.expr],
    lookup: TypeLookup,
) -> ProperType | None:
    """Resolve ``Callable[[A, B], R]`` or ``Callable[..., R]``."""
    from pyflow.analysis.typeinfo.core.typesystem import ANY, CallableType

    if len(args) < 2:
        return CallableType(None, ANY)

    params_expr, return_expr = args[0], args[1]
    return_type = _resolve_expr(return_expr, lookup) or ANY

    if isinstance(params_expr, ast.Constant) and params_expr.value is Ellipsis:
        return CallableType(None, return_type)

    if isinstance(params_expr, ast.List):
        param_items = params_expr.elts
    elif isinstance(params_expr, ast.Tuple):
        param_items = params_expr.elts
    else:
        # ``Callable[P, R]`` where P is a ParamSpec is an arbitrary argument
        # list.  The same applies to ``Concatenate[...]``, which this resolver
        # does not model in detail.
        if _resolve_expr(params_expr, lookup) is None:
            return CallableType(None, return_type)
        param_items = [params_expr]

    param_types = tuple(_resolve_expr(item, lookup) or ANY for item in param_items)
    return CallableType(param_types, return_type)


def _resolve_union_binop(
    node: ast.BinOp,
    lookup: TypeLookup,
) -> ProperType | None:
    """Resolve PEP 604 ``X | Y`` union syntax."""
    left = _resolve_expr(node.left, lookup)
    right = _resolve_expr(node.right, lookup)
    from pyflow.analysis.typeinfo.core.typesystem import ANY

    return _make_union([left or ANY, right or ANY])


def _make_union(items: list[ProperType]) -> ProperType | None:
    """Build a normalized union, returning the item itself for singletons."""
    from pyflow.analysis.typeinfo.core.typesystem import UnionType

    flattened: list[ProperType] = []
    for item in items:
        if isinstance(item, UnionType):
            flattened.extend(item.items)
        else:
            flattened.append(item)
    unique = tuple(sorted(set(flattened)))
    if not unique:
        return None
    if len(unique) == 1:
        return unique[0]
    return UnionType(unique)


def _resolve_literal(
    args: list[ast.expr],
    lookup: TypeLookup,
) -> ProperType | None:
    """Resolve ``Literal[...]`` to the union of literal value runtime types."""
    from pyflow.analysis.typeinfo.core.typesystem import NONE_TYPE

    resolved: list[ProperType] = []
    for arg in args:
        if isinstance(arg, ast.Constant):
            if arg.value is None:
                resolved.append(NONE_TYPE)
            else:
                literal_type = lookup(type(arg.value).__name__)
                if literal_type is not None:
                    resolved.append(literal_type)
            continue
        nested = _resolve_expr(arg, lookup)
        if nested is not None:
            resolved.append(nested)
    return _make_union(resolved)


def _resolve_tuple_literal(
    node: ast.Tuple,
    lookup: TypeLookup,
) -> ProperType | None:
    """Resolve a tuple literal annotation like ``(int, str)``."""
    from pyflow.analysis.typeinfo.core.typesystem import ANY, TupleType

    resolved = [_resolve_expr(element, lookup) or ANY for element in node.elts]
    return TupleType(tuple(resolved), unknown_size=False)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _get_qualified_name(node: ast.expr) -> str:
    """Extract a dotted name from an AST expression node.

    ``ast.Name(id="List") → "List"``
    ``ast.Attribute(value=Name("typing"), attr="List") → "typing.List"``
    """
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return f"{_get_qualified_name(node.value)}.{node.attr}"
    return ""


def _normalize_typing_name(name: str, lookup=None) -> str:
    """Normalize common typing module qualifiers to their short names."""
    if isinstance(lookup, _AliasedTypeLookup):
        name = lookup.qualify(name)
    for prefix in ("typing.", "typing_extensions.", "collections.abc."):
        if name.startswith(prefix):
            return name[len(prefix) :]
    return name


def _extract_subscript_args(slice_: ast.expr) -> list[ast.expr]:
    """Extract arguments from a subscript slice node.

    ``ast.Tuple(elts=[...])`` → list of elts
    ``ast.Index(value=...)`` or bare expr → single-element list
    """
    if isinstance(slice_, ast.Tuple):
        return list(slice_.elts)
    return [slice_]


def _build_generic_instance(
    qualified_name: str,
    args: list[ast.expr],
    lookup: TypeLookup,
) -> ProperType | None:
    """Build ``Instance(list_ti, (T,))`` for ``List[T]`` etc."""
    base_type = lookup(qualified_name)
    if base_type is None and "." in qualified_name:
        base_type = lookup(qualified_name.rsplit(".", 1)[-1])
    if base_type is None:
        return None
    return _build_generic_instance_from_type(base_type, args, lookup)


def _build_generic_instance_from_type(
    base_type: ProperType,
    args: list[ast.expr],
    lookup: TypeLookup,
) -> ProperType | None:
    """Apply type arguments to a base type."""
    from pyflow.analysis.typeinfo.core.typesystem import ANY, Instance

    if not isinstance(base_type, Instance):
        return base_type

    resolved_args = tuple(_resolve_expr(a, lookup) or ANY for a in args)

    return Instance(base_type.type, resolved_args)


def _is_string_annotation(annotation: str) -> bool:
    """Check whether an annotation string is a forward reference (quoted)."""
    stripped = annotation.strip()
    return (stripped.startswith('"') and stripped.endswith('"')) or (
        stripped.startswith("'") and stripped.endswith("'")
    )
