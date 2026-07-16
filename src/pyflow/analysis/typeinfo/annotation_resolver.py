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
from typing import TYPE_CHECKING, Protocol

from pyflow.analysis.typeinfo.gradual_typing import (
    IGNORE_ANNOTATION_PARTS,
    resolve_type_alias,
)

if TYPE_CHECKING:
    from pyflow.analysis.typeinfo.typesystem import ProperType


# ---------------------------------------------------------------------------
# Type lookup protocol
# ---------------------------------------------------------------------------


class TypeLookup(Protocol):
    """Protocol for resolving qualified type names to :class:`ProperType` objects.

    Implementations should return ``None`` for unknown names.
    """

    def __call__(self, qualified_name: str) -> ProperType | None: ...


class BuiltinTypeLookup:
    """Resolve built-in type names, optionally delegating unknown names."""

    def __init__(self, fallback: TypeLookup | None = None) -> None:
        self._fallback = fallback

    def __call__(self, qualified_name: str) -> ProperType | None:
        from pyflow.analysis.typeinfo.typesystem import (
            ANY,
            NONE_TYPE,
            Instance,
            TupleType,
            TypeInfo,
        )

        if qualified_name in {"Any", "typing.Any"}:
            return ANY
        if qualified_name in {"None", "NoneType", "types.NoneType"}:
            return NONE_TYPE
        if qualified_name in {"tuple", "builtins.tuple"}:
            return TupleType((), unknown_size=True)
        if qualified_name.startswith("builtins."):
            qualified_name = qualified_name.rsplit(".", 1)[-1]
        raw = getattr(builtins, qualified_name, None)
        if isinstance(raw, type):
            return Instance(TypeInfo(raw))
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
            from pyflow.analysis.typeinfo.typesystem import NONE_TYPE

            return NONE_TYPE
        if isinstance(node.value, str):
            return resolve_forward_reference(node.value, lookup)
        return None

    if isinstance(node, ast.Attribute):
        qualified_name = _get_qualified_name(node)
        if qualified_name:
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
    from pyflow.analysis.typeinfo.typesystem import NONE_TYPE

    if name == "None":
        return NONE_TYPE
    return lookup(name)


def _resolve_subscript(
    node: ast.Subscript,
    lookup: TypeLookup,
) -> ProperType | None:
    """Resolve a subscript annotation like ``List[int]`` or ``Optional[str]``."""
    base_name = _normalize_typing_name(_get_qualified_name(node.value))

    # Extract subscript arguments
    args = _extract_subscript_args(node.slice)

    # Resolve type alias (List → builtins.list, etc.)
    alias = resolve_type_alias(base_name)
    if alias is not None:
        return _build_generic_instance(alias, args, lookup)

    # Handle special forms
    return _resolve_special_form(base_name, args, lookup)


def _resolve_special_form(
    name: str,
    args: list[ast.expr],
    lookup: TypeLookup,
) -> ProperType | None:
    """Resolve a typing special form to a :class:`ProperType`.

    Handles: ``Optional``, ``Union``, ``Callable``, ``Tuple``, ``Type``,
    ``ClassVar``, ``Final``, ``Annotated``, ``Generic``, ``Protocol``.
    """
    from pyflow.analysis.typeinfo.typesystem import ANY, NONE_TYPE, UNSUPPORTED

    # Wrapper forms: pass through to inner type
    if name in IGNORE_ANNOTATION_PARTS and args:
        return _resolve_expr(args[0], lookup)

    if name == "Optional" and args:
        inner = _resolve_expr(args[0], lookup)
        if inner is None:
            return None
        return _make_union([inner, NONE_TYPE])

    if name == "Union" and args:
        resolved = [_resolve_expr(a, lookup) for a in args]
        return _make_union([r for r in resolved if r is not None])

    if name == "Literal" and args:
        return _resolve_literal(args, lookup)

    if name == "Any":
        return ANY

    if name in {"Never", "NoReturn"}:
        return UNSUPPORTED

    if name == "Type" and args:
        return _resolve_expr(args[0], lookup)

    if name in {"Tuple", "tuple", "builtins.tuple"} and args:
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
    from pyflow.analysis.typeinfo.typesystem import TupleType

    if not args:
        return None

    # Tuple[T, ...] — variable-length
    if len(args) == 2:
        second = args[1]
        if isinstance(second, ast.Constant) and second.value is Ellipsis:
            elem = _resolve_expr(args[0], lookup)
            if elem is not None:
                return TupleType((elem,), unknown_size=True)

    # Tuple[X, Y, Z] — fixed-length
    resolved: list[ProperType] = []
    for arg in args:
        item = _resolve_expr(arg, lookup)
        if item is not None:
            resolved.append(item)
    if not resolved:
        return None
    return TupleType(tuple(resolved), unknown_size=False)


def _resolve_callable(
    args: list[ast.expr],
    lookup: TypeLookup,
) -> ProperType | None:
    """Resolve ``Callable[[A, B], R]`` or ``Callable[..., R]``."""
    from pyflow.analysis.typeinfo.typesystem import ANY, CallableType

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
        param_items = [params_expr]

    param_types = tuple(
        resolved
        for item in param_items
        if (resolved := _resolve_expr(item, lookup)) is not None
    )
    return CallableType(param_types, return_type)


def _resolve_union_binop(
    node: ast.BinOp,
    lookup: TypeLookup,
) -> ProperType | None:
    """Resolve PEP 604 ``X | Y`` union syntax."""
    left = _resolve_expr(node.left, lookup)
    right = _resolve_expr(node.right, lookup)
    return _make_union([t for t in (left, right) if t is not None])


def _make_union(items: list[ProperType]) -> ProperType | None:
    """Build a normalized union, returning the item itself for singletons."""
    from pyflow.analysis.typeinfo.typesystem import UnionType

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
    from pyflow.analysis.typeinfo.typesystem import NONE_TYPE

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
    from pyflow.analysis.typeinfo.typesystem import TupleType

    resolved: list[ProperType] = []
    for element in node.elts:
        item = _resolve_expr(element, lookup)
        if item is not None:
            resolved.append(item)
    if not resolved:
        return None
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


def _normalize_typing_name(name: str) -> str:
    """Normalize common typing module qualifiers to their short names."""
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
    from pyflow.analysis.typeinfo.typesystem import Instance

    if not isinstance(base_type, Instance):
        return base_type

    resolved_args = tuple(
        r for a in args if (r := _resolve_expr(a, lookup)) is not None
    )
    if not resolved_args:
        return base_type

    return Instance(base_type.type, resolved_args)


def _is_string_annotation(annotation: str) -> bool:
    """Check whether an annotation string is a forward reference (quoted)."""
    stripped = annotation.strip()
    return (stripped.startswith('"') and stripped.endswith('"')) or (
        stripped.startswith("'") and stripped.endswith("'")
    )
