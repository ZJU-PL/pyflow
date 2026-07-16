"""PEP 484 gradual typing utilities for the PyFlow type system.

Provides type-alias resolution and type-variable substitution for working
with ``typing`` module constructs like ``List[int]``, ``Dict[str, int]``,
``Optional[str]``, ``Union[int, str]``, and user-defined generics.

The type-alias tables are adapted from Jedi's
``jedi.inference.gradual.typing``
(https://github.com/davidhalter/jedi).

SPDX-FileCopyrightText: 2025 David Halter and contributors
SPDX-FileCopyrightText: 2026 PyFlow Contributors
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import re
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from pyflow.analysis.typeinfo.typesystem import (
        ProperType,
        TypeVarType,
    )

# ---------------------------------------------------------------------------
# Type alias tables — PEP 484 typing → builtins mappings
# ---------------------------------------------------------------------------

TYPE_ALIAS_TYPES: dict[str, str] = {
    "List": "builtins.list",
    "Dict": "builtins.dict",
    "Set": "builtins.set",
    "FrozenSet": "builtins.frozenset",
    "ChainMap": "collections.ChainMap",
    "Counter": "collections.Counter",
    "DefaultDict": "collections.defaultdict",
    "Deque": "collections.deque",
}

PROXY_CLASS_TYPES: set[str] = {"Tuple", "Generic", "Protocol", "Callable", "Type"}

PROXY_TYPES: set[str] = {"Optional", "Union", "ClassVar", "Annotated", "Final"}

IGNORE_ANNOTATION_PARTS: set[str] = {"ClassVar", "Annotated", "Final"}

# ---------------------------------------------------------------------------
# Type alias resolution
# ---------------------------------------------------------------------------


def resolve_type_alias(name: str) -> str | None:
    """Resolve a ``typing`` module alias to its concrete builtin/collections type.

    Args:
        name: A type name from the ``typing`` module (e.g. ``"List"``).

    Returns:
        The fully-qualified concrete type name, or ``None`` if *name*
        is not a known alias.

    Examples:
        >>> resolve_type_alias("List")
        'builtins.list'
        >>> resolve_type_alias("Dict")
        'builtins.dict'
        >>> resolve_type_alias("str")
        None
    """
    return TYPE_ALIAS_TYPES.get(name)


def is_proxy_class(name: str) -> bool:
    """Check whether *name* is a typing proxy class (Tuple, Generic, etc.)."""
    return name in PROXY_CLASS_TYPES


def is_proxy_type(name: str) -> bool:
    """Check whether *name* is a typing proxy value (Optional, Union, etc.)."""
    return name in PROXY_TYPES


def should_ignore_annotation_part(name: str) -> bool:
    """Check whether an annotation part should be ignored (ClassVar, Final, etc.)."""
    return name in IGNORE_ANNOTATION_PARTS


# ---------------------------------------------------------------------------
# Type variable substitution
# ---------------------------------------------------------------------------


def substitute_type_vars(
    type_: ProperType,
    substitutions: dict[str, ProperType],
) -> ProperType:
    """Substitute type variables in *type_* with concrete types.

    Recursively walks the type structure, replacing any :class:`TypeVarType`
    whose name appears in *substitutions*.

    Args:
        type_: The type (possibly containing type variables) to substitute into.
        substitutions: A mapping from type-variable name to concrete type.

    Returns:
        A new type with type variables replaced.  If no substitutions apply,
        the original *type_* is returned unchanged.
    """
    from pyflow.analysis.typeinfo.typesystem import (
        Instance,
        TupleType,
        TypeVarType,
        UnionType,
    )

    if isinstance(type_, TypeVarType):
        return substitutions.get(type_.name, type_)

    if isinstance(type_, Instance) and type_.args:
        new_args = tuple(
            substitute_type_vars(a, substitutions) for a in type_.args
        )
        if new_args != type_.args:
            return Instance(type_.type, new_args)
        return type_

    if isinstance(type_, TupleType) and type_.args:
        new_args = tuple(
            substitute_type_vars(a, substitutions) for a in type_.args
        )
        if new_args != type_.args:
            return TupleType(new_args, unknown_size=type_.unknown_size)
        return type_

    if isinstance(type_, UnionType):
        new_items = tuple(
            substitute_type_vars(i, substitutions) for i in type_.items
        )
        if new_items != type_.items:
            return UnionType(new_items)
        return type_

    return type_


def collect_type_vars(type_: ProperType) -> list[TypeVarType]:
    """Collect all :class:`TypeVarType` instances contained in *type_*.

    Args:
        type_: The type to scan.

    Returns:
        A list of distinct type variables, in depth-first order.
    """
    from pyflow.analysis.typeinfo.typesystem import (
        Instance,
        TupleType,
        TypeVarType,
        UnionType,
    )

    result: list[TypeVarType] = []

    def _collect(t: ProperType) -> None:
        if isinstance(t, TypeVarType):
            if t not in result:
                result.append(t)
            return
        if isinstance(t, Instance) and t.args:
            for a in t.args:
                _collect(a)
        elif isinstance(t, TupleType) and t.args:
            for a in t.args:
                _collect(a)
        elif isinstance(t, UnionType):
            for i in t.items:
                _collect(i)

    _collect(type_)
    return result


# ---------------------------------------------------------------------------
# Type-comment parsing (PEP 484 ``# type:`` comments)
# ---------------------------------------------------------------------------


def split_comment_param_declaration(decl_text: str) -> list[str]:
    """Split a ``# type: (int, str) -> bool`` parameter declaration.

    Handles nested generic brackets (e.g. ``Dict[str, int]`` is treated as
    a single parameter).

    Args:
        decl_text: The parameter declaration text from a type comment.

    Returns:
        A list of type-name strings, one per parameter.

    Examples:
        >>> split_comment_param_declaration("int, str")
        ['int', 'str']
        >>> split_comment_param_declaration("Dict[str, int], bool")
        ['Dict[str, int]', 'bool']
    """
    params: list[str] = []
    depth = 0
    current: list[str] = []

    for ch in decl_text:
        if ch == "[":
            depth += 1
            current.append(ch)
        elif ch == "]":
            depth -= 1
            current.append(ch)
        elif ch == "," and depth == 0:
            params.append("".join(current).strip())
            current = []
        else:
            current.append(ch)

    if current:
        stripped = "".join(current).strip()
        if stripped:
            params.append(stripped)

    return params


def parse_type_comment(comment: str) -> tuple[list[str], str | None]:
    """Parse a PEP 484 type comment into parameter types and return type.

    Supports the format::

        # type: (int, str) -> bool
        # type: (int, str, Dict[str, int]) -> Optional[str]

    Args:
        comment: The full type-comment string (including ``# type:`` prefix).

    Returns:
        A tuple of ``(param_types, return_type)`` where *param_types*
        is a list of type-name strings and *return_type* is a string
        or ``None``.
    """
    match = re.match(r"^#\s*type:\s*\(([^#]*)\)\s*->\s*([^#]*)", comment)
    if not match:
        return [], None

    params_text = match.group(1)
    return_text = match.group(2).strip()
    return split_comment_param_declaration(params_text), return_text or None
