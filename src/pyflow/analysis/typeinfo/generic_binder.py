"""Bind type variables in generic classes to concrete type arguments.

When a generic class is instantiated with type arguments (e.g.
``List[int]``, ``MyDict[str, int]``), this module binds each
:class:`TypeVarType` in the class's parameter list to the
corresponding concrete :class:`ProperType`.

The binding logic is adapted from Jedi's
``jedi.inference.gradual.base`` (https://github.com/davidhalter/jedi).

SPDX-FileCopyrightText: 2025 David Halter and contributors
SPDX-FileCopyrightText: 2026 PyFlow Contributors
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from pyflow.analysis.typeinfo.gradual_typing import substitute_type_vars

if TYPE_CHECKING:
    from pyflow.analysis.typeinfo.typesystem import ProperType, TypeVarType


# ---------------------------------------------------------------------------
# Generic binding
# ---------------------------------------------------------------------------


@dataclass
class GenericBinding:
    """Holds the result of binding type variables to concrete types.

    Attributes:
        mapping: A dictionary mapping type-variable names to concrete types.
        type_vars: The original type-variable list (in declaration order).
    """

    mapping: dict[str, ProperType] = field(default_factory=dict)
    type_vars: list[TypeVarType] = field(default_factory=list)

    def apply(self, type_: ProperType) -> ProperType:
        """Substitute all bound type variables in *type_* with concrete types.

        Args:
            type_: A type that may contain type variables from this binding.

        Returns:
            A new type with type variables replaced.
        """
        return substitute_type_vars(type_, self.mapping)

    def is_bound(self, tv_name: str) -> bool:
        """Check whether a type variable has been bound."""
        return tv_name in self.mapping

    def __bool__(self) -> bool:
        return bool(self.mapping)

    def __repr__(self) -> str:
        return f"GenericBinding({self.mapping})"


def bind_generics(
    type_vars: list[TypeVarType],
    concrete_args: list[ProperType],
) -> GenericBinding:
    """Bind a list of type variables to concrete type arguments.

    Matches type variables to arguments positionally.  If there are fewer
    concrete arguments than type variables, the trailing type variables
    remain unbound.  If there are more concrete arguments, extras are
    ignored.

    Args:
        type_vars: The type-variable parameters (e.g. from ``class Foo(Generic[T, U])``).
        concrete_args: The concrete type arguments (e.g. from ``Foo[int, str]``).

    Returns:
        A :class:`GenericBinding` with the resolved mapping.

    Examples:
        >>> T = TypeVarType("T")
        >>> U = TypeVarType("U")
        >>> ti = TypeInfo(int)
        >>> binding = bind_generics([T, U], [Instance(ti), Instance(ti)])
        >>> binding.mapping
        {'T': Instance(TypeInfo(int)), 'U': Instance(TypeInfo(int))}
    """
    mapping: dict[str, ProperType] = {}

    for tv, arg in zip(type_vars, concrete_args):
        mapping[tv.name] = arg

    return GenericBinding(mapping=mapping, type_vars=list(type_vars))


def bind_generics_from_pairs(
    pairs: list[tuple[TypeVarType, ProperType]],
) -> GenericBinding:
    """Create a :class:`GenericBinding` from explicit (type_var, concrete_type) pairs.

    This is useful when type variables are matched by name rather than
    position (e.g. when matching base-class generics).

    Args:
        pairs: A list of ``(TypeVarType, ProperType)`` tuples.

    Returns:
        A :class:`GenericBinding` with the resolved mapping.
    """
    mapping: dict[str, ProperType] = {}
    type_vars: list[TypeVarType] = []

    for tv, arg in pairs:
        mapping[tv.name] = arg
        if tv not in type_vars:
            type_vars.append(tv)

    return GenericBinding(mapping=mapping, type_vars=type_vars)


def merge_bindings(*bindings: GenericBinding) -> GenericBinding:
    """Merge multiple :class:`GenericBinding` objects into one.

    Later bindings override earlier ones for the same type-variable name.

    Args:
        *bindings: Zero or more bindings to merge.

    Returns:
        A new :class:`GenericBinding` combining all mappings.
    """
    mapping: dict[str, ProperType] = {}
    type_vars: list[TypeVarType] = []

    for b in bindings:
        mapping.update(b.mapping)
        for tv in b.type_vars:
            if tv not in type_vars:
                type_vars.append(tv)

    return GenericBinding(mapping=mapping, type_vars=type_vars)
