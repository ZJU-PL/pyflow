# This file is part of PyFlow.
#
# SPDX-FileCopyrightText: 2019–2026 Pynguin Contributors
# SPDX-License-Identifier: MIT
#
"""Class descriptors, generic parameter metadata, and typeshed member helpers."""

from __future__ import annotations

import collections.abc as cabc
import contextvars
import functools
import inspect
import logging
import re
import sys
import types
from collections import Counter, defaultdict, deque

from pyflow.util.orderedset import OrderedSet

from .types import ANY, CallableType, ProperType, TypeVarType, Variance

_LOGGER = logging.getLogger(__name__)

_STDLIB_ROOT_MODULES = frozenset(getattr(sys, "stdlib_module_names", ())) | {"builtins"}

# Builtin/stdlib generic arities preserved consistently across __init__ and refresh().
_BUILTIN_GENERIC_ARITY: dict[type, int] = {
    dict: 2,
    defaultdict: 2,
    set: 1,
    list: 1,
    deque: 1,
    Counter: 1,
    re.Pattern: 1,
    re.Match: 1,
    contextvars.ContextVar: 1,
}

# Known variance vectors for stdlib immutable/abstract generics when
# ``type_parameters`` was not populated from a stub.
_BUILTIN_GENERIC_VARIANCE: dict[type, tuple[Variance, ...]] = {
    frozenset: (Variance.COVARIANT,),
    cabc.Iterable: (Variance.COVARIANT,),
    cabc.Iterator: (Variance.COVARIANT,),
    cabc.Collection: (Variance.COVARIANT,),
    cabc.Container: (Variance.COVARIANT,),
    cabc.Sequence: (Variance.COVARIANT,),
    cabc.Reversible: (Variance.COVARIANT,),
    cabc.Set: (Variance.COVARIANT,),
    cabc.AsyncIterable: (Variance.COVARIANT,),
    cabc.AsyncIterator: (Variance.COVARIANT,),
    cabc.Mapping: (Variance.INVARIANT, Variance.COVARIANT),
    cabc.MappingView: (Variance.COVARIANT,),
    cabc.KeysView: (Variance.COVARIANT,),
    cabc.ValuesView: (Variance.COVARIANT,),
    cabc.ItemsView: (Variance.COVARIANT, Variance.COVARIANT),
}


@functools.lru_cache(maxsize=4096)
def _typeshed_class_members(full_name: str) -> dict[str, ProperType]:
    """Return bound typeshed member types for a stdlib class, if stubbed."""
    if "." not in full_name:
        return {}
    module_name = full_name.rpartition(".")[0]
    if module_name.split(".", 1)[0] not in _STDLIB_ROOT_MODULES:
        return {}
    try:
        from pyflow.analysis.typeinfo.resolution.typeshed_resolver import (
            resolve_typeshed_class_members,
        )

        return resolve_typeshed_class_members(full_name)
    except Exception:
        return {}


def _is_signatureless_member(member: ProperType) -> bool:
    """Whether a member type carries no information worth keeping."""
    if member == ANY:
        return True
    if not isinstance(member, CallableType):
        return False
    if member.return_type != ANY:
        return False
    return not member.arg_types or all(argument == ANY for argument in member.arg_types)


def _builtin_generic_arity(raw_type: type | types.UnionType) -> int | None:
    if isinstance(raw_type, type):
        return _BUILTIN_GENERIC_ARITY.get(raw_type)
    return None


class ClassDescriptor:
    """Wrapper around a runtime or synthetic Python class.

    Corresponds 1:1 to a class identity keyed by ``full_name``.
    """

    def __init__(self, raw_type: type | types.UnionType):
        self.raw_type = raw_type
        self.name, self.qualname, self.module = ClassDescriptor._extract_name_qualname_module(
            raw_type
        )
        self.full_name = ClassDescriptor.to_full_name(raw_type)
        self.hash = hash(self.full_name)
        self.is_abstract = inspect.isabstract(raw_type)
        self.instance_attributes: OrderedSet[str] = OrderedSet()
        self.attributes: OrderedSet[str] = OrderedSet()
        # Static declarations, populated without executing analysed source.
        self.members: dict[str, ProperType] = {}
        self.is_protocol = bool(getattr(raw_type, "_is_protocol", False))
        # True when a source class declares a base whose members cannot be
        # inspected (third-party or otherwise unresolved).  Structural checks
        # must then stay conservative instead of reporting missing members.
        self.has_unresolved_bases = False
        self.enum_kind: str | None = None
        self.typed_dict_fields: dict[str, ProperType] | None = None
        self.required_keys: frozenset[str] = frozenset()
        self.tuple_fields: tuple[str, ...] | None = None
        self.type_parameters: tuple[TypeVarType, ...] = ()
        self.num_hardcoded_generic_parameters: int | None = _builtin_generic_arity(raw_type)

    @property
    def generic_arity(self) -> int | None:
        """Declared generic parameter arity, preferring ``type_parameters`` over builtin defaults."""
        if self.type_parameters:
            return len(self.type_parameters)
        return self.num_hardcoded_generic_parameters

    def parameter_variance(self, index: int) -> Variance:
        """Return the variance of generic type parameter *index* (defaults to INVARIANT)."""
        if 0 <= index < len(self.type_parameters):
            return self.type_parameters[index].variance
        if isinstance(self.raw_type, type):
            variances = _BUILTIN_GENERIC_VARIANCE.get(self.raw_type)
            if variances is not None and 0 <= index < len(variances):
                return variances[index]
        return Variance.INVARIANT

    def refresh(self, raw_type: type | types.UnionType) -> None:
        """Refresh identity fields after the same class is re-created.

        Project inference creates a fresh synthetic ``type`` object for every
        source class on every module pass.  The descriptor is intentionally
        keyed by full name so instances from earlier passes keep pointing at
        the same analysis object; refreshing the raw type in place prevents an
        early unresolved placeholder from shadowing the real class forever.
        ``members`` and the other analysis-owned fields are preserved because
        callers update those incrementally.
        """
        self.raw_type = raw_type
        self.name, self.qualname, self.module = self._extract_name_qualname_module(raw_type)
        self.is_abstract = inspect.isabstract(raw_type)
        self.is_protocol = bool(getattr(raw_type, "_is_protocol", False))
        self.num_hardcoded_generic_parameters = _builtin_generic_arity(raw_type)

    @staticmethod
    def _extract_name_qualname_module(raw_type: type | types.UnionType) -> tuple[str, str, str]:
        """Extract the name, qualname and module from the given type."""
        if isinstance(raw_type, types.UnionType):
            return "UnionType", "UnionType", "types"

        name = ClassDescriptor.get_dunder_value_from_type(raw_type, "name")
        qualname = ClassDescriptor.get_dunder_value_from_type(raw_type, "qualname")
        module = ClassDescriptor.get_dunder_value_from_type(raw_type, "module")
        return name, qualname, module

    @staticmethod
    def to_full_name(typ: type | types.UnionType) -> str:  # noqa: D417
        """Get the fully qualified name of the given type."""
        if isinstance(typ, types.UnionType):
            return "types.UnionType"

        module = ClassDescriptor.get_dunder_value_from_type(typ, "module")
        qualname = ClassDescriptor.get_dunder_value_from_type(typ, "qualname")
        # CPython 3.13 moved ``pathlib`` into ``pathlib._local``.  Expose the
        # public module name so type strings stay stable across versions.
        if module in {"pathlib._local", "pathlib._abc"}:
            module = "pathlib"
        return f"{module}.{qualname}"

    @staticmethod
    def get_dunder_value_from_type(typ: type, name: str) -> str:
        """Get the dunder value with the given name from the given type."""
        dunder_name = f"__{name}__"
        if hasattr(typ, dunder_name):
            return getattr(typ, dunder_name)

        _LOGGER.error(
            "%s has no attribute __%s__. This method must not be called with instances of types.",
            typ,
            name,
        )
        return getattr(type(typ), dunder_name)

    def __eq__(self, other) -> bool:
        return isinstance(other, ClassDescriptor) and other.full_name == self.full_name

    def __hash__(self):
        return self.hash

    def __repr__(self):
        return f"ClassDescriptor({self.full_name})"
