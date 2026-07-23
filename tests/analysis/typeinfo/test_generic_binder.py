#  This file is part of PyFlow.
#
#  SPDX-FileCopyrightText: 2019–2026 PyFlow Contributors
#
#  SPDX-License-Identifier: MIT
#

from __future__ import annotations

from pyflow.analysis.typeinfo.core.typesystem import (
    Instance,
    TupleType,
    ClassDescriptor,
    TypeVarType,
    UnionType,
)
from pyflow.analysis.typeinfo.resolution.generics import (
    GenericBinding,
    bind_generics,
    bind_generics_from_pairs,
    merge_bindings,
)


_INT = Instance(ClassDescriptor(int))
_STR = Instance(ClassDescriptor(str))
_LIST_INT = Instance(ClassDescriptor(list), (_INT,))


# ---------------------------------------------------------------------------
# bind_generics
# ---------------------------------------------------------------------------


def test_bind_generics_basic() -> None:
    t = TypeVarType("T")
    binding = bind_generics([t], [_INT])
    assert binding.mapping == {"T": _INT}
    assert len(binding.type_vars) == 1


def test_bind_generics_two() -> None:
    t = TypeVarType("T")
    u = TypeVarType("U")
    binding = bind_generics([t, u], [_INT, _STR])
    assert binding.mapping == {"T": _INT, "U": _STR}


def test_bind_generics_fewer_args() -> None:
    t = TypeVarType("T")
    u = TypeVarType("U")
    binding = bind_generics([t, u], [_INT])
    assert binding.mapping == {"T": _INT}
    assert "U" not in binding.mapping


def test_bind_generics_extra_args() -> None:
    t = TypeVarType("T")
    binding = bind_generics([t], [_INT, _STR, _INT])
    assert binding.mapping == {"T": _INT}


def test_bind_generics_empty() -> None:
    binding = bind_generics([], [])
    assert binding.mapping == {}
    assert not binding


# ---------------------------------------------------------------------------
# bind_generics_from_pairs
# ---------------------------------------------------------------------------


def test_bind_generics_from_pairs() -> None:
    t = TypeVarType("T")
    u = TypeVarType("U")
    binding = bind_generics_from_pairs([(t, _INT), (u, _STR)])
    assert binding.mapping == {"T": _INT, "U": _STR}


def test_bind_generics_from_pairs_override() -> None:
    t = TypeVarType("T")
    binding = bind_generics_from_pairs([(t, _INT), (t, _STR)])
    assert binding.mapping == {"T": _STR}


# ---------------------------------------------------------------------------
# GenericBinding.apply
# ---------------------------------------------------------------------------


def test_apply_substitution() -> None:
    t = TypeVarType("T")
    binding = bind_generics([t], [_INT])
    result = binding.apply(t)
    assert result == _INT


def test_apply_in_instance() -> None:
    t = TypeVarType("T")
    ti = ClassDescriptor(list)
    instance = Instance(ti, (t,))
    binding = bind_generics([t], [_INT])
    result = binding.apply(instance)
    assert isinstance(result, Instance)
    assert result.args[0] == _INT  # type: ignore[union-attr]


def test_apply_in_tuple() -> None:
    t = TypeVarType("T")
    tt = TupleType((t, t))
    binding = bind_generics([t], [_INT])
    result = binding.apply(tt)
    assert isinstance(result, TupleType)
    assert result.args == (_INT, _INT)


def test_apply_in_union() -> None:
    t = TypeVarType("T")
    u = TypeVarType("U")
    union = UnionType((t, u))
    binding = bind_generics([t, u], [_INT, _STR])
    result = binding.apply(union)
    assert isinstance(result, UnionType)
    items = list(result.items)
    assert _INT in items
    assert _STR in items


# ---------------------------------------------------------------------------
# GenericBinding.is_bound
# ---------------------------------------------------------------------------


def test_is_bound_true() -> None:
    t = TypeVarType("T")
    binding = bind_generics([t], [_INT])
    assert binding.is_bound("T") is True


def test_is_bound_false() -> None:
    t = TypeVarType("T")
    binding = bind_generics([t], [_INT])
    assert binding.is_bound("U") is False


# ---------------------------------------------------------------------------
# merge_bindings
# ---------------------------------------------------------------------------


def test_merge_bindings() -> None:
    t = TypeVarType("T")
    u = TypeVarType("U")
    b1 = bind_generics([t], [_INT])
    b2 = bind_generics([u], [_STR])
    merged = merge_bindings(b1, b2)
    assert merged.mapping == {"T": _INT, "U": _STR}


def test_merge_bindings_override() -> None:
    t = TypeVarType("T")
    b1 = bind_generics([t], [_INT])
    b2 = bind_generics([t], [_STR])
    merged = merge_bindings(b1, b2)
    assert merged.mapping == {"T": _STR}


def test_merge_bindings_empty() -> None:
    merged = merge_bindings()
    assert merged.mapping == {}
    assert not merged


# ---------------------------------------------------------------------------
# GenericBinding.bool
# ---------------------------------------------------------------------------


def test_binding_bool_true() -> None:
    t = TypeVarType("T")
    binding = bind_generics([t], [_INT])
    assert bool(binding) is True


def test_binding_bool_false() -> None:
    binding = GenericBinding()
    assert bool(binding) is False
