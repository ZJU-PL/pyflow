"""Literal type helpers shared by narrowing and format-string checks."""

from __future__ import annotations

from typing import Iterable

from pyflow.analysis.typeinfo.inference.domain import AbstractTypeValue


def literal_values(value: AbstractTypeValue) -> frozenset[object]:
    """Return the concrete literal alternatives carried by *value*."""
    return value.literal_values


def is_literal(value: AbstractTypeValue) -> bool:
    return bool(value.literal_values) and not value.unknown


def literal_intersection(
    left: AbstractTypeValue,
    right: AbstractTypeValue,
) -> frozenset[object]:
    return left.literal_values & right.literal_values


def literal_union(
    left: AbstractTypeValue,
    right: AbstractTypeValue,
) -> frozenset[object]:
    return left.literal_values | right.literal_values


def contains_literal(value: AbstractTypeValue, literal: object) -> bool:
    return literal in value.literal_values


def narrow_to_literal(
    old: AbstractTypeValue,
    literal: AbstractTypeValue,
) -> AbstractTypeValue:
    """Restrict *old* to the concrete value supplied by *literal*."""
    if not literal.types or literal.unknown:
        return old
    return AbstractTypeValue(
        types=literal.types,
        unknown=old.unknown,
        callable_targets=literal.callable_targets,
        class_targets=literal.class_targets,
        dict_shapes=literal.dict_shapes,
        literal_values=literal.literal_values,
        literal_values_complete=literal.literal_values_complete and not old.unknown,
    )
