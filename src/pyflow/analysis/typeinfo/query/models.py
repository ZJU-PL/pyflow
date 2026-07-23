"""Small public models for lightweight type-information queries."""

from __future__ import annotations

from dataclasses import dataclass, field

from pyflow.analysis.typeinfo.core.typesystem import Instance, ProperType


@dataclass(frozen=True)
class TypeFact:
    """A single type fact for a symbol or member."""

    name: str
    typ: ProperType | None
    raw_annotation: str | None
    source: str
    kind: str


@dataclass(frozen=True)
class FunctionTypeInfo:
    """Callable type information."""

    name: str
    params: dict[str, ProperType | None]
    returns: ProperType | None
    raw_params: dict[str, str | None]
    raw_returns: str | None
    source: str


@dataclass(frozen=True)
class ClassTypeInfo:
    """Class type information."""

    name: str
    typ: Instance
    bases: tuple[ProperType, ...] = ()
    raw_bases: tuple[str, ...] = ()
    members: dict[str, TypeFact] = field(default_factory=dict)
    methods: dict[str, FunctionTypeInfo] = field(default_factory=dict)
    source: str = "source"
