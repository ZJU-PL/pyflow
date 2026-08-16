"""Unified abstract type references and feasible class alternatives."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Optional, Tuple, TYPE_CHECKING

if TYPE_CHECKING:
    from .object import AbstractObject, ClassObject


class TypeRefKind(Enum):
    USER = "user"
    BUILTIN = "builtin"
    NATIVE = "native"
    OPAQUE = "opaque"


@dataclass(frozen=True)
class TypeRef:
    """A type-like value independent of its implementation origin."""

    kind: TypeRefKind
    target: Optional['AbstractObject'] = None
    name: str = ""

    @classmethod
    def user(cls, target: 'ClassObject') -> 'TypeRef':
        return cls(TypeRefKind.USER, target, target.ir.name)

    @classmethod
    def builtin(
        cls, name: str, target: Optional['AbstractObject'] = None
    ) -> 'TypeRef':
        return cls(TypeRefKind.BUILTIN, target, name)

    @classmethod
    def native(cls, target: 'AbstractObject', name: str) -> 'TypeRef':
        return cls(TypeRefKind.NATIVE, target, name)

    @classmethod
    def opaque(
        cls,
        name: str = "<opaque-type>",
        target: Optional['AbstractObject'] = None,
    ) -> 'TypeRef':
        return cls(TypeRefKind.OPAQUE, target, name)

    @property
    def is_opaque(self) -> bool:
        return self.kind in (TypeRefKind.NATIVE, TypeRefKind.OPAQUE)


@dataclass(frozen=True)
class ClassVariant:
    """One feasible abstract class-construction alternative."""

    owner: 'ClassObject'
    effective_bases: Tuple[TypeRef, ...]
    metaclass: TypeRef
    mro: Tuple[TypeRef, ...]
    widened: bool = False


@dataclass(frozen=True)
class InvalidClassVariant:
    """A concrete base/metaclass tuple rejected by class construction."""

    owner: 'ClassObject'
    effective_bases: Tuple[TypeRef, ...]
    reason: str
