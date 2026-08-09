"""Abstract domain for Python class-pollution analysis."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Literal

from pyflow.ir.cfg import graph as cfg_graph
from pyflow.language.python import ast as py_ast


class PollutionRole(str, Enum):
    """Semantic role of one independently propagated pollution fact."""

    INPUT = "input"
    ROOT_OBJECT = "root-object"
    TARGET_OBJECT = "target-object"


class KeyLanguageKind(str, Enum):
    TOP = "top"
    FINITE = "finite"
    SAFE = "safe"


MAGIC_PATH_COMPONENTS = frozenset(
    {
        "__class__",
        "__base__",
        "__bases__",
        "__mro__",
        "__dict__",
        "__globals__",
        "__builtins__",
        "__code__",
        "__func__",
        "__self__",
        "__module__",
        "__subclasses__",
    }
)

GADGET_PATH_COMPONENTS = frozenset(
    {
        "__globals__",
        "__builtins__",
        "__code__",
        "__subclasses__",
    }
)


@dataclass(frozen=True, order=True)
class KeyLanguage:
    """Small finite-height language for attacker-controlled attribute names."""

    kind: KeyLanguageKind
    literals: tuple[str, ...] = ()

    @classmethod
    def top(cls) -> "KeyLanguage":
        return cls(KeyLanguageKind.TOP)

    @classmethod
    def finite(cls, values) -> "KeyLanguage":
        normalized = tuple(sorted(set(values)))
        return cls(KeyLanguageKind.FINITE, normalized)

    @classmethod
    def safe(cls) -> "KeyLanguage":
        return cls(KeyLanguageKind.SAFE)

    def may_contain_magic(self) -> bool:
        if self.kind is KeyLanguageKind.TOP:
            return True
        if self.kind is KeyLanguageKind.SAFE:
            return False
        return any(value in MAGIC_PATH_COMPONENTS for value in self.literals)

    def describe(self) -> str:
        if self.kind is KeyLanguageKind.TOP:
            return "unknown attacker-controlled key"
        if self.kind is KeyLanguageKind.SAFE:
            return "validated safe key"
        return "{" + ", ".join(repr(value) for value in self.literals) + "}"


@dataclass(frozen=True, order=True)
class PollutionOrigin:
    """Stable correlation identity for one external boundary value."""

    procedure: object
    label: str
    ordinal: int = 0


@dataclass(frozen=True, order=True)
class ObjectPathStep:
    """One attribute/item traversal used to reach a mutation target."""

    kind: Literal["attribute", "item"]
    key_language: KeyLanguage
    static_name: str | None = None

    def may_reach_magic(self) -> bool:
        return (
            self.static_name in MAGIC_PATH_COMPONENTS
            if self.static_name is not None
            else self.key_language.may_contain_magic()
        )


@dataclass(frozen=True)
class PollutionFact:
    location: object
    origin: PollutionOrigin
    role: PollutionRole
    key_language: KeyLanguage = KeyLanguage(KeyLanguageKind.TOP)
    object_path: tuple[ObjectPathStep, ...] = ()
    controller: PollutionOrigin | None = None
    access_path: tuple[str, ...] = ()
    recursive_summary: bool = False


@dataclass(frozen=True)
class ExpressionPollutionFact:
    procedure: cfg_graph.Code
    expression: py_ast.PythonASTNode
    origin: PollutionOrigin
    role: PollutionRole
    key_language: KeyLanguage = KeyLanguage(KeyLanguageKind.TOP)
    object_path: tuple[ObjectPathStep, ...] = ()
    controller: PollutionOrigin | None = None
    result_index: int = 0
    access_path: tuple[str, ...] = ()
    recursive_summary: bool = False


PollutionDataFact = PollutionFact | ExpressionPollutionFact


__all__ = [
    "ExpressionPollutionFact",
    "GADGET_PATH_COMPONENTS",
    "KeyLanguage",
    "KeyLanguageKind",
    "MAGIC_PATH_COMPONENTS",
    "ObjectPathStep",
    "PollutionDataFact",
    "PollutionFact",
    "PollutionOrigin",
    "PollutionRole",
]
