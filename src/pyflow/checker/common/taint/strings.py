"""Small finite abstract domain for dynamic Python string selectors."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Iterable


class AbstractStringKind(str, Enum):
    BOTTOM = "bottom"
    CONSTANTS = "constants"
    PREFIX = "prefix"
    TOP = "top"


@dataclass(frozen=True)
class AbstractString:
    kind: AbstractStringKind
    constants: frozenset[str] = frozenset()
    prefix: str | None = None
    max_constants: int = 8

    @classmethod
    def bottom(cls, *, max_constants: int = 8) -> "AbstractString":
        return cls(AbstractStringKind.BOTTOM, max_constants=max_constants)

    @classmethod
    def top(cls, *, max_constants: int = 8) -> "AbstractString":
        return cls(AbstractStringKind.TOP, max_constants=max_constants)

    @classmethod
    def constant(cls, value: str, *, max_constants: int = 8) -> "AbstractString":
        return cls(
            AbstractStringKind.CONSTANTS,
            constants=frozenset({value}),
            max_constants=max_constants,
        )

    @classmethod
    def from_constants(
        cls, values: Iterable[str], *, max_constants: int = 8
    ) -> "AbstractString":
        constants = frozenset(values)
        if not constants:
            return cls.bottom(max_constants=max_constants)
        if len(constants) > max_constants:
            prefix = cls._common_prefix(constants)
            if prefix:
                return cls(
                    AbstractStringKind.PREFIX,
                    prefix=prefix,
                    max_constants=max_constants,
                )
            return cls.top(max_constants=max_constants)
        return cls(
            AbstractStringKind.CONSTANTS,
            constants=constants,
            max_constants=max_constants,
        )

    def leq(self, other: "AbstractString") -> bool:
        if self.kind is AbstractStringKind.BOTTOM:
            return True
        if other.kind is AbstractStringKind.TOP:
            return True
        if self.kind is AbstractStringKind.TOP:
            return False
        if self.kind is AbstractStringKind.CONSTANTS:
            if other.kind is AbstractStringKind.CONSTANTS:
                return self.constants <= other.constants
            if other.kind is AbstractStringKind.PREFIX:
                return all(
                    value.startswith(other.prefix or "") for value in self.constants
                )
        if self.kind is AbstractStringKind.PREFIX:
            return other.kind is AbstractStringKind.PREFIX and (
                self.prefix or ""
            ).startswith(other.prefix or "")
        return False

    def join(self, other: "AbstractString") -> "AbstractString":
        limit = min(self.max_constants, other.max_constants)
        if self.kind is AbstractStringKind.BOTTOM:
            return other
        if other.kind is AbstractStringKind.BOTTOM:
            return self
        if self.kind is AbstractStringKind.TOP or other.kind is AbstractStringKind.TOP:
            return self.top(max_constants=limit)
        if (
            self.kind is AbstractStringKind.CONSTANTS
            and other.kind is AbstractStringKind.CONSTANTS
        ):
            return self.from_constants(
                self.constants | other.constants, max_constants=limit
            )
        prefixes = []
        for value in (self, other):
            if value.kind is AbstractStringKind.PREFIX:
                prefixes.append(value.prefix or "")
            else:
                prefixes.extend(value.constants)
        prefix = self._common_prefix(prefixes)
        if prefix:
            return AbstractString(
                AbstractStringKind.PREFIX,
                prefix=prefix,
                max_constants=limit,
            )
        return self.top(max_constants=limit)

    def may_contain(self, value: str) -> bool:
        if self.kind is AbstractStringKind.BOTTOM:
            return False
        if self.kind is AbstractStringKind.TOP:
            return True
        if self.kind is AbstractStringKind.CONSTANTS:
            return value in self.constants
        return value.startswith(self.prefix or "")

    @staticmethod
    def _common_prefix(values: Iterable[str]) -> str:
        items = list(values)
        if not items:
            return ""
        prefix = items[0]
        for value in items[1:]:
            while prefix and not value.startswith(prefix):
                prefix = prefix[:-1]
            if not prefix:
                break
        return prefix
