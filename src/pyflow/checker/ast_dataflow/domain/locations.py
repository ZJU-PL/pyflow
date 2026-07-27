"""Canonical access-path locations for AST dataflow taint facts.

The taint domain deliberately keeps its location representation independent of
the frontend.  Source-AST analysis can construct locations directly while the
PyFlow heap adapter can translate ``HeapLocation`` instances into the same
selector algebra.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from math import gcd
from typing import Hashable, Iterable, cast


class SelectorKind(str, Enum):
    """Kinds of Python object access retained by the abstraction."""

    ATTRIBUTE = "attribute"
    KEY = "key"
    INDEX = "index"
    INDEX_CLASS = "index-class"
    ITERABLE_ELEMENT = "iterable-element"
    MAPPING_KEY = "mapping-key"
    MAPPING_VALUE = "mapping-value"
    WILDCARD = "wildcard"


@dataclass(frozen=True, order=True)
class AccessSelector:
    """One selector in a bounded object access path."""

    kind: SelectorKind
    value: Hashable | None = None

    @classmethod
    def attribute(cls, name: str) -> "AccessSelector":
        return cls(SelectorKind.ATTRIBUTE, name)

    @classmethod
    def key(cls, value: Hashable) -> "AccessSelector":
        return cls(SelectorKind.KEY, value)

    @classmethod
    def index(cls, value: int) -> "AccessSelector":
        return cls(SelectorKind.INDEX, value)

    @classmethod
    def wildcard(cls) -> "AccessSelector":
        return cls(SelectorKind.WILDCARD)

    @classmethod
    def mapping_key(cls) -> "AccessSelector":
        return cls(SelectorKind.MAPPING_KEY, "<key>")

    @classmethod
    def index_class(cls, modulus: int, residue: int) -> "AccessSelector":
        if modulus <= 0:
            raise ValueError("index-class modulus must be positive")
        return cls(SelectorKind.INDEX_CLASS, (modulus, residue % modulus))

    @property
    def is_precise(self) -> bool:
        return (
            self.kind
            not in {
                SelectorKind.WILDCARD,
                SelectorKind.INDEX_CLASS,
            }
            and self.value is not None
        )

    def may_match(self, other: "AccessSelector") -> bool:
        if self.kind is SelectorKind.WILDCARD or other.kind is SelectorKind.WILDCARD:
            return True
        if self.kind is SelectorKind.INDEX_CLASS and other.kind is SelectorKind.INDEX:
            modulus, residue = self.index_class_parts()
            return cast(int, other.value) % modulus == residue
        if self.kind is SelectorKind.INDEX and other.kind is SelectorKind.INDEX_CLASS:
            return other.may_match(self)
        if (
            self.kind is SelectorKind.INDEX_CLASS
            and other.kind is SelectorKind.INDEX_CLASS
        ):
            left_modulus, left_residue = self.index_class_parts()
            right_modulus, right_residue = other.index_class_parts()
            return (left_residue - right_residue) % gcd(
                left_modulus, right_modulus
            ) == 0
        return self == other

    def index_class_parts(self) -> tuple[int, int]:
        """Return the validated modulus/residue pair for an index class."""

        if self.kind is not SelectorKind.INDEX_CLASS:
            raise ValueError("selector is not an index class")
        value = cast(tuple[int, int], self.value)
        return value


@dataclass(frozen=True, order=True)
class TaintLocation:
    """An abstract storage root followed by zero or more selectors."""

    root: Hashable
    selectors: tuple[AccessSelector, ...] = ()

    def select(self, selector: AccessSelector) -> "TaintLocation":
        return TaintLocation(self.root, (*self.selectors, selector))

    def attribute(self, name: str) -> "TaintLocation":
        return self.select(AccessSelector.attribute(name))

    def key(self, value: Hashable) -> "TaintLocation":
        return self.select(AccessSelector.key(value))

    def index(self, value: int) -> "TaintLocation":
        return self.select(AccessSelector.index(value))

    def wildcard(self) -> "TaintLocation":
        return self.select(AccessSelector.wildcard())

    def index_class(self, modulus: int, residue: int) -> "TaintLocation":
        return self.select(AccessSelector.index_class(modulus, residue))

    @property
    def is_precise(self) -> bool:
        return all(selector.is_precise for selector in self.selectors)

    def is_prefix_of(self, other: "TaintLocation") -> bool:
        """Whether this location conservatively contains ``other``."""

        if self.root != other.root or len(self.selectors) > len(other.selectors):
            return False
        return all(
            left.may_match(right)
            for left, right in zip(self.selectors, other.selectors)
        )

    def may_overlap(self, other: "TaintLocation") -> bool:
        """Whether the two access paths may denote overlapping storage."""

        if self.root != other.root:
            return False
        return all(
            left.may_match(right)
            for left, right in zip(self.selectors, other.selectors)
        )

    def descendants(self, selectors: Iterable[AccessSelector]) -> "TaintLocation":
        return TaintLocation(self.root, (*self.selectors, *tuple(selectors)))

    def summarize(self, max_selectors: int) -> "TaintLocation":
        """Widen a deep path to a wildcard summary at a finite depth."""

        if max_selectors < 1:
            raise ValueError("access-path bound must be positive")
        if len(self.selectors) <= max_selectors:
            return self
        prefix = self.selectors[: max_selectors - 1]
        return TaintLocation(self.root, (*prefix, AccessSelector.wildcard()))

    def render(self) -> str:
        rendered = str(self.root)
        for selector in self.selectors:
            if selector.kind is SelectorKind.ATTRIBUTE:
                rendered += f".{selector.value}"
            elif selector.kind is SelectorKind.INDEX:
                rendered += f"[{selector.value}]"
            elif selector.kind is SelectorKind.INDEX_CLASS:
                modulus, residue = selector.index_class_parts()
                rendered += f"[i % {modulus} = {residue}]"
            elif selector.kind is SelectorKind.KEY:
                rendered += f"[{selector.value!r}]"
            elif selector.kind is SelectorKind.WILDCARD:
                rendered += "[*]"
            else:
                rendered += f".<{selector.kind.value}>"
        return rendered
