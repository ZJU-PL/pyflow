"""Heap selectors, locations, and write descriptors."""

from __future__ import annotations

from dataclasses import dataclass

from .objects import HeapObject
from .policy import UpdatePolicy


@dataclass(frozen=True)
class HeapSelector:
    """One field or element selector below a heap root."""

    kind: str
    value: str
    precise: bool = True

    @classmethod
    def field(cls, name: str) -> "HeapSelector":
        return cls("field", name)

    @classmethod
    def element(cls, subscript: str) -> "HeapSelector":
        return cls("element", subscript)

    @classmethod
    def key(cls, key: str) -> "HeapSelector":
        return cls("key", key)

    @classmethod
    def index(cls, index: int) -> "HeapSelector":
        return cls("index", str(index))

    @classmethod
    def element_type(cls, type_name: str) -> "HeapSelector":
        return cls("element_type", type_name, precise=False)

    @classmethod
    def unknown_field(cls) -> "HeapSelector":
        return cls("field", "*", precise=False)

    @classmethod
    def unknown_element(cls) -> "HeapSelector":
        return cls("element", "[*]", precise=False)

    @classmethod
    def slice(cls) -> "HeapSelector":
        return cls("slice", "[slice]", precise=False)

    @classmethod
    def summary(cls) -> "HeapSelector":
        return cls("summary", "*", precise=False)

    def __repr__(self) -> str:
        kind = self.kind
        if kind == "field":
            return ".*" if not self.precise else f".{self.value}"
        if kind in ("element", "index"):
            return "[*]" if not self.precise else f"[{self.value}]"
        if kind == "key":
            return f"[{self.value!r}]"
        if kind == "element_type":
            return f"[:{self.value}]"
        if kind == "slice":
            return "[:]"
        if kind == "summary":
            return "..."
        return f"HeapSelector({self.kind!r}, {self.value!r})"

    def to_dict(self) -> dict:
        return {
            "kind": self.kind,
            "value": self.value,
            "precise": self.precise,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "HeapSelector":
        return cls(
            kind=data["kind"],
            value=data["value"],
            precise=data.get("precise", True),
        )


@dataclass(frozen=True)
class HeapLocation:
    """Canonical heap location used by IFDS clients.

    Locations are represented as a root plus a path of selectors. This mirrors
    the shape-analysis notion of local/field paths while staying independent of
    the heavier shape engine.
    """

    root: HeapObject
    selectors: tuple[HeapSelector, ...] = ()

    def field(self, name: str) -> "HeapLocation":
        return HeapLocation(
            self.root,
            (*self.selectors, HeapSelector.field(name)),
        )

    def element(self, subscript: str) -> "HeapLocation":
        return HeapLocation(
            self.root,
            (*self.selectors, HeapSelector.element(subscript)),
        )

    def is_nested(self) -> bool:
        return bool(self.selectors)

    def root_location(self) -> "HeapLocation":
        return HeapLocation(self.root)

    def is_prefix_of(self, other: "HeapLocation") -> bool:
        return (
            self.root == other.root
            and len(self.selectors) <= len(other.selectors)
            and other.selectors[: len(self.selectors)] == self.selectors
        )

    def is_precise(self) -> bool:
        return all(selector.precise for selector in self.selectors)

    def __repr__(self) -> str:
        base = repr(self.root)
        if not self.selectors:
            return base
        return base + "".join(repr(s) for s in self.selectors)

    def to_dict(self) -> dict:
        return {
            "root": self.root.to_dict(),
            "selectors": [s.to_dict() for s in self.selectors],
        }


@dataclass(frozen=True)
class HeapWrite:
    """A write target plus its update policy."""

    location: HeapLocation
    policy: UpdatePolicy

    def __repr__(self) -> str:
        return f"HeapWrite({self.location!r}, {self.policy.value})"

    def to_dict(self) -> dict:
        return {
            "location": self.location.to_dict(),
            "policy": self.policy.value,
        }
