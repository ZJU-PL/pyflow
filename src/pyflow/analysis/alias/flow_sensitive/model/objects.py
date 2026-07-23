"""Abstract heap-object identities and their metadata."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Callable


RawStorageProvider = Callable[[object, object], tuple[object, ...]]


class HeapObjectKind(str, Enum):
    """Kind of abstract object used as a heap-location root."""

    LOCAL = "local"
    GLOBAL = "global"
    CELL = "cell"
    PARAMETER = "parameter"
    RETURN = "return"
    ALLOCATION = "allocation"
    CALL_RESULT = "call_result"
    EXTERNAL = "external"
    SUMMARY = "summary"
    UNKNOWN = "unknown"
    STORAGE = "storage"


class HeapObjectFreshness(str, Enum):
    """Whether an abstract object is singleton-like or a summary."""

    FRESH = "fresh"
    SUMMARY = "summary"
    UNKNOWN = "unknown"


class HeapObjectCardinality(str, Enum):
    """Number of concrete objects represented by an abstract root."""

    ONE = "one"
    MANY = "many"
    UNKNOWN = "unknown"


class HeapObjectIdentity(str, Enum):
    """Whether repeated uses of a root denote one symbolic identity."""

    SINGLETON = "singleton"
    SYMBOLIC = "symbolic"
    SUMMARY = "summary"


class HeapEscapeState(str, Enum):
    """Coarse escape state for update-policy decisions."""

    LOCAL = "local"
    ESCAPED = "escaped"
    EXTERNAL = "external"
    UNKNOWN = "unknown"


@dataclass(frozen=True)
class HeapObject:
    """Canonical root object for an abstract heap location."""

    kind: HeapObjectKind
    key: object
    label: str
    type_hint: str | None = None
    allocation_site: object | None = None
    context: tuple[object, ...] = ()
    freshness: HeapObjectFreshness = HeapObjectFreshness.FRESH
    cardinality: HeapObjectCardinality = HeapObjectCardinality.UNKNOWN
    identity: HeapObjectIdentity = HeapObjectIdentity.SUMMARY
    escape: HeapEscapeState = HeapEscapeState.LOCAL

    def is_singleton(self) -> bool:
        if self.kind in {
            HeapObjectKind.EXTERNAL,
            HeapObjectKind.SUMMARY,
            HeapObjectKind.UNKNOWN,
        }:
            return False
        if self.cardinality is not HeapObjectCardinality.ONE:
            return False
        return self.escape is HeapEscapeState.LOCAL

    def has_stable_identity(self) -> bool:
        return self.identity in {
            HeapObjectIdentity.SINGLETON,
            HeapObjectIdentity.SYMBOLIC,
        }

    def __repr__(self) -> str:
        return f"HeapObject({self.kind.value}:{self.label})"

    def to_dict(self) -> dict:
        return {
            "kind": self.kind.value,
            "key": (
                repr(self.key)
                if not isinstance(self.key, (str, int, tuple))
                else self.key
            ),
            "label": self.label,
            "type_hint": self.type_hint,
            "allocation_site": (
                repr(self.allocation_site) if self.allocation_site is not None else None
            ),
            "context": [repr(c) for c in self.context],
            "freshness": self.freshness.value,
            "cardinality": self.cardinality.value,
            "identity": self.identity.value,
            "escape": self.escape.value,
        }
