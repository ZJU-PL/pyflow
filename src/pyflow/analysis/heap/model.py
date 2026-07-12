"""Heap abstraction data model — enums, types, and dataclasses.

This module defines the canonical heap objects, locations, selectors,
policies, and write descriptors shared by the heap abstraction engine
(:mod:`.abstraction`), effect extraction (:mod:`.heap_effects`), and
IFDS clients.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Callable

from .intrinsics import CALL_RETURN_COPY, DEFAULT_HEAP_INTRINSICS


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


class HeapEscapeState(str, Enum):
    """Coarse escape state for update-policy decisions."""

    LOCAL = "local"
    ESCAPED = "escaped"
    EXTERNAL = "external"
    UNKNOWN = "unknown"


class AllocationSensitivity(str, Enum):
    """Static allocation-site partitioning policy."""

    NONE = "none"
    SITE = "site"
    PROCEDURE = "procedure"
    CONTEXT = "context"


class FieldSensitivity(str, Enum):
    """Static field selector precision policy."""

    NONE = "none"
    NAMED_FIELDS = "named_fields"
    BOUNDED_PATH = "bounded_path"


class ContainerSensitivity(str, Enum):
    """Static container selector precision policy."""

    NONE = "none"
    WILDCARD = "wildcard"
    LITERAL_KEYS = "literal_keys"
    BOUNDED_INDICES = "bounded_indices"


class UpdatePolicy(str, Enum):
    """Whether a write can replace prior facts or must join with them."""

    STRONG = "strong"
    WEAK = "weak"


@dataclass(frozen=True)
class HeapPolicy:
    """Fixed precision policy for IFDS heap abstraction.

    The policy is selected before solving and is intentionally not refined by
    the solver.  It controls how abstract objects and selectors are partitioned
    and which locations are singleton enough for strong updates.
    """

    allocation_sensitivity: AllocationSensitivity = AllocationSensitivity.SITE
    field_sensitivity: FieldSensitivity = FieldSensitivity.NAMED_FIELDS
    container_sensitivity: ContainerSensitivity = ContainerSensitivity.LITERAL_KEYS
    max_selector_depth: int | None = 3
    max_index: int = 8
    context_sensitivity_depth: int = 0
    recency: bool = True
    allow_strong_nested_fresh: bool = False
    bind_call_results: bool = True
    track_escapes: bool = True
    escape_on_unresolved_call: bool = True
    escape_on_return: bool = True
    fresh_return_names: frozenset[str] = frozenset()
    summary_return_names: frozenset[str] = frozenset()
    copy_return_names: frozenset[str] = frozenset(
        name
        for name, kind in DEFAULT_HEAP_INTRINSICS.return_kinds.items()
        if kind == CALL_RETURN_COPY
    )
    treat_capitalized_calls_as_fresh: bool = True
    immutable_type_hints: frozenset[str] = frozenset(
        {"int", "str", "float", "bool", "bytes", "tuple", "frozenset",
         "complex", "NoneType", "ellipsis", "range", "slice",
         "datetime.datetime", "datetime.date", "datetime.time", "datetime.timedelta",
         "pathlib.PurePath", "pathlib.PurePosixPath", "pathlib.PureWindowsPath",
         "decimal.Decimal", "fractions.Fraction",
         "enum.Enum",
         "ipaddress.IPv4Address", "ipaddress.IPv6Address",
         "uuid.UUID",
         "re.Pattern"}
    )

    # ── factory presets ──────────────────────────────────────────────

    @classmethod
    def precise(cls) -> "HeapPolicy":
        return cls(
            allocation_sensitivity=AllocationSensitivity.CONTEXT,
            field_sensitivity=FieldSensitivity.NAMED_FIELDS,
            container_sensitivity=ContainerSensitivity.LITERAL_KEYS,
            max_selector_depth=None,
            context_sensitivity_depth=2,
            recency=True,
            allow_strong_nested_fresh=True,
        )

    @classmethod
    def fast(cls) -> "HeapPolicy":
        return cls(
            allocation_sensitivity=AllocationSensitivity.SITE,
            field_sensitivity=FieldSensitivity.NONE,
            container_sensitivity=ContainerSensitivity.NONE,
            recency=False,
            track_escapes=False,
            escape_on_unresolved_call=False,
            escape_on_return=False,
            treat_capitalized_calls_as_fresh=False,
        )

    @classmethod
    def field_insensitive(cls) -> "HeapPolicy":
        return cls(field_sensitivity=FieldSensitivity.NONE)

    @classmethod
    def bounded_path(cls, *, max_depth: int = 3) -> "HeapPolicy":
        return cls(
            field_sensitivity=FieldSensitivity.BOUNDED_PATH,
            max_selector_depth=max_depth,
        )

    @classmethod
    def context_sensitive(cls, *, depth: int = 2) -> "HeapPolicy":
        return cls(
            allocation_sensitivity=AllocationSensitivity.CONTEXT,
            context_sensitivity_depth=depth,
        )

    # ── serialization ────────────────────────────────────────────────

    def to_dict(self) -> dict:
        return {
            "allocation_sensitivity": self.allocation_sensitivity.value,
            "field_sensitivity": self.field_sensitivity.value,
            "container_sensitivity": self.container_sensitivity.value,
            "max_selector_depth": self.max_selector_depth,
            "max_index": self.max_index,
            "context_sensitivity_depth": self.context_sensitivity_depth,
            "recency": self.recency,
            "allow_strong_nested_fresh": self.allow_strong_nested_fresh,
            "bind_call_results": self.bind_call_results,
            "track_escapes": self.track_escapes,
            "escape_on_unresolved_call": self.escape_on_unresolved_call,
            "escape_on_return": self.escape_on_return,
            "fresh_return_names": sorted(self.fresh_return_names),
            "summary_return_names": sorted(self.summary_return_names),
            "copy_return_names": sorted(self.copy_return_names),
            "treat_capitalized_calls_as_fresh": self.treat_capitalized_calls_as_fresh,
            "immutable_type_hints": sorted(self.immutable_type_hints),
        }

    @classmethod
    def from_dict(cls, data: dict) -> "HeapPolicy":
        defaults = cls()
        policy = cls(
            allocation_sensitivity=AllocationSensitivity(data["allocation_sensitivity"]),
            field_sensitivity=FieldSensitivity(data["field_sensitivity"]),
            container_sensitivity=ContainerSensitivity(data["container_sensitivity"]),
            max_selector_depth=data.get("max_selector_depth"),
            max_index=data.get("max_index", 8),
            context_sensitivity_depth=data.get("context_sensitivity_depth", 0),
            recency=data.get("recency", True),
            allow_strong_nested_fresh=data.get("allow_strong_nested_fresh", False),
            bind_call_results=data.get("bind_call_results", True),
            track_escapes=data.get("track_escapes", True),
            escape_on_unresolved_call=data.get("escape_on_unresolved_call", True),
            escape_on_return=data.get("escape_on_return", True),
            fresh_return_names=frozenset(
                data.get("fresh_return_names", defaults.fresh_return_names)
            ),
            summary_return_names=frozenset(
                data.get("summary_return_names", defaults.summary_return_names)
            ),
            copy_return_names=frozenset(
                data.get("copy_return_names", defaults.copy_return_names)
            ),
            treat_capitalized_calls_as_fresh=data.get(
                "treat_capitalized_calls_as_fresh", True
            ),
            immutable_type_hints=frozenset(
                data.get("immutable_type_hints", defaults.immutable_type_hints)
            ),
        )
        policy.validate()
        return policy

    def validate(self) -> None:
        """Raise ValueError if the policy contains incompatible settings."""
        if (
            self.field_sensitivity is FieldSensitivity.BOUNDED_PATH
            and self.max_selector_depth is None
        ):
            raise ValueError(
                "field_sensitivity=BOUNDED_PATH requires max_selector_depth "
                "to be set (not None)"
            )
        if self.max_selector_depth is not None and self.max_selector_depth < 0:
            raise ValueError(
                f"max_selector_depth must be >= 0, got {self.max_selector_depth}"
            )
        if self.max_index < 0:
            raise ValueError(f"max_index must be >= 0, got {self.max_index}")
        if self.context_sensitivity_depth < 0:
            raise ValueError(
                f"context_sensitivity_depth must be >= 0, "
                f"got {self.context_sensitivity_depth}"
            )


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
    escape: HeapEscapeState = HeapEscapeState.LOCAL

    def is_singleton(self) -> bool:
        if self.kind in {
            HeapObjectKind.EXTERNAL,
            HeapObjectKind.SUMMARY,
            HeapObjectKind.UNKNOWN,
        }:
            return False
        if self.freshness is not HeapObjectFreshness.FRESH:
            return False
        return self.escape is HeapEscapeState.LOCAL

    def __repr__(self) -> str:
        return f"HeapObject({self.kind.value}:{self.label})"

    def to_dict(self) -> dict:
        return {
            "kind": self.kind.value,
            "key": repr(self.key) if not isinstance(self.key, (str, int, tuple)) else self.key,
            "label": self.label,
            "type_hint": self.type_hint,
            "allocation_site": repr(self.allocation_site) if self.allocation_site is not None else None,
            "context": [repr(c) for c in self.context],
            "freshness": self.freshness.value,
            "escape": self.escape.value,
        }


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
        return {"kind": self.kind, "value": self.value, "precise": self.precise}

    @classmethod
    def from_dict(cls, data: dict) -> "HeapSelector":
        return cls(kind=data["kind"], value=data["value"], precise=data.get("precise", True))


@dataclass(frozen=True)
class HeapLocation:
    """Canonical heap location used by IFDS clients.

    Locations are represented as a root plus a path of selectors.  This mirrors
    the shape-analysis notion of local/field paths while staying independent of
    the heavier shape engine.
    """

    root: HeapObject
    selectors: tuple[HeapSelector, ...] = ()

    def field(self, name: str) -> "HeapLocation":
        return HeapLocation(self.root, (*self.selectors, HeapSelector.field(name)))

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
        return {"location": self.location.to_dict(), "policy": self.policy.value}
