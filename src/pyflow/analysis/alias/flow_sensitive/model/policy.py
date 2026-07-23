"""Precision and update policies for the flow-sensitive heap model."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

from ..semantics.intrinsics import CALL_RETURN_COPY, DEFAULT_HEAP_INTRINSICS


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
    the solver. It controls how abstract objects and selectors are partitioned
    and which locations are singleton enough for strong updates.
    """

    allocation_sensitivity: AllocationSensitivity = AllocationSensitivity.SITE
    field_sensitivity: FieldSensitivity = FieldSensitivity.NAMED_FIELDS
    container_sensitivity: ContainerSensitivity = ContainerSensitivity.LITERAL_KEYS
    max_selector_depth: int | None = 3
    max_index: int = 8
    context_sensitivity_depth: int = 0
    recency: bool = True
    allow_strong_nested_fresh: bool = True
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
        {
            "int",
            "str",
            "float",
            "bool",
            "bytes",
            "tuple",
            "frozenset",
            "complex",
            "NoneType",
            "ellipsis",
            "range",
            "slice",
            "datetime.datetime",
            "datetime.date",
            "datetime.time",
            "datetime.timedelta",
            "pathlib.PurePath",
            "pathlib.PurePosixPath",
            "pathlib.PureWindowsPath",
            "decimal.Decimal",
            "fractions.Fraction",
            "enum.Enum",
            "ipaddress.IPv4Address",
            "ipaddress.IPv6Address",
            "uuid.UUID",
            "re.Pattern",
        }
    )

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
            "treat_capitalized_calls_as_fresh": (self.treat_capitalized_calls_as_fresh),
            "immutable_type_hints": sorted(self.immutable_type_hints),
        }

    @classmethod
    def from_dict(cls, data: dict) -> "HeapPolicy":
        defaults = cls()
        policy = cls(
            allocation_sensitivity=AllocationSensitivity(
                data["allocation_sensitivity"]
            ),
            field_sensitivity=FieldSensitivity(data["field_sensitivity"]),
            container_sensitivity=ContainerSensitivity(data["container_sensitivity"]),
            max_selector_depth=data.get("max_selector_depth"),
            max_index=data.get("max_index", 8),
            context_sensitivity_depth=data.get("context_sensitivity_depth", 0),
            recency=data.get("recency", True),
            allow_strong_nested_fresh=data.get("allow_strong_nested_fresh", True),
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
                "max_selector_depth must be >= 0, " f"got {self.max_selector_depth}"
            )
        if self.max_index < 0:
            raise ValueError(f"max_index must be >= 0, got {self.max_index}")
        if self.context_sensitivity_depth < 0:
            raise ValueError(
                f"context_sensitivity_depth must be >= 0, "
                f"got {self.context_sensitivity_depth}"
            )
