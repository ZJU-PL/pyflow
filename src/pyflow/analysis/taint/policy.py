"""Shared typed taint policy consumed by IFDS, CPG, and semantic engines."""

from __future__ import annotations

from dataclasses import dataclass, field
from types import MappingProxyType
from typing import FrozenSet, Iterable, Mapping


_SEVERITIES = {"info", "low", "medium", "high", "critical"}


@dataclass(frozen=True)
class TaintRule:
    """One explicit source-kind to sink-kind security policy."""

    rule_id: str
    title: str
    source_kinds: FrozenSet[str]
    sink_kinds: FrozenSet[str]
    severity: str = "medium"
    cwe: str | None = None
    suggestion: str | None = None

    def __post_init__(self) -> None:
        if not self.rule_id.strip():
            raise ValueError("taint rule id must be non-empty")
        if not self.title.strip():
            raise ValueError("taint rule title must be non-empty")
        if not self.source_kinds or not all(self.source_kinds):
            raise ValueError("taint rule must define non-empty source kinds")
        if not self.sink_kinds or not all(self.sink_kinds):
            raise ValueError("taint rule must define non-empty sink kinds")
        if self.severity not in _SEVERITIES:
            raise ValueError(f"unknown taint rule severity: {self.severity!r}")

    def matches(self, source_kind: str, sink_kind: str) -> bool:
        return source_kind in self.source_kinds and sink_kind in self.sink_kinds


@dataclass(frozen=True)
class TaintPolicy:
    """Engine-neutral projection of strict-v2 call models and flow rules."""

    source_kinds_by_call: Mapping[str, FrozenSet[str]] = field(default_factory=dict)
    sink_kinds_by_call: Mapping[str, FrozenSet[str]] = field(default_factory=dict)
    sink_positions_by_call: Mapping[str, FrozenSet[int]] = field(default_factory=dict)
    sink_cwe_by_call: Mapping[str, str] = field(default_factory=dict)
    sink_severity_by_call: Mapping[str, str] = field(default_factory=dict)
    sink_suggestion_by_call: Mapping[str, str] = field(default_factory=dict)
    sanitizer_kinds_by_call: Mapping[str, FrozenSet[str]] = field(default_factory=dict)
    rules: tuple[TaintRule, ...] = ()

    def __post_init__(self) -> None:
        for attribute in (
            "source_kinds_by_call",
            "sink_kinds_by_call",
            "sink_positions_by_call",
            "sink_cwe_by_call",
            "sink_severity_by_call",
            "sink_suggestion_by_call",
            "sanitizer_kinds_by_call",
        ):
            object.__setattr__(
                self,
                attribute,
                MappingProxyType(dict(getattr(self, attribute))),
            )

    @classmethod
    def from_call_models(
        cls,
        call_models: object,
        rules: Iterable[TaintRule],
    ) -> "TaintPolicy":
        mapping = call_models.as_mapping()
        return cls(
            source_kinds_by_call={
                name: model.source_kinds
                for name, model in mapping.items()
                if model.source_kinds
            },
            sink_kinds_by_call={
                name: model.sink_kinds
                for name, model in mapping.items()
                if model.sink_kinds
            },
            sink_positions_by_call={
                name: model.sink_arg_positions
                for name, model in mapping.items()
                if model.sink_kinds
            },
            sink_cwe_by_call={
                name: model.cwe
                for name, model in mapping.items()
                if model.sink_kinds and model.cwe
            },
            sink_severity_by_call={
                name: model.severity
                for name, model in mapping.items()
                if model.sink_kinds and model.severity
            },
            sink_suggestion_by_call={
                name: model.suggestion
                for name, model in mapping.items()
                if model.sink_kinds and model.suggestion
            },
            sanitizer_kinds_by_call={
                name: model.sanitizer_kinds
                for name, model in mapping.items()
                if model.sanitizer_kinds
            },
            rules=tuple(rules),
        )

    @property
    def source_names(self) -> FrozenSet[str]:
        return frozenset(self.source_kinds_by_call)

    @property
    def sink_names(self) -> FrozenSet[str]:
        return frozenset(self.sink_kinds_by_call)

    @staticmethod
    def _resolve_name(mapping: Mapping[str, object], name: str | None) -> str | None:
        if not name:
            return None
        if name in mapping:
            return name
        suffix = f".{name}"
        candidates = [candidate for candidate in mapping if candidate.endswith(suffix)]
        return candidates[0] if len(candidates) == 1 else None

    def source_kinds_for(self, name: str | None) -> FrozenSet[str]:
        key = self._resolve_name(self.source_kinds_by_call, name)
        return self.source_kinds_by_call.get(key, frozenset()) if key else frozenset()

    def sink_kinds_for(self, name: str | None) -> FrozenSet[str]:
        key = self._resolve_name(self.sink_kinds_by_call, name)
        return self.sink_kinds_by_call.get(key, frozenset()) if key else frozenset()

    def sink_positions_for(self, name: str | None) -> FrozenSet[int]:
        key = self._resolve_name(self.sink_positions_by_call, name)
        return self.sink_positions_by_call.get(key, frozenset()) if key else frozenset()

    def sink_cwe_for(self, name: str | None) -> str | None:
        key = self._resolve_name(self.sink_cwe_by_call, name)
        return self.sink_cwe_by_call.get(key) if key else None

    def sink_severity_for(self, name: str | None) -> str | None:
        key = self._resolve_name(self.sink_severity_by_call, name)
        return self.sink_severity_by_call.get(key) if key else None

    def sink_suggestion_for(self, name: str | None) -> str | None:
        key = self._resolve_name(self.sink_suggestion_by_call, name)
        return self.sink_suggestion_by_call.get(key) if key else None

    def sanitizer_kinds_for(self, name: str | None) -> FrozenSet[str]:
        key = self._resolve_name(self.sanitizer_kinds_by_call, name)
        return (
            self.sanitizer_kinds_by_call.get(key, frozenset())
            if key
            else frozenset()
        )

    def matching_rules(
        self,
        source_kinds: Iterable[str],
        sink_kinds: Iterable[str],
    ) -> tuple[TaintRule, ...]:
        source_set = frozenset(source_kinds)
        sink_set = frozenset(sink_kinds)
        return tuple(
            rule
            for rule in self.rules
            if rule.source_kinds & source_set and rule.sink_kinds & sink_set
        )
