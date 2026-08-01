"""Shared typed taint policy consumed by IFDS, CPG, and semantic engines."""

from __future__ import annotations

from dataclasses import dataclass, field
from types import MappingProxyType
from typing import FrozenSet, Iterable, Mapping

from pyflow.analysis.entrypoints import EntryPointDefaults


_SEVERITIES = {"info", "low", "medium", "high", "critical"}


def call_name_suffix_matches(qualified: str, alias: str) -> bool:
    """Match an ordinary shortened spelling against a qualified call name."""
    return qualified == alias or qualified.endswith(f".{alias}")


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
    sink_behavior_by_call: Mapping[str, str] = field(default_factory=dict)
    sanitizer_kinds_by_call: Mapping[str, FrozenSet[str]] = field(default_factory=dict)
    rules: tuple[TaintRule, ...] = ()
    entry_point_defaults: EntryPointDefaults = EntryPointDefaults()

    def __post_init__(self) -> None:
        for attribute in (
            "source_kinds_by_call",
            "sink_kinds_by_call",
            "sink_positions_by_call",
            "sink_cwe_by_call",
            "sink_severity_by_call",
            "sink_suggestion_by_call",
            "sink_behavior_by_call",
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
        entry_point_defaults: EntryPointDefaults | None = None,
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
            sink_behavior_by_call={
                name: model.sink_behavior
                for name, model in mapping.items()
                if model.sink_kinds and model.sink_behavior
            },
            sanitizer_kinds_by_call={
                name: model.sanitizer_kinds
                for name, model in mapping.items()
                if model.sanitizer_kinds
            },
            rules=tuple(rules),
            entry_point_defaults=entry_point_defaults or EntryPointDefaults(),
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
        candidates = [
            candidate
            for candidate in mapping
            if call_name_suffix_matches(candidate, name)
        ]
        if len(candidates) == 1:
            return candidates[0]
        if candidates:
            first = mapping[candidates[0]]
            if all(mapping[candidate] == first for candidate in candidates[1:]):
                return candidates[0]
        return None

    @staticmethod
    def _matching_names(
        mapping: Mapping[str, object], name: str | None
    ) -> tuple[str, ...]:
        if not name:
            return ()
        if name in mapping:
            return (name,)
        matches = tuple(
            candidate
            for candidate in mapping
            if call_name_suffix_matches(candidate, name)
        )
        if matches:
            return matches
        leaf = name.rsplit(".", 1)[-1]
        return tuple(
            candidate for candidate in mapping if candidate.rsplit(".", 1)[-1] == leaf
        )

    def source_kinds_for(self, name: str | None) -> FrozenSet[str]:
        keys = self._matching_names(self.source_kinds_by_call, name)
        return frozenset(
            kind for key in keys for kind in self.source_kinds_by_call[key]
        )

    def sink_kinds_for(self, name: str | None) -> FrozenSet[str]:
        keys = self._matching_names(self.sink_kinds_by_call, name)
        return frozenset(kind for key in keys for kind in self.sink_kinds_by_call[key])

    def sink_positions_for(self, name: str | None) -> FrozenSet[int]:
        keys = self._matching_names(self.sink_positions_by_call, name)
        return frozenset(
            position for key in keys for position in self.sink_positions_by_call[key]
        )

    def sink_cwe_for(self, name: str | None) -> str | None:
        # An exact sink model without CWE metadata intentionally leaves the
        # classification unspecified (for example ``json.loads``). Do not
        # borrow metadata from an unrelated API that merely shares its leaf
        # name. For an unresolved receiver such as ``c.execute``, however,
        # consistent metadata across all leaf candidates is conservative.
        if name in self.sink_kinds_by_call and name not in self.sink_cwe_by_call:
            return None
        key = self._resolve_name(self.sink_cwe_by_call, name)
        if key:
            return self.sink_cwe_by_call[key]
        if not name:
            return None
        leaf = name.rsplit(".", 1)[-1]
        values = {
            value
            for candidate, value in self.sink_cwe_by_call.items()
            if candidate.rsplit(".", 1)[-1] == leaf
        }
        return next(iter(values)) if len(values) == 1 else None

    def sink_severity_for(self, name: str | None) -> str | None:
        key = self._resolve_name(self.sink_severity_by_call, name)
        return self.sink_severity_by_call.get(key) if key else None

    def sink_suggestion_for(self, name: str | None) -> str | None:
        key = self._resolve_name(self.sink_suggestion_by_call, name)
        return self.sink_suggestion_by_call.get(key) if key else None

    def sink_behavior_for(self, name: str | None) -> str | None:
        key = self._resolve_name(self.sink_behavior_by_call, name)
        return self.sink_behavior_by_call.get(key) if key else None

    def sanitizer_kinds_for(self, name: str | None) -> FrozenSet[str]:
        key = self._resolve_name(self.sanitizer_kinds_by_call, name)
        return (
            self.sanitizer_kinds_by_call.get(key, frozenset()) if key else frozenset()
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
