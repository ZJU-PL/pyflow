"""Shared typed taint policy consumed by IFDS, CPG, and semantic engines."""

from __future__ import annotations

from dataclasses import dataclass, field
from types import MappingProxyType
from typing import FrozenSet, Iterable, Mapping

from pyflow.analysis.entrypoints import EntryPointDefaults

_SEVERITIES = {"info", "low", "medium", "high", "critical"}


def call_name_suffix_matches(qualified: str, alias: str) -> bool:
    """Match an ordinary shortened spelling against a qualified call name."""
    # A leaf such as ``items`` or ``__init__`` provides no evidence about
    # the receiver's library. Imported aliases are resolved by the frontend;
    # shortened qualified spellings still retain their receiver component.
    return (
        qualified == alias
        or ("." in alias and qualified.endswith(f".{alias}"))
        or ("." in qualified and alias.endswith(f".{qualified}"))
    )


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
    entrypoint_source: bool = True

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
    modeled_call_names: FrozenSet[str] = frozenset()

    def __post_init__(self) -> None:
        suffix_indexes: dict[int, dict[str, tuple[str, ...]]] = {}
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
            proxy = MappingProxyType(dict(getattr(self, attribute)))
            object.__setattr__(self, attribute, proxy)
            by_suffix: dict[str, list[str]] = {}
            for key in proxy:
                dot = key.find(".")
                while dot != -1:
                    suffix = key[dot + 1 :]
                    if "." in suffix:
                        by_suffix.setdefault(suffix, []).append(key)
                    dot = key.find(".", dot + 1)
            suffix_indexes[id(proxy)] = {suffix: tuple(keys) for suffix, keys in by_suffix.items()}
        object.__setattr__(self, "_suffix_indexes", suffix_indexes)
        object.__setattr__(self, "_match_cache", {})
        object.__setattr__(self, "_resolve_cache", {})

    @classmethod
    def from_call_models(
        cls,
        call_models: object,
        rules: Iterable[TaintRule],
        entry_point_defaults: EntryPointDefaults | None = None,
    ) -> "TaintPolicy":
        mapping = call_models.as_mapping()
        return cls(
            modeled_call_names=frozenset(mapping),
            source_kinds_by_call={
                name: model.source_kinds for name, model in mapping.items() if model.source_kinds
            },
            sink_kinds_by_call={
                name: model.sink_kinds for name, model in mapping.items() if model.sink_kinds
            },
            sink_positions_by_call={
                name: model.sink_arg_positions
                for name, model in mapping.items()
                if model.sink_kinds
            },
            sink_cwe_by_call={
                name: model.cwe for name, model in mapping.items() if model.sink_kinds and model.cwe
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

    def _suffix_candidates(self, mapping: Mapping[str, object], name: str) -> tuple[str, ...]:
        if "." not in name:
            return ()
        suffix_indexes = getattr(self, "_suffix_indexes", None)
        by_suffix = suffix_indexes.get(id(mapping)) if suffix_indexes is not None else None
        if by_suffix is None:
            return tuple(
                candidate for candidate in mapping if call_name_suffix_matches(candidate, name)
            )
        found: list[str] = []
        seen: set[str] = set()
        # Case 1: qualified in mapping ends with "." + name
        for candidate in by_suffix.get(name, ()):
            if candidate not in seen:
                seen.add(candidate)
                found.append(candidate)
        # Case 2: name ends with "." + qualified (where qualified has ".")
        dot = name.find(".")
        while dot != -1:
            suffix = name[dot + 1 :]
            if "." in suffix and suffix in mapping and suffix not in seen:
                seen.add(suffix)
                found.append(suffix)
            dot = name.find(".", dot + 1)
        return tuple(found)

    def _resolve_name(self, mapping: Mapping[str, object], name: str | None) -> str | None:
        if not name:
            return None
        if name in mapping:
            return name
        if "." not in name:
            return None
        cache = getattr(self, "_resolve_cache", None)
        cache_key = (id(mapping), name)
        if cache is not None and cache_key in cache:
            return cache[cache_key]
        candidates = self._suffix_candidates(mapping, name)
        result: str | None = None
        if len(candidates) == 1:
            result = candidates[0]
        elif candidates:
            first = mapping[candidates[0]]
            if all(mapping[candidate] == first for candidate in candidates[1:]):
                result = candidates[0]
        if cache is not None:
            if len(cache) >= 8192:
                cache.clear()
            cache[cache_key] = result
        return result

    def _matching_names(self, mapping: Mapping[str, object], name: str | None) -> tuple[str, ...]:
        if not name:
            return ()
        if name in mapping:
            return (name,)
        # A known pure call must not borrow source/sink semantics from a
        # different library that happens to use the same method name.
        if name in self.modeled_call_names:
            return ()
        if "." not in name:
            return ()
        cache = getattr(self, "_match_cache", None)
        cache_key = (id(mapping), name)
        if cache is not None and cache_key in cache:
            return cache[cache_key]
        matches = self._suffix_candidates(mapping, name)
        if cache is not None:
            if len(cache) >= 8192:
                cache.clear()
            cache[cache_key] = matches
        return matches

    def source_kinds_for(self, name: str | None) -> FrozenSet[str]:
        keys = self._matching_names(self.source_kinds_by_call, name)
        return frozenset(kind for key in keys for kind in self.source_kinds_by_call[key])

    def sink_kinds_for(self, name: str | None) -> FrozenSet[str]:
        keys = self._matching_names(self.sink_kinds_by_call, name)
        return frozenset(kind for key in keys for kind in self.sink_kinds_by_call[key])

    def sink_positions_for(self, name: str | None) -> FrozenSet[int]:
        keys = self._matching_names(self.sink_positions_by_call, name)
        return frozenset(position for key in keys for position in self.sink_positions_by_call[key])

    def sink_cwe_for(self, name: str | None) -> str | None:
        # An exact sink model without CWE metadata intentionally leaves the
        # classification unspecified (for example ``json.loads``). Do not
        # borrow metadata from an unrelated API that merely shares its leaf
        # name. Unresolved receivers do not establish a library identity.
        if (
            name in self.modeled_call_names or name in self.sink_kinds_by_call
        ) and name not in self.sink_cwe_by_call:
            return None
        key = self._resolve_name(self.sink_cwe_by_call, name)
        if key:
            return self.sink_cwe_by_call[key]
        return None

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
        return self.sanitizer_kinds_by_call.get(key, frozenset()) if key else frozenset()

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
