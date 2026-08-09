"""Declarative access-path registry for security-sensitive Python objects."""

from __future__ import annotations

from dataclasses import dataclass
from fnmatch import fnmatchcase
import json
from pathlib import Path
from typing import Iterable

from .model import CapabilityOperation
from .effects import ExternalEffectKind, ExternalEffectSummary


@dataclass(frozen=True)
class CapabilityPattern:
    access_path: str
    operation: CapabilityOperation
    capability: str
    category: str
    runtime_guarded: bool = False

    @property
    def static_prefix(self) -> str:
        wildcard_positions = [
            pos for token in ("*", "?", "[") if (pos := self.access_path.find(token)) >= 0
        ]
        if not wildcard_positions:
            return self.access_path
        return self.access_path[: min(wildcard_positions)].rstrip(".")


class CapabilityRegistry:
    def __init__(
        self,
        patterns: Iterable[CapabilityPattern] = (),
        effects: Iterable[ExternalEffectSummary] = (),
    ) -> None:
        self._patterns = tuple(patterns)
        self._effects = tuple(effects)

    @property
    def patterns(self) -> tuple[CapabilityPattern, ...]:
        return self._patterns

    @property
    def effects(self) -> tuple[ExternalEffectSummary, ...]:
        return self._effects

    @classmethod
    def from_json(cls, path: str | Path) -> "CapabilityRegistry":
        """Load a versioned declarative capability model."""
        source = Path(path)
        payload = json.loads(source.read_text(encoding="utf-8"))
        if payload.get("schema_version") != 1:
            raise ValueError(f"unsupported capability schema in {source}")
        patterns = []
        for entry in payload.get("patterns", ()):
            operation = CapabilityOperation(entry["operation"])
            for access_path in entry["access_paths"]:
                patterns.append(
                    CapabilityPattern(
                        access_path=access_path,
                        operation=operation,
                        capability=entry["capability"],
                        category=entry.get("category", entry["capability"].split(".", 1)[0]),
                        runtime_guarded=bool(entry.get("runtime_guarded", False)),
                    )
                )
        effects = []
        for entry in payload.get("effects", ()):
            kind = ExternalEffectKind(entry["kind"])
            arguments = tuple(entry.get("arguments", ()))
            for access_path in entry["access_paths"]:
                effects.append(ExternalEffectSummary(access_path, kind, arguments))
        return cls(patterns, effects)

    def extended(self, other: "CapabilityRegistry") -> "CapabilityRegistry":
        """Return a registry with project-specific patterns appended."""
        return CapabilityRegistry(
            (*self._patterns, *other.patterns),
            (*self._effects, *other.effects),
        )

    def effects_for(self, access_path: str) -> tuple[ExternalEffectSummary, ...]:
        return tuple(effect for effect in self._effects if effect.matches(access_path))

    def match(
        self,
        access_path: str,
        operation: CapabilityOperation,
    ) -> tuple[CapabilityPattern, ...]:
        return tuple(
            pattern
            for pattern in self._patterns
            if pattern.operation is operation
            and fnmatchcase(access_path, pattern.access_path)
        )

    def reachable(self, access_path: str) -> tuple[CapabilityPattern, ...]:
        """Return capabilities obtainable from a sensitive or carrier object."""
        prefix = access_path.removesuffix(".<return>")
        matches = []
        for pattern in self._patterns:
            static = pattern.static_prefix
            if (
                fnmatchcase(prefix, pattern.access_path)
                or static == prefix
                or static.startswith(prefix + ".")
                or prefix.startswith(static + ".")
            ):
                matches.append(pattern)
        return tuple(matches)


__all__ = ["CapabilityPattern", "CapabilityRegistry"]
