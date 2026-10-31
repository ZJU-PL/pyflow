"""Declarative access-path registry for security-sensitive Python objects."""

from __future__ import annotations

from dataclasses import dataclass
from functools import lru_cache
import json
from pathlib import Path
import re
from typing import Iterable

from .model import CapabilityOperation
from .effects import ExternalEffectKind, ExternalEffectSummary


@lru_cache(maxsize=1024)
def _compile_pattern(pattern: str) -> re.Pattern[str]:
    """Compile an access path pattern into a regex that respects dot delimiters."""
    if pattern.endswith(".*"):
        base = pattern[:-2]
        base_regex = re.escape(base).replace(r"\*", r"[^.]*")
        return re.compile(rf"^{base_regex}(\..+)?$")
    parts = pattern.split(".")
    regex_parts = [re.escape(part).replace(r"\*", r"[^.]*") for part in parts]
    return re.compile(r"^" + r"\.".join(regex_parts) + r"$")


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
            and _compile_pattern(pattern.access_path).match(access_path)
        )

    def reachable(self, access_path: str) -> tuple[CapabilityPattern, ...]:
        """Approximate potential capabilities using access-path prefixes.

        This is a syntactic over-approximation, not proof that a member exists
        or that the recipient can exercise the corresponding operation.
        """
        # ``<return>`` marks a value produced by the modelled operation (an
        # open file, a socket, a urlopen response).  Such a value carries the
        # capability of the operation that produced it, so the suffix is
        # transparent for the reachability query.
        origins = [access_path]
        if ".<return>" in access_path:
            stripped = access_path
            while ".<return>" in stripped:
                stripped = stripped.replace(".<return>", "")
            origins.append(stripped)
        matches = []
        for pattern in self._patterns:
            compiled = _compile_pattern(pattern.access_path)
            static = pattern.static_prefix
            for origin in origins:
                if (
                    compiled.match(origin)
                    or static == origin
                    or static.startswith(origin + ".")
                    or (pattern.access_path.endswith(".*") and origin.startswith(static + "."))
                ):
                    matches.append(pattern)
                    break
        return tuple(matches)


__all__ = ["CapabilityPattern", "CapabilityRegistry"]
