"""Framework-aware lazy rule-pack loader.

Loads JSON rule packs on demand based on framework detection via import
string matching.  Packs are cached per process — each is parsed once.

Usage::

    from pyflow.analysis.ifds.clients.registry import load_registry

    registry = load_registry()
    registry.detect(["from flask import Flask", "open('file')"])
    models = registry.active_models()
"""

from __future__ import annotations

import json
import logging
from functools import lru_cache
from pathlib import Path
from typing import FrozenSet, Iterable, Mapping, Sequence

from .._call_model import STATE_CLOSE, STATE_OPEN, STATE_USE, CallModel, CallModelRegistry

_log = logging.getLogger(__name__)

_REGISTRY_DIR = Path(__file__).parent


class RulePack:
    """A single framework rule pack loaded from a JSON file."""

    def __init__(self, data: dict) -> None:
        self.framework: str = data.get("framework", "unknown")
        self.description: str = data.get("description", "")
        self.detection: dict = data.get("detection", {})
        self._models_data: list[dict] = data.get("models", [])

    @property
    def detection_imports(self) -> tuple[str, ...]:
        return tuple(self.detection.get("imports", ()))

    @property
    def detection_patterns(self) -> tuple[str, ...]:
        return tuple(self.detection.get("patterns", ()))

    def matches(self, source_lines: Iterable[str]) -> bool:
        """Return True when *source_lines* indicate this framework is used."""
        text = "\n".join(source_lines)
        for imp in self.detection_imports:
            if imp in text:
                return True
        for pat in self.detection_patterns:
            if pat in text:
                return True
        return False

    def to_call_models(self) -> tuple[CallModel, ...]:
        models: list[CallModel] = []
        for entry in self._models_data:
            name = entry.get("call", "")
            if not name:
                continue
            models.append(
                CallModel(
                    name=name,
                    taint_source=entry.get("taint_source", False),
                    taint_sink=entry.get("taint_sink", False),
                    taint_sanitizer=entry.get("taint_sanitizer", False),
                    nullness_nullable_return=entry.get(
                        "nullness_nullable_return", False
                    ),
                    typestate_actions=_parse_typestate(entry),
                    resource_arg_positions=frozenset(
                        entry.get("resource_arg_positions", [0])
                    ),
                    track_method_receiver=entry.get("track_method_receiver", True),
                )
            )
        return tuple(models)


def _parse_typestate(entry: dict) -> FrozenSet[str]:
    actions: set[str] = set()
    if entry.get("typestate_open"):
        actions.add(STATE_OPEN)
    if entry.get("typestate_close"):
        actions.add(STATE_CLOSE)
    if entry.get("typestate_use"):
        actions.add(STATE_USE)
    return frozenset(actions)


@lru_cache(maxsize=1)
def _available_packs() -> tuple[RulePack, ...]:
    packs: list[RulePack] = []
    for path in sorted(_REGISTRY_DIR.glob("*.json")):
        try:
            data = json.loads(path.read_text())
            packs.append(RulePack(data))
        except Exception:
            _log.debug("Failed to load rule pack %s", path.name, exc_info=True)
    return tuple(packs)


class Registry:
    """Lazy-loaded, framework-aware call model registry.

    Packs are loaded from JSON files in the ``registry/`` directory.
    Detection runs on source text; matching packs are activated and
    their models merged into a single ``CallModelRegistry``.
    """

    def __init__(self) -> None:
        self._active_packs: list[RulePack] = []
        self._detected: set[str] = set()

    def detect(self, source_lines: Iterable[str]) -> FrozenSet[str]:
        """Scan *source_lines* for framework markers and activate matching packs."""
        lines = tuple(source_lines)
        for pack in _available_packs():
            if pack.framework in self._detected:
                continue
            if pack.matches(lines):
                self._detected.add(pack.framework)
                self._active_packs.append(pack)
        return frozenset(self._detected)

    def activate(self, *framework_names: str) -> None:
        """Explicitly activate packs by framework name."""
        for pack in _available_packs():
            if pack.framework in framework_names and pack.framework not in self._detected:
                self._detected.add(pack.framework)
                self._active_packs.append(pack)

    def activate_all(self) -> None:
        """Activate every available pack (for exhaustive analysis)."""
        for pack in _available_packs():
            if pack.framework not in self._detected:
                self._detected.add(pack.framework)
                self._active_packs.append(pack)

    @property
    def detected_frameworks(self) -> FrozenSet[str]:
        return frozenset(self._detected)

    def active_models(self) -> CallModelRegistry:
        """Return a ``CallModelRegistry`` merging all active packs."""
        models: list[CallModel] = []
        for pack in self._active_packs:
            models.extend(pack.to_call_models())
        return CallModelRegistry(models)

    def as_config(
        self,
        *,
        extra_sources: Iterable[str] = (),
        extra_sinks: Iterable[str] = (),
        extra_sanitizers: Iterable[str] = (),
    ):
        """Build a ``TaintConfiguration`` from active models.

        Intended as a drop-in for programmatic ``TaintConfiguration``
        construction.  Only the taint-related fields are populated.
        """
        from ...clients.taint import TaintConfiguration

        models = self.active_models()
        mapping = models.as_mapping()
        sources: set[str] = set(extra_sources)
        sinks: set[str] = set(extra_sinks)
        sanitizers: set[str] = set(extra_sanitizers)
        for name, model in mapping.items():
            if model.taint_source:
                sources.add(name)
            if model.taint_sink:
                sinks.add(name)
            if model.taint_sanitizer:
                sanitizers.add(name)
        return TaintConfiguration(
            source_names=frozenset(sources),
            sink_names=frozenset(sinks),
            sanitizer_names=frozenset(sanitizers),
        )


def load_registry() -> Registry:
    """Return the singleton process-wide registry."""
    return Registry()
