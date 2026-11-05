"""Cross-run cache for project type inference.

A :class:`ProjectInferenceCache` stores ``ModuleInferenceResult`` objects keyed
by a Merkle fingerprint of the module source and the sources of everything it
transitively imports, plus the inference options.  Sharing one cache between
``ProjectTypeInferenceEngine`` runs (LSP snapshots, repeated CLI queries) skips
modules whose dependency closure did not change.

The cache owns the ``TypeSystem`` so cached results reference the same class
descriptors as analyses performed by later runs.
"""

from __future__ import annotations

import hashlib
from dataclasses import fields

from pyflow.analysis.typeinfo.core.typesystem import TypeSystem
from pyflow.analysis.typeinfo.inference.models import ModuleInferenceResult


def options_fingerprint(options: object) -> str:
    """Stable fingerprint of an ``InferenceOptions`` value."""
    parts = [f"{item.name}={getattr(options, item.name)!r}" for item in fields(options)]
    return hashlib.sha256("\0".join(parts).encode("utf-8")).hexdigest()


class ProjectInferenceCache:
    """Reusable per-module inference results."""

    def __init__(self, *, type_system: TypeSystem | None = None) -> None:
        self.type_system = type_system or TypeSystem()
        self._entries: dict[str, tuple[str, ModuleInferenceResult]] = {}
        self.hits = 0

    def get(
        self,
        module_name: str,
        fingerprint: str,
        options_key: str,
    ) -> ModuleInferenceResult | None:
        """Return the cached result when *fingerprint* still matches."""
        entry = self._entries.get(module_name)
        if entry is None:
            return None
        key, result = entry
        if key != f"{fingerprint}:{options_key}":
            return None
        self.hits += 1
        return result

    def put(
        self,
        module_name: str,
        fingerprint: str,
        options_key: str,
        result: ModuleInferenceResult,
    ) -> None:
        """Store (or replace) the result for one module."""
        self._entries[module_name] = (f"{fingerprint}:{options_key}", result)

    def clear(self) -> None:
        """Drop every cached result."""
        self._entries.clear()
        self.hits = 0
