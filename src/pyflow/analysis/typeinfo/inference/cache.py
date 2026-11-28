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
from typing import Any

from pyflow.analysis.cache.summary_cache import SummaryCache, SummaryCacheKey
from pyflow.analysis.typeinfo.core.typesystem import TypeSystem
from pyflow.analysis.typeinfo.inference.models import ModuleInferenceResult
from pyflow.language.environment import AnalysisEnvironment

TYPE_SUMMARY_SCHEMA_VERSION = "type_summary.v1"


def options_fingerprint(options: object) -> str:
    """Stable fingerprint of an ``InferenceOptions`` value."""
    parts = [f"{item.name}={getattr(options, item.name)!r}" for item in fields(options)]
    return hashlib.sha256("\0".join(parts).encode("utf-8")).hexdigest()


def serialize_module_summary(result: ModuleInferenceResult) -> dict[str, Any]:
    """Serialize a module's public type & diagnostic summary to JSON-safe data."""
    return {
        "schema_version": TYPE_SUMMARY_SCHEMA_VERSION,
        "module_name": result.module_name,
        "status": result.status,
        "converged": result.converged,
        "iterations": result.iterations,
        "symbols": {
            name: {
                "type": str(sym.typ) if sym.typ is not None else None,
                "complete": sym.is_complete,
            }
            for name, sym in sorted(result.symbols.items())
        },
        "functions": {
            name: {
                "return_type": str(fn.return_type) if fn.return_type is not None else None,
                "is_async": fn.is_async,
                "is_generator": fn.is_generator,
                "method_kind": fn.method_kind,
            }
            for name, fn in sorted(result.functions.items())
        },
        "diagnostics": [
            d.to_diagnostic(module_name=result.module_name).to_dict() for d in result.diagnostics
        ],
    }


class ProjectInferenceCache:
    """Reusable per-module inference results with optional persistent SummaryCache."""

    def __init__(
        self,
        *,
        type_system: TypeSystem | None = None,
        summary_cache: SummaryCache | None = None,
        environment: AnalysisEnvironment | None = None,
    ) -> None:
        self.type_system = type_system or TypeSystem()
        self.summary_cache = summary_cache
        self.environment = environment or AnalysisEnvironment.current(type_checking=True)
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
        if self.summary_cache is not None:
            env_fp = f"{self.environment.fingerprint()}:{options_key[:16]}"
            cache_key = SummaryCacheKey(
                namespace="type_summary",
                module_name=module_name,
                file_hash=fingerprint,
                env_fingerprint=env_fp,
                dependency_hash=fingerprint,
                schema_version=TYPE_SUMMARY_SCHEMA_VERSION,
            )
            self.summary_cache.put(cache_key, serialize_module_summary(result))

    def get_persisted_summary(
        self,
        module_name: str,
        fingerprint: str,
        options_key: str,
    ) -> dict[str, Any] | None:
        """Return a persisted JSON module type summary from :attr:`summary_cache`."""
        if self.summary_cache is None:
            return None
        env_fp = f"{self.environment.fingerprint()}:{options_key[:16]}"
        cache_key = SummaryCacheKey(
            namespace="type_summary",
            module_name=module_name,
            file_hash=fingerprint,
            env_fingerprint=env_fp,
            dependency_hash=fingerprint,
            schema_version=TYPE_SUMMARY_SCHEMA_VERSION,
        )
        return self.summary_cache.get(cache_key)

    def clear(self) -> None:
        """Drop every cached result."""
        self._entries.clear()
        self.hits = 0
