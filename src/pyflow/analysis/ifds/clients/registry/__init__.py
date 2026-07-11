"""Framework-aware rule pack registry.

Provides lazy-loaded, framework-aware call models for IFDS analyses.
Packs are JSON files in this directory, each describing sources, sinks,
sanitizers, nullness, and typestate behavior for a specific framework.
"""

from .loader import Registry, load_registry

__all__ = ["Registry", "load_registry"]
