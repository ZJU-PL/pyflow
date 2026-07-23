"""Public entry point for semantic taint detection.

The implementation lives in :mod:`._semantic_taint` so this stable import path
stays small and focused on the detector's public surface.
"""

from ._semantic_taint import (
    DEFAULT_SINKS,
    DEFAULT_SOURCES,
    TAINT_SINKS,
    TAINT_SOURCES,
    FunctionSummary,
    SemanticTaintDetector,
    get_cwe_for_sink,
)

__all__ = [
    "DEFAULT_SINKS",
    "DEFAULT_SOURCES",
    "TAINT_SINKS",
    "TAINT_SOURCES",
    "FunctionSummary",
    "SemanticTaintDetector",
    "get_cwe_for_sink",
]
