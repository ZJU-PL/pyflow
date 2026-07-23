"""Compatibility exports for the semantic taint detector implementation.

The implementation is split into focused modules for configuration, shared
models, interprocedural orchestration, and local AST analysis.
"""

from ._semantic_taint_config import (
    DEFAULT_SINKS,
    DEFAULT_SOURCES,
    TAINT_SINKS,
    TAINT_SOURCES,
    get_cwe_for_sink,
)
from ._semantic_taint_detector import SemanticTaintDetector
from ._semantic_taint_local import _LocalSemanticTaintAnalyzer
from ._semantic_taint_models import FunctionSummary

__all__ = [
    "DEFAULT_SINKS",
    "DEFAULT_SOURCES",
    "TAINT_SINKS",
    "TAINT_SOURCES",
    "FunctionSummary",
    "SemanticTaintDetector",
    "_LocalSemanticTaintAnalyzer",
    "get_cwe_for_sink",
]
