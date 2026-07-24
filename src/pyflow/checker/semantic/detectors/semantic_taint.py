"""Public entry point for strict-policy semantic taint detection."""

from ._semantic_taint_detector import SemanticTaintDetector
from ._semantic_taint_models import FunctionSummary

__all__ = [
    "FunctionSummary",
    "SemanticTaintDetector",
]
