"""Detector registry for the semantic analyzer.

Available Detectors:
- SemanticTaintDetector: Production-ready consolidated taint detector
"""

from .semantic_taint import SemanticTaintDetector

__all__ = [
    "SemanticTaintDetector",  # Production use
]
