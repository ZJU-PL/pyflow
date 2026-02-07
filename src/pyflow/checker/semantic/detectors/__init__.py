"""Detector registry for the semantic analyzer.

Available Detectors:
- SemanticTaintDetector: Consolidated taint detector with full features
- TaintDetector2: Reference implementation using PyFlow's IPA infrastructure
- NullDereferenceDetector: Detects potential null pointer dereferences
- LeakDetector: Detects resource leaks

Use SemanticTaintDetector for production. Use TaintDetector2 to study
PyFlow's analysis infrastructure (IPA, StoreGraph, etc.).
"""

from .semantic_taint import SemanticTaintDetector
from .taint2 import TaintDetector2  # Reference: PyFlow infrastructure usage
from .null_dereference import NullDereferenceDetector
from .leak import LeakDetector

__all__ = [
    "SemanticTaintDetector",  # Production use
    "TaintDetector2",          # Reference only
    "NullDereferenceDetector",
    "LeakDetector",
]
