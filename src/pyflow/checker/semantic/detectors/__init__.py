"""Detector registry for the semantic analyzer.

Available Detectors:
- SemanticTaintDetector: Production-ready consolidated taint detector
- TaintDetector2: Reference implementation (not currently importable - for study)
- NullDereferenceDetector: Detects null pointer dereferences
- LeakDetector: Detects resource leaks

Note: TaintDetector2 is preserved for studying PyFlow's infrastructure
(IPA, StoreGraph, fixed-point iteration) but has import issues.
"""

from .semantic_taint import SemanticTaintDetector
from .null_dereference import NullDereferenceDetector
from .leak import LeakDetector

__all__ = [
    "SemanticTaintDetector",  # Production use
    "NullDereferenceDetector",
    "LeakDetector",
]
