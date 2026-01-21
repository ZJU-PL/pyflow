"""Detector registry for the bug finder."""

from .taint import TaintDetector
from .null_dereference import NullDereferenceDetector
from .leak import LeakDetector

__all__ = ["TaintDetector", "NullDereferenceDetector", "LeakDetector"]
