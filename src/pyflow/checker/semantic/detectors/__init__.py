"""Detector registry for the bug finder."""

from .taint import TaintDetector
from .misuse import MisuseDetector
from .lifetime import LifetimeEscapeDetector

__all__ = ["TaintDetector", "MisuseDetector", "LifetimeEscapeDetector"]
