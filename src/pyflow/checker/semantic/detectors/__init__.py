"""Detector registry for the bug finder."""

from .taint import TaintDetector
from .hazards import HazardsDetector
from .leak import LeakDetector

__all__ = ["TaintDetector", "HazardsDetector", "LeakDetector"]
