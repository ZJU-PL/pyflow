"""Detector registry for the AST dataflow analyzer.

Available Detectors:
- ASTDataflowTaintDetector: Production-ready consolidated taint detector
"""

from .taint import ASTDataflowTaintDetector

__all__ = [
    "ASTDataflowTaintDetector",  # Production use
]
