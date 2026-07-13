"""Pointer analysis module for PythonStAn.

This module provides k-CFA pointer analysis capabilities integrated
with the PythonStAn analysis framework.
"""

# Import from refactored k-CFA implementation
from .kcfa import PointerAnalysis, Config, AnalysisResult

# Create alias for backwards compatibility
PointerAnalysisDriver = PointerAnalysis

__all__ = [
    "PointerAnalysis",
    "PointerAnalysisDriver",
    "Config",
    "AnalysisResult"
]
