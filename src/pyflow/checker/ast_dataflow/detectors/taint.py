"""Public entry point for strict-policy AST dataflow taint detection."""

from ._taint_detector import ASTDataflowTaintDetector
from ._taint_models import (
    FunctionSummary,
    ASTDataflowTaintDiagnostic,
    ASTDataflowTaintFinding,
    ASTDataflowTaintResult,
)

__all__ = [
    "FunctionSummary",
    "ASTDataflowTaintDiagnostic",
    "ASTDataflowTaintDetector",
    "ASTDataflowTaintFinding",
    "ASTDataflowTaintResult",
]
