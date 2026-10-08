"""Public entry point for strict-policy AST dataflow taint detection."""

from ._taint_detector import ASTDataflowTaintDetector
from ._taint_models import (
    FunctionSummary,
    ASTDataflowTaintFinding,
    ASTDataflowTaintResult,
    ASTDataflowTraceStep,
)

__all__ = [
    "FunctionSummary",
    "ASTDataflowTaintDetector",
    "ASTDataflowTaintFinding",
    "ASTDataflowTaintResult",
    "ASTDataflowTraceStep",
]
