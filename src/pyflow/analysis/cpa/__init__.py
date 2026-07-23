"""Constraint-based interprocedural analysis.

The implementation lives in :mod:`pyflow.analysis.cpa.engine`; this package
exports the small, supported entry-point surface used by the analysis pipeline.
"""

from .engine import (
    InterproceduralDataflow,
    evaluate,
    evaluateWithImage,
    foldFunctionIR,
)

__all__ = [
    "InterproceduralDataflow",
    "evaluate",
    "evaluateWithImage",
    "foldFunctionIR",
]
