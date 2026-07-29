"""CFG simplification passes.

This module provides simplification passes for control flow graphs,
including dead flow elimination, optimization, and garbage collection.
"""

from . import killflow, optimize, gc
from .revision import CFGTransformTransaction


def evaluate(compiler, g, *, commit_revision=True):
    """Run CFG simplification passes.

    Args:
        compiler: Compiler context for simplification.
        g: CFG graph to simplify.
    """
    transaction = (
        CFGTransformTransaction(g, "cfg-simplify") if commit_revision else None
    )
    killflow.evaluate(compiler, g)
    optimize.evaluate(compiler, g, commit_revision=False)
    gc.evaluate(compiler, g)
    return transaction.commit() if transaction is not None else None
