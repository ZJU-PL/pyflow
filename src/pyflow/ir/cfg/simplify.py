"""CFG simplification passes.

This module provides simplification passes for control flow graphs,
including dead flow elimination, optimization, and garbage collection.
"""

from pyflow.ir.core import ensure_code_indexed, index_cfg

from . import killflow, optimize, gc
from .revision import CFGTransformTransaction


def evaluate(compiler, g, *, commit_revision=True):
    """Run CFG simplification passes.

    Args:
        compiler: Compiler context for simplification.
        g: CFG graph to simplify.
    """
    transaction = CFGTransformTransaction(g, "cfg-simplify") if commit_revision else None
    killflow.evaluate(compiler, g)
    optimize.evaluate(compiler, g, commit_revision=False)
    gc.evaluate(compiler, g)
    if transaction is not None:
        return transaction.commit()
    if getattr(g, "code", None) is not None:
        catalog = ensure_code_indexed(g.code, rebuild_semantics=False)
        index_cfg(catalog, g, rebuild_semantics=False)
    return None
