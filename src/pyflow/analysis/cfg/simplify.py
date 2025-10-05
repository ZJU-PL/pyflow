"""CFG simplification passes.

This module provides simplification passes for control flow graphs,
including dead flow elimination, optimization, and garbage collection.
"""

from . import killflow, optimize, gc


def evaluate(compiler, g):
    """Run CFG simplification passes.
    
    Args:
        compiler: Compiler context for simplification.
        g: CFG graph to simplify.
    """
    killflow.evaluate(compiler, g)
    optimize.evaluate(compiler, g)
    gc.evaluate(compiler, g)
