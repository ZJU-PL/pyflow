"""
Simplification Pass for PyFlow.

This module provides a high-level simplification pass that combines constant
folding and dead code elimination to simplify and optimize code.

The simplification pass:
- Leverages type inference to eliminate indirect calls
- Folds and propagates constants
- Eliminates dead code
- In effect, attempts to "de-dynamicize" Python by making it more static

This is a composite optimization that orchestrates multiple simpler optimizations.
"""

from . import fold
from . import dce
from pyflow.optimization.dataflow.base import InternalError

from io import StringIO
from pyflow.language.python.simplecodegen import SimpleCodeGen

from pyflow.language.python import ast

#
# Leverages type inference to eliminate indirect calls,
# fold and propigate constants, etc.
# In effect, this pass attempts to "de-dynamicize" Python
#


def evaluateCode(compiler, prgm, node, outputAnchors=None):
    """Simplify a single code node.
    
    Args:
        compiler: Compiler context
        prgm: Program being optimized
        node: Code node to simplify
        outputAnchors: Optional output anchors for DCE
        
    Performs constant folding followed by dead code elimination.
    """
    assert node.isCode(), type(node)

    try:
        fold.evaluateCode(compiler, prgm, node)

        # Can't process arbitrary abstract code nodes.
        if node.isStandardCode():
            dce.evaluateCode(compiler, node, outputAnchors)

    except InternalError:
        print()
        print("#######################################")
        print("Function generated an internal error...")
        print("#######################################")
        sio = StringIO()
        scg = SimpleCodeGen(sio)
        scg.process(node)
        print(sio.getvalue())
        raise


def evaluate(compiler, prgm):
    """Main entry point for simplification pass.
    
    Args:
        compiler: Compiler context
        prgm: Program to simplify
        
    Applies simplification to all live code in the program.
    """
    with compiler.console.scope("simplify"):
        for code in prgm.liveCode:
            if not code.annotation.descriptive:
                evaluateCode(compiler, prgm, code)
