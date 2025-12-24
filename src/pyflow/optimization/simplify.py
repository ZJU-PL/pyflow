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
    """
    Simplify a single code node by applying constant folding and DCE.
    
    This function applies the simplification pass to a single code node,
    which consists of:
    1. Constant folding: Evaluate constant expressions at compile time
    2. Dead code elimination: Remove unreachable and unused code
    
    The two passes are applied in sequence because:
    - Constant folding creates new opportunities for DCE (e.g., folding
      conditionals can make branches unreachable)
    - DCE removes code that folding couldn't optimize
    
    Args:
        compiler: Compiler instance with extractor and other components
        prgm: Program being optimized (may be None)
        node: Code node to simplify
        outputAnchors: Optional set of output anchors for DCE liveness
                      analysis (variables that must be considered live)
        
    Raises:
        InternalError: If an internal error occurs during optimization
                      (prints the code for debugging)
    """
    assert node.isCode(), type(node)

    try:
        # Step 1: Constant folding
        fold.evaluateCode(compiler, prgm, node)

        # Step 2: Dead code elimination (only for standard code)
        # Can't process arbitrary abstract code nodes.
        if node.isStandardCode():
            dce.evaluateCode(compiler, node, outputAnchors)

    except InternalError:
        # Print the code for debugging when internal errors occur
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
    """
    Main entry point for the simplification pass.
    
    Applies simplification (constant folding + DCE) to all live code in
    the program. Descriptive code is skipped as it represents detailed
    behavioral information that should be preserved.
    
    Args:
        compiler: Compiler instance
        prgm: Program to simplify
        
    The simplification pass is typically run early in the optimization
    pipeline to create opportunities for later optimizations.
    """
    with compiler.console.scope("simplify"):
        for code in prgm.liveCode:
            # Skip descriptive code (preserve behavioral information)
            if not code.annotation.descriptive:
                evaluateCode(compiler, prgm, code)
