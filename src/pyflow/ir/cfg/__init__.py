"""Control Flow Graph (CFG) analysis for PyFlow.

This package provides comprehensive control flow graph construction, analysis,
and transformation capabilities for Python programs.

Key components:
- CFG construction from AST with control flow handling
- Dominance analysis and dominance frontiers
- Static Single Assignment (SSA) form construction
- Structural analysis for loops and control structures
- CFG transformations and optimizations
- Dead code elimination and code motion
- Graph algorithms for CFG manipulation

The CFG module is primarily used for:
- Program optimization and transformation
- Data flow analysis foundations
- Control dependence analysis
- Loop analysis and optimization
- Dead code elimination
"""

from . import (
    transform,
    graph,
    dom,
    ssa,
    ssatransform,
    structuralanalysis,
    optimize,
    simplify,
    inline,
    gc,
    dfs,
    dump,
    expandphi,
    killflow,
    verifier,
)

from .verifier import CFGVerificationError, verify_cfg

__all__ = ["CFGVerificationError", "verify_cfg"]
