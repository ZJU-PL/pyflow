"""
Optimization passes for PyFlow static analysis.

This package contains a comprehensive suite of optimization passes that transform
Python code during static analysis to improve performance, reduce code size, and
enable better analysis precision. The optimizations operate on pyflow's intermediate
representation (IR) and are designed to be semantics-preserving.

Optimization Categories:
    - Constant Folding (fold.py): Compile-time evaluation of constant expressions
    - Dead Code Elimination (dce.py): Removal of unreachable and unused code
    - Simplification (simplify.py): Composite pass combining folding and DCE
    - Data Flow Optimizations (dataflow/): Forward/backward data flow analysis
    - Load/Store Elimination: Removal of redundant memory operations
    - Method Call Optimization (methodcall.py): Direct call conversion
    - Code Cloning (clone.py): Context-specific function specialization
    - Code Inlining (codeinlining.py): Function body substitution
    - Term Rewriting (termrewrite.py): Pattern-based code transformations

Optimization Pipeline:
    The optimizations are typically applied in phases:
    1. Analysis Phase: IPA, CPA, lifetime analysis
    2. Simplification Phase: Constant folding, DCE, control flow simplification
    3. Advanced Phase: Method optimization, cloning, inlining
    4. Finalization Phase: Load/store elimination, program culling

All optimizations are designed to preserve program semantics while improving
analysis precision and enabling further optimizations.
"""
