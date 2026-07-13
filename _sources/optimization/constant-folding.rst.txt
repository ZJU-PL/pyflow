Constant Folding and Propagation
==================================

Constant folding evaluates constant expressions at compile time, replacing them with their computed values. This reduces runtime overhead and enables further optimizations.

Overview
--------

The ``fold.py`` module implements constant folding using:

- **FoldRewrite**: AST rewriting pass that replaces constant expressions
- **FoldAnalysis**: Forward data flow analysis tracking constant values
- **FoldTraverse**: Traversal framework for applying transformations

How It Works
~~~~~~~~~~~~

1. Identifies compile-time constants using ``existingConstant()`` checks
2. Uses forward data flow analysis to track constants through assignments
3. Evaluates binary/unary operations and built-in functions
4. Replaces variable references with their constant values when known

Example Transformations
------------------------

.. code-block:: python

   # Arithmetic: 2 + 3 → 5, x * 4 → 20
   # Strings: "Hello" + " " + "World" → "Hello World"
   # Booleans: if True and x → if x
   # Propagation: PI * radius → 3.14159 * 5 (when constants known)

Implementation Details
----------------------

Uses forward data flow analysis from ``dataflow/forward.py``:
- Lattice with ``top`` (unknown) and ``undefined`` values
- Meet function: intersection of constant sets
- Transfer functions: assignments propagate, operations evaluate when operands constant

Special optimizations: float multiplication by 0/1/-1, addition with 0, identity operations.

Dead Code Elimination (dce.py)
-------------------------------

Removes unreachable code and unused assignments:

- Code after unconditional returns
- Unused variable assignments
- Unreachable branches (e.g., ``if False:``)

The ``simplify.py`` module orchestrates both: first folds constants, then eliminates dead code. This ordering is important as constant folding creates new dead code opportunities.

Limitations
-----------

- Cannot fold runtime-dependent expressions
- Does not eliminate operations with side effects
- May be conservative due to data flow analysis precision
- Limited without path-sensitive analysis

Performance Impact
------------------

Eliminates runtime computation, reduces code size, and enables further optimizations. Operates in linear time relative to program size.
