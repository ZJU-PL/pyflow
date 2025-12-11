Control Flow Optimizations
===========================

Simplifies program structure by removing unnecessary branches, merging basic blocks, and eliminating unreachable code. Includes control flow simplification, program culling, and dead code elimination.

Control Flow Simplification (simplify.py)
-------------------------------------------

Performs basic block merging, jump optimization, conditional simplification, and unreachable code removal:

.. code-block:: python

   # Merges blocks with single successor/predecessor
   # Removes unnecessary jumps
   # Simplifies: if True: return x → return x
   # Removes code after unconditional returns

Program Culling (cullprogram.py)
---------------------------------

Whole-program optimization removing unused functions, classes, and modules.

How It Works
~~~~~~~~~~~~

1. Live code analysis identifies called functions
2. Tracks function contexts
3. Removes unused functions/contexts
4. Optimizes imports

Relies on call graph, context-sensitive analysis, and type information to determine reachability.

Dead Code Elimination (dce.py)
-------------------------------

Removes unused assignments and unreachable blocks. Preserves operations with side effects. Uses liveness analysis, use-definition chains, and reaching definitions.

Example: ``DEBUG = False`` with conditional debug prints → debug code removed. Loops with constant false conditions → conditions removed.

Limitations
-----------

Limited without path-sensitive analysis, conservative about side effects, cannot optimize runtime-dependent code.

Performance Impact
------------------

Reduces code size by 10-30%, improves cache locality, faster execution via better branch prediction. Operates in linear time.

Integration
-----------

Works with constant folding (enables branch elimination), inlining (more simplification opportunities), cloning (specializes paths), and data flow analysis (provides liveness info).
