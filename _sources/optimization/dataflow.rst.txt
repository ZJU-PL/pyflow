Data Flow Optimizations
========================

Data flow optimizations analyze value flow and eliminate redundant memory operations, crucial for performance in loops and hot paths.

Overview
--------

Framework components:

- **base.py**: Lattice structures (``top``, ``bottom``, ``undefined``), meet functions, transfer function base classes
- **forward.py**: Reaching definitions, constant propagation, available expressions (iterative fixed-point, SSA support)
- **reverse.py**: Live variables, reaching uses, dead code detection

Load Elimination (loadelimination.py)
--------------------------------------

Removes redundant memory reads when values are already available.

How It Works
~~~~~~~~~~~~

1. Converts to SSA form for precise tracking
2. Uses dominance analysis for safe elimination
3. Creates signatures based on memory location, SSA version, and fields
4. Forwards values from stores to subsequent loads
5. Eliminates common subexpressions

Example
~~~~~~~

.. code-block:: python

   # Before: x = obj.field; y = obj.field  # Redundant
   # After:  x = obj.field; y = x  # Forwarded
   
   # Store-load forwarding: obj.field = v; result = obj.field → result = v

Dead Store Elimination (storeelimination.py)
---------------------------------------------

Removes memory writes that are never read before being overwritten or object destruction.

How It Works
~~~~~~~~~~~~

1. Live variable analysis identifies live memory locations
2. Collects all store operations
3. Marks stores as dead if location never read and object doesn't leak
4. Removes dead stores via code rewriting

Performs whole-program analysis tracking reads across functions, considering object lifetime. Reports statistics: "Total stores analyzed: 1000, eliminated: 250 (25.0%)"

Limitations
-----------

- **Load Elimination**: Conservative with uncertain aliasing, requires SSA form, limited without path sensitivity
- **Store Elimination**: Cannot eliminate stores with side effects, conservative about liveness, limited by inter-procedural precision

Performance Impact
------------------

Reduces memory operations by 20-40% in typical programs. Load elimination reduces memory traffic (especially in loops), store elimination reduces writes and cache pollution. Operates in polynomial time.

Integration
-----------

Works best with constant folding (creates more constants), dead code elimination (removes dead stores/loads), inlining (more opportunities), and cloning (improves precision).
