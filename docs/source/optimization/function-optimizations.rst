Function and Method Optimizations
==================================

Transforms function calls and method invocations to improve performance using type information and call graph analysis. Includes inlining, method call optimization, argument normalization, and code cloning.

Function Inlining (codeinlining.py)
------------------------------------

Replaces function calls with function bodies, eliminating call overhead.

Inlining Criteria
~~~~~~~~~~~~~~~~~

- Small size: ≤4 operations (configurable ``maxOps``)
- Few call sites: ≤1 call (configurable ``maxInvokes``)
- No complex features: no returns from loops/try, no ops after return, no *args/**kwargs
- No recursion (checked via call graph)

Context-sensitive: different contexts inlined separately. Prevents recursion via trace tracking. Counts operations to limit code growth. Immediately applies simplification after inlining.

Method Call Optimization (methodcall.py)
----------------------------------------

Converts dynamic method dispatch to direct calls when target is statically known.

Recognizes patterns: ``obj.attr`` → direct access, ``function.__get__()`` → direct function, ``method.__call__()`` → direct call. Eliminates virtual calls when all targets are the same. Handles polymorphism via cloning, type switches, or context unification.

Argument Normalization (argumentnormalization.py)
--------------------------------------------------

Simplifies calling conventions by eliminating *args/**kwargs when possible.

Optimizes default arguments (makes explicit), normalizes keyword to positional arguments, eliminates *args/**kwargs when unused. Enables inlining, eliminates packing/unpacking overhead, enables further optimizations.

Code Cloning (clone.py)
-----------------------

Creates specialized function versions for different calling contexts.

Unifies similar contexts using union-find (reduces duplication), separates different contexts (enables specialization). Decisions based on type information, call patterns, and optimization opportunities.

Limitations
-----------

- **Inlining**: Code size growth, cannot inline recursive/complex functions, limited by *args/**kwargs
- **Method Optimization**: Limited by type precision, struggles with high polymorphism
- **Argument Normalization**: Cannot eliminate when actually used, limited by call site analysis
- **Cloning**: Code size growth, context explosion risk

Performance Impact
------------------

- Inlining: 10-30% speedup (moderate overhead)
- Method optimization: 20-50% speedup (low overhead)
- Argument normalization: 5-15% reduction (low overhead)
- Cloning: 10-40% speedup (can be expensive with many contexts)

Integration
-----------

Works with type analysis (provides info), constant folding (optimizes inlined code), dead code elimination (removes unused clones), and control flow simplification.
