Advanced Optimizations
=======================

Sophisticated transformations requiring deep program analysis: call conversion, boolean elimination, term rewriting, and general code rewriting.

Call Conversion (callconverter.py)
-----------------------------------

Optimizes built-in/library/FFI calls: converts builtins to direct operations (e.g., ``len([1,2,3])`` → ``3``), specializes library calls (e.g., ``math.sqrt(4.0)`` → ``2.0``), optimizes FFI calls with direct calls and argument marshalling.

Boolean Conversion Elimination (convertboolelimination.py)
----------------------------------------------------------

Removes unnecessary ``bool()`` conversions: eliminates redundant conversions for already-boolean values, always-boolean expressions (e.g., ``bool(x == y)`` → ``x == y``), and conditional simplifications (e.g., ``if bool(x): return True else False`` → ``return x``).

Term Rewriting (termrewrite.py)
--------------------------------

Performs algebraic simplifications and expression normalization: ``x * 0 → 0``, ``x * 1 → x``, ``x + 0 → x``, ``x / 1 → x``. Normalizes expressions (e.g., ``(a + b) + c → a + b + c``). Rewrites method calls to direct calls when target known. Applies commutativity, associativity, distributivity, and identity element optimizations.

Code Rewriting Framework (rewrite.py)
--------------------------------------

General pattern-based transformation framework. Supports AST pattern matching, safe transformation application (preserves semantics, updates annotations), and integration with simplification. Used by load/store elimination, dead code elimination, and custom optimizations.

Limitations
-----------

- **Call Conversion**: Cannot optimize dynamic calls, limited by type precision
- **Boolean Elimination**: Must preserve truthiness semantics, some conversions necessary
- **Term Rewriting**: Limited rewrite rules, careful with floating point
- **Code Rewriting**: Must preserve semantics, may miss opportunities

Performance Impact
------------------

- Call conversion: 5-20% speedup (builtin-heavy code)
- Boolean elimination: 2-5% overhead reduction
- Term rewriting: 5-15% speedup
- Code rewriting: varies by transformation

Operates in polynomial time. Works with type analysis, constant folding, data flow, and control flow optimizations.

Best Practices
--------------

Most effective with many builtins, redundant operations, rewritable patterns, and precise type info. Can configure rewrite rules, complexity limits, and code size growth. Use ``--dump`` flags for debugging.
