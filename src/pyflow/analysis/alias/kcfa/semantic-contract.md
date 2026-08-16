# k-CFA Semantic Contract

The k-CFA engine is a sound **may-analysis** for the Python subset it models.
Its public results and internal extensions must obey these rules:

1. A points-to set contains every modeled abstract target that may reach the
   queried location. An empty set means “no target is currently known”; it does
   not by itself prove that the concrete value is impossible.
2. A negative alias answer is valid only when the relevant query is complete.
   Unsupported behavior must flow to affected values/effects and completeness
   metadata, rather than existing only as a global diagnostic.
3. Kernel state grows monotonically. Solver scheduling (FIFO, LIFO, or any fair
   randomized order) may affect performance, never the fixed-point result.
4. A `must` fact may only come from a stable structural proof. It must not be
   inferred from a points-to set being temporarily empty or non-empty.
5. Abstract-object interning is owned by one analysis run. Concurrent or
   re-entrant runs must never reinterpret another run's points-to bits.

These are correctness requirements, not optional precision goals. A model may
conservatively return extra targets or an incomplete result; it may not silently
drop a feasible modeled target.
