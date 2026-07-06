# MEMORY_LEAK Synthetic Test Suite

## Bug Type: MEMORY_LEAK

**Definition**: Unbounded memory growth where allocated objects are retained indefinitely without bounds or cleanup, leading to exhaustion of available memory.

## Test Coverage

### True Positives (5 test cases - code that SHOULD be flagged as MEMORY_LEAK)

1. **tp_01_unbounded_list_growth.py**
   - Pattern: Global list accumulates data in loop without bound
   - Semantic: `global_accumulator` grows indefinitely (1M iterations × 1K elements)
   - Detection: Symbolic execution should detect unbounded growth in global state

2. **tp_02_circular_reference_gc_prevention.py**
   - Pattern: Circular references between objects prevent garbage collection
   - Semantic: Node pairs reference each other, forming cycles with large data payloads
   - Detection: Cycle detector should flag unreachable circular structures

3. **tp_03_global_cache_without_cleanup.py**
   - Pattern: Global cache dictionary accumulates without eviction policy
   - Semantic: Cache grows with every unique key (100K keys × 1K elements each)
   - Detection: Unbounded dictionary growth in global state

4. **tp_04_event_handlers_never_removed.py**
   - Pattern: Event handlers registered but never unregistered
   - Semantic: Handler list grows, each capturing large closure context
   - Detection: Collection growth without corresponding removal operations

5. **tp_05_closure_capture_large_context.py**
   - Pattern: Closures capture large data and are retained in global list
   - Semantic: Each closure retains 10K element array, 10K closures total
   - Detection: Unbounded closure list with captured contexts

### True Negatives (5 test cases - SAFE code that should NOT be flagged)

1. **tn_01_bounded_buffer_max_size.py**
   - Pattern: Buffer with explicit max size, evicts old items
   - Semantic: Collection size capped at 1000 items (LRU eviction)
   - Proof: `len(buffer) ≤ max_size` is maintained invariant

2. **tn_02_weakref_proper_usage.py**
   - Pattern: Weak references don't prevent garbage collection
   - Semantic: Cache entries can be collected when no strong refs exist
   - Proof: Weakrefs don't contribute to reachability set

3. **tn_03_context_scoped_allocations.py**
   - Pattern: Allocations within function scope are freed on return
   - Semantic: Local `data` list is deallocated after each `process_batch` call
   - Proof: Stack-scoped allocations have bounded lifetime

4. **tn_04_handler_proper_cleanup.py**
   - Pattern: Event handlers explicitly cleared after use
   - Semantic: `emitter.clear()` removes all handler references
   - Proof: Final state has empty handler list

5. **tn_05_lru_cache_eviction.py**
   - Pattern: LRU cache with eviction policy
   - Semantic: Cache maintains `capacity` bound via `popitem` on overflow
   - Proof: `len(cache) ≤ capacity` maintained after each `put`

## Semantic Model Requirements

### Unsafe Region: MEMORY_LEAK

For a state `σ` with heap `H` and time `t`:

```
Unsafe_MEMORY_LEAK(σ) ≡ ∃ object o ∈ H. 
  (reachable(o, σ) ∧ 
   size(reachable_set(σ)) → ∞ as t → ∞ ∧
   ¬∃ cleanup_op that bounds growth)
```

### Detection Strategy

1. **Static bounded growth analysis**: Track collection operations (append, insert, add) vs removal operations (pop, remove, clear)
2. **Invariant synthesis**: For collections, check if `len(c) ≤ K` for some constant K
3. **Cycle detection**: Identify circular reference patterns that prevent GC
4. **Scope analysis**: Distinguish heap-allocated vs stack-scoped lifetime
5. **Contract modeling**: Unknown library calls default to "may allocate unboundedly"

### Key Challenges

- **Unbounded loops**: `while True` or very large iteration counts complicate symbolic execution
- **Garbage collection**: Python's GC can reclaim cycles, but analyzer must be conservative
- **Context sensitivity**: Need to distinguish local vs global allocations
- **Unknown calls**: Libraries may allocate (e.g., `json.loads`) - requires contracts

## Expected Analyzer Behavior

- **TRUE POSITIVES**: Report `BUG` with witness trace showing unbounded growth
- **TRUE NEGATIVES**: Report `SAFE` with proof of bounded invariant OR `UNKNOWN` if proof synthesis fails
- **NO FALSE POSITIVES**: Must not flag bounded/scoped allocations
- **NO FALSE NEGATIVES**: Must flag clear unbounded accumulation patterns

## Validation

Run analyzer on this suite and verify:
- True Positive Rate: 5/5 = 100% (all bugs detected)
- True Negative Rate: 5/5 = 100% (no false alarms)
- Precision: TP/(TP+FP) = 100%
- Recall: TP/(TP+FN) = 100%
