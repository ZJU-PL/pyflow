# DEADLOCK Synthetic Test Suite

**Bug Type**: DEADLOCK  
**Definition**: A situation where two or more threads are blocked forever, each waiting for the other to release a resource.

## Test Coverage

### True Positives (5 tests - MUST be detected as BUG)

1. **tp_01_circular_lock_acquisition.py**
   - Classic AB-BA deadlock pattern
   - Thread 1: acquires A → tries B
   - Thread 2: acquires B → tries A
   - Expected: DEADLOCK detected with circular wait dependency

2. **tp_02_self_deadlock_non_reentrant.py**
   - Self-deadlock on non-reentrant Lock
   - Single thread tries to acquire same Lock twice (recursive call)
   - Expected: DEADLOCK detected (Lock is not reentrant)

3. **tp_03_condition_wait_with_held_lock.py**
   - Condition variable wait while holding another lock
   - Thread 1: holds A, waits on condition (needs B)
   - Thread 2: holds B (condition lock), tries A
   - Expected: DEADLOCK detected with inter-thread coordination failure

4. **tp_04_three_way_deadlock.py**
   - Three-way circular deadlock (A→B→C→A)
   - Three threads create circular dependency
   - Expected: DEADLOCK detected with multi-thread cycle

5. **tp_05_nested_lock_acquisition_mixed_order.py**
   - Nested lock acquisition with inconsistent ordering
   - Function 1: acquires A→B→C
   - Function 2: acquires C→B→A (reverse order)
   - Expected: DEADLOCK detected with conflicting lock orderings

### True Negatives (5 tests - MUST NOT be flagged as bugs)

1. **tn_01_consistent_lock_ordering.py**
   - Consistent lock ordering across all threads
   - All threads acquire A before B (same order)
   - Expected: SAFE - consistent ordering prevents circular wait

2. **tn_02_rlock_reentrant_safe.py**
   - RLock allows reentrant acquisition
   - Same thread can safely acquire RLock multiple times
   - Expected: SAFE - RLock is designed for reentrant use

3. **tn_03_timeout_based_acquisition.py**
   - Timeout-based lock acquisition with fallback
   - Uses lock.acquire(timeout=...) to avoid indefinite blocking
   - Expected: SAFE - timeout prevents indefinite deadlock

4. **tn_04_single_lock_all_resources.py**
   - Single lock protects all shared resources
   - No circular wait possible with only one lock
   - Expected: SAFE - single lock eliminates circular dependency

5. **tn_05_queue_based_coordination.py**
   - Lock-free coordination using Queue
   - Producer-consumer pattern with internally synchronized Queue
   - Expected: SAFE - Queue coordination is deadlock-free

## Semantic Model Requirements

### Unsafe Predicate Definition

A program state σ exhibits DEADLOCK iff:

```
∃ threads T = {t₁, t₂, ..., tₙ} where:
  ∀ tᵢ ∈ T: tᵢ is blocked waiting for resource Rᵢ
  ∀ tᵢ ∈ T: Rᵢ is held by t_{(i+1) mod n}
  (circular wait condition)
```

### Key Semantic Features

1. **Lock acquisition tracking**
   - Model lock identity and ownership
   - Track which thread holds which locks
   - Track lock acquisition order per thread

2. **Wait-for graph construction**
   - Nodes: threads and locks
   - Edges: "thread T waits for lock L" and "lock L held by thread T'"
   - Cycle detection: deadlock iff wait-for graph contains cycle

3. **Lock types**
   - `threading.Lock`: non-reentrant (same thread cannot re-acquire)
   - `threading.RLock`: reentrant (same thread can re-acquire)
   - `threading.Condition`: wraps a lock, requires acquisition for wait/notify

4. **Temporal analysis**
   - Must reason about concurrent execution paths
   - Lock ordering across multiple threads
   - Potential for circular wait (not just actual observed deadlock in one trace)

### Z3 Encoding Strategy

1. **Static lock ordering analysis**
   - Extract lock acquisition order from each thread/function
   - Build lock precedence graph
   - Check for cycles in precedence graph across threads

2. **Dynamic symbolic execution**
   - Model thread interleavings
   - Track lock acquisition/release events
   - Detect circular wait conditions in explored paths

3. **Lock-set analysis**
   - For each program point, compute possible held locks
   - Check for nested acquisitions and ordering conflicts

### Proof Strategy (SAFE cases)

1. **Consistent ordering proof**
   - Show total ordering on locks respected by all threads
   - No cycles possible in wait-for graph

2. **Single lock proof**
   - Show all critical sections use same lock
   - No circular dependency possible

3. **Bounded waiting proof**
   - Show timeouts or other mechanisms prevent indefinite blocking
   - Fallback paths exist when locks unavailable

## Anti-Cheating Constraints

❌ **FORBIDDEN**:
- Pattern matching for `Lock()` vs `RLock()` in source
- Regex detection of "thread1" and "thread2" naming
- Heuristics based on sleep() calls or thread count
- Declaring SAFE because no deadlock observed in one execution

✅ **REQUIRED**:
- Proper lock identity and ownership tracking in machine state
- Wait-for graph construction and cycle detection
- Lock ordering analysis across all threads
- Reachability analysis of circular wait conditions
- For SAFE: proof that lock ordering prevents cycles OR timeout mechanisms exist

## Validation Protocol

Run each test through the analyzer:

```bash
python -m pyfromscratch.cli --analyze tests/synthetic_suite/DEADLOCK/tp_*.py
python -m pyfromscratch.cli --analyze tests/synthetic_suite/DEADLOCK/tn_*.py
```

Expected results:
- All `tp_*.py` → `BUG (DEADLOCK)` with wait-for graph showing cycle
- All `tn_*.py` → `SAFE` with proof of deadlock-freedom OR `UNKNOWN` if analysis is incomplete

## Notes

- Deadlock detection is UNDECIDABLE in general (Turing-equivalent)
- Sound approximation may yield UNKNOWN for complex cases
- Static analysis may produce false positives on infeasible interleavings
- Dynamic analysis may miss deadlocks that require specific scheduling
- The goal: detect obvious deadlock patterns (TP tests) without flagging safe patterns (TN tests)
