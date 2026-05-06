# STACK_OVERFLOW Synthetic Test Suite

## Bug Type: STACK_OVERFLOW (RecursionError)

**Definition**: Stack overflow occurs when recursive function calls exhaust the call stack due to unbounded or excessively deep recursion.

**Python Semantics**: Python has a configurable recursion limit (`sys.getrecursionlimit()`, default ~1000). Exceeding this limit raises `RecursionError`.

---

## True Positives (Must Detect as BUG)

### tp_01_unbounded_recursion.py
**Pattern**: Classic unbounded recursion with no base case
- Function calls itself unconditionally
- No termination condition
- **Expected**: RecursionError after ~1000 calls

### tp_02_mutual_recursion_deep.py
**Pattern**: Mutual recursion without depth limit
- Two functions call each other alternately
- No base case or depth check
- **Expected**: RecursionError from alternating calls

### tp_03_deep_recursion_traversal.py
**Pattern**: Recursive data structure traversal
- Deeply nested structure (depth=10000)
- Recursive traversal without tail-call optimization
- **Expected**: RecursionError during traversal

### tp_04_fibonacci_naive_deep.py
**Pattern**: Naive recursive fibonacci with large input
- Exponential call tree
- Input n=5000 creates paths deeper than recursion limit
- **Expected**: RecursionError in one of the deep branches

### tp_05_json_like_parser_deep.py
**Pattern**: Recursive parser with pathological input
- Deeply nested dictionary structure (depth=5000)
- Recursive descent parsing
- **Expected**: RecursionError during parsing

---

## True Negatives (Must NOT Flag as BUG)

### tn_01_tail_recursion_with_limit.py
**Pattern**: Explicit depth limit with early termination
- Tracks recursion depth explicitly
- Raises ValueError before hitting system limit
- **Why Safe**: Controlled failure mode (ValueError, not RecursionError)

### tn_02_iterative_conversion.py
**Pattern**: Iterative implementation instead of recursive
- Factorial and fibonacci using loops
- Constant stack space (O(1))
- **Why Safe**: No recursion, unbounded input size is safe

### tn_03_setrecursionlimit_guarded.py
**Pattern**: Increased limit with input validation
- Uses `sys.setrecursionlimit()` to raise limit
- Validates input stays well below limit (safety margin)
- **Why Safe**: Explicit bounds checking prevents limit violation

### tn_04_bounded_recursion_base_case.py
**Pattern**: Well-structured recursion with guaranteed termination
- Proper base cases (empty list, binary search bounds)
- Recursion depth bounded by input size (linear or logarithmic)
- Small inputs guarantee safety
- **Why Safe**: Base case ensures termination within limits

### tn_05_trampoline_pattern.py
**Pattern**: Trampoline pattern converts recursion to iteration
- Returns thunks (deferred computations) instead of direct calls
- Trampoline executor runs in iterative loop
- **Why Safe**: No actual recursion, constant stack depth

---

## Key Semantic Distinctions

1. **Unbounded vs Bounded**: True positives have no termination guarantee; true negatives have explicit bounds or iterative alternatives.

2. **Depth Awareness**: True negatives explicitly track or limit recursion depth; true positives ignore depth.

3. **Base Cases**: True negatives have reachable base cases that guarantee termination within system limits.

4. **Alternative Patterns**: True negatives may use trampolines, iteration, or increased limits with validation.

---

## Verification Strategy

For a **semantically faithful** STACK_OVERFLOW detector:

- **Model the call stack explicitly** as part of machine state σ
- **Track recursion depth** per function/call chain
- **Unsafe predicate**: `U_STACK_OVERFLOW(σ) := depth(σ.call_stack) > RECURSION_LIMIT`
- **Reachability**: Use ranking functions or depth analysis to prove recursion is bounded
- **SAFE proof**: Show recursion depth is bounded by a value less than the limit (e.g., via explicit checks or structural induction on input)

**Note**: Simply detecting "recursive call" is not sufficient—many safe programs use recursion. The detector must prove unboundedness or excessive depth relative to the limit.
