# ASSERT_FAIL Synthetic Test Suite

## Bug Type: ASSERT_FAIL

**Definition**: An assertion statement (`assert condition, message`) fails, raising an `AssertionError` that propagates to the top level without being caught.

**Semantic Unsafe Region**: Machine state where an `AssertionError` is raised and there is no enclosing exception handler that catches `AssertionError` (or a base class like `Exception` or `BaseException`) before reaching the top-level frame.

**Key Distinctions**:
- ASSERT_FAIL vs PANIC: ASSERT_FAIL is specifically about `assert` statements and `AssertionError`, while PANIC covers any unhandled exception
- Handled assertions (caught by try-except) are SAFE for ASSERT_FAIL purposes
- Debug mode vs production: assertions can be disabled with `-O`, affecting reachability

## True Positives (BUG)

### tp_01_unconditional_assert_false.py
- **Violation**: `assert False` always fails
- **Location**: Line 10 in `always_fails()`
- **Reason**: Unconditional assertion failure with no handler

### tp_02_impossible_condition.py
- **Violation**: `assert x > x` - logically impossible
- **Location**: Line 11 in `check_impossible()`
- **Reason**: Condition can never be satisfied (tautological falsity)

### tp_03_failing_precondition.py
- **Violation**: `assert x >= 0` fails when x = -5
- **Location**: Line 12 in `sqrt_positive()`
- **Reason**: Precondition violated by caller, no handler

### tp_04_loop_invariant_violation.py
- **Violation**: `assert counter <= limit` fails during iteration
- **Location**: Line 16 in `process_with_limit()`
- **Reason**: Loop body accumulates values exceeding stated invariant bound

### tp_05_postcondition_violation.py
- **Violation**: `assert result > 0` fails on negative result
- **Location**: Line 15 in `compute_positive_value()`
- **Reason**: Computation produces value violating postcondition

## True Negatives (SAFE)

### tn_01_always_true_condition.py
- **Safe**: `assert True` always passes
- **Reason**: No path reaches AssertionError state

### tn_02_precondition_satisfied.py
- **Safe**: Precondition `assert x >= 0` holds with x = 25
- **Reason**: Caller provides valid input satisfying constraint

### tn_03_debug_only_assertions.py
- **Safe**: Assertions compiled out with `-O` flag
- **Reason**: In optimized mode, assert statements are removed (context-dependent safety)

### tn_04_caught_assertion_error.py
- **Safe**: AssertionError caught by try-except
- **Reason**: Exception handler prevents propagation to top-level

### tn_05_loop_invariant_maintained.py
- **Safe**: Loop invariant `counter <= limit` maintained by conditional guard
- **Reason**: Guard condition `if counter + item <= limit` ensures invariant holds

## Barrier Certificate Requirements

For a SAFE verdict on ASSERT_FAIL:

1. **Initial condition**: No assertion is violated in initial state
2. **Inductive step**: For every assert statement:
   - Either: prove assertion condition is always True at that program point
   - Or: prove AssertionError is always caught by an enclosing handler
3. **Unsafe separation**: Barrier function `B(σ)` must satisfy:
   - `B(σ) ≥ ε` when assertion conditions hold or are handled
   - `B(σ) ≤ -ε` when AssertionError propagates unhandled to top-level

## Analysis Considerations

1. **Context-sensitivity**: Must track exception handlers and their scope
2. **Path-sensitivity**: Assertion reachability may depend on earlier branches
3. **Interprocedural**: Assertions in callees require analysis of caller context
4. **Loop invariants**: Assertions in loops require inductive proof over iterations
5. **Optimizations**: Python's `-O` flag disables assertions (affects reachability)

## Ground Truth Validation

Expected analyzer results:
- **True Positives**: 5 files should report BUG (ASSERT_FAIL)
- **True Negatives**: 5 files should report SAFE or have proof that AssertionError is unreachable/handled
- **Precision**: 1.0 (no false positives)
- **Recall**: 1.0 (all true bugs found)
