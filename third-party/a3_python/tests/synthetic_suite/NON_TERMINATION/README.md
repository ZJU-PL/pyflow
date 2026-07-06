# NON_TERMINATION Synthetic Test Suite

This directory contains ground-truth test cases for the NON_TERMINATION bug type.

## Bug Type: NON_TERMINATION

**Definition**: A program or function that never terminates (infinite loop, unbounded recursion, or circular dependency without exit).

**Barrier Certificate Approach**: 
- Use **ranking functions** to prove termination
- A ranking function `ρ: S → ℕ` maps states to natural numbers
- Must satisfy: `∀s,s'. (s → s' ∧ ρ(s) ≥ 0) ⇒ ρ(s') < ρ(s)` (strictly decreasing)
- If no ranking function exists for a loop/recursion, report UNKNOWN or BUG (if infinite path is reachable)

## Test Cases

### True Positives (BUG - Non-Termination)

1. **tp_01_while_true_no_break.py**: Unconditional `while True` loop with no break/return/raise
2. **tp_02_loop_non_decreasing_counter.py**: Loop counter increments instead of making progress toward exit condition
3. **tp_03_mutual_recursion_no_base_case.py**: Functions call each other indefinitely without base case
4. **tp_04_recursion_wrong_base_case.py**: Recursive function where base case is unreachable (wrong direction)
5. **tp_05_loop_condition_never_false.py**: Loop condition depends on variable that is never modified

### True Negatives (SAFE - Termination Guaranteed)

1. **tn_01_bounded_loop_with_range.py**: `for i in range(N)` - bounded iteration
2. **tn_02_recursion_proper_base_case.py**: Factorial recursion with reachable base case and progress
3. **tn_03_loop_guaranteed_progress.py**: While loop with strictly decreasing counter
4. **tn_04_while_true_with_break.py**: `while True` with reachable break condition
5. **tn_05_mutual_recursion_with_base.py**: Mutual recursion (even/odd check) with proper base cases

## Expected Analyzer Behavior

- **True Positives**: Analyzer should report `BUG (NON_TERMINATION)` with:
  - Identification of the non-terminating loop/recursion
  - Explanation of why no ranking function exists
  - Infinite path trace (if reachability-based)

- **True Negatives**: Analyzer should report `SAFE` with:
  - A ranking function or termination proof
  - Or report `UNKNOWN` if proof cannot be constructed (but NOT `BUG`)

## Ranking Function Examples

For `tn_03_loop_guaranteed_progress.py`:
- Ranking function: `ρ(n) = n` (where n is the loop counter)
- Invariant: `n ≥ 0`
- Progress: `n' = n - 1`, so `n' < n` (strictly decreasing)

For `tn_02_recursion_proper_base_case.py` (factorial):
- Ranking function: `ρ(n) = n`
- Base case: `n ≤ 1` stops recursion
- Progress: recursive call with `n - 1`, so `ρ(n-1) < ρ(n)`

## Ground Truth Summary

- **Total cases**: 10
- **True positives**: 5
- **True negatives**: 5
- **Expected precision**: 1.0 (no false positives)
- **Expected recall**: 1.0 (all true positives detected)
