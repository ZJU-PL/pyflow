# DIV_ZERO Synthetic Test Suite

This directory contains ground-truth test cases for the `DIV_ZERO` bug class.

## Bug Class Definition

**DIV_ZERO**: Division by zero, which raises `ZeroDivisionError` in Python.

Applies to:
- Regular division: `a / b`
- Floor division: `a // b`
- Modulo: `a % b`

## Unsafe Predicate

`Unsafe_DIV_ZERO(σ)` is true when:
- The machine state σ is about to execute a division operation (BINARY_OP with `/`, `//`, or `%`)
- The divisor operand on the stack has value 0

## Test Cases

### True Positives (Must be flagged as BUG)

1. **tp_01_direct_literal.py**: Division by literal zero `x / 0`
   - Simplest case, unconditional bug

2. **tp_02_variable_zero.py**: Division by variable set to zero
   - Tests that analyzer tracks concrete zero value through variables

3. **tp_03_modulo_zero.py**: Modulo by zero `x % 0`
   - Tests that modulo operator is checked

4. **tp_04_floor_division_zero.py**: Floor division by zero `x // 0`
   - Tests that floor division operator is checked

5. **tp_05_conditional_path_to_zero.py**: Conditional path where divisor becomes zero
   - Tests path-sensitive analysis: bug exists only on one branch
   - When `flag=False`, divisor is set to 0 before division

### True Negatives (Must NOT be flagged as BUG)

1. **tn_01_nonzero_check.py**: Division guarded by `if divisor != 0:`
   - Tests that analyzer respects guard conditions

2. **tn_02_nonzero_constant.py**: Division by non-zero constant `x / 5`
   - Tests constant folding / static analysis of literals

3. **tn_03_exception_handler.py**: Division wrapped in try-except
   - Tests exception handling (may be SAFE or UNKNOWN depending on policy)
   - The exception is caught, so no unhandled error escapes

4. **tn_04_all_paths_nonzero.py**: All control flow paths ensure non-zero divisor
   - Tests path merging: divisor is either 10 or 5, never 0

5. **tn_05_default_fallback.py**: Potentially-zero divisor replaced with default
   - Pattern: `divisor or 1` ensures divisor is never 0
   - Tests short-circuit evaluation tracking

## Expected Analyzer Behavior

### For True Positives (tp_*.py)

- **Result**: `BUG`
- **Evidence**: Symbolic trace showing path to division operation with divisor == 0
- **Witness**: Concrete counterexample (input values that trigger the bug)

### For True Negatives (tn_*.py)

- **Result**: `SAFE` (if proof exists) or `UNKNOWN` (if proof not found)
- **Must NOT report**: `BUG` (would be false positive)
- **For SAFE**: Barrier certificate or inductive invariant proving divisor != 0

## Validation Protocol

1. Run analyzer on each test file
2. Compare result against expected label (BUG/SAFE)
3. For BUG results:
   - Verify witness trace is valid
   - Check that concrete replay triggers ZeroDivisionError
4. For SAFE results:
   - Verify proof artifact exists
   - Check that proof is valid (barrier certificate checked by Z3)

## Semantic Notes

- Python integers are arbitrary precision, but division by zero always raises exception
- The `/` operator returns float, `//` returns int (for int operands)
- Both `0` and `0.0` trigger the error (and any value with `__bool__` = False and numeric value 0)
- Complex numbers: `1 / 0j` does NOT raise ZeroDivisionError (it returns complex infinity)

## Anti-Cheating Requirements

The analyzer must NOT:
- Pattern match on literal `/ 0` in source text
- Use AST-level regex detection
- Rely on variable names like "zero" or "divisor"

The analyzer MUST:
- Operate on bytecode semantics (BINARY_OP execution)
- Track symbolic values through Z3 constraints
- Produce Z3-based proof or counterexample
