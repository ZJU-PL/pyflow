# FP_DOMAIN Synthetic Test Suite

This directory contains ground-truth test cases for **FP_DOMAIN** (floating-point domain errors).

## Bug Definition

**FP_DOMAIN** represents calls to mathematical functions with arguments outside their valid domain, resulting in domain errors (typically `ValueError` in Python).

Common examples:
- `math.sqrt(x)` where `x < 0`
- `math.log(x)` where `x <= 0`
- `math.asin(x)` or `math.acos(x)` where `|x| > 1`

## Test Structure

### True Positives (TP) - Programs with REAL bugs

1. **tp_01_sqrt_negative.py**: `math.sqrt(-4)` - direct negative argument
2. **tp_02_log_negative.py**: `math.log(-5.0)` - logarithm of negative
3. **tp_03_log_zero.py**: `math.log(0.0)` - logarithm of zero (undefined)
4. **tp_04_asin_out_of_range.py**: `math.asin(1.5)` - arcsine above valid range
5. **tp_05_acos_below_range.py**: `math.acos(-2.0)` - arccosine below valid range

**Expected analyzer output**: `BUG (FP_DOMAIN)` with witness trace

### True Negatives (TN) - SAFE programs

1. **tn_01_sqrt_checked.py**: sqrt with non-negative check (`if x >= 0`)
2. **tn_02_log_positive_check.py**: log with positive check (`if value > 0`)
3. **tn_03_asin_clamped.py**: asin with input clamped to `[-1, 1]`
4. **tn_04_exception_handler.py**: domain error caught in try-except
5. **tn_05_valid_constants.py**: all functions called with valid constant inputs

**Expected analyzer output**: `SAFE` (with proof) or `UNKNOWN` (acceptable if no proof found)

**Critical**: Must NOT report these as `BUG`

## Semantic Model Requirements

To detect FP_DOMAIN bugs semantically (not via regex), the analyzer must:

1. **Model math library functions as contracts** with preconditions:
   - `sqrt(x)` requires `x >= 0`
   - `log(x)` requires `x > 0`
   - `asin(x)`, `acos(x)` require `-1 <= x <= 1`

2. **Track value ranges symbolically** via Z3 constraints

3. **Check unsafe predicate**: At call site `f(args)`, check if any argument violates the precondition under current path constraints

4. **Extract witness traces** showing concrete argument values that trigger the domain error

5. **Recognize safe patterns**:
   - Explicit domain checks before call
   - Exception handlers catching `ValueError`
   - Constant arguments provably in valid domain

## Anti-Cheating Constraints

**Forbidden approaches**:
- Regex matching `math.sqrt` and warning unconditionally
- Pattern matching on negative literals without symbolic reasoning
- Heuristics based on variable names (e.g., "negative" in name)

**Required approach**:
- Symbolic execution with range tracking
- Constraint-based checking: Is `x < 0` reachable at `sqrt(x)`?
- Z3 query to find counterexample inputs

## Validation Protocol

Run the analyzer on all 10 files and compare results:

```bash
python -m pyfromscratch.cli --scan tests/synthetic_suite/FP_DOMAIN/
```

Expected metrics:
- **True Positive Rate**: 5/5 (100%) - all TP files should report BUG
- **False Positive Rate**: 0/5 (0%) - no TN files should report BUG
- **Precision**: 100%
- **Recall**: 100%

Any deviation indicates a bug in the analyzer's FP_DOMAIN detection.
