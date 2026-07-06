# PANIC Synthetic Test Suite

## Bug Type: PANIC (Unhandled Exception Program Termination)

**Definition**: A PANIC occurs when an exception is raised and not caught by any exception handler, causing the program to terminate abnormally. This includes unhandled exceptions, sys.exit() calls in library code, and assertion failures in production code.

## Test Coverage

### True Positives (5 tests - MUST report BUG)

1. **tp_01_unhandled_exception.py**
   - ValueError raised from int() with no exception handler
   - Exception propagates to top level causing crash
   - Ground truth: BUG

2. **tp_02_raise_without_try.py**
   - Unconditional raise RuntimeError with no try-except
   - Exception guaranteed to propagate uncaught
   - Ground truth: BUG

3. **tp_03_sys_exit_in_library.py**
   - Library function calls sys.exit(1) instead of raising exception
   - Violates "library code shouldn't terminate program" contract
   - Ground truth: BUG

4. **tp_04_assertion_error_in_prod.py**
   - assert statement fails with no AssertionError handler
   - Assertion can fail in production (not just debug mode)
   - Ground truth: BUG

5. **tp_05_exception_in_finally_block.py**
   - ZeroDivisionError raised in finally block
   - Masks any pending exception and propagates uncaught
   - Ground truth: BUG

### True Negatives (5 tests - MUST report SAFE)

1. **tn_01_proper_exception_handling.py**
   - ValueError caught by try-except block
   - Safe default returned on exception
   - Ground truth: SAFE

2. **tn_02_graceful_degradation.py**
   - Top-level exception handler catches all potential failures
   - Program continues with degraded functionality (fallback values)
   - Ground truth: SAFE

3. **tn_03_exception_chaining.py**
   - Exceptions caught, re-wrapped with context via `raise ... from`
   - Top-level handler catches the chained exception
   - Ground truth: SAFE

4. **tn_04_exception_logged_not_raised.py**
   - Exceptions caught and converted to return values (success, result) tuples
   - No exception propagates outside the function
   - Ground truth: SAFE

5. **tn_05_top_level_catch_all.py**
   - Top-level `except Exception` catches all exception types
   - Handler doesn't re-raise, ensuring no program termination
   - Ground truth: SAFE

## Semantic Analysis Requirements

For each test, the analyzer must:

1. **Identify exception sources**: Track all operations that can raise exceptions
   - Function calls (built-ins, library functions, user functions)
   - Operators (division, indexing, etc.)
   - Explicit raise statements
   - assert statements

2. **Model exception propagation**: Track exception flow through call stack
   - Exception handlers (try-except blocks)
   - finally blocks (which can mask exceptions)
   - Exception chaining (raise ... from)

3. **Verify exception handling completeness**:
   - For BUG: Prove there exists a path where exception reaches top level
   - For SAFE: Prove all exception paths are caught by handlers

4. **Special cases**:
   - sys.exit() is semantically equivalent to raising SystemExit
   - assert statements raise AssertionError when condition is False
   - finally blocks execute even with pending exception
   - Exceptions in finally block mask the original exception

## Anti-Cheating Constraints

FORBIDDEN approaches:
- ❌ Pattern matching on "raise" keyword in source
- ❌ Checking for "try:" and "except:" presence via text search
- ❌ Heuristics based on "sys.exit" string matching
- ❌ Declaring SAFE because no exception handler was found (that's a BUG!)

REQUIRED approaches:
- ✅ Model exception raising as control-flow edges in CFG
- ✅ Track exception handlers as exceptional edges to handler blocks
- ✅ Symbolic execution with exception state in machine state
- ✅ Reachability analysis: can uncaught exception reach module top-level?
- ✅ Barrier certificates proving no exception escapes (for SAFE claims)

## Expected Analyzer Behavior

### For True Positives (BUG reports):
- Output format: `BUG: PANIC at {file}:{line} in {function}`
- Must include: The specific exception type that goes uncaught
- Must include: Witness trace showing path from exception source to top level
- Optional: Concrete repro (DSE-generated inputs that trigger the bug)

### For True Negatives (SAFE reports):
- Output format: `SAFE: PANIC checked at {file}:{line}`
- Must include: The exception handler that prevents the panic
- Must include: Proof artifact (e.g., "all exception sources within try-block scope")
- Never report SAFE by absence of evidence (must have positive proof)

## Validation Metrics

When validating the analyzer against this suite:

- **True Positive Rate**: Fraction of tp_*.py files correctly reported as BUG
- **True Negative Rate**: Fraction of tn_*.py files correctly reported as SAFE
- **False Positive Rate**: Fraction of tn_*.py files incorrectly reported as BUG (MUST be 0%)
- **False Negative Rate**: Fraction of tp_*.py files incorrectly reported as SAFE (MUST be 0%)

Target: 100% TP rate, 100% TN rate, 0% FP rate, 0% FN rate.
