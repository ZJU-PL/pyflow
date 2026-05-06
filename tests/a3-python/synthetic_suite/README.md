# Synthetic Test Suite: Ground Truth for 20 Bug Types

## Purpose

This suite exists to **debug the debugger**: it provides ground-truth labeled test cases for all 20 bug types covered by the barrier-certificate-based analyzer.

Every test case is explicitly labeled with:
- **Expected Result**: BUG, SAFE, or UNKNOWN
- **Bug Type**: The specific bug class (e.g., DIV_ZERO, BOUNDS, etc.)
- **Rationale**: Why this case should produce the expected result

## Methodology

For each bug type, we generate:
1. **True Positives**: Code with KNOWN bugs that MUST be detected
2. **True Negatives**: Safe code that MUST NOT be flagged
3. **Edge Cases**: Borderline/tricky cases to stress-test the detector

## Success Criteria

The analyzer must achieve:
- **True Positive Rate = 1.0** (catch all real bugs)
- **True Negative Rate = 1.0** (no false positives on safe code)
- **Precision = 1.0** (when it says BUG, it must be right)
- **Recall = 1.0** (when there's a bug, it must find it)

Any deviation indicates:
- Either the test is mislabeled (rare, fix the label)
- Or the analyzer has a bug (likely, fix the analyzer)

## Directory Structure

```
tests/synthetic_suite/
├── README.md (this file)
├── GROUND_TRUTH_MANIFEST.json (expected results for all 200 tests)
├── INTEGER_OVERFLOW/
│   ├── tp_01_ctypes_overflow.py
│   ├── tp_02_array_overflow.py
│   ├── ... (5 true positives)
│   ├── tn_01_pure_python_arithmetic.py
│   └── ... (5 true negatives)
├── DIV_ZERO/
│   ├── tp_*.py (5 true positives)
│   └── tn_*.py (5 true negatives)
├── FP_DOMAIN/
├── USE_AFTER_FREE/
├── DOUBLE_FREE/
├── MEMORY_LEAK/
├── UNINIT_MEMORY/
├── NULL_PTR/
├── BOUNDS/
├── DATA_RACE/
├── DEADLOCK/
├── SEND_SYNC/
├── NON_TERMINATION/
├── PANIC/
├── ASSERT_FAIL/
├── STACK_OVERFLOW/
├── TYPE_CONFUSION/
├── ITERATOR_INVALID/
├── INFO_LEAK/
└── TIMING_CHANNEL/
```

**Total: 200 test files (10 per bug type: 5 true positives + 5 true negatives)**

## Naming Convention

- `tp_##_description.py`: True Positive - Code with a KNOWN bug
- `tn_##_description.py`: True Negative - Safe code (no bug)

Each file contains code demonstrating the bug or safety pattern with descriptive names.

## Validation Protocol

1. **Run analyzer on entire suite:**
   ```bash
   python -m pyfromscratch.cli --scan tests/synthetic_suite --output results/synthetic_suite_results.json
   ```

2. **Validate results against ground truth:**
   ```bash
   python scripts/validate_synthetic_suite.py --results results/synthetic_suite_results.json
   ```

3. **Interpret results:**
   - **True Positive (TP)**: Analyzer correctly reports BUG for a known-buggy test
   - **True Negative (TN)**: Analyzer correctly reports SAFE for a safe test  
   - **False Positive (FP)**: Analyzer reports BUG but ground truth says SAFE → **analyzer bug**
   - **False Negative (FN)**: Analyzer reports SAFE but ground truth says BUG → **analyzer bug**
   - **Unknown**: Analyzer returns UNKNOWN (conservative; acceptable but track ratio)

4. **Target Metrics:**
   - Precision = TP / (TP + FP) = **1.0 target**
   - Recall = TP / (TP + FN) = **1.0 target**
   - Accuracy = (TP + TN) / Total = **1.0 target**

5. **If discrepancies found:**
   - First verify the ground truth label is correct
   - Fix the analyzer's symbolic model (never add heuristics)
   - Re-run and validate again

## Anti-Cheating Rule

The analyzer must NOT:
- Hardcode behaviors for this test suite
- Parse filenames/paths/comments as signals
- Use heuristics to "guess" the expected result

Every BUG/SAFE claim must come from the symbolic/barrier model.
