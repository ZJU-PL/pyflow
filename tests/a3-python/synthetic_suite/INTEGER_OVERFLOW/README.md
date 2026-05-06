# INTEGER_OVERFLOW Synthetic Test Suite

This directory contains ground-truth test cases for INTEGER_OVERFLOW bug detection.

## Bug Definition

INTEGER_OVERFLOW occurs when an arithmetic operation produces a result that exceeds the representable range of the target integer type, causing:
- Wraparound/modular arithmetic (unsigned overflow)
- Undefined behavior (signed overflow in some contexts)
- Silent truncation or loss of semantic meaning

In Python, this primarily occurs at the **native boundary**:
- `ctypes` fixed-width integer types (c_int8, c_uint8, etc.)
- `array` module typed arrays
- `struct` pack/unpack operations
- Native extensions with bounded integer types

Pure Python integers have arbitrary precision and **never overflow**.

## Test Cases

### True Positives (MUST detect as BUG)

1. **tp_01_ctypes_overflow.py**: c_int8 overflow (127 + 50 → -106)
2. **tp_02_array_overflow.py**: array('b') signed byte overflow
3. **tp_03_struct_pack_overflow.py**: struct.pack wrapping on large values
4. **tp_04_multiplication_overflow.py**: c_uint8 multiplication overflow
5. **tp_05_underflow.py**: c_int8 underflow (subtraction below -128)

### True Negatives (MUST NOT flag as BUG)

1. **tn_01_pure_python_arithmetic.py**: Arbitrary precision arithmetic (safe)
2. **tn_02_bounded_arithmetic.py**: Checked arithmetic with range validation
3. **tn_03_small_constants.py**: Small values safe in any context
4. **tn_04_checked_ctypes.py**: ctypes with pre-operation validation
5. **tn_05_try_except_pattern.py**: Overflow detection via try-except

## Detection Strategy

The analyzer must:

1. **Track fixed-width type contexts**: ctypes assignments, array operations, struct packing
2. **Model wraparound semantics**: Understand that ctypes assignments can wrap
3. **Check overflow predicates**: For operation `result = a OP b`, check if result exceeds type bounds
4. **Distinguish from pure Python**: Pure Python int operations are always safe

## Expected Results

| Test Case | Expected Result | Reason |
|-----------|----------------|--------|
| tp_01 | BUG | c_int8(100) + 50 overflows |
| tp_02 | BUG | array('b') wraps 150 → -106 |
| tp_03 | BUG | struct.pack('h', 40000) wraps |
| tp_04 | BUG | c_uint8 multiplication overflow |
| tp_05 | BUG | c_int8 underflow on subtraction |
| tn_01 | SAFE | Pure Python, arbitrary precision |
| tn_02 | SAFE | Bounds checked before operations |
| tn_03 | SAFE | All values small and safe |
| tn_04 | SAFE | Explicit validation before ctypes use |
| tn_05 | SAFE | try-except catches overflows |

## Validation

Run analyzer on each test case:
```bash
python -m pyfromscratch.cli tests/synthetic_suite/INTEGER_OVERFLOW/tp_*.py
python -m pyfromscratch.cli tests/synthetic_suite/INTEGER_OVERFLOW/tn_*.py
```

Expected: 5 BUGs detected (tp_*), 0 BUGs for tn_*.
