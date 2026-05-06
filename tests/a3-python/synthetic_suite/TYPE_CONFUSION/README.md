# TYPE_CONFUSION Synthetic Test Suite

This directory contains ground-truth test cases for the TYPE_CONFUSION bug class.

## Bug Definition

**TYPE_CONFUSION**: Dynamic dispatch or type errors violating expected protocol. Occurs when:
- A function receives a value of unexpected type and performs operations invalid for that type
- Union types are used without proper type narrowing
- Duck typing assumptions are violated (missing attributes/methods)
- Type coercions fail in arithmetic or comparisons

## Test Structure

### True Positives (5 tests) - MUST be flagged as BUG

1. **tp_01_wrong_type_passed.py**: Function expects dict but receives int, causing AttributeError on `.get()` call
2. **tp_02_union_without_narrowing.py**: Function parameter allows multiple types but calls method without isinstance check
3. **tp_03_dynamic_attribute_wrong_class.py**: Code assumes object has 'name' attribute but receives object without it
4. **tp_04_numeric_string_confusion.py**: String passed where number expected, causing TypeError in arithmetic
5. **tp_05_iterator_protocol_violation.py**: Non-iterable passed to for-loop causing TypeError

### True Negatives (5 tests) - MUST NOT be flagged as BUG

1. **tn_01_isinstance_check.py**: Proper isinstance checks before type-specific operations
2. **tn_02_validated_annotations.py**: Runtime type validation matching annotations
3. **tn_03_protocol_duck_typing.py**: hasattr checks before attribute access (duck typing)
4. **tn_04_union_proper_narrowing.py**: Union type with exhaustive isinstance narrowing
5. **tn_05_try_except_type_errors.py**: AttributeError/TypeError caught in exception handlers

## Semantic Definition

A TYPE_CONFUSION bug is reached when:

```
σ ⊢ o.attr  where  type(o) ∉ types_with_attr(attr)
σ ⊢ o.method(...)  where  type(o) ∉ types_with_method(method)
σ ⊢ op(x, y)  where  (type(x), type(y)) ∉ valid_operand_types(op)
σ ⊢ for item in obj  where  type(obj) ∉ iterable_types
```

And the resulting AttributeError/TypeError propagates without being caught.

## Expected Analyzer Behavior

- **True Positives**: Must report BUG with witness trace showing reachable path to type error
- **True Negatives**: Must report SAFE (with proof) or UNKNOWN (if analysis incomplete), but NOT BUG
- **Witness Requirements**: For BUG results, must provide:
  - Function name and line number where type error occurs
  - Expected type vs actual type along witness path
  - Complete call stack leading to error

## Running These Tests

```bash
# Run analyzer on single test
python -m pyfromscratch.cli tests/synthetic_suite/TYPE_CONFUSION/tp_01_wrong_type_passed.py

# Validate entire suite
python scripts/validate_synthetic_suite.py TYPE_CONFUSION
```

## Ground Truth Validation

Each test file includes:
- Header comment with Expected result (BUG/SAFE)
- Semantic reason for classification
- Inline comments explaining the type confusion point

The validation script compares analyzer output against these ground-truth labels.
