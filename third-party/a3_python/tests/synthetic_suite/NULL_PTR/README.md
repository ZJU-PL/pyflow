# NULL_PTR Synthetic Test Suite

**Bug Type:** NULL_PTR (None misuse)

## Ground Truth Labels

### True Positives (BUG - must be caught)

1. **tp_01_method_call_on_none.py**: Method call on None
   - None value returned from function, method invoked on None
   - Expected: AttributeError at method call

2. **tp_02_attribute_access_on_none_return.py**: Attribute access on None return value
   - dict.get() with missing key returns None, attribute accessed
   - Expected: AttributeError at attribute access

3. **tp_03_subscript_on_none.py**: Subscript operation on None
   - Function returns None conditionally, subscript used without check
   - Expected: TypeError at subscript operation

4. **tp_04_iteration_over_none.py**: Iteration over None
   - Function returns None, used in for-loop
   - Expected: TypeError ('NoneType' object is not iterable)

5. **tp_05_conditional_none_path.py**: Conditional path leads to None dereference
   - Control flow assigns None on some paths, method called regardless
   - Expected: AttributeError on None path

### True Negatives (SAFE - must NOT be flagged)

1. **tn_01_none_check_before_use.py**: None check before use
   - Explicit `if result is not None:` guard before dereference
   - All uses protected by None check

2. **tn_02_optional_default_fallback.py**: Optional with default fallback
   - dict.get() with default value ensures non-None result
   - No None dereference possible

3. **tn_03_type_narrowing_isinstance.py**: Type narrowing via isinstance
   - isinstance() check both validates type and excludes None
   - Type guard establishes safety

4. **tn_04_guaranteed_non_none_return.py**: Guaranteed non-None return
   - Function returns list on all paths (never None)
   - No None value reaches dereference

5. **tn_05_all_paths_assign_non_none.py**: All paths assign non-None before use
   - All control paths assign dict (not None)
   - Guaranteed non-None at dereference point

## Semantic Model Requirements

For each test case, the analyzer must:

1. **Track None values**: Symbolic execution must distinguish None from other values
2. **Model dereference operations**: Method calls, attribute access, subscript, iteration all dereference
3. **Control flow sensitivity**: Track which paths can reach None vs non-None
4. **Type guards**: isinstance checks and explicit `is not None` conditions narrow types
5. **Relational semantics**: dict.get() with default never returns None

## Unsafe Predicate

```
U_NULL_PTR(σ) ::= ∃ operation ∈ {method_call, attr_access, subscript, iteration}.
                  value_at(σ, operation.target) = None
```

## Expected Detector Behavior

- **BUG**: If symbolic execution finds a reachable path where None reaches a dereference operation
- **SAFE**: If barrier certificate proves None cannot reach dereference (via type guards, control flow, or initialization invariants)
- **UNKNOWN**: If over-approximation of unknown functions may produce None and no proof exists

## Anti-Cheating Notes

- Do NOT use pattern matching on "None" in source text
- Do NOT rely on variable names or comments
- MUST track None symbolically through Z3 encoding
- MUST model each dereference operation semantically
- None checks must be tracked in path conditions
