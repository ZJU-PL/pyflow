# BOUNDS Bug Type - Synthetic Test Suite

## Bug Type Definition

**BOUNDS**: Out-of-bounds access to sequences, mappings, or iterators.

### Semantic Unsafe Predicate

In machine state σ, BOUNDS is violated when:
- **Sequence access**: `seq[i]` where `i < -len(seq)` or `i >= len(seq)` (for non-negative i)
- **Dictionary access**: `dict[key]` where `key ∉ dict.keys()`
- **Iterator protocol**: Accessing exhausted iterator without StopIteration handling

Unhandled exceptions: `IndexError`, `KeyError`

## Test Suite Structure

### True Positives (BUG cases) - 5 files

1. **tp_01_list_index_out_of_range.py**
   - Bug: Access items[5] on 3-element list
   - Violation: index >= len(sequence)

2. **tp_02_negative_index_beyond_length.py**
   - Bug: Access items[-10] on 4-element list
   - Violation: abs(negative_index) > len(sequence)

3. **tp_03_dict_missing_key.py**
   - Bug: Access data['missing_key'] on dict without that key
   - Violation: key not in dict domain

4. **tp_04_computed_index_overflow.py**
   - Bug: Access arr[len(arr)] - off-by-one error
   - Violation: index == len(sequence) (one past valid range)

5. **tp_05_tuple_indexing_past_end.py**
   - Bug: Access coordinates[3] on 3-element tuple
   - Violation: index >= len(tuple)

### True Negatives (SAFE cases) - 5 files

1. **tn_01_index_with_bounds_check.py**
   - Safety: Explicit `if 0 <= index < len(items)` guard
   - Invariant: All accesses gated by bounds predicate

2. **tn_02_dict_get_with_default.py**
   - Safety: dict.get() with default parameter
   - Invariant: No KeyError path exists

3. **tn_03_range_based_iteration.py**
   - Safety: `range(len(items))` guarantees valid indices
   - Invariant: Loop variable `i` satisfies `0 <= i < len(items)`

4. **tn_04_enumerate_safe_access.py**
   - Safety: enumerate() yields valid (index, value) pairs
   - Invariant: Python guarantee on enumerate indices

5. **tn_05_try_except_keyerror.py**
   - Safety: KeyError caught in exception handler
   - Invariant: Exception path handled explicitly

## Expected Analyzer Behavior

### For True Positives
- **Report**: BUG (BOUNDS violation)
- **Witness**: Concrete trace showing:
  - Sequence/dict creation
  - Index/key value
  - Out-of-bounds access point
- **Z3 model**: Constraint showing `index >= len` or `key ∉ domain`

### For True Negatives
- **Report**: SAFE (with proof) or UNKNOWN (acceptable)
- **Barrier certificate** (if SAFE):
  - Invariant: `0 <= index < len(container)` or `key ∈ dict.keys()`
  - Or: Exception handler covers all BOUNDS paths
- **Never**: Spurious BUG report on these cases

## Validation Criteria

- True Positive Rate on TP files: 100% (all 5 must be flagged as BUG)
- False Positive Rate on TN files: 0% (none of the 5 should be flagged as BUG)
- Precision = TP / (TP + FP) = 5 / (5 + 0) = 1.0
- Recall = TP / (TP + FN) = 5 / 5 = 1.0

## Anti-Cheating Verification

These tests are designed to prevent superficial pattern matching:

- **No text-based detection**: Detector must not rely on variable names like "out_of_range"
- **Semantic reasoning required**: Must model sequence lengths and index values in Z3
- **Exception semantics**: Must understand handler scopes and exception propagation
- **No hardcoding**: Same detector logic must generalize to arbitrary programs

## Implementation Notes for Analyzer

1. **Sequence Length Tracking**: Model `len(seq)` as Z3 symbolic value or abstract domain bound
2. **Index Range Analysis**: For each access `seq[i]`, generate constraint: `0 <= i < len(seq)` (or `-len(seq) <= i < len(seq)` for negative indices)
3. **Dictionary Domain**: Track set of valid keys; for `dict[k]`, require `k ∈ keys(dict)`
4. **Exception Edges**: CFG must include IndexError/KeyError exceptional edges from access operations
5. **Proof Obligation**: For SAFE claim, need barrier certificate showing bounds invariant holds
