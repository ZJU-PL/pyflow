# ITERATOR_INVALID Test Suite

**Bug Type**: Collection modification during iteration violates iterator protocol invariants.

## Semantic Definition

The `ITERATOR_INVALID` bug occurs when:
1. An iterator is created over a collection (dict, set, list)
2. The collection structure is modified during iteration (size change, element insertion/removal)
3. The iterator's internal state becomes inconsistent with the collection

### Manifestations in Python

**Dict/Set (Python 3.7+)**:
- `RuntimeError: dictionary changed size during iteration`
- `RuntimeError: Set changed size during iteration`

**List**:
- Silent corruption: elements skipped or processed multiple times
- Infinite loops (if appending during iteration)
- No explicit RuntimeError (indices shift silently)

## Unsafe Predicate `U_ITERATOR_INVALID(σ)`

In machine state σ, iterator invalidation occurs when:
```
∃ iter_obj ∈ Heap(σ) : 
  iter_obj.type = Iterator ∧
  iter_obj.collection_ref = coll_id ∧
  Heap(σ)[coll_id].structure_version ≠ iter_obj.expected_version
```

Where:
- `structure_version` is incremented on size-changing mutations (add, remove, pop)
- `expected_version` is captured at iterator creation
- Mismatch indicates invalidation

## True Positives (5 cases)

### tp_01: Dict modification during iteration
- **Pattern**: `del data[key]` inside `for key in data:`
- **Error**: `RuntimeError: dictionary changed size during iteration`

### tp_02: List append during for-loop
- **Pattern**: `items.append(x)` inside `for item in items:`
- **Behavior**: Unbounded growth, potential infinite loop

### tp_03: Set add while iterating
- **Pattern**: `values.add(x)` inside `for val in values:`
- **Error**: `RuntimeError: Set changed size during iteration`

### tp_04: List remove during iteration
- **Pattern**: `numbers.remove(x)` inside `for num in numbers:`
- **Behavior**: Silent corruption, elements skipped due to index shift

### tp_05: Dict keys view mutation
- **Pattern**: `data[new_key] = val` inside `for key in data.keys():`
- **Error**: `RuntimeError: dictionary changed size during iteration`

## True Negatives (5 cases)

### tn_01: Iterate over dict copy
- **Pattern**: `for key in list(data.keys()): del data[key]`
- **Safety**: `list()` creates independent snapshot

### tn_02: List snapshot before mutation
- **Pattern**: `for num in numbers[:]: numbers.remove(num)`
- **Safety**: Slice `[:]` creates copy

### tn_03: Separate collection for additions
- **Pattern**: Accumulate modifications in separate list, apply after iteration
- **Safety**: No structural mutation during iteration

### tn_04: List comprehension with filter
- **Pattern**: `result = [x for x in items if predicate(x)]`
- **Safety**: Functional style creates new collection

### tn_05: Dict comprehension for transformation
- **Pattern**: `result = {k: v for k, v in data.items() if condition}`
- **Safety**: No mutation of original during comprehension

## Detector Requirements (Barrier-Theoretic)

1. **Track collection structure versions**: Each collection has a version counter incremented on mutations
2. **Track iterator expectations**: Iterators capture expected version at creation
3. **Check version mismatch**: At each iterator advance, verify `current_version == expected_version`
4. **Path-sensitive analysis**: Distinguish iterator-over-original vs iterator-over-copy

### Sound Over-Approximation

To avoid false negatives, conservatively flag:
- Any mutation to collection `C` while iterator over `C` is live
- Unless proven that iterator is over an independent copy/view

### False Positive Avoidance

Recognize safe patterns:
- `list(collection)`, `collection[:]`, `collection.copy()`
- Comprehensions (create new collections)
- Mutations to different collections
- Mutations after iterator exhaustion

## Ground Truth Labels

| File | Expected | Reason |
|------|----------|--------|
| tp_01_dict_modification_during_iteration.py | BUG | Dict mutated during iteration |
| tp_02_list_append_during_for_loop.py | BUG | List grows unboundedly during iteration |
| tp_03_set_add_while_iterating.py | BUG | Set mutated during iteration |
| tp_04_list_remove_during_iteration.py | BUG | List removal causes index corruption |
| tp_05_dict_keys_view_mutation.py | BUG | Dict keys view invalidated |
| tn_01_iterate_over_dict_copy.py | SAFE | Iterates over `list(keys)` snapshot |
| tn_02_list_snapshot_before_mutation.py | SAFE | Iterates over slice copy `[:]` |
| tn_03_separate_collection_for_additions.py | SAFE | Modifications deferred until after iteration |
| tn_04_list_comprehension_filter.py | SAFE | Comprehension creates new list |
| tn_05_dict_comprehension_transform.py | SAFE | Comprehension creates new dict |

## Validation Commands

```bash
# Run each true positive (should raise RuntimeError or exhibit corruption)
python tests/synthetic_suite/ITERATOR_INVALID/tp_01_dict_modification_during_iteration.py
python tests/synthetic_suite/ITERATOR_INVALID/tp_02_list_append_during_for_loop.py
python tests/synthetic_suite/ITERATOR_INVALID/tp_03_set_add_while_iterating.py
python tests/synthetic_suite/ITERATOR_INVALID/tp_04_list_remove_during_iteration.py
python tests/synthetic_suite/ITERATOR_INVALID/tp_05_dict_keys_view_mutation.py

# Run each true negative (should complete successfully)
python tests/synthetic_suite/ITERATOR_INVALID/tn_01_iterate_over_dict_copy.py
python tests/synthetic_suite/ITERATOR_INVALID/tn_02_list_snapshot_before_mutation.py
python tests/synthetic_suite/ITERATOR_INVALID/tn_03_separate_collection_for_additions.py
python tests/synthetic_suite/ITERATOR_INVALID/tn_04_list_comprehension_filter.py
python tests/synthetic_suite/ITERATOR_INVALID/tn_05_dict_comprehension_transform.py
```

## References

- Python docs: [Iterator protocol](https://docs.python.org/3/library/stdtypes.html#iterator-types)
- PEP 234: [Iterators](https://www.python.org/dev/peps/pep-0234/)
- CPython implementation: `Objects/dictobject.c` (ma_version_tag for dicts)
