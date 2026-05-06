"""
Test the collection emptiness tracking for improved DIV_ZERO and BOUNDS detection.

Key insight: We don't need specialized bug types like EMPTY_COLLECTION_DIV.
Instead, we track `Emptiness` through dataflow:
- len() of empty collection → zeroness = ZERO → DIV_ZERO
- len() of maybe-empty collection → zeroness = TOP → DIV_ZERO (lower confidence)
- collection[0] where emptiness = EMPTY → BOUNDS (high confidence)
"""

from pyflow.a3_python.semantics.bytecode_summaries import (
    Emptiness, DictKeySet, AbstractValue
)


def test_emptiness_lattice():
    """Test Emptiness lattice operations."""
    assert Emptiness.EMPTY.join(Emptiness.NON_EMPTY) == Emptiness.TOP
    assert Emptiness.EMPTY.join(Emptiness.EMPTY) == Emptiness.EMPTY
    assert Emptiness.NON_EMPTY.join(Emptiness.NON_EMPTY) == Emptiness.NON_EMPTY
    assert Emptiness.TOP.join(Emptiness.EMPTY) == Emptiness.TOP
    print("✓ Emptiness lattice tests passed")


def test_dict_key_set():
    """Test DictKeySet tracking."""
    d1 = DictKeySet.from_keys({'a', 'b'}, complete=True)
    assert d1.has_key('a')
    assert d1.has_key('b')
    assert not d1.has_key('c')
    assert d1.missing_key('c')  # Complete dict, c is missing
    
    d2 = DictKeySet.from_keys({'a'}, complete=False)
    assert d2.has_key('a')
    assert not d2.missing_key('c')  # Open dict, can't say c is missing
    
    # Join of two DictKeySets
    d3 = d1.join(d2)
    assert d3.has_key('a')  # a is in both
    assert not d3.has_key('b')  # b only in d1
    
    print("✓ DictKeySet tests passed")


def test_abstract_value_const():
    """Test AbstractValue.from_const with collections."""
    # Empty list
    v1 = AbstractValue.from_const([])
    assert v1.emptiness == Emptiness.EMPTY
    
    # Non-empty list
    v2 = AbstractValue.from_const([1, 2, 3])
    assert v2.emptiness == Emptiness.NON_EMPTY
    
    # Dict with keys
    v3 = AbstractValue.from_const({'a': 1, 'b': 2})
    assert v3.emptiness == Emptiness.NON_EMPTY
    assert v3.dict_keys.has_key('a')
    assert v3.dict_keys.has_key('b')
    
    # Empty dict
    v4 = AbstractValue.from_const({})
    assert v4.emptiness == Emptiness.EMPTY
    
    # List with zeros (for scale detection)
    v5 = AbstractValue.from_const([1, 0, 2])
    assert v5.may_contain_zeros == True
    
    v6 = AbstractValue.from_const([1, 2, 3])
    assert v6.may_contain_zeros == False
    
    print("✓ AbstractValue.from_const tests passed")


# Pattern tests - these are the bugs we want to detect
def example_empty_collection_div(data):
    """BUG: Division by len() of potentially empty collection."""
    # sum(data) / len(data) crashes if data is []
    return sum(data) / len(data)


def example_empty_collection_index(results):
    """BUG: Indexing [0] on potentially empty collection."""
    # results[0] crashes if results is []
    return results[0]


def example_dict_key_missing(context):
    """BUG: Dict access without .get() for potentially missing key."""
    # context["message"] crashes if "message" not in context
    return context["message"]


def example_scale_zero_normalize(feature, prep):
    """BUG: Division by scale array that may contain zeros."""
    # (feature - center) / scale crashes if scale contains 0
    import numpy as np
    return (np.array(feature) - np.array(prep["center"])) / np.array(prep["scale"])


# Safe patterns - these should NOT be flagged
def safe_empty_collection_div(data):
    """SAFE: Guarded division."""
    if len(data) > 0:
        return sum(data) / len(data)
    return 0


def safe_dict_key_missing(context):
    """SAFE: Using .get() with default."""
    return context.get("message", "default")


def safe_empty_collection_index(results):
    """SAFE: Guarded indexing."""
    if results:
        return results[0]
    return None


if __name__ == '__main__':
    test_emptiness_lattice()
    test_dict_key_set()
    test_abstract_value_const()
    
    print("\n✓ All lattice tests completed")
    print("\nThe Emptiness lattice enables better detection of existing bugs:")
    print("  - DIV_ZERO: Triggered when dividing by len() of potentially empty collection")
    print("    (because len([]) = 0, and zeroness lattice tracks this)")
    print("  - BOUNDS: Triggered with higher confidence when indexing [0] on empty collection")
    print("    (because emptiness = EMPTY means IndexError is certain)")
    print("\nNo new bug types needed - just better tracking for existing types.")
