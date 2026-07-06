"""
ITERATOR_INVALID True Negative #1: Iterate over dict copy
Expected: SAFE

Pattern: Creating a snapshot copy (list(dict)) before modification
ensures the iterator is independent of the original collection.
"""

def process_items_safely():
    data = {'a': 1, 'b': 2, 'c': 3, 'd': 4}
    
    # SAFE: Iterating over copy of keys
    for key in list(data.keys()):  # list() creates snapshot
        if data[key] > 2:
            del data[key]  # Safe - not modifying what we're iterating
    
    return data

if __name__ == '__main__':
    result = process_items_safely()
    print(f"Result: {result}")
    assert result == {'a': 1, 'b': 2}
