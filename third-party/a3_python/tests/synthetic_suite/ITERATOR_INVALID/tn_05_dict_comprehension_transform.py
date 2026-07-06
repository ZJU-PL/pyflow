"""
ITERATOR_INVALID True Negative #5: Dict comprehension for transformation
Expected: SAFE

Pattern: Dictionary comprehension creates new dict, does not mutate
during iteration. No iterator invalidation risk.
"""

def transform_dict():
    data = {'a': 1, 'b': 2, 'c': 3, 'd': 4}
    
    # SAFE: Dict comprehension creates new dict
    result = {key: value for key, value in data.items() if value <= 2}
    
    return result

if __name__ == '__main__':
    result = transform_dict()
    print(f"Result: {result}")
    assert result == {'a': 1, 'b': 2}
