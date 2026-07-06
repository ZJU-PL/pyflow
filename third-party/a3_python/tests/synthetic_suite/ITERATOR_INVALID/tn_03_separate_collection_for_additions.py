"""
ITERATOR_INVALID True Negative #3: Separate collection for additions
Expected: SAFE

Pattern: Collect modifications in a separate collection, apply after
iteration completes. No iterator invalidation.
"""

def process_list_deferred():
    items = [1, 2, 3]
    to_add = []
    
    # SAFE: Collect additions separately
    for item in items:
        to_add.append(item * 2)
    
    # Apply additions after iteration
    items.extend(to_add)
    
    return items

if __name__ == '__main__':
    result = process_list_deferred()
    print(f"Result: {result}")
    assert result == [1, 2, 3, 2, 4, 6]
