"""
ITERATOR_INVALID True Negative #2: List snapshot before mutation
Expected: SAFE

Pattern: Creating a list copy via slicing [:] creates an independent
iterator that is not affected by mutations to the original.
"""

def remove_evens_safely():
    numbers = [1, 2, 3, 4, 5, 6, 7, 8]
    
    # SAFE: Iterate over copy, modify original
    for num in numbers[:]:  # Slice creates copy
        if num % 2 == 0:
            numbers.remove(num)
    
    return numbers

if __name__ == '__main__':
    result = remove_evens_safely()
    print(f"Result: {result}")
    assert all(x % 2 == 1 for x in result), "Should contain only odd numbers"
    assert result == [1, 3, 5, 7]
