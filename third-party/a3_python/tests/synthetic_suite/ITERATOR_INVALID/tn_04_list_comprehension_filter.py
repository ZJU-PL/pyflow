"""
ITERATOR_INVALID True Negative #4: List comprehension with filter
Expected: SAFE

Pattern: List comprehensions create new collections without mutating
the original during iteration. Functional style is inherently safe.
"""

def remove_evens_comprehension():
    numbers = [1, 2, 3, 4, 5, 6, 7, 8]
    
    # SAFE: List comprehension creates new list
    result = [num for num in numbers if num % 2 == 1]
    
    return result

if __name__ == '__main__':
    result = remove_evens_comprehension()
    print(f"Result: {result}")
    assert result == [1, 3, 5, 7]
