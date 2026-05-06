"""
ITERATOR_INVALID True Positive #4: List removal during iteration
Expected: BUG (Iterator invalidation - elements skipped)

Semantic bug: Removing items from a list during iteration causes
index-based corruption. Elements are skipped because removal shifts
subsequent indices.
"""

def remove_evens():
    numbers = [1, 2, 3, 4, 5, 6, 7, 8]
    
    # BUG: Removing items during iteration skips elements
    # Expected to remove [2, 4, 6, 8], but will miss some due to index shift
    for num in numbers:
        if num % 2 == 0:
            numbers.remove(num)  # Iterator corruption - some evens remain
    
    return numbers

if __name__ == '__main__':
    result = remove_evens()
    print(f"Result: {result}")
    # Will likely contain some even numbers that were skipped
    assert all(x % 2 == 1 for x in result), f"Bug: Still has evens: {result}"
