"""
BOUNDS True Positive #2: Negative index beyond length

Expected: BUG (IndexError)
Bug location: Line accessing items[-10] when list has only 4 elements
Semantic basis: BOUNDS violation - negative index with abs(index) > len(sequence)
"""

def negative_index_beyond():
    items = ['a', 'b', 'c', 'd']
    # BUG: -10 is beyond the start of the list (needs at least 10 elements)
    value = items[-10]
    return value

if __name__ == "__main__":
    result = negative_index_beyond()
    print(f"Result: {result}")
