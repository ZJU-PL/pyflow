"""
BOUNDS True Positive #1: List index out of range

Expected: BUG (IndexError)
Bug location: Line accessing items[5] when list has only 3 elements
Semantic basis: BOUNDS violation - index >= len(sequence)
"""

def access_out_of_bounds():
    items = [10, 20, 30]
    # BUG: Index 5 is out of range for a 3-element list
    value = items[5]
    return value

if __name__ == "__main__":
    result = access_out_of_bounds()
    print(f"Result: {result}")
