"""
BOUNDS True Positive #5: Tuple indexing past end

Expected: BUG (IndexError)
Bug location: Line accessing coordinates[3] when tuple has 3 elements
Semantic basis: BOUNDS violation - index 3 on 3-element tuple (valid: 0-2)
"""

def tuple_index_past_end():
    coordinates = (10, 20, 30)
    # BUG: Index 3 is out of range for 3-element tuple
    z_value = coordinates[3]
    return z_value

if __name__ == "__main__":
    result = tuple_index_past_end()
    print(f"Result: {result}")
