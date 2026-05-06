"""
BOUNDS True Positive #4: Computed index overflow

Expected: BUG (IndexError)
Bug location: Line accessing arr[index] where index = len(arr)
Semantic basis: BOUNDS violation - valid indices are [0, len-1], attempting len itself
"""

def computed_index_overflow():
    arr = [1, 2, 3, 4, 5]
    # BUG: index = 5 is out of range for 5-element list (valid: 0-4)
    index = len(arr)
    value = arr[index]
    return value

if __name__ == "__main__":
    result = computed_index_overflow()
    print(f"Result: {result}")
