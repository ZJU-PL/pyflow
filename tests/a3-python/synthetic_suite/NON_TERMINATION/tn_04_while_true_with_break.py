"""
TRUE NEGATIVE: NON_TERMINATION
Safe: Loop with explicit break condition

Expected: SAFE
Reason: while True with reachable break statement guarantees termination
"""

def search_with_break(target, items):
    """while True with explicit break - guaranteed termination."""
    index = 0
    while True:
        if index >= len(items):  # Termination: exhausted all items
            break
        if items[index] == target:  # Termination: found target
            return index
        index += 1  # Progress: index increases
    return -1

if __name__ == "__main__":
    result = search_with_break(42, [1, 2, 3, 42, 5])
    print(f"Found at index: {result}")
