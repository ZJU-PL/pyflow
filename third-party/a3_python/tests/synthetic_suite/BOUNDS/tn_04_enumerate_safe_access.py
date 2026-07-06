"""
BOUNDS True Negative #4: Enumerate safe access

Expected: SAFE
Safety mechanism: enumerate() yields valid (index, value) pairs
Semantic basis: Python enumerate guarantees index invariant
"""

def safe_enumerate():
    items = [100, 200, 300, 400]
    result = {}
    # SAFE: enumerate guarantees valid indices
    for i, value in enumerate(items):
        result[i] = value
    return result

if __name__ == "__main__":
    result = safe_enumerate()
    print(f"Result: {result}")
