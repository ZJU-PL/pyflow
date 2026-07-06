"""
BOUNDS True Negative #3: Range-based iteration

Expected: SAFE
Safety mechanism: range(len(items)) guarantees valid indices
Semantic basis: For-loop range invariant ensures index < len(items)
"""

def safe_range_iteration():
    items = ['x', 'y', 'z']
    result = []
    # SAFE: range(len(items)) ensures all indices are valid
    for i in range(len(items)):
        result.append(items[i])
    return result

if __name__ == "__main__":
    result = safe_range_iteration()
    print(f"Result: {result}")
