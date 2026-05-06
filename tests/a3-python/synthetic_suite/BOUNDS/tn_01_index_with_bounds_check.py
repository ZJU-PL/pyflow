"""
BOUNDS True Negative #1: Index with bounds check

Expected: SAFE
Safety mechanism: Explicit bounds check before access
Semantic basis: All paths guard access with (0 <= index < len(items))
"""

def safe_index_with_check(index):
    items = [10, 20, 30, 40, 50]
    # SAFE: Bounds check ensures index is valid
    if 0 <= index < len(items):
        value = items[index]
        return value
    return None

if __name__ == "__main__":
    result = safe_index_with_check(2)
    print(f"Result: {result}")
