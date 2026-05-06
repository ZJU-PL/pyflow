"""
STACK_OVERFLOW True Negative #3: sys.setrecursionlimit with Guard
Ground Truth: SAFE

Increased recursion limit with validation that input stays within bounds.
Explicit check ensures we never approach the limit.
"""

import sys

def deep_computation(n, limit):
    """Recursive function with validated depth."""
    if n >= limit - 100:  # Safety margin before actual limit
        raise ValueError(f"Input {n} too close to recursion limit {limit}")
    
    if n == 0:
        return 0
    return 1 + deep_computation(n - 1, limit)

def main():
    # Set higher recursion limit
    old_limit = sys.getrecursionlimit()
    new_limit = 5000
    sys.setrecursionlimit(new_limit)
    
    print(f"Recursion limit: {old_limit} -> {new_limit}")
    
    # Compute with validated depth (well within limit)
    safe_depth = 1000
    result = deep_computation(safe_depth, new_limit)
    print(f"deep_computation({safe_depth}) = {result}")
    
    # Restore original limit
    sys.setrecursionlimit(old_limit)

if __name__ == "__main__":
    main()
