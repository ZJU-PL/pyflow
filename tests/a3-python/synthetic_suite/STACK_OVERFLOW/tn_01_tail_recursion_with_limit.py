"""
STACK_OVERFLOW True Negative #1: Tail Recursion with Explicit Limit
Ground Truth: SAFE

Recursive function with explicit depth limit.
Raises ValueError when limit exceeded instead of stack overflow.
"""

def factorial_limited(n, max_depth=100, depth=0):
    """Factorial with explicit recursion depth limit."""
    if depth >= max_depth:
        raise ValueError(f"Recursion depth limit exceeded: {max_depth}")
    
    if n <= 1:
        return 1
    return n * factorial_limited(n - 1, max_depth, depth + 1)

def main():
    # Compute factorial with safe depth
    result = factorial_limited(10)
    print(f"10! = {result}")
    
    # Attempting excessive depth raises ValueError, not RecursionError
    try:
        result = factorial_limited(200, max_depth=100)
    except ValueError as e:
        print(f"Caught expected error: {e}")

if __name__ == "__main__":
    main()
