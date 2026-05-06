"""
STACK_OVERFLOW True Positive #1: Unbounded Recursion
Ground Truth: BUG (RecursionError)

Classic unbounded recursion with no base case.
Each call pushes a new frame, eventually exhausting the call stack.
"""

def infinite_recursion(n):
    """Recursive function without base case - always recurses."""
    return infinite_recursion(n + 1)

def main():
    # Direct call to function without base case
    result = infinite_recursion(0)
    print(f"Result: {result}")  # Never reached

if __name__ == "__main__":
    main()
