"""
STACK_OVERFLOW True Positive #2: Mutual Recursion Without Depth Limit
Ground Truth: BUG (RecursionError)

Two functions call each other without proper termination.
The alternating calls still consume stack frames until exhaustion.
"""

def func_a(n):
    """Calls func_b without bounds check."""
    return func_b(n + 1)

def func_b(n):
    """Calls func_a without bounds check."""
    return func_a(n + 1)

def main():
    # Start mutual recursion - no depth limit will save us
    result = func_a(0)
    print(f"Result: {result}")  # Never reached

if __name__ == "__main__":
    main()
