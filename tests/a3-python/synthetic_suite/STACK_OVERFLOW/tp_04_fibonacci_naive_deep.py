"""
STACK_OVERFLOW True Positive #4: Naive Fibonacci with Large Input
Ground Truth: BUG (RecursionError)

Naive recursive fibonacci with exponential call tree.
Even moderate n values can exhaust the stack due to deep recursion paths.
"""

def fibonacci(n):
    """Naive recursive fibonacci - no memoization."""
    if n <= 1:
        return n
    return fibonacci(n - 1) + fibonacci(n - 2)

def main():
    # Request fibonacci of large number
    # The recursion tree grows exponentially deep
    n = 5000
    print(f"Computing fibonacci({n})...")
    result = fibonacci(n)  # STACK_OVERFLOW during deep recursion
    print(f"fibonacci({n}) = {result}")

if __name__ == "__main__":
    main()
