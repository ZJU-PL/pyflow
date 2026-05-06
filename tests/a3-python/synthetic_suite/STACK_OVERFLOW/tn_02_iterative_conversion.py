"""
STACK_OVERFLOW True Negative #2: Iterative Conversion
Ground Truth: SAFE

Iterative implementation instead of recursive.
Uses constant stack space regardless of input size.
"""

def factorial_iterative(n):
    """Iterative factorial - no recursion."""
    result = 1
    for i in range(2, n + 1):
        result *= i
    return result

def fibonacci_iterative(n):
    """Iterative fibonacci - no recursion."""
    if n <= 1:
        return n
    
    a, b = 0, 1
    for _ in range(2, n + 1):
        a, b = b, a + b
    return b

def main():
    # Large inputs are safe with iteration
    print(f"1000! has {len(str(factorial_iterative(1000)))} digits")
    print(f"fibonacci(1000) computed successfully")
    fib = fibonacci_iterative(1000)
    print(f"Result has {len(str(fib))} digits")

if __name__ == "__main__":
    main()
