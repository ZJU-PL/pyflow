"""
TRUE NEGATIVE: NON_TERMINATION
Safe: Recursion with proper base case

Expected: SAFE
Reason: Base case is reachable and recursive call makes progress toward it
"""

def factorial(n):
    """Classic recursion with proper base case."""
    if n <= 1:  # Base case: stops recursion
        return 1
    else:
        return n * factorial(n - 1)  # Progress: n decreases

if __name__ == "__main__":
    result = factorial(10)
    print(f"Factorial: {result}")
