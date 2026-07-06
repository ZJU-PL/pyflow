"""
TRUE NEGATIVE: NON_TERMINATION
Safe: Mutual recursion with proper base cases

Expected: SAFE
Reason: Both functions have base cases and make progress toward them
"""

def is_even(n):
    """Even check via mutual recursion with proper base case."""
    if n == 0:
        return True
    else:
        return is_odd(n - 1)  # Progress: n decreases

def is_odd(n):
    """Odd check via mutual recursion with proper base case."""
    if n == 0:
        return False
    else:
        return is_even(n - 1)  # Progress: n decreases

if __name__ == "__main__":
    result_even = is_even(10)
    result_odd = is_odd(7)
    print(f"10 is even: {result_even}, 7 is odd: {result_odd}")
