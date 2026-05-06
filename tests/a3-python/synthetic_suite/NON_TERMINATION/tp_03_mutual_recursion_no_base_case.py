"""
TRUE POSITIVE: NON_TERMINATION
Bug: Mutual recursion without proper base case

Expected: BUG (NON_TERMINATION)
Reason: Functions call each other indefinitely with no terminating condition
"""

def function_a(n):
    """Calls function_b unconditionally."""
    return function_b(n + 1)

def function_b(n):
    """Calls function_a unconditionally."""
    return function_a(n + 1)

if __name__ == "__main__":
    result = function_a(0)
