"""
TRUE POSITIVE: NON_TERMINATION
Bug: Recursive function with unreachable base case

Expected: BUG (NON_TERMINATION)
Reason: Base case condition is never satisfied due to wrong comparison
"""

def countdown_wrong(n):
    """Countdown that never reaches base case."""
    if n == 0:  # Base case for n == 0
        return "done"
    else:
        # For n > 0, we increment instead of decrement
        # For n < 0, we increment away from 0
        return countdown_wrong(n + 1)

if __name__ == "__main__":
    result = countdown_wrong(5)
