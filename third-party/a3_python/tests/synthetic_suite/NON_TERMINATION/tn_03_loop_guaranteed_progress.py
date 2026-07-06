"""
TRUE NEGATIVE: NON_TERMINATION
Safe: While loop with guaranteed progress toward termination

Expected: SAFE
Reason: Loop variable strictly decreases and termination condition is reachable
"""

def countdown(n):
    """While loop with guaranteed progress."""
    while n > 0:  # Condition: n > 0
        print(f"Countdown: {n}")
        n -= 1    # Progress: n strictly decreases
    return "Done"

if __name__ == "__main__":
    result = countdown(10)
    print(result)
