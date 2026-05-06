"""
TRUE NEGATIVE: NON_TERMINATION
Safe: Bounded loop with range iterator

Expected: SAFE
Reason: range() provides bounded iteration, guaranteed to terminate
"""

def bounded_loop_with_range():
    """Loop with range iterator - guaranteed termination."""
    total = 0
    for i in range(100):  # Bounded: exactly 100 iterations
        total += i
    return total

if __name__ == "__main__":
    result = bounded_loop_with_range()
    print(f"Sum: {result}")
