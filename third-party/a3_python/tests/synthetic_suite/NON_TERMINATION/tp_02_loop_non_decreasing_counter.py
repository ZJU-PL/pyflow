"""
TRUE POSITIVE: NON_TERMINATION
Bug: Loop with counter that never reaches termination condition

Expected: BUG (NON_TERMINATION)
Reason: Counter increments but condition checks for decrement to zero
"""

def non_decreasing_counter():
    """Loop where counter moves in wrong direction."""
    i = 0
    while i >= 0:  # Condition expects i to become negative
        i += 1     # But i only increases - never terminates
        if i > 1000000:  # This condition never triggers loop exit
            pass

if __name__ == "__main__":
    non_decreasing_counter()
