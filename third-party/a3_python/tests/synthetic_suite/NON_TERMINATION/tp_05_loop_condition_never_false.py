"""
TRUE POSITIVE: NON_TERMINATION
Bug: Loop condition that can never become false

Expected: BUG (NON_TERMINATION)
Reason: Loop modifies unrelated variable, condition variable never changes
"""

def loop_wrong_variable():
    """Loop modifies wrong variable, condition never becomes false."""
    target = 10
    count = 0
    
    while target > 0:  # Condition checks 'target'
        count += 1      # But we modify 'count' instead
        # target never changes, so condition always true
    
    return count

if __name__ == "__main__":
    result = loop_wrong_variable()
