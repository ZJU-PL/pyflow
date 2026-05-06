"""
TRUE POSITIVE: NON_TERMINATION
Bug: while True without any break/return/raise - infinite loop

Expected: BUG (NON_TERMINATION)
Reason: Loop has no exit condition and runs forever
"""

def infinite_loop():
    """Unconditional infinite loop."""
    counter = 0
    while True:
        counter += 1
        # No break, no return, no raise - just infinite iteration

if __name__ == "__main__":
    infinite_loop()
