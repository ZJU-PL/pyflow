"""
DOUBLE_FREE True Negative #4: Flag-based double-call prevention

Ground truth: SAFE
Reasoning: Using an explicit flag to track whether close() has been called.
All paths check the flag before closing.

The analyzer should verify:
- Flag ensures close() called at most once
- All conditional paths respect the flag
- No double-free possible
"""

class FlaggedResource:
    def __init__(self):
        self.is_closed = False
    
    def close(self):
        if self.is_closed:
            return
        # Actual cleanup
        self.is_closed = True

def flag_based_prevention(error_case):
    r = FlaggedResource()
    
    try:
        if error_case:
            raise ValueError("error")
    except ValueError:
        r.close()
    finally:
        r.close()  # SAFE: flag prevents actual double close

if __name__ == "__main__":
    flag_based_prevention(True)
