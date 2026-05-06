"""
ASSERT_FAIL True Negative 04: Assertion with exception handler

Expected: SAFE (exception does not propagate)
Reason: AssertionError is caught by try-except, does not propagate to top-level
Semantic: Unsafe region (AssertionError) is reachable but handled
"""

def guarded_assert(x):
    try:
        assert x > 0, "x must be positive"
        return x * 2
    except AssertionError as e:
        # Handle the assertion failure gracefully
        print(f"Assertion failed: {e}")
        return 0

if __name__ == "__main__":
    # Even with invalid input, no unhandled assertion
    result = guarded_assert(-5)
    print(f"Result: {result}")
