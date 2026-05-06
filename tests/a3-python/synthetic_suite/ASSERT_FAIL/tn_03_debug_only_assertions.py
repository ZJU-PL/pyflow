"""
ASSERT_FAIL True Negative 03: Debug-only assertions (disabled with -O)

Expected: SAFE (when optimizations enabled)
Reason: assert statements are compiled out when Python runs with -O flag
Semantic: No assertion checking in optimized mode, no AssertionError possible
Note: In verification context, this is SAFE if target environment uses -O
"""

def debug_check(value):
    # These assertions are removed in optimized builds
    assert isinstance(value, int), "Value must be integer"
    assert value > 0, "Value must be positive"
    return value * 2

if __name__ == "__main__":
    # When run with python -O, assertions are disabled
    result = debug_check(10)
    print(f"Result: {result}")
