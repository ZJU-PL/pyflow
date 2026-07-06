"""
ASSERT_FAIL True Positive 03: Failing precondition assertion

Expected: BUG (ASSERT_FAIL)
Reason: Precondition assertion fails when passed negative value
Bug location: Line 12
Semantic unsafe region: sqrt_positive called with negative input violates precondition
"""

import math

def sqrt_positive(x):
    assert x >= 0, "Input must be non-negative"
    return math.sqrt(x)

if __name__ == "__main__":
    # Call with negative value, violating precondition
    result = sqrt_positive(-5)
    print(f"Result: {result}")
