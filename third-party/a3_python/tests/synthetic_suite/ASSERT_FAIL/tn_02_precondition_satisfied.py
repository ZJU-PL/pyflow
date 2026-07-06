"""
ASSERT_FAIL True Negative 02: Precondition satisfied

Expected: SAFE
Reason: Precondition assertion passes because input satisfies constraint
Semantic: All paths through function satisfy assertion condition
"""

import math

def sqrt_positive(x):
    assert x >= 0, "Input must be non-negative"
    return math.sqrt(x)

if __name__ == "__main__":
    # Call with valid non-negative value
    result = sqrt_positive(25)
    print(f"Result: {result}")
