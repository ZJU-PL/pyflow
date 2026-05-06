"""
FP_DOMAIN True Negative #1: sqrt with non-negative check

Ground truth: SAFE
Reason: sqrt only called with non-negative value (checked before use)
No bug: Proper domain validation
"""

import math

def safe_sqrt(x):
    # SAFE: Check ensures non-negative before sqrt
    if x >= 0:
        return math.sqrt(x)
    else:
        return 0.0

if __name__ == "__main__":
    result = safe_sqrt(16.0)
    print(f"Result: {result}")
