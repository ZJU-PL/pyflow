"""
FP_DOMAIN True Negative #2: log with positive check

Ground truth: SAFE
Reason: log only called with positive value (checked before use)
No bug: Domain constraint satisfied
"""

import math

def safe_log(value):
    # SAFE: Ensures positive value before log
    if value > 0:
        return math.log(value)
    else:
        return float('-inf')

if __name__ == "__main__":
    result = safe_log(10.0)
    print(f"Log: {result}")
