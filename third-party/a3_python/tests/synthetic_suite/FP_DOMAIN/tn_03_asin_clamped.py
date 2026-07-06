"""
FP_DOMAIN True Negative #3: asin with bounded input

Ground truth: SAFE
Reason: Input is clamped to [-1, 1] before asin
No bug: Domain constraint enforced
"""

import math

def safe_asin(x):
    # SAFE: Clamp to valid domain [-1, 1]
    clamped = max(-1.0, min(1.0, x))
    return math.asin(clamped)

if __name__ == "__main__":
    result = safe_asin(0.5)
    print(f"Angle: {result}")
