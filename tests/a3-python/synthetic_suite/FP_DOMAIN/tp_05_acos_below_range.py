"""
FP_DOMAIN True Positive #5: acos below valid range

Ground truth: BUG (FP_DOMAIN)
Reason: math.acos() requires argument in [-1, 1]; -2.0 is out of range
Bug location: Line with math.acos(-2.0)
"""

import math

def inverse_cosine(x):
    # BUG: acos domain is [-1, 1], but x is -2.0
    result = math.acos(x)
    return result

if __name__ == "__main__":
    inverse_cosine(-2.0)
