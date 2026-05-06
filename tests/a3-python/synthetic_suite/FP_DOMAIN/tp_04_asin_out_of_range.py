"""
FP_DOMAIN True Positive #4: asin outside [-1, 1]

Ground truth: BUG (FP_DOMAIN)
Reason: math.asin() requires argument in [-1, 1]; 1.5 is out of range
Bug location: Line with math.asin(1.5)
"""

import math

def compute_angle(value):
    # BUG: asin domain is [-1, 1], but value is 1.5
    angle = math.asin(value)
    return angle

if __name__ == "__main__":
    compute_angle(1.5)
