"""
FP_DOMAIN True Positive #1: sqrt of negative number

Ground truth: BUG (FP_DOMAIN)
Reason: math.sqrt() with negative argument raises ValueError (domain error)
Bug location: Line with math.sqrt(-4)
"""

import math

def compute():
    x = -4
    # BUG: sqrt of negative number - domain error
    result = math.sqrt(x)
    return result

if __name__ == "__main__":
    compute()
