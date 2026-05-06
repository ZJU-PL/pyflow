"""
FP_DOMAIN True Positive #3: log of zero

Ground truth: BUG (FP_DOMAIN)
Reason: math.log(0) raises ValueError (domain error)
Bug location: Line with math.log(0.0)
"""

import math

def process_value():
    data = 0.0
    # BUG: log(0) is undefined (domain error)
    result = math.log(data)
    return result

if __name__ == "__main__":
    process_value()
