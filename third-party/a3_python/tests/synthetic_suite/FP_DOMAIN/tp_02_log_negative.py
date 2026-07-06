"""
FP_DOMAIN True Positive #2: log of negative number

Ground truth: BUG (FP_DOMAIN)
Reason: math.log() with negative argument raises ValueError (domain error)
Bug location: Line with math.log(-5.0)
"""

import math

def analyze_data(value):
    # BUG: logarithm of negative number
    log_value = math.log(value)
    return log_value

if __name__ == "__main__":
    analyze_data(-5.0)
