"""
FP_DOMAIN True Negative #5: Valid constant inputs

Ground truth: SAFE
Reason: All math functions called with valid constant arguments
No bug: Trivially safe due to constants in valid domain
"""

import math

def compute_with_constants():
    # SAFE: All arguments are in valid domain
    sqrt_result = math.sqrt(25.0)  # Positive
    log_result = math.log(10.0)    # Positive
    asin_result = math.asin(0.5)   # In [-1, 1]
    acos_result = math.acos(0.5)   # In [-1, 1]
    
    return sqrt_result + log_result + asin_result + acos_result

if __name__ == "__main__":
    result = compute_with_constants()
    print(f"Result: {result}")
