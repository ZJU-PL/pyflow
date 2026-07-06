"""
FP_DOMAIN True Negative #4: exception handler for domain errors

Ground truth: SAFE
Reason: Domain error is caught and handled (no unhandled exception)
No bug: Error handling prevents propagation
"""

import math

def robust_sqrt(x):
    # SAFE: Domain error caught and handled
    try:
        return math.sqrt(x)
    except ValueError:
        # Handle domain error gracefully
        return None

if __name__ == "__main__":
    result = robust_sqrt(-4)
    if result is None:
        print("Invalid input handled")
