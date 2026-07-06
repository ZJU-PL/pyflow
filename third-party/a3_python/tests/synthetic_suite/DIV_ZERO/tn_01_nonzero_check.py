"""
DIV_ZERO True Negative #1: Division with non-zero check

EXPECTED: SAFE
REASON: Divisor is explicitly checked to be non-zero before division

The guard prevents division by zero from ever happening.
"""

def safe_division_with_check(numerator, divisor):
    if divisor != 0:
        result = numerator / divisor
        return result
    else:
        return None

if __name__ == "__main__":
    print(safe_division_with_check(10, 2))
    print(safe_division_with_check(10, 0))
