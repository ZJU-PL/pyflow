"""
DIV_ZERO True Negative #5: Default value pattern

EXPECTED: SAFE
REASON: Potentially-zero divisor is replaced with safe default before use

This is a common defensive pattern: or-coalesce to ensure non-zero.
"""

def safe_division_with_default(numerator, divisor):
    safe_divisor = divisor or 1  # If divisor is 0 (falsy), use 1
    result = numerator / safe_divisor
    return result

if __name__ == "__main__":
    print(safe_division_with_default(10, 2))
    print(safe_division_with_default(10, 0))
