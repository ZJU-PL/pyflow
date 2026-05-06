"""
DIV_ZERO True Positive #1: Direct division by zero literal

EXPECTED: BUG (DIV_ZERO)
REASON: Division by literal zero - unconditionally triggers ZeroDivisionError

This is the simplest possible division by zero case.
"""

def divide_by_zero():
    x = 10
    result = x / 0  # BUG: Division by zero
    return result

if __name__ == "__main__":
    divide_by_zero()
