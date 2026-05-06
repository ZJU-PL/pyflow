"""
DIV_ZERO True Positive #4: Floor division by zero

EXPECTED: BUG (DIV_ZERO)
REASON: Floor division (//) also raises ZeroDivisionError

All three division operators (/, //, %) must be checked.
"""

def floor_divide_by_zero():
    a = 17
    b = 0
    quotient = a // b  # BUG: Floor division by zero
    return quotient

if __name__ == "__main__":
    floor_divide_by_zero()
