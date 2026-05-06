"""
DIV_ZERO True Positive #3: Modulo by zero

EXPECTED: BUG (DIV_ZERO)
REASON: Modulo operator also triggers ZeroDivisionError with zero divisor

Modulo (%) is another division operation that must be checked.
"""

def modulo_by_zero():
    x = 100
    y = 0
    remainder = x % y  # BUG: Modulo by zero
    return remainder

if __name__ == "__main__":
    modulo_by_zero()
