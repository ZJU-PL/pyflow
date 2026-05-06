"""
DIV_ZERO True Negative #3: Division with try-except handler

EXPECTED: SAFE (or UNKNOWN - debatable)
REASON: ZeroDivisionError is caught and handled

This is a common defensive programming pattern. Whether it's "SAFE" depends on
your definition - the exception is handled, but the operation still attempts
division by zero. For the purpose of this test, we consider it SAFE because
no unhandled exception escapes.
"""

def safe_division_with_exception_handling(a, b):
    try:
        result = a / b
        return result
    except ZeroDivisionError:
        return float('inf')

if __name__ == "__main__":
    print(safe_division_with_exception_handling(10, 2))
    print(safe_division_with_exception_handling(10, 0))
