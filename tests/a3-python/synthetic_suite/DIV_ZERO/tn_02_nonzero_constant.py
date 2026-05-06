"""
DIV_ZERO True Negative #2: Division by non-zero constant

EXPECTED: SAFE
REASON: Divisor is a non-zero literal constant

Constants can be statically verified to be non-zero.
"""

def divide_by_constant():
    x = 100
    result = x / 5  # SAFE: 5 is non-zero
    return result

if __name__ == "__main__":
    print(divide_by_constant())
