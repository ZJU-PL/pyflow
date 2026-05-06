"""
DIV_ZERO True Positive #2: Division by variable that is zero

EXPECTED: BUG (DIV_ZERO)
REASON: Variable is set to zero and then used as divisor

The symbolic analyzer must track that divisor == 0 and flag the division.
"""

def divide_by_variable():
    numerator = 42
    divisor = 0
    result = numerator / divisor  # BUG: divisor is 0
    return result

if __name__ == "__main__":
    divide_by_variable()
