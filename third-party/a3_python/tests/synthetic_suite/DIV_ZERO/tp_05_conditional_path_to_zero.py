"""
DIV_ZERO True Positive #5: Conditional path where divisor becomes zero

EXPECTED: BUG (DIV_ZERO)
REASON: On one control flow path, divisor is set to zero before use

This tests path-sensitive analysis: the bug exists on the else branch.
"""

def conditional_divide(flag):
    x = 100
    if flag:
        divisor = 10
    else:
        divisor = 0  # This path makes divisor zero
    
    result = x / divisor  # BUG: divisor can be 0 (when flag is False)
    return result

if __name__ == "__main__":
    conditional_divide(False)
