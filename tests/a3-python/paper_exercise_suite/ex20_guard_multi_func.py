"""
Papers #1, #3 + #20 exercise: Guard patterns with helper functions.

Guarded operations across multiple helper functions exercise both
the bytecode-level guard proofs (Papers #1, #3) and compositional
reasoning (Paper #20).

Target papers: #1, #3, #20
Expected: SAFE
"""


def safe_divide(a, b):
    if b != 0:
        return a / b
    return 0.0


def safe_modulo(a, b):
    if b != 0:
        return a % b
    return 0


def safe_ratio_and_remainder(a, b):
    return safe_divide(a, b), safe_modulo(a, b)
