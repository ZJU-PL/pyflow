"""
Papers #1, #3 exercise: Multiple guarded hazards in one file.

Several different guarded operations to give the bytecode scanner
more opportunities for proofs.

Target papers: #1, #3
Expected: SAFE
"""
import math


def safe_ops(x, y, items, idx):
    # Guarded division
    if y != 0:
        ratio = x / y

    # Guarded modulo
    if y != 0:
        remainder = x % y

    # Guarded sqrt
    if x >= 0:
        root = math.sqrt(x)

    # Guarded index
    if 0 <= idx < len(items):
        val = items[idx]

    return True
