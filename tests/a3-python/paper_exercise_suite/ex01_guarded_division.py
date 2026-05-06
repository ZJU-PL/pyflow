"""
Paper #1 exercise: Guarded division (HSCC'04 barrier certificate).

The guard `divisor != 0` dominates the division site, so the
bytecode-level analysis can prove DIV_ZERO is unreachable.

Target papers: #1 (HSCC04 div-zero guard), #3 (SOS emptiness guard)
Expected: SAFE
"""

def safe_divide(x, divisor):
    if divisor != 0:
        return x / divisor
    return 0
