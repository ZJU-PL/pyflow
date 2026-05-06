"""
Papers #1, #3 exercise: Guarded sqrt (FP_DOMAIN hazard guard).

The guard `x >= 0` ensures math.sqrt(x) is safe.

Target papers: #1, #3
Expected: SAFE
"""
import math


def safe_sqrt(x):
    if x >= 0:
        return math.sqrt(x)
    return 0.0
