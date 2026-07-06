"""
Papers #1-#20 exercise: Guard + loop + multi-function (BUG variant).

Contains a guarded division (safe), a while loop (safe),
and multiple functions (safe), BUT also an unguarded sqrt
on a value that could be negative.

Target papers: all 20
Expected: BUG (unguarded negative sqrt)
"""
import math


def transform(x):
    return math.sqrt(x)   # BUG: x could be negative


def process(items):
    total = 0
    i = 0
    while i < len(items):
        total += items[i]
        i += 1
    return total


def pipeline(data, val):
    s = process(data)
    t = transform(val)   # may pass negative val
    return s + t
