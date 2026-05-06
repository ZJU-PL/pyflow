"""
All papers exercise: Combined guard + while-loop + multiple functions.

Has a guarded division (Papers #1, #3), a while-loop for affine
model engines (Papers #2, #4-19), and multiple functions for
compositional reasoning (Paper #20).

Target papers: #1, #2, #3, #4, #5, #6, #7, #8, #9, #10, #11, #12,
               #13, #14, #15, #16, #17, #18, #19, #20
Expected: SAFE
"""


def safe_divide(a, b):
    if b != 0:
        return a / b
    return 0


def accumulate(n):
    total = 0
    i = 0
    while i < n:
        total += i
        i += 1
    return total


def combined(a, b, n):
    ratio = safe_divide(a, b)
    total = accumulate(n)
    return ratio + total
