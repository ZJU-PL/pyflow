"""
Papers #2-#19 exercise: Countdown while-loop (decrementing).

    while x > 0:
        x -= 1

Affine model: guard(x > 0), update(x' = x - 1), init(x = 10).
Safety: x >= 0 (non-negativity is maintained).

Target papers: #2, #4, #5, #6, #7, #8, #9, #10, #11, #12, #13, #14,
               #15, #16, #17, #18, #19
Expected: SAFE
"""

def countdown(n):
    x = n
    while x > 0:
        x -= 1
    return x
