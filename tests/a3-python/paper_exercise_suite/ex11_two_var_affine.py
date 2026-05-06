"""
Papers #2-#19 exercise: Two-variable affine system.

    while x < 10 and y < 20:
        x += 1
        y += 2

Larger state space to exercise barrier certificate methods
that handle multi-dimensional transition systems.

Target papers: #2, #4, #5, #6, #7, #8, #9, #10, #11, #12, #13, #14,
               #15, #16, #17, #18, #19
Expected: SAFE
"""


def two_var_affine():
    x = 0
    y = 0
    while x < 10:
        x += 1
        y += 2
    return x, y
