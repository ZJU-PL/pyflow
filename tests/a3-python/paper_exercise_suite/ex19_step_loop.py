"""
Papers #2-#19 exercise: While-loop with step > 1.

    while x < 100:
        x += 3

Non-unit step to exercise engines that need to handle
non-trivial affine updates.

Target papers: #2, #4, #5, #6, #7, #8, #9, #10, #11, #12, #13, #14,
               #15, #16, #17, #18, #19
Expected: SAFE
"""


def skip_count():
    x = 0
    while x < 100:
        x += 3
    return x
