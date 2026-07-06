"""
Papers #2-#19 exercise: Two-variable while-loop (richer affine model).

    while i < n:
        i += 1

Two variables make the verification harder, exercising engines
that handle multi-dimensional transition systems.

Target papers: #2, #4, #5, #6, #7, #8, #9, #10, #11, #12, #13, #14,
               #15, #16, #17, #18, #19
Expected: SAFE
"""

def bounded_loop(n):
    i = 0
    while i < n:
        i += 1
    return i
