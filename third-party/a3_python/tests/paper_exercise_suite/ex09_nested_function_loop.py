"""
Papers #2-#19 exercise: While-loop with nested function.

The while loop is inside a function, testing that the analyzer
scans nested code objects for affine loop models.

Target papers: #2, #4-19
Expected: SAFE
"""


def outer():
    def inner(limit):
        x = 0
        while x < limit:
            x += 1
        return x
    return inner(10)
