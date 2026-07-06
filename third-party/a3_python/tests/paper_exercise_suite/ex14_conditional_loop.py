"""
Papers #2-#19 exercise: While-loop inside a conditional.

The loop only runs when the condition is met, testing
that the analyzer handles control flow around loops.

Target papers: #2, #4-19
Expected: SAFE
"""


def conditional_loop(n):
    result = 0
    if n > 0:
        i = 0
        while i < n:
            result += i
            i += 1
    return result
