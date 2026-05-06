"""
Papers #2-#19 exercise: Bounded while-loop with accumulator.

    total = 0; i = 0
    while i < n:
        total += i
        i += 1

Two modified variables: both total and i get updated,
producing a richer affine transition relation.

Target papers: #2, #4, #5, #6, #7, #8, #9, #10, #11, #12, #13, #14,
               #15, #16, #17, #18, #19
Expected: SAFE
"""


def sum_up_to(n):
    total = 0
    i = 0
    while i < n:
        total += i
        i += 1
    return total
