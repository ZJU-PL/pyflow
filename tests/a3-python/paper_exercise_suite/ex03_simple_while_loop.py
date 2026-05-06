"""
Papers #2-#19 exercise: Simple while-loop counter (affine model).

    while x < 10:
        x += 1

This creates an extractable affine transition model:
  guard: x < 10
  update: x' = x + 1
  init: x >= 0
  safety: x >= 0   (always non-negative)

Every loop-based verification engine should be able to prove safety.

Target papers: #2, #4, #5, #6, #7, #8, #9, #10, #11, #12, #13, #14,
               #15, #16, #17, #18, #19
Expected: SAFE
"""

def count_up():
    x = 0
    while x < 10:
        x += 1
    return x
