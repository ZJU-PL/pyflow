"""
Papers #1-#20 exercise (BUG variant): Unguarded division (true positive).

Division without a guard — the analyzer should flag this as a BUG.

Target papers: #1, #3 (should detect the hazard)
Expected: BUG
"""


def risky_divide(a, b):
    return a / b   # b could be 0 — no guard!
