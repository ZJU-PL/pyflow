"""
Papers #1, #3 exercise: Guarded list-index (BOUNDS hazard guard).

The guard `0 <= idx < len(items)` ensures safe array access.

Target papers: #1, #3
Expected: SAFE
"""


def safe_access(items, idx):
    if 0 <= idx < len(items):
        return items[idx]
    return None
