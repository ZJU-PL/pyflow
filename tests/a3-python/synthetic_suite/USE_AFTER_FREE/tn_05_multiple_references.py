"""
USE_AFTER_FREE True Negative 5: Multiple references prevent free

Expected: SAFE
Reason: Multiple references to an object prevent it from being freed on single del.
        The object is still alive through the other reference.
"""

def test_multiple_references():
    items = [1, 2, 3]
    alias = items
    del items
    alias.append(4)  # SAFE: object still alive through alias

if __name__ == "__main__":
    test_multiple_references()
