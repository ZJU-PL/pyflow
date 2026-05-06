"""
USE_AFTER_FREE True Negative 3: Copy before del pattern

Expected: SAFE
Reason: Making a copy before del ensures the data is preserved.
        No use-after-free; the copy is independent.
"""

def test_copy_before_del():
    items = [1, 2, 3]
    items_copy = items.copy()
    del items
    items_copy.append(4)  # SAFE: using the copy, not freed object

if __name__ == "__main__":
    test_copy_before_del()
