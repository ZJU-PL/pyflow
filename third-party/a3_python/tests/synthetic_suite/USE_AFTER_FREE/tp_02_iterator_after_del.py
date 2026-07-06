"""
USE_AFTER_FREE True Positive 2: Iterator use after del

Expected: BUG - USE_AFTER_FREE
Reason: After deleting the collection, the iterator holds a reference to freed state.
        Attempting to iterate after del is use-after-free.
"""

def test_iterator_after_del():
    items = [1, 2, 3]
    it = iter(items)
    del items
    next(it)  # BUG: iterator refers to deleted collection

if __name__ == "__main__":
    test_iterator_after_del()
