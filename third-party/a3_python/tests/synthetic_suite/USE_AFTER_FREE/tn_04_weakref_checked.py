"""
USE_AFTER_FREE True Negative 4: Weakref with None check

Expected: SAFE
Reason: Checking if weakref is None before use prevents use-after-free.
        Proper defensive pattern.
"""
import weakref

def test_weakref_checked():
    obj = [1, 2, 3]
    weak = weakref.ref(obj)
    del obj
    alive = weak()
    if alive is not None:  # SAFE: check before use
        alive.append(4)

if __name__ == "__main__":
    test_weakref_checked()
