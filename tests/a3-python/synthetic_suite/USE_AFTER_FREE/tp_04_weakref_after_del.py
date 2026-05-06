"""
USE_AFTER_FREE True Positive 4: Weakref dereference after del

Expected: BUG - USE_AFTER_FREE
Reason: Dereferencing a weakref after the referent is deleted is use-after-free.
        The weakref may return None or raise, but accessing without check is a bug.
"""
import weakref

def test_weakref_after_del():
    obj = [1, 2, 3]
    weak = weakref.ref(obj)
    del obj
    weak().append(4)  # BUG: dereference after object is freed

if __name__ == "__main__":
    test_weakref_after_del()
