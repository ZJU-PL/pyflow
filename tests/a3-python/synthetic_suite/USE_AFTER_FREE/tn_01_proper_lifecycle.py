"""
USE_AFTER_FREE True Negative 1: Proper resource lifecycle

Expected: SAFE
Reason: File is used only before close(), respecting lifecycle.
        No use-after-free occurs.
"""

def test_proper_lifecycle():
    f = open("/dev/null", "w")
    f.write("data")
    f.close()  # SAFE: no use after this point

if __name__ == "__main__":
    test_proper_lifecycle()
