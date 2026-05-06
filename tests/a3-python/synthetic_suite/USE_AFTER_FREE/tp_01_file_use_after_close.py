"""
USE_AFTER_FREE True Positive 1: File use after close()

Expected: BUG - USE_AFTER_FREE
Reason: Reading from a file after calling close() is use-after-free semantics.
        The file handle/resource is freed, but we attempt to use it.
"""

def test_file_use_after_close():
    f = open("/dev/null", "w")
    f.close()
    f.write("data")  # BUG: use after close

if __name__ == "__main__":
    test_file_use_after_close()
