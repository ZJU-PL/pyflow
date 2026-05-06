"""
USE_AFTER_FREE True Positive 3: Resource use after context manager exit

Expected: BUG - USE_AFTER_FREE
Reason: After exiting the with-block, the resource is freed.
        Using it outside the block is use-after-free.
"""

def test_context_manager_after_exit():
    with open("/dev/null", "w") as f:
        pass
    f.write("data")  # BUG: file handle used after with-block exit

if __name__ == "__main__":
    test_context_manager_after_exit()
