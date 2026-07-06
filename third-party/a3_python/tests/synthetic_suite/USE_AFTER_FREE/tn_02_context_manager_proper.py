"""
USE_AFTER_FREE True Negative 2: Context manager proper usage

Expected: SAFE
Reason: All resource usage is within the with-block.
        Resource is automatically freed at exit; no use-after-free.
"""

def test_context_manager_proper():
    with open("/dev/null", "w") as f:
        f.write("data")
    # SAFE: no use of f after this point

if __name__ == "__main__":
    test_context_manager_proper()
