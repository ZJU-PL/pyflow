"""
DOUBLE_FREE True Positive #1: File double close()

Ground truth: BUG - DOUBLE_FREE
Reasoning: Closing the same file object twice. The second close() operates on
an already-closed resource handle. In CPython this is often tolerated (no-op),
but semantically it's a double-free pattern at the resource level.

The analyzer should detect:
- First close() transitions file to closed state
- Second close() is called on already-closed handle (double-free)
"""

def double_close_file():
    f = open("example.txt", "w")
    f.write("data")
    f.close()
    # BUG: double close
    f.close()

if __name__ == "__main__":
    double_close_file()
