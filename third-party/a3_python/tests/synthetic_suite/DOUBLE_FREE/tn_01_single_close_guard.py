"""
DOUBLE_FREE True Negative #1: Single close with guard

Ground truth: SAFE
Reasoning: File is closed only once, with a guard that prevents double-close.
The closed flag is checked before calling close() again.

The analyzer should verify:
- close() is called at most once
- Guard condition prevents second close()
- No double-free occurs
"""

def single_close_with_guard():
    f = open("example.txt", "w")
    f.write("data")
    f.close()
    
    # SAFE: guard prevents double close
    if not f.closed:
        f.close()

if __name__ == "__main__":
    single_close_with_guard()
