"""
DOUBLE_FREE True Positive #4: Conditional path double close

Ground truth: BUG - DOUBLE_FREE
Reasoning: Both conditional branches close the same file, leading to double-free
when the file is closed in the first branch and then closed again at the end.

The analyzer should detect:
- All paths through the function lead to close() being called twice
- Second close() is on already-closed file (double-free)
"""

def conditional_double_close(condition):
    f = open("data.txt", "w")
    f.write("hello")
    
    if condition:
        f.close()  # First close
    else:
        f.write("more")
    
    # BUG: double close (close already happened if condition=True)
    f.close()

if __name__ == "__main__":
    conditional_double_close(True)
