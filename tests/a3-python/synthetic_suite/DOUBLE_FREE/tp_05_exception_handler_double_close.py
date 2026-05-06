"""
DOUBLE_FREE True Positive #5: Exception handler double close

Ground truth: BUG - DOUBLE_FREE
Reasoning: Close in finally block and also after try-except. The finally
block always executes, so close() is called, then close() is called again
after the try-except block.

The analyzer should detect:
- finally block guarantees first close()
- Second close() after try-except operates on already-closed file (double-free)
"""

def exception_handler_double_close():
    f = open("output.txt", "w")
    
    try:
        f.write("data")
    finally:
        f.close()  # First close (always executes)
    
    # BUG: double close after finally
    f.close()

if __name__ == "__main__":
    exception_handler_double_close()
