"""
DOUBLE_FREE True Positive #3: Nested context manager double-exit

Ground truth: BUG - DOUBLE_FREE
Reasoning: Manually calling __exit__ on a context manager that has already
exited through the with-statement. The __exit__ is invoked twice on the same
resource, which is a double-free pattern.

The analyzer should detect:
- with-statement invokes __exit__ automatically on block exit
- Manual __exit__ call afterward operates on already-exited context (double-free)
"""

class Resource:
    def __init__(self):
        self.closed = False
    
    def __enter__(self):
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        if self.closed:
            raise RuntimeError("Double close detected")
        self.closed = True
        return False

def nested_context_double_exit():
    r = Resource()
    with r:
        pass  # __exit__ called here automatically
    # BUG: manual __exit__ after with-block
    r.__exit__(None, None, None)

if __name__ == "__main__":
    nested_context_double_exit()
