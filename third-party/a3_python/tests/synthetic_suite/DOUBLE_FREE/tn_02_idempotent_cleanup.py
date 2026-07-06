"""
DOUBLE_FREE True Negative #2: Idempotent cleanup pattern

Ground truth: SAFE
Reasoning: Using a custom idempotent close method that tracks state and
only performs the actual close once. This is a common defensive pattern.

The analyzer should verify:
- Internal state prevents double-free
- Multiple close() calls are safe (idempotent)
- No actual double-free occurs
"""

class SafeResource:
    def __init__(self):
        self._closed = False
        self._handle = "resource_handle"
    
    def close(self):
        if not self._closed:
            # Actual close operation
            self._handle = None
            self._closed = True
        # Second call is no-op

def idempotent_cleanup():
    r = SafeResource()
    r.close()
    # SAFE: idempotent close pattern
    r.close()

if __name__ == "__main__":
    idempotent_cleanup()
