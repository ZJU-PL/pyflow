"""
Trace debugging utilities.

This module provides context managers for debugging that help identify
where exceptions occur and provide context about the execution state.
"""

class trace(object):
    """
    Context manager that prints trace information if an exception is raised.
    
    This is useful for debugging to identify which code path or data value
    was being processed when an exception occurred. The trace data is only
    printed if an exception is raised within the context.
    
    Attributes:
        data: Data to print if an exception occurs (typically a string
              describing the context or operation)
    
    Example:
        >>> with trace("processing user input"):
        ...     # ... code that might raise an exception ...
        ...     raise ValueError("invalid input")
        <TRACE> 'processing user input'
        Traceback (most recent call last):
        ...
    """
    __slots__ = "data"

    def __init__(self, data):
        """
        Initialize trace context manager.
        
        Args:
            data: Data to print if an exception occurs (any type, will be
                  converted to string representation)
        """
        self.data = data

    def __enter__(self):
        """Enter the trace context (no action needed)."""
        pass

    def __exit__(self, type, value, tb):
        """
        Exit the trace context and print trace if exception occurred.
        
        Args:
            type: Exception type, or None if no exception
            value: Exception value, or None if no exception
            tb: Traceback, or None if no exception
        """
        if type is not None:
            print("<TRACE> %r" % (self.data,))
