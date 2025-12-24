"""
Blame tracing utilities for error attribution.

This module provides utilities for tracing the call stack and determining
the source location (filename and line number) of code that led to an error.
This is useful for error reporting and debugging to show where problems
originated in the call chain.
"""

import sys
import dis


def lineForInstruction(code, instruction):
    """
    Find the source line number for a bytecode instruction offset.
    
    Maps a bytecode instruction offset to the corresponding source line number
    by examining the line number table in the code object.
    
    Args:
        code: Code object (from function.__code__)
        instruction: Bytecode instruction offset (f_lasti)
        
    Returns:
        int: Source line number corresponding to the instruction
    """
    line = 1

    for i, l in dis.findlinestarts(code):
        if i > instruction:
            break
        line = l

    return line


def traceBlame(offset, count):
    """
    Trace the call stack and return blame information.
    
    Inspects the call stack starting at the given offset and returns
    information about the calling functions, including filename, line number,
    and function name. This is used for error reporting to show where
    errors originated.
    
    The function traces backwards through the call stack, collecting
    information about each frame. It handles both regular Python execution
    (using f_lineno) and optimized execution (using f_lasti and bytecode
    instruction mapping).
    
    Args:
        offset: Stack frame offset (0 = current frame, 1 = caller, etc.)
        count: Number of stack frames to trace
        
    Returns:
        tuple: Tuple of strings in format "filename:lineno in function_name"
               representing the call stack from oldest to newest
        
    Example:
        >>> def inner():
        ...     return traceBlame(2, 3)  # Trace 3 frames starting 2 levels up
        >>> def middle():
        ...     return inner()
        >>> def outer():
        ...     return middle()
        >>> outer()  # Returns blame trace of outer -> middle -> inner
    """
    lines = []

    for i in range(count):
        try:
            # Get frame at offset (counting from oldest to newest)
            caller = sys._getframe(offset + (count - i - 1))
            name = caller.f_code.co_name

            # Determine line number
            # Note: f_lasti (last instruction) may be inaccurate when psyco is used
            if hasattr(caller, "f_lasti"):
                # Use bytecode instruction offset for more accurate line numbers
                lineno = lineForInstruction(caller.f_code, caller.f_lasti)
            else:
                # Fall back to f_lineno if f_lasti not available
                lineno = caller.f_lineno

            filename = caller.f_code.co_filename
            del caller  # Destroy a circular reference to avoid memory leaks

            lines.append("%s:%d in %s" % (filename, lineno, name))
        except:
            # Skip frames that can't be accessed (e.g., C extension frames)
            pass

    return tuple(lines)
