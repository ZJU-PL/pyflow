"""
Exception classes for compiler error handling.

This module defines exceptions used to signal compilation errors and abort
the compilation process when unrecoverable errors are encountered.
"""


class CompilerAbort(Exception):
    """Exception raised when compilation must be aborted.

    This exception is raised when the compiler encounters errors that prevent
    successful compilation. It is typically raised by the ErrorHandler after
    collecting and reporting all compilation errors.

    Example:
        if error_count > 0:
            raise CompilerAbort()
    """
    pass
