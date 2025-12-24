"""
Error handling for PyFlow compilation and analysis.

This module defines custom exception classes for different types of errors
that can occur during PyFlow's static analysis and compilation process.
"""


class TemporaryLimitation(Exception):
    """
    Exception raised for temporary limitations in the implementation.
    
    This exception is used to indicate that a feature is not yet fully
    implemented or has known limitations that will be addressed in the future.
    """
    pass


class InternalError(Exception):
    """
    Exception raised for internal errors in PyFlow.
    
    This exception indicates a bug or unexpected condition in PyFlow's
    internal implementation, as opposed to an error in the user's code.
    """
    pass


class CompilerAbort(Exception):
    """
    Exception raised to abort compilation/analysis.
    
    This exception is used to gracefully abort the compilation process,
    typically for testing or debugging purposes. It can be caught to
    stop analysis at a specific point.
    """
    pass


def abort(msg=None):
    """
    Abort compilation with an optional message.
    
    Convenience function to raise CompilerAbort exception.
    
    Args:
        msg: Optional message explaining why compilation was aborted
        
    Raises:
        CompilerAbort: Always raises this exception
    """
    raise CompilerAbort(msg)
