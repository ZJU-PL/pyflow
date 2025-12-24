"""
Debugger utilities for post-mortem debugging.

This module provides decorators that automatically start a debugger when
an exception occurs, allowing interactive debugging of failed code paths.
"""

from functools import wraps


def conditional(cond, func):
    """
    Conditionally apply a decorator based on a condition.
    
    If cond is True, returns func (which should be a decorator).
    If cond is False, returns a no-op decorator that passes through unchanged.
    
    Args:
        cond: Boolean condition
        func: Decorator function to return if cond is True
        
    Returns:
        Decorator function (either func or a passthrough)
    """
    if cond:
        return func
    else:
        def passthroughTemp(func):
            return func
        return passthroughTemp


def debugOnFailiure(func):
    """
    Decorator that starts a debugger if an exception is thrown.
    
    When applied to a function, if the function raises an exception, this
    decorator will:
    1. Print the full traceback
    2. Start pdb (Python debugger) in post-mortem mode
    3. Re-raise the exception after debugging
    
    This is useful for debugging functions that are difficult to step through
    interactively, as it allows you to inspect the state at the point of failure.
    
    Args:
        func: Function to wrap with debug-on-failure behavior
        
    Returns:
        Wrapped function that starts debugger on exception
        
    Example:
        >>> @debugOnFailiure
        ... def problematic_function():
        ...     x = 1 / 0
        >>> problematic_function()  # Will start pdb if exception occurs
    """
    @wraps(func)
    def debugOnFailiureDecorator(*args, **kargs):
        try:
            return func(*args, **kargs)
        except:
            import traceback
            # Print full traceback for context
            traceback.print_exc()

            try:
                import pdb
                # Start post-mortem debugger
                pdb.post_mortem()
            except Exception as e:
                print("Cannot start debugger: " + str(e))

            # Re-raise the exception after debugging
            raise

    return debugOnFailiureDecorator


def conditionalDebugOnFailiure(cond):
    """
    Conditionally apply debug-on-failure decorator.
    
    Creates a decorator that only enables debug-on-failure behavior if
    the condition is True. This allows enabling/disabling debugging
    based on runtime configuration or flags.
    
    Args:
        cond: Boolean condition determining whether to enable debugging
        
    Returns:
        Decorator function that conditionally enables debug-on-failure
        
    Example:
        >>> DEBUG = True
        >>> @conditionalDebugOnFailiure(DEBUG)
        ... def my_function():
        ...     pass
    """
    return conditional(cond, debugOnFailiure)
