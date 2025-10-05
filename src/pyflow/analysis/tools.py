"""Analysis tools and utilities for PyFlow.

This module provides utility functions for analyzing Python programs,
including operations extraction, side effect detection, and call analysis.
"""

from pyflow.analysis.astcollector import getOps


def codeOps(code):
    """Extract operations from a code object.
    
    Args:
        code: Code object to extract operations from.
        
    Returns:
        List of operations in the code.
    """
    ops, lcls = getOps(code)
    return ops


def codeLocals(code):
    """Extract local variables from a code object.
    
    Args:
        code: Code object to extract locals from.
        
    Returns:
        List of local variables in the code.
    """
    ops, lcls = getOps(code)
    return lcls


def codeOpsLocals(code):
    """Extract both operations and locals from a code object.
    
    Args:
        code: Code object to extract from.
        
    Returns:
        Tuple of (operations, locals).
    """
    return getOps(code)


def mightHaveSideEffect(op):
    """Check if an operation might have side effects.
    
    Args:
        op: Operation to check.
        
    Returns:
        bool: True if the operation might have side effects.
    """
    modifies = op.annotation.modifies
    if modifies and not modifies[0]:
        return False
    return True


def singleObject(lcl):
    """Check if a local variable references a single preexisting object.
    
    Args:
        lcl: Local variable to check.
        
    Returns:
        Object if the local references exactly one preexisting object, None otherwise.
    """
    references = lcl.annotation.references
    if references:
        refs = references[0]
        if len(refs) == 1:
            obj = refs[0].xtype.obj
            if obj.isPreexisting():
                return obj
    return None


def singleCall(op):
    """Check if an operation makes a single function call.
    
    Args:
        op: Operation to check.
        
    Returns:
        Code object if the operation calls exactly one function, None otherwise.
    """
    invokes = op.annotation.invokes

    if invokes and invokes[0]:
        targets = set([code for code, context in invokes[0]])
        if len(targets) == 1:
            return targets.pop()

    return None


emptySet = frozenset()


def opInvokesContexts(code, op, opContext):
    invokes = op.annotation.invokes

    if invokes:
        cindex = code.annotation.contexts.index(opContext)
        if invokes[1][cindex]:
            return frozenset([context for func, context in invokes[1][cindex]])

    return emptySet
