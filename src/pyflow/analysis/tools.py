"""Analysis tools and utilities for PyFlow.

This module provides utility functions for analyzing Python programs,
including operations extraction, side effect detection, and call analysis.
"""

from pyflow.analysis.astcollector import getOps
from pyflow.ir.core import AnalysisFacts, MissingAnalysisFact


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


def mightHaveSideEffect(code, op):
    """Check if an operation might have side effects.

    Args:
        op: Operation to check.

    Returns:
        bool: True if the operation might have side effects.
    """
    catalog = getattr(code, "ir_catalog", None)
    if catalog is None:
        return True
    try:
        semantics = catalog.semantics_of(op, code=code)
    except KeyError:
        return True
    return bool(semantics.writes)


def singleObject(code, lcl):
    """Check if a local variable references a single preexisting object.

    Args:
        lcl: Local variable to check.

    Returns:
        Object if the local references exactly one preexisting object, None otherwise.
    """
    try:
        refs = AnalysisFacts.for_code(code).merged_references(code, lcl)
    except MissingAnalysisFact:
        return None
    if len(refs) == 1:
        obj = next(iter(refs)).xtype.obj
        if obj.isPreexisting():
            return obj
    return None


def singleCall(code, op):
    """Check if an operation makes a single function call.

    Args:
        op: Operation to check.

    Returns:
        Code object if the operation calls exactly one function, None otherwise.
    """
    try:
        invokes = AnalysisFacts.for_code(code).merged_call_targets(code, op)
    except MissingAnalysisFact:
        return None
    targets = {target_code for target_code, _context in invokes}
    if len(targets) == 1:
        return targets.pop()

    return None


emptySet = frozenset()


def opInvokesContexts(code, op, opContext):
    try:
        invokes = AnalysisFacts.for_code(code).call_targets(code, op, opContext)
    except MissingAnalysisFact:
        return emptySet
    return frozenset(context for _func, context in invokes)
