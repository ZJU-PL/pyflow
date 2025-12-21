"""
Source origin tracking for AST nodes.

This module provides utilities for tracking and formatting the source
location (file, line, column) and context (name) of AST nodes.
"""

from pyflow.util.monkeypatch.xcollections import namedtuple


def originString(origin):
    """Format an Origin object as a human-readable string.

    Creates a formatted string describing the source location and context
    of an AST node.

    Args:
        origin: Origin object, or None.

    Returns:
        Formatted string like 'File "file.py", line 10:5 in function_name'
        or "<unknown origin>" if origin is None.
    """
    if origin is None:
        return "<unknown origin>"

    if origin.filename:
        s = 'File "%s"' % origin.filename
    else:
        s = ""

    if origin.lineno is None or origin.lineno < 0:
        needComma = False
    elif origin.col is None or origin.col < 0:
        if s:
            s += ", "
        s = "%sline %d" % (s, origin.lineno)
        needComma = True
    else:
        if s:
            s += ", "
        s = "%sline %d:%d" % (s, origin.lineno, origin.col)
        needComma = True

    if origin.name:
        if s:
            if needComma:
                s += ", "
            else:
                s += " "
        s = "%sin %s" % (s, origin.name)

    return s


# Named tuple representing source origin information
# Fields:
#   name: Contextual name (e.g., function or class name)
#   filename: Source filename
#   lineno: Line number (1-indexed, or None/negative if unknown)
#   col: Column number (0-indexed, or None/negative if unknown)
# Methods:
#   originString(): Returns formatted string representation
Origin = namedtuple(
    "Origin", "name filename lineno col", dict(originString=originString)
)
