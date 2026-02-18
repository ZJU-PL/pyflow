"""
Stub implementation of _pyflow module.

WARNING: This is a pure-Python stub that replaces the missing native C extension.
The real extension returns actual C function pointer addresses (integers).
This stub returns opaque tuples instead, which are NOT integers and will break
any code that performs arithmetic on the result, compares it to a raw integer,
or passes it to a C API.

Any analysis that depends on precise C-level pointer values will produce
incorrect results when using this stub.
"""

import warnings as _warnings

_warnings.warn(
    "pyflow._pyflow: native C extension not found; using pure-Python stub. "
    "Analyses that rely on C function pointer values will be unsound.",
    RuntimeWarning,
    stacklevel=1,
)


def cfuncptr(obj):
    """
    Stub implementation of cfuncptr.

    Returns a stable, hashable identifier for the object.  The real
    implementation returns an integer (C pointer address); this stub
    returns an integer derived from the object's identity so that
    callers that only need a unique key still work correctly.

    NOTE: The returned value is NOT a real C pointer and must not be
    used for pointer arithmetic or passed to C APIs.
    """
    # Return a plain int so that callers expecting an integer do not
    # immediately crash (e.g. comparisons, dict keys).  Using id() is
    # safe for the lifetime of the object.
    return id(obj)


# Additional stub functions that might be needed
def get_object_pointer(obj):
    """Stub for getting object pointers."""
    return cfuncptr(obj)


def get_function_pointer(func):
    """Stub for getting function pointers."""
    return cfuncptr(func)
