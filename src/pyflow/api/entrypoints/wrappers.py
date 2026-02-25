"""
Argument wrappers for PyFlow entry point declarations.

This module provides wrapper classes for representing function arguments
in PyFlow's entry point declaration system. Wrappers allow the system to
represent different types of arguments (constants, instances, null) in
a uniform way.
"""


class ArgumentWrapper:
    """
    Base class for argument wrappers.

    All argument wrappers inherit from this class. Wrappers provide
    a uniform interface for getting objects and slots from extractors
    and dataflow graphs.
    """

    pass


class InstanceWrapper(ArgumentWrapper):
    """
    Wrapper for type objects (for creating instances).

    This wrapper represents a type/class that will be instantiated.
    Used when declaring entry points that create instances of classes.

    Attributes:
        typeobj: The type/class object to wrap
    """

    def __init__(self, typeobj):
        self.typeobj = typeobj

    def getObject(self, extractor):
        return extractor.getInstance(self.typeobj)

    def get(self, dataflow):
        return dataflow.getInstanceSlot(self.typeobj)


class ExistingWrapper(ArgumentWrapper):
    """
    Wrapper for existing Python objects (constants, functions, etc.).

    This wrapper represents an existing Python object that should be
    used as-is. Used for constants, function references, and other
    existing objects.

    Attributes:
        pyobj: The Python object to wrap
    """

    def __init__(self, pyobj):
        self.pyobj = pyobj

    def getObject(self, extractor):
        return extractor.getObject(self.pyobj)

    def get(self, dataflow):
        return dataflow.getExistingSlot(self.pyobj)


class NullWrapper(ArgumentWrapper):
    """
    Wrapper representing a missing/null argument.

    Used when an optional argument (like *args or **kwargs) is not
    present in a function call. Always returns None/False.
    """

    def get(self, dataflow):
        return None

    def __nonzero__(self):
        return False

    __bool__ = __nonzero__


nullWrapper = NullWrapper()
