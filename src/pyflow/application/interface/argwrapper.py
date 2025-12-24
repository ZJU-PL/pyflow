"""
Argument wrappers for PyFlow interface declarations.

This module provides wrapper classes for representing function arguments
in PyFlow's interface declaration system. Wrappers allow the system to
represent different types of arguments (constants, instances, null) in
a uniform way.

**Wrapper Types:**
- ExistingWrapper: Wraps existing Python objects (constants, functions)
- InstanceWrapper: Wraps type objects (for creating instances)
- NullWrapper: Represents missing arguments (e.g., no *args, **kwargs)
"""
class ArgumentWrapper(object):
    """
    Base class for argument wrappers.
    
    All argument wrappers inherit from this class. Wrappers provide
    a uniform interface for getting objects and slots from extractors
    and dataflow graphs.
    """
    pass


# Thin wrappers made to work with decompiler.programextractor
class InstanceWrapper(ArgumentWrapper):
    """
    Wrapper for type objects (for creating instances).
    
    This wrapper represents a type/class that will be instantiated.
    Used when declaring entry points that create instances of classes.
    
    Attributes:
        typeobj: The type/class object to wrap
    """
    def __init__(self, typeobj):
        """
        Initialize an instance wrapper.
        
        Args:
            typeobj: Type/class object to wrap
        """
        self.typeobj = typeobj

    def getObject(self, extractor):
        """
        Get an instance object from the extractor.
        
        Args:
            extractor: Program extractor instance
            
        Returns:
            Instance object for this type
        """
        return extractor.getInstance(self.typeobj)

    def get(self, dataflow):
        """
        Get an instance slot from the dataflow graph.
        
        Args:
            dataflow: Dataflow graph
            
        Returns:
            Instance slot for this type
        """
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
        """
        Initialize an existing wrapper.
        
        Args:
            pyobj: Python object to wrap (can be None)
        """
        self.pyobj = pyobj

    def getObject(self, extractor):
        """
        Get the object from the extractor.
        
        Args:
            extractor: Program extractor instance
            
        Returns:
            The wrapped Python object
        """
        return extractor.getObject(self.pyobj)

    def get(self, dataflow):
        """
        Get an existing slot from the dataflow graph.
        
        Args:
            dataflow: Dataflow graph
            
        Returns:
            Existing slot for this object
        """
        return dataflow.getExistingSlot(self.pyobj)


# Used when an argument, such as varg or karg, is not present.
class NullWrapper(ArgumentWrapper):
    """
    Wrapper representing a missing/null argument.
    
    Used when an optional argument (like *args or **kwargs) is not
    present in a function call. Always returns None/False.
    """
    def get(self, dataflow):
        """
        Get None (no slot for null arguments).
        
        Args:
            dataflow: Dataflow graph (unused)
            
        Returns:
            None
        """
        return None

    def __nonzero__(self):
        """
        Null wrapper is always falsy.
        
        Returns:
            False
        """
        return False


# Global singleton instance for null arguments
nullWrapper = NullWrapper()


# Stub for missing AttrDeclaration class
class AttrDeclaration(object):
    def __init__(self, *args, **kwargs):
        pass


# Stub for missing ArrayDeclaration class
class ArrayDeclaration(object):
    def __init__(self, *args, **kwargs):
        pass
