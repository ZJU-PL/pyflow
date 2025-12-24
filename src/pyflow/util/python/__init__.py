"""
Python object introspection and manipulation utilities.

This module provides low-level utilities for working with Python objects,
functions, modules, and descriptors. These utilities are used throughout
pyflow for:
- Function manipulation (replacing globals)
- Module introspection (finding modules by their global dictionary)
- Descriptor handling (creating unique names for slot descriptors)

These are advanced utilities that work with Python's internal object model.
"""

import sys
import types


def replaceGlobals(f, g):
    """
    Create a new function with replaced global namespace.
    
    This function creates a copy of function f but with a different global
    namespace (g). This is useful for executing functions in different
    contexts, such as when analyzing code from different modules.
    
    Warning:
        This operation loses the original function's closure. Any variables
        captured from the enclosing scope will not be available in the new
        function.
    
    Args:
        f: Function to copy (must be a types.FunctionType)
        g: New global dictionary to use for the function
        
    Returns:
        types.FunctionType: New function with replaced globals
        
    Raises:
        AssertionError: If f is not a FunctionType
        
    Example:
        >>> def original():
        ...     return x  # Uses global 'x'
        >>> new_globals = {'x': 42}
        >>> new_func = replaceGlobals(original, new_globals)
        >>> new_func()
        42
    """
    # HACK closure is lost
    assert isinstance(f, types.FunctionType), type(f)
    return types.FunctionType(f.__code__, g, f.__name__, f.__defaults__)


def moduleForGlobalDict(glbls):
    """
    Find the module that owns a given global dictionary.
    
    This function searches through sys.modules to find which module's
    __dict__ matches the provided global dictionary. This is useful for
    determining which module a function or code object came from.
    
    Args:
        glbls: Global dictionary (__dict__) from a module
        
    Returns:
        tuple: (module_name, module_object) where module_name is the
               fully qualified module name and module_object is the module
        
    Raises:
        AssertionError: If glbls doesn't have "__file__" or if no matching
                      module is found in sys.modules
        
    Example:
        >>> import mymodule
        >>> name, mod = moduleForGlobalDict(mymodule.__dict__)
        >>> name
        'mymodule'
        >>> mod is mymodule
        True
    """
    assert "__file__" in glbls, "Global dictionary does not come from a module?"

    for name, module in sys.modules.items():
        if module and module.__dict__ is glbls:
            assert module.__file__ == glbls["__file__"]
            return (name, module)
    assert False


# Note that the unique name may change between runs, as it takes the id of a type.
def uniqueSlotName(descriptor):
    """
    Generate a unique name for a slot descriptor.
    
    Python's slot descriptors (used for __slots__) don't have unique
    identifiers across different classes. This function creates a unique
    name by combining the descriptor's name, the class name, and the
    class's id (memory address).
    
    The resulting name has the format: "{name}#{class_name}#{class_id}"
    
    Note:
        The unique name may change between program runs because it uses
        the id() of the class, which is based on memory address. However,
        within a single run, it provides a stable unique identifier.
    
    Args:
        descriptor: A MemberDescriptorType or GetSetDescriptorType
                   (Python slot descriptors)
        
    Returns:
        str: Unique name for the descriptor in the format
             "{name}#{class_name}#{class_id}"
             
    Raises:
        AssertionError: If descriptor is not a MemberDescriptorType or
                      GetSetDescriptorType
        
    Example:
        >>> class MyClass:
        ...     __slots__ = ['x', 'y']
        >>> name = uniqueSlotName(MyClass.x)
        >>> name
        'x#MyClass#140234567890'
        
    Note:
        GetSetDescriptors are not technically slots, but they're handled
        here for compatibility with Python's descriptor system.
    """
    # HACK GetSetDescriptors are not really slots?
    assert isinstance(
        descriptor, (types.MemberDescriptorType, types.GetSetDescriptorType)
    ), (descriptor, type(descriptor), dir(descriptor))
    name = descriptor.__name__
    objClass = descriptor.__objclass__
    return "%s#%s#%d" % (name, objClass.__name__, id(objClass))
