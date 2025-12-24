"""Type-based dispatch system for PyFlow.

This module provides a type-based dispatch system that allows methods to be
selected based on the runtime type of their arguments, similar to multiple
dispatch or method overloading in other languages.
"""

from __future__ import print_function

__all__ = [
    "TypeDispatcher",
    "defaultdispatch",
    "dispatch",
    "TypeDispatchError",
    "TypeDispatchDeclarationError",
]

import inspect


def flattenTypesInto(l, result):
    """Flatten nested type lists into a flat list.
    
    Args:
        l: List of types (can contain nested lists/tuples).
        result: List to append flattened types to.
        
    Raises:
        TypeDispatchDeclarationError: If non-type objects are found.
    """
    for child in l:
        if isinstance(child, (list, tuple)):
            flattenTypesInto(child, result)
        else:
            if not isinstance(child, type):
                raise TypeDispatchDeclarationError(
                    "Expected a type, got %r instead." % child
                )
            result.append(child)


def dispatch(*types):
    """Decorator for type-based method dispatch.
    
    Marks a method as handling dispatch for the specified types. When the
    TypeDispatcher calls the method, it will select the appropriate overload
    based on the runtime types of the arguments.
    
    Args:
        *types: Type objects that this method handles.
        
    Returns:
        Decorated function with dispatch metadata.
    """
    def dispatchF(f):
        def dispatchWrap(*args, **kargs):
            return f(*args, **kargs)

        dispatchWrap.__original__ = f
        dispatchWrap.__dispatch__ = []
        flattenTypesInto(types, dispatchWrap.__dispatch__)
        return dispatchWrap

    return dispatchF


def defaultdispatch(f):
    """Decorator for default dispatch method.
    
    Marks a method as the default handler when no specific type dispatch
    method matches the arguments.
    
    Args:
        f: Function to mark as default dispatch handler.
        
    Returns:
        Decorated function with default dispatch metadata.
    """
    def defaultWrap(*args, **kargs):
        return f(*args, **kargs)

    defaultWrap.__original__ = f
    defaultWrap.__dispatch__ = (None,)
    return defaultWrap


def dispatch__call__(self, p, *args):
    """
    Dispatch a call based on the type of the first argument.
    
    This function implements the core dispatch logic:
    1. Look up the exact type in the dispatch table
    2. If not found, search the method resolution order (MRO) for a matching superclass
    3. Optionally try name-based dispatch (visitor pattern style)
    4. Fall back to default handler if no match found
    5. Cache the result for future lookups
    
    The dispatch table is built by the metaclass from methods decorated with
    @dispatch(type) or @defaultdispatch.
    
    Args:
        self: TypeDispatcher instance
        p: First argument (type determines which method to call)
        *args: Additional arguments to pass to the dispatched method
        
    Returns:
        Result of calling the appropriate handler method
    """
    t = type(p)
    table = self.__typeDispatchTable__

    # Try direct lookup first (fast path for cached types)
    func = table.get(t)

    if func is None:
        # Search for a matching superclass
        # This should occur only once per class (then cached).

        if self.__concrete__:
            # Concrete mode: only check exact type, not inheritance
            possible = (t,)
        else:
            # Normal mode: check MRO (method resolution order)
            # This allows dispatching to base class handlers
            possible = t.mro()

        for supercls in possible:
            func = table.get(supercls)

            if func is not None:
                break
            elif self.__namedispatch__:
                # Name-based dispatch emulates "visitor" pattern
                # Allows evolutionary refactoring by naming methods like visitClassName
                # Example: visitListNode, visitDictNode, etc.
                name = self.__nameprefix__ + t.__name__
                func = type(self).__dict__.get(name)

                if func is not None:
                    break

        # Fall back to default handler if no specific handler found
        if func is None:
            func = table.get(None)

        # Cache the function that we found for this type
        # Future calls with the same type will use the fast path
        table[t] = func

    return func(self, p, *args)


class TypeDispatchError(Exception):
    """
    Exception raised when type dispatch fails.
    
    This is raised when a TypeDispatcher is called with a type that has
    no handler and no default handler is available (should not happen if
    defaultdispatch is properly defined).
    """
    pass


class TypeDispatchDeclarationError(Exception):
    """
    Exception raised when type dispatch is incorrectly declared.
    
    This is raised during class definition if:
    - Multiple handlers are declared for the same type
    - No default handler is provided
    - Invalid type objects are used in @dispatch decorators
    """
    pass


def exceptionDefault(self, node, *args):
    """
    Default handler that raises an exception.
    
    This is the default defaultdispatch handler. It raises a TypeDispatchError
    indicating that the dispatcher cannot handle the given type. Subclasses
    should override this with @defaultdispatch to provide their own default
    behavior.
    
    Args:
        self: TypeDispatcher instance
        node: Object that couldn't be dispatched
        *args: Additional arguments
        
    Raises:
        TypeDispatchError: Always, indicating unhandled type
    """
    raise TypeDispatchError("%r cannot handle %r\n%r" % (type(self), type(node), node))


def inlineAncestor(t, lut):
    """
    Inline dispatch table entries from an ancestor class.
    
    This function merges dispatch table entries from a base class into
    the lookup table being built. It only adds entries that haven't been
    defined in the current class (allowing subclasses to override).
    
    Args:
        t: Class to get dispatch table from
        lut: Lookup table dictionary to update
    """
    if hasattr(t, "__typeDispatchTable__"):
        # Search for types that haven't been defined, yet.
        # This allows inheritance: subclasses inherit handlers from base classes
        # but can override them by redefining with @dispatch
        for k, v in t.__typeDispatchTable__.items():
            if k not in lut:
                lut[k] = v


class typedispatcher(type):
    """
    Metaclass that builds type dispatch tables for TypeDispatcher classes.
    
    This metaclass processes methods decorated with @dispatch or @defaultdispatch
    and builds a lookup table mapping types to handler functions. The table is
    stored in __typeDispatchTable__ and used by dispatch__call__ to route calls
    to the appropriate handler.
    
    The metaclass:
    1. Scans class methods for dispatch decorators
    2. Builds a type -> handler mapping
    3. Inherits handlers from base classes (allowing overrides)
    4. Ensures a default handler exists
    5. Stores the dispatch table in the class
    """
    def __new__(self, name, bases, d):
        """
        Create a TypeDispatcher class with dispatch table.
        
        Args:
            self: The metaclass
            name: Name of the class being created
            bases: Base classes
            d: Class dictionary
            
        Returns:
            New class with __typeDispatchTable__ attribute
            
        Raises:
            TypeDispatchDeclarationError: If dispatch is incorrectly declared
        """
        lut = {}  # Lookup table: type -> handler function
        restore = {}  # Map: method name -> unwrapped function

        # Build the type lookup table from the local declaration
        for k, v in d.items():
            if hasattr(v, "__dispatch__") and hasattr(v, "__original__"):
                # This is a method decorated with @dispatch or @defaultdispatch
                types = v.__dispatch__  # List of types or (None,) for default
                original = v.__original__  # Original unwrapped function

                for t in types:
                    if t in lut:
                        # Multiple handlers for the same type - error!
                        raise TypeDispatchDeclarationError(
                            "%s has declared with multiple handlers for type %s"
                            % (name, t.__name__)
                        )
                    else:
                        lut[t] = original

                # Store unwrapped function to restore in class dict
                restore[k] = original

        # Remove the wrapper functions from the methods
        # Replace them with the original unwrapped functions
        d.update(restore)

        # Search and inline dispatch tables from the MRO
        # This allows inheritance: subclasses inherit handlers from base classes
        for base in bases:
            for t in inspect.getmro(base):
                inlineAncestor(t, lut)

        # Ensure a default handler exists
        if None not in lut:
            raise TypeDispatchDeclarationError("%s has no default dispatch" % (name,))

        # Store the dispatch table in the class
        d["__typeDispatchTable__"] = lut

        return type.__new__(self, name, bases, d)


class TypeDispatcher(object, metaclass=typedispatcher):
    """
    Base class for type-based method dispatch (multiple dispatch).
    
    This class provides a multiple dispatch system where methods are selected
    based on the runtime type of the first argument. This is similar to method
    overloading in languages like C++ or Java, but determined at runtime.
    
    Usage:
        1. Inherit from TypeDispatcher
        2. Decorate methods with @dispatch(Type) for specific types
        3. Decorate one method with @defaultdispatch for fallback
        4. Call the dispatcher with an object - appropriate method is called
    
    Example:
        >>> class MyDispatcher(TypeDispatcher):
        ...     @dispatch(int)
        ...     def handle(self, obj):
        ...         return "integer"
        ...     @dispatch(str)
        ...     def handle(self, obj):
        ...         return "string"
        ...     @defaultdispatch
        ...     def handle(self, obj):
        ...         return "other"
        >>> d = MyDispatcher()
        >>> d(42)
        'integer'
        >>> d("hello")
        'string'
        >>> d([1, 2, 3])
        'other'
    
    Attributes:
        __concrete__: If True, only exact type matches (no inheritance lookup)
        __namedispatch__: If True, enable name-based dispatch (visitor pattern)
        __nameprefix__: Prefix for name-based dispatch methods (default: "visit")
    """
    __dispatch__ = dispatch__call__
    __call__ = dispatch__call__
    exceptionDefault = defaultdispatch(exceptionDefault)
    __concrete__ = False  # If True, disable inheritance-based dispatch

    __namedispatch__ = False  # Enable name-based dispatch (visitClassName pattern)
    __nameprefix__ = "visit"  # Prefix for name-based dispatch methods
