"""
Singleton pattern utilities for creating single-instance classes.

This module provides utilities for creating singleton classes, where only
one instance of the class can exist. This is useful for stateless classes
that serve as namespaces or type dispatchers, avoiding unnecessary instance
creation.

The singleton pattern is implemented using a metaclass that automatically
creates and returns a single instance when the class is defined.
"""

__all__ = ("singleton", "instance")


class singletonMetaclass(type):
    """
    Metaclass that automatically creates a singleton instance.
    
    When a class using this metaclass is defined, it automatically:
    1. Creates the class (with "Type" appended to the name)
    2. Instantiates it immediately
    3. Returns the instance instead of the class
    
    This ensures only one instance of the class can exist.
    """
    def __new__(self, name, bases, d):
        """
        Create a singleton class and return its instance.
        
        Args:
            self: The metaclass
            name: Name of the class being created
            bases: Base classes
            d: Class dictionary
            
        Returns:
            Instance of the created class (not the class itself)
        """
        # Provide default __repr__ if not defined
        if "__repr__" not in d:
            def __repr__(self):
                return name
            d["__repr__"] = __repr__
        
        # Create class with "Type" suffix to avoid name collision
        cls = type.__new__(self, name + "Type", bases, d)
        # Immediately create and return the singleton instance
        return cls()


class singleton(object, metaclass=singletonMetaclass):
    """
    Base class for singleton objects.
    
    Classes that inherit from singleton automatically become singletons.
    When the class is defined, a single instance is created and the class
    name refers to that instance, not the class itself.
    
    This is useful for stateless classes that serve as namespaces or
    type dispatchers, where creating multiple instances would be wasteful.
    
    Example:
        >>> class MySingleton(singleton):
        ...     def method(self):
        ...         return "hello"
        >>> MySingleton  # This is the instance, not the class
        MySingleton
        >>> MySingleton.method()
        'hello'
        >>> MySingleton is MySingleton  # Always the same instance
        True
    """
    __slots__ = ()


# The singleton class itself is a singleton, so 'singleton' now refers
# to the instance, not the class. Get the actual class for reference.
singleton = type(singleton)


def instance(cls):
    """
    Decorator for turning a class into a pseudo-singleton.
    
    This function immediately instantiates a class and returns the instance.
    It's a simpler alternative to the singleton metaclass for cases where
    you want to create a single instance without using inheritance.
    
    This is handy for stateless TypeDispatcher classes where you want
    a single instance to use for dispatch rather than creating new
    instances each time.
    
    Args:
        cls: Class to instantiate
        
    Returns:
        Instance of the class
        
    Example:
        >>> class MyDispatcher:
        ...     pass
        >>> dispatcher = instance(MyDispatcher)
        >>> dispatcher  # This is an instance, not the class
        <MyDispatcherType object at ...>
    """
    cls.__name__ += "Type"
    return cls()
