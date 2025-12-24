"""
Canonical object management for static analysis.

This module provides utilities for canonicalization, a technique that ensures
equivalent objects share the same identity. This is crucial for static analysis
as it enables efficient comparison, merging, and caching of analysis results.

Canonicalization is used throughout pyflow for:
- Type canonicalization (ensuring equivalent types are identical)
- Name canonicalization (slot names, variable names, etc.)
- Context canonicalization (operation contexts, code contexts)
- Expression canonicalization (ensuring equivalent expressions share identity)

Key concepts:
- CanonicalObject: Base class for objects that are compared by canonical values
- CanonicalCache: Factory that ensures only one canonical instance per value
- Sentinel: Special marker objects for representing sentinel values
"""

from .monkeypatch import xcollections


class Sentinel(object):
    """
    A sentinel object used as a special marker value.
    
    Sentinels are used to represent special values that need to be distinguished
    from regular objects. They are commonly used for:
    - Representing "no value" or "missing" states
    - Marking special control flow points
    - Representing sentinel values in algorithms
    
    Attributes:
        name: String identifier for this sentinel
        
    Example:
        >>> NO_VALUE = Sentinel("NO_VALUE")
        >>> NO_VALUE
        NO_VALUE
        >>> NO_VALUE == Sentinel("NO_VALUE")
        False  # Different instances
    """
    __slots__ = "name", "__weakref__"

    def __init__(self, name):
        """
        Initialize a sentinel with a name.
        
        Args:
            name: String identifier for this sentinel
        """
        self.name = name

    def __repr__(self):
        """Return the sentinel's name as its string representation."""
        return self.name


class CanonicalObject(object):
    """
    Base class for objects that are compared by their canonical values.
    
    Canonical objects are equal if they have the same type and the same
    canonical values (the arguments passed to setCanonical). This enables
    efficient comparison and ensures that equivalent objects can share
    the same identity when used with CanonicalCache.
    
    Canonical objects are used extensively in pyflow for:
    - Type representations (ensuring equivalent types are identical)
    - Slot names (local variables, fields, etc.)
    - Analysis contexts (operation contexts, code contexts)
    - Signatures (function signatures, call signatures)
    
    Attributes:
        canonical: Tuple of canonical values that define this object's identity
        hash: Precomputed hash value for efficient hashing
        
    Example:
        >>> class MyCanonical(CanonicalObject):
        ...     pass
        >>> obj1 = MyCanonical(1, 2, 3)
        >>> obj2 = MyCanonical(1, 2, 3)
        >>> obj1 == obj2
        True  # Equal because canonical values match
        >>> obj1 is obj2
        False  # But different instances (unless cached)
    """
    __slots__ = "canonical", "hash", "__weakref__"

    def __init__(self, *args):
        """
        Initialize a canonical object with canonical values.
        
        Args:
            *args: Values that define this object's canonical identity
        """
        self.setCanonical(*args)

    def setCanonical(self, *args):
        """
        Set the canonical values for this object.
        
        The canonical values define the object's identity. Two canonical objects
        are equal if they have the same type and the same canonical values.
        
        Args:
            *args: Values that define this object's canonical identity
        """
        self.canonical = args
        # Hash combines type identity with canonical values
        self.hash = id(type(self)) ^ hash(args)

    def __hash__(self):
        """
        Return the hash value for this canonical object.
        
        Returns:
            int: Precomputed hash value
        """
        return self.hash

    def __eq__(self, other):
        """
        Check if this canonical object equals another.
        
        Two canonical objects are equal if they have the same type and
        the same canonical values.
        
        Args:
            other: Object to compare with
            
        Returns:
            bool: True if objects are equal (same type and canonical values)
        """
        return type(self) == type(other) and self.canonical == other.canonical

    def __repr__(self):
        """
        Return a string representation of this canonical object.
        
        Returns:
            str: String in format "ClassName(val1, val2, ...)"
        """
        canonicalStr = ", ".join([repr(obj) for obj in self.canonical])
        return "%s(%s)" % (type(self).__name__, canonicalStr)


class CanonicalCache(object):
    """
    Factory that ensures only one canonical instance per value.
    
    This class provides canonicalization by caching objects. When you request
    an object with certain canonical values, you get back the same instance
    if an equivalent object was created before. This ensures that equivalent
    objects share identity, enabling efficient comparison and reducing memory.
    
    The cache uses weak references, so cached objects can be garbage collected
    when no longer referenced elsewhere.
    
    Attributes:
        create: Factory function that creates new objects from arguments
        cache: Weak cache that stores canonical instances
        
    Example:
        >>> class Point(CanonicalObject):
        ...     pass
        >>> cache = CanonicalCache(Point)
        >>> p1 = cache(1, 2)
        >>> p2 = cache(1, 2)
        >>> p1 is p2
        True  # Same instance returned
        >>> p3 = cache(3, 4)
        >>> p1 is p3
        False  # Different canonical values
    """
    def __init__(self, create):
        """
        Initialize a canonical cache.
        
        Args:
            create: Factory function/class that creates objects from arguments.
                   Should accept the same arguments as CanonicalObject.__init__
        """
        self.create = create
        self.cache = xcollections.weakcache()

    def __call__(self, *args):
        """
        Get or create a canonical instance.
        
        If an equivalent object (same type and canonical values) exists in
        the cache, returns that instance. Otherwise, creates a new instance
        using the factory function and caches it.
        
        Args:
            *args: Arguments to pass to the factory function
            
        Returns:
            Canonical instance (cached if equivalent one exists)
        """
        return self.cache[self.create(*args)]
