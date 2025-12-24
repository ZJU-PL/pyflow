"""
Extended collections module with lazy dictionaries and weak reference caching.

This module provides specialized collection types used throughout pyflow for
efficient memory management and lazy initialization of data structures.
"""

from weakref import ref
from collections import *
from .xnamedtuple import namedtuple


class lazydict(defaultdict):
    """
    A defaultdict that passes the key to the factory function.
    
    Unlike the standard defaultdict, which calls the factory with no arguments,
    lazydict passes the missing key as an argument to the factory function.
    This allows the factory to create values based on the key itself.
    
    This is useful for creating dictionaries where the value depends on the key,
    such as creating analysis objects for each block in a control flow graph.
    
    Attributes:
        default_factory: Callable that takes a key and returns a value
        
    Example:
        >>> d = lazydict(lambda key: f"value_for_{key}")
        >>> d["foo"]
        'value_for_foo'
        >>> d["bar"]
        'value_for_bar'
        >>> "foo" in d
        True
    """
    __slots__ = ()

    def __missing__(self, key):
        """
        Create a value for a missing key using the factory function.
        
        Args:
            key: The missing key
            
        Returns:
            The value created by calling default_factory(key)
        """
        result = self.default_factory(key)
        self[key] = result
        return result


class weakcache(object):
    """
    A cache that uses weak references to automatically clean up entries.
    
    This cache stores objects using weak references as keys. When the original
    object is garbage collected, the cache entry is automatically removed.
    This prevents memory leaks when caching objects that may be deleted.
    
    The cache returns canonical instances: if you look up an object that is
    equal to a previously cached object, you get back the original cached
    instance. This is useful for canonicalization in static analysis.
    
    This is used extensively in pyflow for:
    - Canonical object caching (ensuring one instance per canonical value)
    - Type caching (avoiding duplicate type objects)
    - Name caching (canonicalizing slot names and identifiers)
    
    Attributes:
        data: Dictionary mapping weak references to cached objects
        _remove: Callback function for weak reference cleanup
        
    Example:
        >>> cache = weakcache()
        >>> obj1 = [1, 2, 3]
        >>> cached1 = cache[obj1]
        >>> cached2 = cache[obj1]  # Same object returned
        >>> cached1 is cached2
        True
        >>> obj2 = [1, 2, 3]  # Equal but different object
        >>> cached3 = cache[obj2]
        >>> cached1 is cached3  # Same cached instance
        True
    """
    __slots__ = "data", "_remove", "__weakref__"

    def __init__(self, dict=None):
        """
        Initialize a weakcache.
        
        Args:
            dict: Optional initial dictionary (currently unused, kept for compatibility)
        """
        self.data = {}

        def remove(wr, weakself=ref(self)):
            """
            Callback for when a weak reference is garbage collected.
            
            Removes the weak reference from the cache when the referenced
            object is deleted. This prevents the cache from growing unbounded.
            
            Args:
                wr: The weak reference that was collected
                weakself: Weak reference to self (to avoid keeping self alive)
            """
            self = weakself()

            if self is not None:
                try:
                    del self.data[wr]
                except KeyError:
                    # Weakref already removed, ignore
                    pass

        self._remove = remove

    def __getitem__(self, key):
        """
        Get or create a cached canonical instance for a key.
        
        If the key (or an equal object) has been cached before, returns the
        original cached instance. Otherwise, caches the key and returns it.
        
        Args:
            key: Object to look up or cache
            
        Returns:
            The canonical cached instance of the key
            
        Note:
            The key must be hashable and support weak references. Unhashable
            types (like lists, dicts) will raise TypeError.
        """
        wr = ref(key, self._remove)

        if wr in self.data:
            result = self.data[wr]()
        else:
            result = None

        if result is None:
            self.data[wr] = wr
            result = key

        return result

    def __delitem__(self, key):
        """
        Remove a key from the cache.
        
        Args:
            key: The key to remove
            
        Raises:
            KeyError: If the key is not in the cache
        """
        del self.data[ref(key)]

    def __contains__(self, key):
        """
        Check if a key is in the cache.
        
        Args:
            key: The key to check
            
        Returns:
            bool: True if the key (or an equal object) is cached
            
        Note:
            Returns False if the key is not hashable or doesn't support
            weak references (e.g., lists, dicts).
        """
        try:
            wr = ref(key)
        except TypeError:
            return False
        return wr in self.data

    def __iter__(self):
        """
        Iterate over all cached objects.
        
        Yields:
            All objects currently in the cache (skipping garbage collected ones)
        """
        for wr in self.data.keys():
            obj = wr()
            if obj is not None:
                yield obj

    def __len__(self):
        """
        Return the number of entries in the cache.
        
        Returns:
            int: Number of cached entries (including garbage collected ones)
            
        Note:
            The count may include entries where the object has been garbage
            collected but the weak reference hasn't been cleaned up yet.
        """
        return len(self.data)
