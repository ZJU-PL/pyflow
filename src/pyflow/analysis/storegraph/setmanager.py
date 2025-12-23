"""Set manager for efficient set operations in store graph.

This module provides CachedSetManager for efficient set operations on
frozen sets. It caches sets to avoid duplicate allocations and provides
operations like union, difference, and coercion.
"""

import sys
from pyflow.util.monkeypatch import xcollections


class CachedSetManager(object):
    """Manages cached frozen sets for efficient set operations.
    
    CachedSetManager caches frozen sets to avoid duplicate allocations.
    All set operations return cached sets when possible, reducing memory
    usage and improving performance.
    
    Attributes:
        cache: Weak cache mapping frozensets to themselves
        _emptyset: Cached empty set
    """
    def __init__(self):
        """Initialize set manager."""
        self.cache = xcollections.weakcache()
        self._emptyset = self.cache[frozenset()]

    def coerce(self, values):
        """Coerce values to a cached frozen set.
        
        Args:
            values: Iterable of values
            
        Returns:
            frozenset: Cached frozen set
        """
        return self.cache[frozenset(values)]

    def empty(self):
        """Get the cached empty set.
        
        Returns:
            frozenset: Cached empty set
        """
        return self._emptyset

    def inplaceUnion(self, a, b):
        """Compute union of two sets, returning cached result.
        
        Args:
            a: First frozen set
            b: Second frozen set
            
        Returns:
            frozenset: Cached union set
        """
        if a is b:
            return a
        elif not a:
            return self.cache[b]
        elif not b:
            return self.cache[a]
        else:
            return self.cache[a.union(b)]

    def diff(self, a, b):
        """Compute set difference (a - b), returning cached result.
        
        Args:
            a: First frozen set
            b: Second frozen set
            
        Returns:
            frozenset: Cached difference set
        """
        if a is b:
            return self._emptyset
        elif not b:
            return self.cache[a]
        else:
            return self.cache[a - b]

    def tempDiff(self, a, b):
        """Compute temporary set difference (not cached).
        
        Used when the result is temporary and doesn't need caching.
        
        Args:
            a: First frozen set
            b: Second frozen set
            
        Returns:
            frozenset: Difference set (not cached)
        """
        if a is b:
            return self._emptyset
        elif not b:
            return a
        else:
            return a - b

    def iter(self, s):
        """Iterate over a set.
        
        Args:
            s: Set to iterate
            
        Returns:
            iterator: Iterator over set elements
        """
        return iter(s)

    def memory(self):
        """Estimate memory usage of cache.
        
        Returns:
            int: Estimated memory in bytes
        """
        mem = sys.getsizeof(self.cache)
        for s in self.cache:
            mem += sys.getsizeof(s)
        return mem
