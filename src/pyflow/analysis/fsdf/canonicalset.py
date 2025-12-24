"""
Canonical Set Manager for Flow-Sensitive Data Flow Analysis.

This module provides a manager for creating canonical (unique) set
representations. Sets with the same elements are represented by the
same frozenset object, enabling efficient comparison and reducing
memory usage through interning.

**Canonicalization:**
The manager maintains a cache of all sets it has created. When a
new set is requested, it checks if an equivalent set already exists
and returns that instead of creating a new one. This ensures that
sets with the same elements are identical objects (can be compared
with `is` instead of `==`).

**Use Cases:**
- Flow-sensitive analysis: Representing sets of values that may vary
  by control flow path
- Set operations: Union, intersection with canonical results
- Memory efficiency: Sharing set representations across contexts
"""

import sys


class CanonicalSetManager(object):
    """
    Manages canonical (interned) set representations.
    
    This class provides canonical set operations where sets with the
    same elements are represented by the same object. This enables:
    - Efficient comparison using identity (`is`) instead of equality
    - Memory savings through sharing of set representations
    - Consistent set objects across different contexts
    
    **Canonicalization Strategy:**
    Uses a dictionary cache keyed by frozensets. When creating a set,
    converts to frozenset and looks it up in the cache. If found,
    returns the cached version; otherwise, caches and returns it.
    
    Attributes:
        cache: Dictionary mapping frozensets to themselves (for interning)
        _emptyset: Cached empty set (most common case)
    """
    def __init__(self):
        """Initialize a canonical set manager."""
        self.cache = {}
        emptyset = frozenset()
        self._emptyset = self.cache.setdefault(emptyset, emptyset)

    def empty(self):
        """
        Get the canonical empty set.
        
        Returns:
            The canonical empty frozenset
        """
        return self._emptyset

    def canonical(self, iterable):
        """
        Create a canonical set from an iterable.
        
        Converts the iterable to a frozenset and returns the canonical
        (cached) version if it exists, otherwise creates and caches it.
        
        Args:
            iterable: Iterable to convert to a canonical set
            
        Returns:
            Canonical frozenset with the same elements
        """
        s = frozenset(iterable)
        return self.cache.setdefault(s, s)

    def _canonical(self, s):
        """
        Canonicalize an existing frozenset.
        
        Internal method that looks up a frozenset in the cache.
        
        Args:
            s: Frozenset to canonicalize
            
        Returns:
            Canonical version of the frozenset
        """
        return self.cache.setdefault(s, s)

    def inplaceUnion(self, a, b):
        """
        Compute union of two sets and return canonical result.
        
        Note: Despite the name, this doesn't modify the inputs.
        The "inplace" refers to the fact that the result may reuse
        one of the input sets if appropriate.
        
        Args:
            a: First set (frozenset)
            b: Second set (frozenset)
            
        Returns:
            Canonical frozenset representing the union
        """
        return self._canonical(a.union(b))

    def union(self, a, b):
        """
        Compute union of two sets and return canonical result.
        
        Args:
            a: First set (frozenset)
            b: Second set (frozenset)
            
        Returns:
            Canonical frozenset representing the union
        """
        return self._canonical(a.union(b))

    def intersection(self, a, b):
        """
        Compute intersection of two sets and return canonical result.
        
        Args:
            a: First set (frozenset)
            b: Second set (frozenset)
            
        Returns:
            Canonical frozenset representing the intersection
        """
        return self._canonical(a.intersection(b))

    def uncachedDiff(self, a, b):
        """
        Compute set difference without caching.
        
        Used when the result is temporary and doesn't need to be
        canonicalized (e.g., for intermediate computations).
        
        Args:
            a: First set
            b: Second set
            
        Returns:
            Set difference (a - b) as a regular frozenset
        """
        return a - b

    def iter(self, s):
        """
        Iterate over a set.
        
        Args:
            s: Set to iterate over
            
        Returns:
            Iterator over the set elements
        """
        return iter(s)

    def memory(self):
        """
        Estimate memory usage of the cache.
        
        Computes approximate memory usage by summing:
        - Size of the cache dictionary
        - Size of each cached frozenset
        
        Returns:
            Estimated memory usage in bytes
        """
        mem = sys.getsizeof(self.cache)
        for s in self.cache.keys():
            mem += sys.getsizeof(s)
        return mem
