"""
Union-Find (Disjoint Set Union) data structure.

This module provides an efficient Union-Find data structure for managing
disjoint sets. It supports:
- Finding the representative (root) of a set containing an element
- Unioning two or more sets together
- Path compression for efficient lookups
- Union by size (weight) for balanced trees

The Union-Find data structure is used in pyflow for:
- Finding connected components in graphs
- Tracking equivalence classes
- Merging analysis results
- Cycle detection

Time complexity:
- Find: O(α(n)) amortized (where α is the inverse Ackermann function)
- Union: O(α(n)) amortized
- Overall: Nearly constant time per operation
"""

class UnionFind(object):
    """
    Union-Find data structure with path compression and union by size.
    
    This implementation uses:
    - Path compression: Flattens the tree during find operations
    - Union by size: Always attaches smaller trees to larger ones
    
    Attributes:
        parents: Dictionary mapping objects to their parent in the union tree
        weights: Dictionary mapping roots to the size of their set
    """
    __slots__ = "parents", "weights"

    def __init__(self):
        """Initialize an empty Union-Find structure."""
        self.parents = {}
        self.weights = {}

    def __getitem__(self, obj):
        """
        Find the root (representative) of the set containing obj.
        
        If obj is not in any set, returns obj itself. Otherwise, finds
        the root of obj's set using path compression.
        
        Args:
            obj: Object to find the root for
            
        Returns:
            Root object representing the set containing obj
        """
        if obj not in self.parents:
            return obj
        else:
            return self.getItemCompress(obj)

    def __iter__(self):
        """
        Iterate over all objects that are part of sets.
        
        Yields:
            All objects that have been unioned (have parents)
        """
        return self.parents.keys()

    def getItemCompress(self, obj):
        """
        Find root with path compression.
        
        Recursively finds the root while flattening the tree by making
        each node point directly to the root. This improves future lookups.
        
        Args:
            obj: Object to find root for
            
        Returns:
            Root object of the set containing obj
        """
        parent = self.parents[obj]
        if parent == obj:
            # obj is the root
            return parent
        else:
            # Recursively find root and compress path
            root = self.getItemCompress(parent)
            self.parents[obj] = root  # Path compression
            return root

    def union(self, first, *objs):
        """
        Union two or more sets together.
        
        Merges the sets containing the given objects. Uses union by size
        (weight) to keep trees balanced - always attaches smaller trees
        to larger ones.
        
        Args:
            first: First object (required)
            *objs: Additional objects to union with first
            
        Returns:
            Root object of the merged set
            
        Example:
            >>> uf = UnionFind()
            >>> uf.union(1, 2, 3)  # Union sets containing 1, 2, 3
            >>> uf[1] == uf[2] == uf[3]
            True
        """
        if objs:
            # Find all roots and determine the largest set
            biggestRoot = self[first]
            maxWeight = self.weights.get(biggestRoot, 1)
            roots = set()
            roots.add(biggestRoot)

            for obj in objs:
                root = self[obj]
                if root not in roots:
                    weight = self.weights.get(root, 1)
                    if weight > maxWeight:
                        # Found a larger set, use it as the new root
                        biggestRoot = root
                        maxWeight = weight
                    roots.add(root)

            # The biggest root is intentionally left in roots,
            # So we ensure that self.parents[biggestRoot] exists.
            if len(roots) > 1:
                # Merge all sets into the largest one
                weight = 0
                for root in roots:
                    self.parents[root] = biggestRoot
                    weight += self.weights.pop(root, 1)

                self.weights[biggestRoot] = weight

            return biggestRoot
        else:
            # No additional objects, just return root of first
            return self[first]

    def copy(self):
        """
        Create a deep copy of this Union-Find structure.
        
        Returns:
            New UnionFind instance with copied parents and weights
        """
        u = UnionFind()
        u.parents.update(self.parents)
        u.weights.update(self.weights)
        return u

    def dump(self):
        """
        Print the internal structure for debugging.
        
        Outputs all parent relationships in the union tree.
        """
        for k, v in self.parents.items():
            print("%r  ->  %r" % (k, v))
