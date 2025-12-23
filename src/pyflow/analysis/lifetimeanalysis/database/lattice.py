"""Lattice-based schemas for lifetime analysis database.

This module provides set-based schemas that implement lattice operations
(union, intersection) for efficient merging of analysis information.
"""

from . import base


class SetSchema(base.Schema):
    """Schema for sets (with None representing empty set).
    
    SetSchema validates and manages sets. None represents the empty set
    (bottom of the lattice).
    """
    __slots = ()

    def validate(self, arg):
        """Validate that argument is a set or None.
        
        Args:
            arg: Value to validate
            
        Raises:
            SchemaError: If value is not a set or None
        """
        if isinstance(arg, (set, type(None))):
            return True
        else:
            raise base.SchemaError("Expected set, got %s" % type(arg).__name__)

    def missing(self):
        """Get missing (empty) value.
        
        Returns:
            None: Represents empty set
        """
        return None

    def copy(self, original):
        """Copy a set value.
        
        Args:
            original: Set to copy (or None)
            
        Returns:
            set or None: Copy of the set
        """
        if original is None:
            return None
        else:
            return set(original)


class SetUnionSchema(SetSchema):
    """Schema for set union operations.
    
    SetUnionSchema implements union lattice operations. Merging sets
    computes their union. Used for accumulating read/modify sets.
    """
    __slots = ()

    def merge(self, *args):
        """Merge sets using union.
        
        Args:
            *args: Sets to merge (None represents empty set)
            
        Returns:
            set or None: Union of all sets (None if empty)
        """
        current = set()
        for arg in args:
            if arg is None:
                continue
            current.update(arg)

        if not current:
            return None

        return current

    def inplaceMerge(self, *args):
        """Merge sets in-place using union.
        
        Merges additional sets into the first argument.
        
        Args:
            *args: Sets to merge (first is target, rest are sources)
            
        Returns:
            tuple: (merged set, changed flag)
        """
        current = args[0]

        if not current:
            current = set()
            oldLen = 0
        else:
            oldLen = len(current)

        for arg in args[1:]:
            if arg is None:
                continue
            current.update(arg)

        if not current:
            return None, False

        newLen = len(current)

        return current, newLen != oldLen


setUnionSchema = SetUnionSchema()


class SetIntersectionSchema(SetSchema):
    """Schema for set intersection operations.
    
    SetIntersectionSchema implements intersection lattice operations.
    Merging sets computes their intersection. Used for finding common
    elements across multiple paths.
    """
    __slots = ()

    def merge(self, *args):
        """Merge sets using intersection.
        
        Args:
            *args: Sets to merge (None represents empty set)
            
        Returns:
            set or None: Intersection of all sets (None if empty)
        """
        current = self.copy(args[0])

        if not current:
            return None

        for arg in args[1:]:
            if arg is None:
                current.clear()
                return current

            current.intersection_update(arg)

        if not current:
            current = None

        return current

    def inplaceMerge(self, *args):
        """Merge sets in-place using intersection.
        
        Merges additional sets into the first argument using intersection.
        
        Args:
            *args: Sets to merge (first is target, rest are sources)
            
        Returns:
            tuple: (intersected set, changed flag)
        """
        current = args[0]

        if not current:
            return None, False

        oldLen = len(current)

        for arg in args[1:]:
            if arg is None:
                current.clear()
                return current, oldLen != 0

            current.intersection_update(arg)

        changed = oldLen != len(current)

        if not current:
            current = None

        return current, changed


setIntersectionSchema = SetIntersectionSchema()
