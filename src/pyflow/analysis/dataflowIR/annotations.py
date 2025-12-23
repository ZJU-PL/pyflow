"""Annotation structures for dataflow IR nodes.

This module provides annotation classes for attaching analysis results
to dataflow IR nodes. Annotations store information computed by various
analysis passes, such as:
- Read/modify sets for operations
- Value sets for slots
- Object properties (preexisting, unique, final)

Annotations are immutable and can be rewritten to create new versions
with updated values.
"""

class CorrelatedAnnotation(object):
    """Annotation with both flat and correlated views.
    
    Some annotations can be viewed in two ways:
    - Flat: Simple set-based view
    - Correlated: View that preserves correlations between values
    
    Attributes:
        flat: Flat annotation view
        correlated: Correlated annotation view
    """
    __slots__ = "flat", "correlated"

    def __init__(self, flat, correlated):
        """Initialize correlated annotation.
        
        Args:
            flat: Flat annotation view
            correlated: Correlated annotation view
        """
        self.flat = flat
        self.correlated = correlated


class DataflowAnnotation(object):
    """Base class for dataflow IR annotations.
    
    Annotations are immutable objects attached to dataflow nodes.
    They can be rewritten to create new versions with updated values.
    """
    __slots__ = ()

    def rewrite(self, **kwds):
        """Create a new annotation with updated values.
        
        Creates a new annotation of the same type with specified fields
        updated. Fields not specified retain their current values.
        
        Args:
            **kwds: Keyword arguments for fields to update
            
        Returns:
            DataflowAnnotation: New annotation with updated values
            
        Raises:
            AssertionError: If unknown field names are provided
        """
        # Make sure extraneous keywords were not given.
        for name in kwds.keys():
            assert name in self.__slots__, name

        values = {}
        for name in self.__slots__:
            if name in kwds:
                value = kwds[name]
            else:
                value = getattr(self, name)
            values[name] = value

        return type(self)(**values)


class DataflowOpAnnotation(DataflowAnnotation):
    """Annotation for operation nodes.
    
    Stores read/modify/allocate sets and mask information for operations.
    These annotations are computed by analysis passes and used for
    optimizations and further analysis.
    
    Attributes:
        read: Set of slots read by this operation
        modify: Set of slots modified by this operation
        allocate: Set of objects allocated by this operation
        mask: Mask information (for shape analysis)
    """
    __slots__ = "read", "modify", "allocate", "mask"

    def __init__(self, read, modify, allocate, mask):
        """Initialize operation annotation.
        
        Args:
            read: Read set (slots read)
            modify: Modify set (slots modified)
            allocate: Allocate set (objects allocated)
            mask: Mask information
        """
        self.read = read
        self.modify = modify
        self.allocate = allocate
        self.mask = mask


class DataflowSlotAnnotation(DataflowAnnotation):
    """Annotation for slot nodes.
    
    Stores value set and uniqueness information for slots.
    
    Attributes:
        values: Set of values this slot may hold
        unique: Whether this slot has a unique value
    """
    __slots__ = "values", "unique"

    def __init__(self, values, unique):
        """Initialize slot annotation.
        
        Args:
            values: Set of possible values
            unique: Whether slot has unique value
        """
        self.values = values
        self.unique = unique


class DataflowObjectAnnotation(DataflowAnnotation):
    """Annotation for object nodes.
    
    Stores object properties including preexisting status, uniqueness,
    mask information, and finality.
    
    Attributes:
        preexisting: Whether object existed before function entry
        unique: Whether object is unique (not aliased)
        mask: Mask information (for shape analysis)
        final: Whether object is final (immutable after creation)
    """
    __slots__ = "preexisting", "unique", "mask", "final"

    def __init__(self, preexisting, unique, mask, final):
        """Initialize object annotation.
        
        Args:
            preexisting: Whether object existed before entry
            unique: Whether object is unique
            mask: Mask information
            final: Whether object is final
        """
        self.preexisting = preexisting
        self.unique = unique
        self.mask = mask
        self.final = final

    def __repr__(self):
        """String representation for debugging.
        
        Returns:
            str: Representation of the annotation
        """
        return "%s(preexisting=%r, unique=%r, mask=%r, final=%r)" % (
            type(self).__name__,
            self.preexisting,
            self.unique,
            self.mask,
            self.final,
        )
