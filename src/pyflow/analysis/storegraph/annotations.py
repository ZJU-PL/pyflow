"""Annotations for store graph objects and fields.

This module provides annotation classes for attaching analysis results
to objects and fields in the store graph. Annotations are immutable and
can be rewritten to create new versions.
"""

from pyflow.language.asttools import Annotation


class ObjectAnnotation(Annotation):
    """Annotation for ObjectNode with analysis results.
    
    ObjectAnnotation stores analysis results for objects:
    - preexisting: Whether object existed before function entry
    - unique: Whether object is unique (not aliased)
    - final: Whether object is final (immutable after creation)
    - uniform: Whether object has uniform shape (shape analysis)
    - input: Whether object is an input parameter
    
    Attributes:
        preexisting: Whether object is preexisting
        unique: Whether object is unique
        final: Whether object is final
        uniform: Whether object is uniform
        input: Whether object is input
    """
    __slots__ = "preexisting", "unique", "final", "uniform", "input"

    def __init__(self, preexisting, unique, final, uniform, input):
        """Initialize object annotation.
        
        Args:
            preexisting: Whether object is preexisting
            unique: Whether object is unique
            final: Whether object is final
            uniform: Whether object is uniform
            input: Whether object is input
        """
        self.preexisting = preexisting
        self.unique = unique
        self.final = final
        self.uniform = uniform
        self.input = input


class FieldAnnotation(Annotation):
    """Annotation for SlotNode (fields) with analysis results.
    
    FieldAnnotation stores analysis results for fields:
    - unique: Whether field has unique value
    
    Attributes:
        unique: Whether field is unique
    """
    __slots__ = ("unique",)

    def __init__(self, unique):
        """Initialize field annotation.
        
        Args:
            unique: Whether field is unique
        """
        self.unique = unique


emptyFieldAnnotation = FieldAnnotation(False)
emptyObjectAnnotation = ObjectAnnotation(False, False, False, False, False)
