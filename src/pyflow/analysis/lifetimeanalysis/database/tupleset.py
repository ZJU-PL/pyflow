"""Tuple set schemas for lifetime analysis database.

This module provides tuple set schemas for storing sets of tuples in the
lifetime analysis database. Tuple sets enable efficient storage and querying
of structured relationships (e.g., invocation relationships).
"""

from . import base


class TupleSetSchema(base.Schema):
    """Schema for sets of tuples.
    
    TupleSetSchema defines sets where each element is a tuple validated
    by valueschema. Used for storing relationships like (code, context)
    or (code, op, context) tuples.
    
    Attributes:
        valueschema: StructureSchema for tuple structure
    """
    def __init__(self, valueschema):
        """Initialize tuple set schema.
        
        Args:
            valueschema: StructureSchema for tuple structure
        """
        self.valueschema = valueschema

    def instance(self):
        """Create a tuple set instance.
        
        Returns:
            TupleSet: New tuple set instance
        """
        return TupleSet(self)

    def missing(self):
        """Get missing (empty) value.
        
        Returns:
            TupleSet: Empty tuple set instance
        """
        return self.instance()

    def validate(self, args):
        """Validate tuple arguments.
        
        Args:
            args: Tuple to validate
            
        Raises:
            SchemaError: If tuple is invalid
        """
        self.valueschema.validate(args)

    def inplaceMerge(self, target, *args):
        """Merge tuple sets in-place.
        
        Adds all tuples from source sets to target.
        
        Args:
            target: Target tuple set
            *args: Source tuple sets to merge
            
        Returns:
            tuple: (target set, changed flag)
        """
        oldLen = len(target)
        for arg in args:
            for value in arg:
                target.add(*value)
        newLen = len(target)
        return target, oldLen != newLen


class TupleSet(object):
    """Tuple set instance for database.
    
    TupleSet stores a set of tuples, each validated by the schema.
    Used for storing relationships like invocation relationships.
    
    Attributes:
        schema: TupleSetSchema for this set
        data: Set storing tuples
    """
    def __init__(self, schema):
        """Initialize a tuple set.
        
        Args:
            schema: TupleSetSchema for this set
        """
        assert isinstance(schema, TupleSetSchema), type(schema)
        self.schema = schema
        self.data = set()

    def __len__(self):
        """Get number of tuples.
        
        Returns:
            int: Number of tuples
        """
        return len(self.data)

    def __iter__(self):
        """Iterate over tuples.
        
        Returns:
            iterator: Iterator over tuples
        """
        return iter(self.data)

    def add(self, *args):
        """Add a tuple to the set.
        
        Args:
            *args: Tuple elements
            
        Raises:
            SchemaError: If tuple is invalid
        """
        self.schema.validate(args)
        self.data.add(args)

    def remove(self, *args):
        """Remove a tuple from the set.
        
        Args:
            *args: Tuple elements
            
        Raises:
            DatabaseError: If tuple is not in set
        """
        self.schema.validate(args)
        if not args in self.data:
            raise base.DatabaseError(
                "Cannot remove tuple %r from database, as the tuple is not in the database"
                % (args,)
            )
        self.data.remove(args)
