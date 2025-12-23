"""Mapping schemas for lifetime analysis database.

This module provides mapping (dictionary) schemas for storing key-value
pairs in the lifetime analysis database. Mappings enable efficient lookup
and merging of analysis information.
"""

from . import base


class MappingSchema(base.Schema):
    """Schema for key-value mappings.
    
    MappingSchema defines mappings from keys (validated by keyschema)
    to values (validated by valueschema). Used for storing analysis
    information indexed by program points, contexts, etc.
    
    Attributes:
        keyschema: Schema for keys
        valueschema: Schema for values
    """
    __slots__ = "keyschema", "valueschema"

    def __init__(self, keyschema, valueschema):
        """Initialize mapping schema.
        
        Args:
            keyschema: Schema for keys
            valueschema: Schema for values
        """
        self.keyschema = keyschema
        self.valueschema = valueschema

    def instance(self):
        """Create a mapping instance.
        
        Returns:
            Mapping: New mapping instance
        """
        return Mapping(self)

    def missing(self):
        """Get missing (empty) value.
        
        Returns:
            Mapping: Empty mapping instance
        """
        return self.instance()

    def validateKey(self, args):
        """Validate a key.
        
        Args:
            args: Key to validate
            
        Raises:
            SchemaError: If key is invalid
        """
        self.keyschema.validate(args)

    def validateValue(self, args):
        """Validate a value.
        
        Args:
            args: Value to validate
            
        Raises:
            SchemaError: If value is invalid
        """
        self.valueschema.validate(args)

    def inplaceMerge(self, target, *args):
        """Merge mappings in-place.
        
        Merges all key-value pairs from source mappings into target.
        
        Args:
            target: Target mapping
            *args: Source mappings to merge
            
        Returns:
            tuple: (target mapping, changed flag)
        """
        changed = False
        for arg in args:
            for key, value in arg:
                changed |= target.merge(key, value)
        return target, changed


class Mapping(object):
    """Mapping (dictionary) instance for database.
    
    Mapping stores key-value pairs with schema validation. Values
    are merged according to the value schema when the same key appears
    multiple times.
    
    Attributes:
        schema: MappingSchema for this mapping
        data: Dictionary storing key-value pairs
    """
    __slots__ = "schema", "data"

    def __init__(self, schema):
        """Initialize a mapping.
        
        Args:
            schema: MappingSchema for this mapping
        """
        assert isinstance(schema, MappingSchema), type(schema)
        self.schema = schema
        self.data = {}

    def __getitem__(self, key):
        """Get value for a key (creating if missing).
        
        Args:
            key: Key to look up
            
        Returns:
            object: Value for key (may be missing value)
        """
        self.schema.validateKey(key)

        if not key in self.data:
            result = self.schema.valueschema.missing()
            self.data[key] = result
        else:
            result = self.data[key]

        return result

    def __len__(self):
        """Get number of entries.
        
        Returns:
            int: Number of entries
        """
        return len(self.data)

    def __iter__(self):
        """Iterate over key-value pairs.
        
        Returns:
            iterator: Iterator over (key, value) pairs
        """
        return iter(self.data.items())

    def forget(self):
        """Forget all keys, merging all values.
        
        Returns:
            object: Merged value from all entries
        """
        return self.schema.valueschema.merge(*self.data.values())

    def merge(self, key, value):
        """Merge a value into this mapping.
        
        Merges value into existing value for key (or creates new entry).
        
        Args:
            key: Key to merge value for
            value: Value to merge
            
        Returns:
            bool: True if mapping changed
        """
        result, changed = self.schema.valueschema.inplaceMerge(self[key], value)
        if changed:
            self.data[key] = result
        return changed
