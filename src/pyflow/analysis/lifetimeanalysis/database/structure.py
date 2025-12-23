"""Structure schemas for lifetime analysis database.

This module provides structure schemas for representing structured data
in the lifetime analysis database. Structures are tuples with named fields,
each with its own schema.
"""

from . import base

import collections


class WildcardSchema(base.Schema):
    """Schema that accepts any value (no validation).
    
    Used for contexts and other values that don't need validation.
    """
    __slots__ = ()

    def __init__(self):
        """Initialize wildcard schema."""
        pass

    def validate(self, args):
        """Validate arguments (always succeeds).
        
        Args:
            args: Arguments to validate (ignored)
        """
        pass


class TypeSchema(base.Schema):
    """Schema that validates types.
    
    TypeSchema validates that values are instances of specific types.
    Used for validating AST nodes, code objects, etc.
    
    Attributes:
        type_: Type or tuple of types to validate against
    """
    def __init__(self, type_):
        """Initialize type schema.
        
        Args:
            type_: Type or tuple of types
        """
        self.type_ = type_

    def validate(self, args):
        """Validate that argument is instance of type.
        
        Args:
            args: Value to validate
            
        Raises:
            SchemaError: If value is not instance of type
        """
        if not isinstance(args, self.type_):
            raise base.SchemaError(
                "Expected type %r, got %r." % (self.type_, type(args))
            )

    def instance(self):
        """Create instance (not supported for types).
        
        Raises:
            SchemaError: Types cannot be instantiated directly
        """
        raise base.SchemaError("Cannot directly create instances of types.")

    def missing(self):
        """Get missing value (not supported for types).
        
        Raises:
            SchemaError: Types cannot have missing values
        """
        return self.instance()


class CallbackSchema(base.Schema):
    """Schema that validates using a callback function.
    
    CallbackSchema uses a callback function to validate values.
    Used for complex validation logic (e.g., code.isCode()).
    
    Attributes:
        validator: Callback function(value) -> bool
    """
    def __init__(self, validator):
        """Initialize callback schema.
        
        Args:
            validator: Validation callback function
        """
        self.validator = validator

    def validate(self, args):
        """Validate using callback function.
        
        Args:
            args: Value to validate
            
        Raises:
            SchemaError: If callback returns False
        """
        if not self.validator(args):
            raise base.SchemaError("Callback did not validate %r." % (type(args)))

    def instance(self):
        """Create instance (not supported for callbacks).
        
        Raises:
            SchemaError: Callback schemas cannot be instantiated directly
        """
        raise base.SchemaError("Cannot directly create instances of callback schemas.")

    def missing(self):
        """Get missing value (not supported for callbacks).
        
        Raises:
            SchemaError: Callback schemas cannot have missing values
        """
        return self.instance()


class StructureSchema(base.Schema):
    """Schema for structured data (named tuples).
    
    StructureSchema defines structures with named fields, each with
    its own schema. Structures are represented as named tuples.
    
    Attributes:
        fields: List of (name, fieldSchema) tuples
        map: Dictionary mapping field names to schemas
        type_: Named tuple type for this structure
    """
    __slots__ = "fields", "map", "type_"

    def __init__(self, *fields):
        """Initialize structure schema.
        
        Args:
            *fields: (name, fieldSchema) tuples defining fields
        """
        self.fields = []
        self.map = {}

        for name, field in fields:
            self.__addField(name, field)

        # HACK no typename, just 'structure'?
        names = [name for name, field in fields]
        self.type_ = collections.namedtuple("structure", names)

    def instance(self):
        raise base.SchemaError("Cannot directly create instances of structures.")

    def missing(self):
        return self.type_(*[field.missing() for (name, field) in self.fields])

    def __addField(self, name, field):
        if name in self.map:
            raise base.SchemaError(
                "Structure has multiple definitions for name '%s'" % (name,)
            )

        self.fields.append((name, field))
        self.map[name] = field

    def field(self, name):
        if name not in self.map:
            raise base.SchemaError("Schema for structures has no field '%s'" % (name,))
        return self.map[name]

    def fieldnames(self):
        return self.map.keys()

    def validate(self, args):
        assert isinstance(args, tuple), args

        if len(args) != len(self.fields):
            raise base.SchemaError(
                "Structure has %d fields, but %d fields were given."
                % (len(self.fields), len(args))
            )

        for (name, field), arg in zip(self.fields, args):
            field.validate(arg)

    def inplaceMerge(self, target, *args):
        self.validate(target)
        for arg in args:
            self.validate(arg)

        accum = []

        changed = False
        for (name, fieldSchema), targetfield, argfields in zip(
            self.fields, target, zip(*args)
        ):
            result, fieldChanged = fieldSchema.inplaceMerge(targetfield, *argfields)
            accum.append(result)
            changed |= fieldChanged

        output = self.type_(*accum)
        return output, changed

    def merge(self, *args):
        for arg in args:
            self.validate(arg)

        accum = []

        for (name, fieldSchema), argfields in zip(self.fields, zip(*args)):
            result = fieldSchema.merge(*argfields)
            accum.append(result)

        output = self.type_(*accum)
        return output
