"""Base schema classes for lifetime analysis database.

This module provides the base Schema class and exceptions for the database
system used by lifetime analysis. Schemas define the structure and validation
rules for database entries.
"""

class SchemaError(Exception):
    """Exception raised for schema validation errors."""
    pass


class DatabaseError(Exception):
    """Exception raised for database operation errors."""
    pass


class Schema(object):
    """Abstract base class for database schemas.
    
    Schemas define the structure, validation, and merge operations for
    database entries. They provide:
    - Validation: Check if values conform to schema
    - Instance creation: Create empty instances
    - Merging: Combine multiple values according to schema rules
    
    Subclasses implement specific schema types (sets, mappings, structures, etc.).
    """
    __slots__ = ()

    def __call__(self):
        """Create a schema instance (convenience method).
        
        Returns:
            object: Schema instance
        """
        return self.instance()

    def validateNoRaise(self, args):
        """Validate arguments without raising exception.
        
        Args:
            args: Arguments to validate
            
        Returns:
            bool: True if valid, False otherwise
        """
        try:
            self.validate(args)
        except SchemaError:
            return False
        else:
            return True

    def merge(self, *args):
        """Merge multiple values according to schema rules.
        
        Creates a new instance and merges all arguments into it.
        
        Args:
            *args: Values to merge
            
        Returns:
            object: Merged value
        """
        target = self.missing()
        target, changed = self.inplaceMerge(target, *args)
        return target
