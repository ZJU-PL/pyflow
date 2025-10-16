"""
Pointer analysis data structures for PyFlow.

This module provides the fundamental pointer types used in points-to analysis,
including literal pointers for tracking literal values and name pointers for
tracking variable references and function arguments.
"""


class Pointer(object):
    """
    Base class for all pointer types in points-to analysis.
    
    A pointer represents a set of values that a variable or expression can
    point to during program execution. This is the foundation of points-to
    analysis in PyFlow.
    """
    
    def __init__(self):
        """Initialize a pointer with an empty set of values."""
        self.values = set()  # Set of values this pointer can point to

    def add(self, item):
        """
        Add a single item to the pointer's values.
        
        Args:
            item: The item to add to the pointer.
        """
        self.values.add(item)

    def add_set(self, s):
        """
        Add all items from a set to the pointer's values.
        
        Args:
            s (set): The set of items to add.
        """
        self.values = self.values.union(s)

    def get(self):
        """
        Get all values this pointer can point to.
        
        Returns:
            set: The set of values.
        """
        return self.values

    def merge(self, pointer):
        """
        Merge another pointer's values into this one.
        
        Args:
            pointer (Pointer): The pointer to merge from.
        """
        self.values = self.values.union(pointer.values)


class LiteralPointer(Pointer):
    """
    Pointer type for tracking literal values.
    
    This pointer type tracks what literal values (strings, integers, etc.)
    a variable or expression can point to during program execution.
    """
    
    # Constants for different literal types
    STR_LIT = "STRING"      # String literal type
    INT_LIT = "INTEGER"     # Integer literal type
    UNK_LIT = "UNKNOWN"     # Unknown literal type

    def add(self, item):
        """
        Add a literal item to the pointer, categorizing by type.
        
        Instead of storing the actual literal value, we store a type indicator
        to avoid storing potentially large literal values in memory.
        
        Args:
            item: The literal item to add.
        """
        if isinstance(item, str):
            self.values.add(item)
        elif isinstance(item, int):
            self.values.add(item)
        else:
            self.values.add(self.UNK_LIT)


class NamePointer(Pointer):
    """
    Pointer type for tracking variable references and function arguments.
    
    This pointer type is more sophisticated than LiteralPointer, tracking
    both positional and named arguments for function calls, as well as
    the relationships between different variable names.
    """
    
    def __init__(self):
        """Initialize a name pointer with argument tracking structures."""
        super().__init__()
        self.pos_to_name = {}  # Maps position numbers to argument names
        self.name_to_pos = {}  # Maps argument names to position numbers
        self.args = {}         # Maps argument names to their values

    def _sanitize_pos(self, pos):
        """
        Validate and sanitize a position number.
        
        Args:
            pos: The position to validate.
            
        Returns:
            The sanitized position.
            
        Raises:
            PointerError: If the position is invalid.
        """
        try:
            int(pos)
        except ValueError:
            raise PointerError("Invalid position for argument")

        return pos

    def get_or_create(self, name):
        """
        Get an argument set by name, creating it if it doesn't exist.
        
        Args:
            name (str): The argument name.
            
        Returns:
            set: The argument set for the given name.
        """
        if name not in self.args:
            self.args[name] = set()
        return self.args[name]

    def add_arg(self, name, item):
        """
        Add an item to a named argument.
        
        Args:
            name (str): The argument name.
            item: The item to add (string, set, etc.).
            
        Raises:
            Exception: If the item type is not supported.
        """
        self.get_or_create(name)
        if isinstance(item, str):
            self.args[name].add(item)
        elif isinstance(item, set):
            self.args[name] = self.args[name].union(item)
        else:
            raise Exception()

    def add_lit_arg(self, name, item):
        """
        Add a literal item to a named argument.
        
        Args:
            name (str): The argument name.
            item: The literal item to add.
        """
        arg = self.get_or_create(name)
        if isinstance(item, str):
            arg.add(LiteralPointer.STR_LIT)
        elif isinstance(item, int):
            arg.add(LiteralPointer.INT_LIT)
        else:
            arg.add(LiteralPointer.UNK_LIT)

    def add_pos_arg(self, pos, name, item):
        pos = self._sanitize_pos(pos)
        if not name:
            if self.pos_to_name.get(pos, None):
                name = self.pos_to_name[pos]
            else:
                name = str(pos)
        self.pos_to_name[pos] = name
        self.name_to_pos[name] = pos

        self.add_arg(name, item)

    def add_name_arg(self, name, item):
        self.add_arg(name, item)

    def add_pos_lit_arg(self, pos, name, item):
        pos = self._sanitize_pos(pos)
        if not name:
            name = str(pos)
        self.pos_to_name[pos] = name
        self.name_to_pos[name] = pos
        self.add_lit_arg(name, item)

    def get_pos_arg(self, pos):
        pos = self._sanitize_pos(pos)
        name = self.pos_to_name.get(pos, None)
        return self.get_arg(name)

    def get_arg(self, name):
        if self.args.get(name, None):
            return self.args[name]

    def get_args(self):
        return self.args

    def get_pos_args(self):
        args = {}
        for pos, name in self.pos_to_name.items():
            args[pos] = self.args[name]
        return args

    def get_pos_of_name(self, name):
        if name in self.name_to_pos:
            return self.name_to_pos[name]

    def get_pos_names(self):
        return self.pos_to_name

    def merge(self, pointer):
        """
        Merge another NamePointer into this one.
        
        This method merges both the base pointer values and the argument
        information from another NamePointer.
        
        Args:
            pointer (NamePointer): The pointer to merge from.
        """
        super().merge(pointer)
        if hasattr(pointer, "get_pos_names"):
            # Merge positional to name mappings
            for pos, name in pointer.get_pos_names().items():
                self.pos_to_name[pos] = name
            # Merge argument information
            for name, arg in pointer.get_args().items():
                self.add_arg(name, arg)


class PointerError(Exception):
    """Exception raised for pointer-related errors."""
    pass