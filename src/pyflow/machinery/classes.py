"""
Class management and hierarchy tracking for PyFlow.

This module provides classes for managing Python class definitions, inheritance
hierarchies, and method resolution order (MRO) computation.
"""


class ClassManager:
    """
    Manages class definitions and their relationships.
    
    This class maintains a registry of all class definitions encountered during
    analysis, allowing for efficient lookup and management of class hierarchies.
    """
    
    def __init__(self):
        """Initialize the class manager with an empty registry."""
        self.names = {}  # Maps class names to ClassNode instances

    def get(self, name):
        """
        Retrieve a class node by name.
        
        Args:
            name (str): The name of the class to retrieve.
            
        Returns:
            ClassNode or None: The class node if found, None otherwise.
        """
        if name in self.names:
            return self.names[name]

    def create(self, name, module):
        """
        Create a new class node or return existing one.
        
        Args:
            name (str): The name of the class.
            module (str): The module where the class is defined.
            
        Returns:
            ClassNode: The created or existing class node.
        """
        if name not in self.names:
            cls = ClassNode(name, module)
            self.names[name] = cls
        return self.names[name]

    def get_classes(self):
        """
        Get all registered classes.
        
        Returns:
            dict: Dictionary mapping class names to ClassNode instances.
        """
        return self.names


class ClassNode:
    """
    Represents a single class definition with its inheritance hierarchy.
    
    This class tracks a class's name, module, and method resolution order (MRO)
    which determines the order in which base classes are searched for attributes.
    """
    
    def __init__(self, ns, module):
        """
        Initialize a class node.
        
        Args:
            ns (str): The class namespace/name.
            module (str): The module where the class is defined.
        """
        self.ns = ns  # Class namespace/name
        self.module = module  # Module containing the class
        self.mro = [ns]  # Method Resolution Order, starts with self

    def add_parent(self, parent):
        """
        Add a parent class to the inheritance hierarchy.
        
        Args:
            parent (str or list): Single parent class name or list of parent names.
        """
        if isinstance(parent, str):
            self.mro.append(parent)
        elif isinstance(parent, list):
            for item in parent:
                self.mro.append(item)
        self.fix_mro()  # Remove duplicates after adding

    def fix_mro(self):
        """
        Remove duplicate entries from the MRO while preserving order.
        
        This ensures each class appears only once in the method resolution order.
        """
        new_mro = []
        for idx, item in enumerate(self.mro):
            # Skip if this item appears later in the list
            if self.mro[idx + 1 :].count(item) > 0:
                continue
            new_mro.append(item)
        self.mro = new_mro

    def get_mro(self):
        """
        Get the current method resolution order.
        
        Returns:
            list: List of class names in MRO order.
        """
        return self.mro

    def get_module(self):
        """
        Get the module where this class is defined.
        
        Returns:
            str: The module name.
        """
        return self.module

    def compute_mro(self):
        """
        Compute and update the method resolution order.
        
        This method ensures the MRO follows Python's C3 linearization algorithm
        for proper inheritance resolution.
        """
        res = []
        self.mro.reverse()  # Start from the end
        for parent in self.mro:
            if parent not in res:
                res.append(parent)

        res.reverse()  # Restore correct order
        self.mro = res

    def clear_mro(self):
        """
        Reset the MRO to contain only the class itself.
        
        This removes all inheritance relationships, leaving only the base class.
        """
        self.mro = [self.ns]