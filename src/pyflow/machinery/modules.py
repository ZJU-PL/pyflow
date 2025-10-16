"""
Module management for PyFlow static analysis.

This module provides functionality for managing internal and external modules,
tracking their methods and metadata during analysis.
"""


class ModuleManager:
    """
    Manages internal and external modules during analysis.
    
    This class maintains separate registries for internal modules (part of the
    analyzed codebase) and external modules (dependencies, builtins, etc.).
    """
    
    def __init__(self):
        """Initialize the module manager with empty registries."""
        self.internal = {}  # Maps module names to internal Module objects
        self.external = {}  # Maps module names to external Module objects

    def create(self, name, fname, external=False):
        """
        Create a new module and add it to the appropriate registry.
        
        Args:
            name (str): The module name.
            fname (str): The filename of the module.
            external (bool): Whether this is an external module.
            
        Returns:
            Module: The created module object.
        """
        mod = Module(name, fname)
        if external:
            self.external[name] = mod
        else:
            self.internal[name] = mod
        return mod

    def get(self, name):
        """
        Retrieve a module by name, checking both internal and external registries.
        
        Args:
            name (str): The module name to look up.
            
        Returns:
            Module or None: The module if found, None otherwise.
        """
        if name in self.internal:
            return self.internal[name]
        if name in self.external:
            return self.external[name]

    def get_internal_modules(self):
        """
        Get all internal modules.
        
        Returns:
            dict: Dictionary mapping module names to Module objects.
        """
        return self.internal

    def get_external_modules(self):
        """
        Get all external modules.
        
        Returns:
            dict: Dictionary mapping module names to Module objects.
        """
        return self.external


class Module:
    """
    Represents a single module with its metadata and methods.
    
    This class tracks information about a module including its name, filename,
    and the methods it contains.
    """
    
    def __init__(self, name, filename):
        """
        Initialize a module.
        
        Args:
            name (str): The module name.
            filename (str): The filename of the module.
        """
        self.name = name
        self.filename = filename
        self.methods = dict()  # Maps method names to method metadata

    def get_name(self):
        """
        Get the module name.
        
        Returns:
            str: The module name.
        """
        return self.name

    def get_filename(self):
        """
        Get the module filename.
        
        Returns:
            str: The module filename.
        """
        return self.filename

    def get_methods(self):
        """
        Get all methods in this module.
        
        Returns:
            dict: Dictionary mapping method names to method metadata.
        """
        return self.methods

    def add_method(self, method, first=None, last=None):
        """
        Add a method to this module.
        
        Args:
            method (str): The method name.
            first (int, optional): First line number of the method.
            last (int, optional): Last line number of the method.
        """
        if not self.methods.get(method, None):
            self.methods[method] = dict(name=method, first=first, last=last)