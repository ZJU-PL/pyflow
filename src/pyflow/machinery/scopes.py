"""
Scope management for PyFlow static analysis.

This module provides functionality for managing lexical scopes during analysis,
tracking variable definitions and their scope hierarchy. It uses Python's
symtable module to build accurate scope information from source code.
"""

import symtable

from pyflow.machinery.utils import join_ns


class ScopeManager(object):
    """
    Manages lexical scopes and their hierarchy.
    
    This class processes Python source code using the symtable module to build
    accurate scope information, tracking function and class definitions along
    with their hierarchical relationships.
    """

    def __init__(self):
        """Initialize the scope manager with an empty scope registry."""
        self.scopes = {}  # Maps namespace to ScopeItem objects

    def handle_module(self, modulename, filename, contents):
        """
        Process a module and build its scope hierarchy.
        
        This method uses Python's symtable module to analyze the source code
        and build a complete scope hierarchy including functions and classes.
        
        Args:
            modulename (str): The name of the module.
            filename (str): The filename of the module.
            contents (str): The source code contents.
            
        Returns:
            dict: Dictionary containing lists of functions and classes found.
        """
        functions = []
        classes = []

        def process(namespace, parent, table):
            """
            Recursively process a symbol table and its children.
            
            Args:
                namespace (str): The current namespace.
                parent (ScopeItem): The parent scope item.
                table (symtable.SymbolTable): The symbol table to process.
            """
            if table.get_name() == "top" and table.get_lineno() == 0:
                name = ""
            else:
                name = table.get_name()

            if name:
                fullns = join_ns(namespace, name)
            else:
                fullns = namespace

            # Track function and class definitions
            if table.get_type() == "function":
                functions.append(fullns)

            if table.get_type() == "class":
                classes.append(fullns)

            # Create scope item and process children
            sc = self.create_scope(fullns, parent)

            for t in table.get_children():
                process(fullns, sc, t)

        # Start processing from the top-level symbol table
        process(
            modulename, None, symtable.symtable(contents, filename, compile_type="exec")
        )
        return {"functions": functions, "classes": classes}

    def handle_assign(self, ns, target, defi):
        """
        Handle a variable assignment in the given namespace.
        
        Args:
            ns (str): The namespace where the assignment occurs.
            target (str): The target variable name.
            defi: The definition being assigned.
        """
        scope = self.get_scope(ns)
        if scope:
            scope.add_def(target, defi)

    def get_def(self, current_ns, var_name):
        """
        Get a variable definition by walking up the scope hierarchy.
        
        This method searches for a variable definition starting from the given
        namespace and walking up the scope hierarchy until found.
        
        Args:
            current_ns (str): The current namespace to start searching from.
            var_name (str): The variable name to look up.
            
        Returns:
            The variable definition if found, None otherwise.
        """
        current_scope = self.get_scope(current_ns)
        while current_scope:
            defi = current_scope.get_def(var_name)
            if defi:
                return defi
            current_scope = current_scope.parent

    def get_scope(self, namespace):
        """
        Get a scope by namespace.
        
        Args:
            namespace (str): The namespace to look up.
            
        Returns:
            ScopeItem or None: The scope if found, None otherwise.
        """
        if namespace in self.get_scopes():
            return self.get_scopes()[namespace]

    def create_scope(self, namespace, parent):
        """
        Create a new scope or return existing one.
        
        Args:
            namespace (str): The namespace for the scope.
            parent (ScopeItem): The parent scope item.
            
        Returns:
            ScopeItem: The created or existing scope item.
        """
        if namespace not in self.scopes:
            sc = ScopeItem(namespace, parent)
            self.scopes[namespace] = sc
        return self.scopes[namespace]

    def get_scopes(self):
        """
        Get all scopes in the manager.
        
        Returns:
            dict: Dictionary mapping namespaces to ScopeItem objects.
        """
        return self.scopes


class ScopeItem(object):
    """
    Represents a single lexical scope in the program.
    
    A scope item tracks variable definitions within a specific namespace,
    maintains counters for anonymous constructs (lambdas, dicts, lists),
    and maintains a reference to its parent scope for hierarchical lookup.
    """
    
    def __init__(self, fullns, parent):
        """
        Initialize a scope item.
        
        Args:
            fullns (str): The full namespace of this scope.
            parent (ScopeItem): The parent scope item.
            
        Raises:
            ScopeError: If parent is not a ScopeItem or fullns is not a string.
        """
        if parent and not isinstance(parent, ScopeItem):
            raise ScopeError("Parent must be a ScopeItem instance")

        if not isinstance(fullns, str):
            raise ScopeError("Namespace should be a string")

        self.parent = parent          # Parent scope for hierarchical lookup
        self.defs = {}               # Maps variable names to definitions
        self.lambda_counter = 0      # Counter for anonymous lambda functions
        self.dict_counter = 0        # Counter for anonymous dictionary literals
        self.list_counter = 0        # Counter for anonymous list literals
        self.fullns = fullns         # Full namespace of this scope

    def get_ns(self):
        """
        Get the namespace of this scope.
        
        Returns:
            str: The full namespace.
        """
        return self.fullns

    def get_defs(self):
        """
        Get all variable definitions in this scope.
        
        Returns:
            dict: Dictionary mapping variable names to definitions.
        """
        return self.defs

    def get_def(self, name):
        """
        Get a variable definition by name.
        
        Args:
            name (str): The variable name to look up.
            
        Returns:
            The definition if found, None otherwise.
        """
        defs = self.get_defs()
        if name in defs:
            return defs[name]

    def get_lambda_counter(self):
        """
        Get the current lambda counter value.
        
        Returns:
            int: The lambda counter value.
        """
        return self.lambda_counter

    def get_dict_counter(self):
        """
        Get the current dictionary counter value.
        
        Returns:
            int: The dictionary counter value.
        """
        return self.dict_counter

    def get_list_counter(self):
        """
        Get the current list counter value.
        
        Returns:
            int: The list counter value.
        """
        return self.list_counter

    def inc_lambda_counter(self, val=1):
        """
        Increment the lambda counter.
        
        Args:
            val (int): The amount to increment by.
            
        Returns:
            int: The new counter value.
        """
        self.lambda_counter += val
        return self.lambda_counter

    def inc_dict_counter(self, val=1):
        """
        Increment the dictionary counter.
        
        Args:
            val (int): The amount to increment by.
            
        Returns:
            int: The new counter value.
        """
        self.dict_counter += val
        return self.dict_counter

    def inc_list_counter(self, val=1):
        """
        Increment the list counter.
        
        Args:
            val (int): The amount to increment by.
            
        Returns:
            int: The new counter value.
        """
        self.list_counter += val
        return self.list_counter

    def reset_counters(self):
        """
        Reset all counters to zero.
        
        This is useful when reusing scope items or clearing state.
        """
        self.lambda_counter = 0
        self.dict_counter = 0
        self.list_counter = 0

    def add_def(self, name, defi):
        """
        Add a variable definition to this scope.
        
        Args:
            name (str): The variable name.
            defi: The definition to add.
        """
        self.defs[name] = defi

    def merge_def(self, name, to_merge):
        """
        Merge a definition into this scope.
        
        If the variable already exists, merge the points-to information.
        Otherwise, add it as a new definition.
        
        Args:
            name (str): The variable name.
            to_merge: The definition to merge.
        """
        if name not in self.defs:
            self.defs[name] = to_merge
            return

        self.defs[name].merge_points_to(to_merge.get_points_to())


class ScopeError(Exception):
    """Exception raised for scope-related errors."""
    pass