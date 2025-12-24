"""
Security Checker Context.

This module provides a Context class that wraps the raw context dictionary
and provides convenient property accessors for security tests. The context
contains information about the current AST node being analyzed, including
call information, imports, file information, and more.

**Context Contents:**
- Node information: Current AST node, location (lineno, col_offset)
- Call information: Function name, arguments, keywords
- Import information: Imported modules, aliases
- File information: Filename, file data
- String/bytes values: Literal string and bytes values

**Usage:**
Security tests receive a Context object that provides easy access to
relevant information without needing to know the internal dictionary
structure.
"""

import ast
from . import utils


class Context:
    """
    Context wrapper for security tests.
    
    Provides convenient property accessors for accessing context information
    in security tests. The context is built by the SecurityNodeVisitor and
    contains all relevant information about the current AST node being analyzed.
    
    **Property Accessors:**
    - call_args: List of function call arguments
    - call_function_name: Function name (not fully qualified)
    - call_function_name_qual: Fully qualified function name
    - call_keywords: Dictionary of keyword arguments
    - node: Raw AST node
    - string_val: String literal value (if current node is a string)
    - bytes_val: Bytes literal value (if current node is bytes)
    - filename: Current filename
    - import_aliases: Dictionary of import aliases
    
    Attributes:
        _context: Internal context dictionary
    """
    def __init__(self, context_object=None):
        """
        Initialize a context wrapper.
        
        Args:
            context_object: Dictionary containing context information,
                          or None for empty context
        """
        self._context = context_object or {}

    def __repr__(self):
        return f"<Context {self._context}>"

    @property
    def call_args(self):
        """
        Get a list of function call arguments.
        
        Extracts argument values from the call node, converting AST literals
        to Python values where possible.
        
        Returns:
            List of argument values (or attribute names if not literal)
        """
        if "call" not in self._context or not hasattr(self._context["call"], "args"):
            return []
        return [arg.attr if hasattr(arg, "attr") else self._get_literal_value(arg) 
                for arg in self._context["call"].args]

    @property
    def call_args_count(self):
        """
        Get the number of arguments in a function call.
        
        Returns:
            Number of arguments, or None if not a call node
        """
        return len(self._context["call"].args) if "call" in self._context and hasattr(self._context["call"], "args") else None

    @property
    def call_function_name(self):
        """
        Get the function name (not fully qualified).
        
        Returns:
            Function name (e.g., "loads") or None
        """
        return self._context.get("name")

    @property
    def call_function_name_qual(self):
        """
        Get the fully qualified function name.
        
        Returns:
            Fully qualified name (e.g., "pickle.loads") or None
        """
        return self._context.get("qualname")

    @property
    def call_keywords(self):
        """
        Get a dictionary of keyword arguments.
        
        Extracts keyword argument names and values from the call node.
        
        Returns:
            Dictionary mapping argument names to values, or None if not a call
        """
        if "call" not in self._context or not hasattr(self._context["call"], "keywords"):
            return None
        return {li.arg: (li.value.attr if hasattr(li.value, "attr") else self._get_literal_value(li.value))
                for li in self._context["call"].keywords}

    @property
    def node(self):
        """Get the raw AST node associated with the context"""
        return self._context.get("node")

    @property
    def string_val(self):
        """Get the value of a standalone string object"""
        return self._context.get("str")

    @property
    def bytes_val(self):
        """Get the value of a standalone bytes object"""
        return self._context.get("bytes")

    @property
    def filename(self):
        return self._context.get("filename")

    @property
    def file_data(self):
        return self._context.get("file_data")

    @property
    def import_aliases(self):
        return self._context.get("import_aliases")

    def _get_literal_value(self, literal):
        """
        Convert AST literal nodes to native Python types.
        
        Handles various AST literal node types, including compatibility
        with both Python < 3.8 (separate Num, Str, Bytes nodes) and
        Python 3.8+ (unified Constant node).
        
        Args:
            literal: AST literal node
            
        Returns:
            Python value, or None if not a recognized literal type
        """
        literal_map = {
            ast.Num: lambda x: x.n,
            ast.Str: lambda x: x.s,
            # Python 3.8+ folds several literal nodes into `ast.Constant`.
            # This keeps keyword/arg extraction working across versions.
            ast.Constant: lambda x: x.value,
            ast.List: lambda x: [self._get_literal_value(li) for li in x.elts],
            ast.Tuple: lambda x: tuple(self._get_literal_value(ti) for ti in x.elts),
            ast.Set: lambda x: {self._get_literal_value(si) for si in x.elts},
            ast.Dict: lambda x: dict(zip(x.keys, x.values)),
            ast.Ellipsis: lambda x: None,
            ast.Name: lambda x: x.id,
            ast.NameConstant: lambda x: str(x.value),
            ast.Bytes: lambda x: x.s,
        }
        return literal_map.get(type(literal), lambda x: None)(literal)

    def get_call_arg_value(self, argument_name):
        """
        Get the value of a named keyword argument in a function call.
        
        Args:
            argument_name: Name of the keyword argument
            
        Returns:
            Argument value, or None if not found or not a call
        """
        kwd_values = self.call_keywords
        return kwd_values.get(argument_name) if kwd_values else None

    def check_call_arg_value(self, argument_name, argument_values=None):
        """
        Check if a named argument has a specific value.
        
        Useful for checking if dangerous parameters are set (e.g.,
        shell=True in subprocess calls).
        
        Args:
            argument_name: Name of the keyword argument
            argument_values: Single value or list of values to check against
            
        Returns:
            True if argument exists and value matches, False if doesn't match,
            None if argument doesn't exist
        """
        arg_value = self.get_call_arg_value(argument_name)
        if arg_value is None:
            return None
        values = argument_values if isinstance(argument_values, list) else [argument_values]
        return arg_value in values

    def is_module_being_imported(self, module):
        """
        Check if the specified module is currently being imported.
        
        Checks the "module" field in context, which is set during
        Import/ImportFrom node visits.
        
        Args:
            module: Module name to check
            
        Returns:
            True if this module is being imported in the current node
        """
        return self._context.get("module") == module

    def is_module_imported_exact(self, module):
        """
        Check if a specified module has been imported (exact match).
        
        Checks against the accumulated imports set, which contains
        all modules imported so far in the file.
        
        Args:
            module: Module name to check (exact match)
            
        Returns:
            True if module has been imported
        """
        return module in self._context.get("imports", [])

    def is_module_imported_like(self, module):
        """
        Check if a specified module has been imported (partial match).
        
        Checks if the module name appears as a substring in any imported
        module name. Useful for checking if any module from a package
        has been imported.
        
        Args:
            module: Module name to check (partial match)
            
        Returns:
            True if any imported module contains this name
        """
        imports = self._context.get("imports", [])
        return any(module in imp for imp in imports)
