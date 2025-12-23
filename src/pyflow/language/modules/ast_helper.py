"""AST helper functions for PyFlow.

This module provides utilities for generating and manipulating Python AST:
- AST generation: Parse Python files and generate normalized AST
- Python 2 to 3 conversion: Automatic conversion of Python 2 code
- Call name extraction: Extract function call names from AST nodes
- Argument handling: Utilities for working with function arguments

Key functions:
- generate_ast: Generate normalized AST from Python file
- get_call_names: Extract call names from AST nodes
- get_call_names_as_string: Get call names as dotted string
"""

import ast
import logging
import os
import subprocess
from functools import lru_cache

from .transformer import PytTransformer

log = logging.getLogger(__name__)
BLACK_LISTED_CALL_NAMES = ['self']
recursive = False


def _convert_to_3(path):  # pragma: no cover
    """Convert Python 2 file to Python 3 using 2to3.
    
    Attempts to convert a Python 2 file to Python 3 format using
    the 2to3 tool. This is used as a fallback when AST parsing fails.
    
    Args:
        path: Path to Python file to convert
        
    Raises:
        SystemExit: If 2to3 is not installed or conversion fails
    """
    try:
        log.warn('##### Trying to convert %s to Python 3. #####', path)
        subprocess.call(['2to3', '-w', path])
    except subprocess.SubprocessError:
        log.exception('Check if 2to3 is installed. https://docs.python.org/2/library/2to3.html')
        exit(1)


@lru_cache()
def generate_ast(path):
    """Generate normalized AST from a Python file.
    
    Parses a Python file and applies AST transformations (async removal,
    chained call expansion, etc.) to produce a normalized AST suitable
    for static analysis.
    
    Automatically attempts Python 2 to 3 conversion if parsing fails.
    Results are cached per file path.
    
    Args:
        path: Path to Python file (e.g., 'example/foo/bar.py')
        
    Returns:
        ast.Module: Normalized AST tree
        
    Raises:
        IOError: If path is not a file
        SyntaxError: If parsing and conversion both fail
    """
    if os.path.isfile(path):
        with open(path, 'r') as f:
            try:
                tree = ast.parse(f.read())
                return PytTransformer().visit(tree)
            except SyntaxError:  # pragma: no cover
                global recursive
                if not recursive:
                    _convert_to_3(path)
                    recursive = True
                    return generate_ast(path)
                else:
                    raise SyntaxError('The ast module can not parse the file'
                                      ' and the python 2 to 3 conversion'
                                      ' also failed.')
    raise IOError('Input needs to be a file. Path: ' + path)


def _get_call_names_helper(node):
    """Recursively extract function call names from AST node.
    
    Traverses AST nodes to extract function names from call expressions.
    Handles Name, Attribute, Subscript, and Str nodes.
    
    Args:
        node: AST node to extract names from
        
    Yields:
        str: Function names found in the node
    """
    if isinstance(node, ast.Name):
        if node.id not in BLACK_LISTED_CALL_NAMES:
            yield node.id
    elif isinstance(node, ast.Subscript):
        yield from _get_call_names_helper(node.value)
    elif isinstance(node, ast.Str):
        yield node.s
    elif isinstance(node, ast.Attribute):
        yield node.attr
        yield from _get_call_names_helper(node.value)


def get_call_names(node):
    """Get list of call names from an AST node.
    
    Extracts function call names from a call expression AST node,
    returning them in reverse order (outermost to innermost).
    
    Args:
        node: AST call node to extract names from
        
    Returns:
        list: List of call names (reversed order)
    """
    return reversed(list(_get_call_names_helper(node)))


def _list_to_dotted_string(list_of_components):
    """Convert a list to a dotted string.
    
    Args:
        list_of_components: List of string components
        
    Returns:
        str: Components joined with dots
    """
    return '.'.join(list_of_components)


def get_call_names_as_string(node):
    """Get call names as a dotted string.
    
    Extracts call names and formats them as a dotted string
    (e.g., "obj.method.submethod").
    
    Args:
        node: AST call node to extract names from
        
    Returns:
        str: Dotted string representation of call names
    """
    return _list_to_dotted_string(get_call_names(node))


class Arguments():
    """Represents function arguments from an AST function definition.
    
    Arguments extracts and organizes argument information from an
    ast.FunctionDef or ast.AsyncFunctionDef node's args attribute.
    It provides convenient access to all argument types.
    
    Attributes:
        args: List of positional arguments (ast.arg)
        varargs: Variable arguments (*args) or None
        kwarg: Keyword arguments (**kwargs) or None
        kwonlyargs: List of keyword-only arguments
        defaults: List of default values for positional args
        kw_defaults: List of default values for keyword-only args
        arguments: Flattened list of all argument names
    """

    def __init__(self, args):
        """Initialize argument container.
        
        Args:
            args: ast.arguments node from function definition
        """
        self.args = args.args
        self.varargs = args.vararg
        self.kwarg = args.kwarg
        self.kwonlyargs = args.kwonlyargs
        self.defaults = args.defaults
        self.kw_defaults = args.kw_defaults

        self.arguments = list()
        if self.args:
            self.arguments.extend([x.arg for x in self.args])
        if self.varargs:
            self.arguments.extend(self.varargs.arg)
        if self.kwarg:
            self.arguments.extend(self.kwarg.arg)
        if self.kwonlyargs:
            self.arguments.extend([x.arg for x in self.kwonlyargs])

    def __getitem__(self, key):
        """Get argument by index.
        
        Args:
            key: Index of argument
            
        Returns:
            str: Argument name at index
        """
        return self.arguments.__getitem__(key)

    def __len__(self):
        """Get number of positional arguments.
        
        Returns:
            int: Number of positional arguments
        """
        return self.args.__len__()