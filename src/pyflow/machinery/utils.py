"""
Utility functions and constants for PyFlow machinery.

This module provides utility functions for namespace manipulation, name generation
for anonymous constructs, and various constants used throughout the machinery
package.
"""

import os


def get_lambda_name(counter):
    """
    Generate a unique name for an anonymous lambda function.
    
    Args:
        counter (int): The counter value for uniqueness.
        
    Returns:
        str: A unique lambda name.
    """
    return "<lambda{}>".format(counter)


def get_dict_name(counter):
    """
    Generate a unique name for an anonymous dictionary literal.
    
    Args:
        counter (int): The counter value for uniqueness.
        
    Returns:
        str: A unique dictionary name.
    """
    return "<dict{}>".format(counter)


def get_list_name(counter):
    """
    Generate a unique name for an anonymous list literal.
    
    Args:
        counter (int): The counter value for uniqueness.
        
    Returns:
        str: A unique list name.
    """
    return "<list{}>".format(counter)


def get_int_name(counter):
    """
    Generate a unique name for an anonymous integer literal.
    
    Args:
        counter (int): The counter value for uniqueness.
        
    Returns:
        str: A unique integer name.
    """
    return "<int{}>".format(counter)


def join_ns(*args):
    """
    Join multiple namespace components into a dotted namespace.
    
    Args:
        *args: Variable number of namespace components.
        
    Returns:
        str: The joined namespace string.
    """
    return ".".join([arg for arg in args])


def to_mod_name(name, package=None):
    """
    Convert a file path to a module name.
    
    Args:
        name (str): The file path or name.
        package (str, optional): Package name (unused).
        
    Returns:
        str: The module name.
    """
    return os.path.splitext(name)[0].replace("/", ".")


# Special names for various constructs
RETURN_NAME = "<RETURN>"           # Name for function return values
LAMBDA_NAME = "<LAMBDA_{}>"        # Template for lambda function names (needs formatting)
BUILTIN_NAME = "<builtin>"         # Name for built-in functions and objects
EXT_NAME = "<external>"            # Name for external dependencies

# Definition type constants
FUN_DEF = "FUNCTIONDEF"            # Function definition type
NAME_DEF = "NAMEDEF"               # Variable/name definition type
MOD_DEF = "MODULEDEF"              # Module definition type
CLS_DEF = "CLASSDEF"               # Class definition type
EXT_DEF = "EXTERNALDEF"            # External definition type

# Base class names
OBJECT_BASE = "object"             # Python's base object class

# Special method names
CLS_INIT = "__init__"              # Class constructor method
ITER_METHOD = "__iter__"           # Iterator protocol method
NEXT_METHOD = "__next__"           # Iterator protocol method
STATIC_METHOD = "staticmethod"     # Static method decorator

# Error and invalid names
INVALID_NAME = "<**INVALID**>"     # Marker for invalid names

# Analysis operation types
CALL_GRAPH_OP = "call-graph"       # Call graph analysis operation
KEY_ERR_OP = "key-error"           # Key error analysis operation