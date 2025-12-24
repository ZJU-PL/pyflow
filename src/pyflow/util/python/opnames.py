"""
Python operator name mappings and utilities.

This module provides mappings between Python operator symbols and their corresponding
magic method names (e.g., "__add__", "__sub__", etc.). It is used throughout pyflow
for static analysis of Python code, particularly for:
- Constant folding (evaluating operations at compile time)
- Code generation (emitting correct operator method calls)
- Type inference (understanding operator semantics)

The module distinguishes between:
- Binary operators: +, -, *, /, etc.
- Comparison operators: >, <, ==, etc.
- Unary operators: +, -, ~
- In-place operators: +=, -=, etc.
"""

# Lookup table mapping binary operator symbols to their base method names
# (without the leading/trailing underscores)
opLUT = {
    "+": "add",
    "-": "sub",
    "*": "mul",
    "//": "floordiv",
    "/": "div",
    "%": "mod",
    "**": "pow",
    "<<": "lshift",
    ">>": "rshift",
    "&": "and",
    "|": "or",
    "^": "xor",
}

# Comparison operators: maps operator symbol to method name
# Example: ">" -> "__gt__"
compare = {">": "gt", "<": "lt", ">=": "ge", "<=": "le", "==": "eq", "!=": "ne"}

# Reverse comparison operators: when using reflected comparison (e.g., a < b calls b.__gt__(a))
# Maps operator to the method name that will be called on the right operand
compareRev = {">": "lt", "<": "gt", ">=": "le", "<=": "ge", "==": "eq", "!=": "ne"}

# Operator precedence for binary operators (higher number = lower precedence)
# Used for determining evaluation order in expressions
# Based on Python's operator precedence rules
binaryOpPrecedence = {
    "+": 12,      # Addition
    "-": 12,      # Subtraction
    "*": 11,      # Multiplication
    "/": 11,      # Division
    "//": 11,     # Floor division
    "%": 11,      # Modulo
    "**": 8,      # Exponentiation (right-associative)
    "<<": 13,     # Left shift
    ">>": 13,     # Right shift
    "&": 14,      # Bitwise AND
    "^": 15,      # Bitwise XOR
    "|": 16,      # Bitwise OR
    "in": 19,     # Membership test
    "not in": 19, # Negated membership test
    "is": 18,     # Identity test
    "is not": 18, # Negated identity test
}

# Operators that must have spaces around them when used in code
# (to distinguish from other operators, e.g., "not in" vs "notin")
mustHaveSpace = set(("in", "not in", "is", "is not"))

# Maps operator symbols to their full magic method names
# Populated below for both regular and in-place operators
binaryOpName = {}

# Maps binary operators to their forward magic method names (e.g., "+" -> "__add__")
forward = {}

# Maps binary operators to their reverse/reflected magic method names (e.g., "+" -> "__radd__")
# Used when the left operand doesn't support the operation
reverse = {}

# Maps binary operators to their in-place magic method names (e.g., "+" -> "__iadd__")
inplace = {}

# Set of all binary operator symbols
binaryOps = set()

# Set of all in-place operator symbols (e.g., "+=", "-=")
inplaceOps = set()

# Maps in-place operators to their fallback binary operator
# If __iadd__ is not available, Python falls back to __add__
inplaceFallback = {}

# Build mappings for arithmetic and bitwise operators
for op, name in opLUT.items():
    iop = op + "="  # Create in-place operator (e.g., "+" -> "+=")
    forward[op] = "__%s__" % name      # Forward method: a + b -> a.__add__(b)
    reverse[op] = "__r%s__" % name     # Reverse method: a + b -> b.__radd__(a) if a.__add__ fails
    inplace[op] = "__i%s__" % name     # In-place method: a += b -> a.__iadd__(b)
    binaryOps.add(op)
    inplaceOps.add(iop)
    inplaceFallback[iop] = op  # "+=" falls back to "+" if __iadd__ not available

    binaryOpName[op] = "__%s__" % name   # Regular binary operator method
    binaryOpName[iop] = "__i%s__" % name # In-place operator method

# Build mappings for comparison operators
for op, name in compare.items():
    forward[op] = "__%s__" % name
    # For comparisons, reverse uses the opposite comparison
    # e.g., a < b -> b.__gt__(a) if a.__lt__ fails
    reverse[op] = "__%s__" % compareRev[op]
    binaryOps.add(op)
    binaryOpPrecedence[op] = 17  # Comparison operators have precedence 17

    binaryOpName[op] = "__%s__" % name

# Unary prefix operators: maps operator symbol to magic method name
unaryPrefixLUT = {"+": "__pos__", "-": "__neg__", "~": "__invert__"}

# Precedence for unary prefix operators
unaryPrefixPrecedence = {"+": 10, "-": 10, "~": 9}

# Set of all unary operator symbols
unaryOps = set(unaryPrefixLUT.keys())

# Alias for convenience (unary operators use the same mapping as LUT)
unaryPrefixOpName = unaryPrefixLUT


def binaryOpMethodNames(op):
    """
    Get the forward and reverse magic method names for a binary operator.
    
    This function returns both the forward method (called on the left operand)
    and the reverse method (called on the right operand if forward fails).
    
    Args:
        op: Binary operator symbol (e.g., "+", "-", "*")
        
    Returns:
        tuple: (forward_method_name, reverse_method_name)
               e.g., ("__add__", "__radd__") for "+"
               
    Example:
        >>> forward, reverse = binaryOpMethodNames("+")
        >>> forward
        '__add__'
        >>> reverse
        '__radd__'
    """
    return forward[op], reverse[op]
