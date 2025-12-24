"""
Runtime operator application utilities.

This module provides functions to apply Python operators and functions at runtime,
primarily used for constant folding during static analysis. Constant folding evaluates
expressions with known constant values at compile time rather than runtime, which
improves analysis precision and performance.

The module uses Python's operator module to access the underlying functions that
implement each operator, allowing safe evaluation of operations on Python objects.
"""

import operator
from . import opnames


class ApplyError(Exception):
    """
    Exception raised when an operator or function application fails.
    
    This typically occurs during constant folding when:
    - An operator is not recognized
    - A runtime error occurs during evaluation (e.g., division by zero)
    - Type errors occur (e.g., unsupported operand types)
    """
    pass


def applyFunction(func, vargs=(), kargs={}):
    """
    Apply a function with given positional and keyword arguments.
    
    This is a wrapper around function calls that catches all exceptions and
    converts them to ApplyError for consistent error handling during constant folding.
    
    Args:
        func: The function to call
        vargs: Tuple of positional arguments (default: empty tuple)
        kargs: Dictionary of keyword arguments (default: empty dict)
        
    Returns:
        The result of calling func(*vargs, **kargs)
        
    Raises:
        ApplyError: If the function call raises any exception
        
    Example:
        >>> applyFunction(lambda x, y: x + y, (1, 2))
        3
        >>> applyFunction(pow, (2, 3), {"mod": 5})
        3
    """
    try:
        result = func(*vargs, **kargs)
    except:
        raise ApplyError("Error folding '%s'" % str(func))

    return result


def applyBinaryOp(op, l, r):
    """
    Apply a binary operator to two operands.
    
    This function evaluates binary operations (e.g., +, -, *, /) at runtime.
    It is used during constant folding to evaluate expressions with known constant
    values, such as "2 + 3" -> 5.
    
    Args:
        op: Binary operator symbol (e.g., "+", "-", "*", "/", "==")
        l: Left operand (any Python object)
        r: Right operand (any Python object)
        
    Returns:
        The result of applying the operator to the operands
        
    Raises:
        ApplyError: If the operator is not recognized or if evaluation fails
                   (e.g., division by zero, type mismatch)
                   
    Example:
        >>> applyBinaryOp("+", 2, 3)
        5
        >>> applyBinaryOp("*", "a", 3)
        'aaa'
        >>> applyBinaryOp("==", [1, 2], [1, 2])
        True
    """
    if not op in opnames.binaryOpName:
        raise ApplyError("Unreconsized binary operator: %r" % op)

    name = opnames.binaryOpName[op]
    func = getattr(operator, name)
    return applyFunction(func, (l, r))


def applyUnaryPrefixOp(op, expr):
    """
    Apply a unary prefix operator to an expression.
    
    This function evaluates unary operations (e.g., +, -, ~) at runtime.
    Used during constant folding for expressions like "-5" -> -5 or "~0" -> -1.
    
    Args:
        op: Unary prefix operator symbol (e.g., "+", "-", "~")
        expr: The operand expression (any Python object)
        
    Returns:
        The result of applying the unary operator to the expression
        
    Raises:
        ApplyError: If the operator is not recognized or if evaluation fails
        
    Example:
        >>> applyUnaryPrefixOp("-", 5)
        -5
        >>> applyUnaryPrefixOp("+", -3)
        -3
        >>> applyUnaryPrefixOp("~", 0)
        -1
    """
    if not op in opnames.unaryPrefixOpName:
        raise ApplyError("Unreconsized unary prefix operator: %r" % op)

    name = opnames.unaryPrefixOpName[op]
    func = getattr(operator, name)
    return applyFunction(func, (expr,))


def applyBool(expr):
    """
    Apply the bool() builtin to an expression.
    
    Converts any Python object to its boolean value. Used during constant folding
    for boolean contexts and conditional expressions.
    
    Args:
        expr: The expression to convert to boolean (any Python object)
        
    Returns:
        bool: The boolean value of the expression
        
    Example:
        >>> applyBool(0)
        False
        >>> applyBool([1, 2])
        True
        >>> applyBool("")
        False
    """
    return applyFunction(bool, (expr,))


def applyNot(expr):
    """
    Apply the logical NOT operator to an expression.
    
    Returns the logical negation of the expression's truth value. Used during
    constant folding for "not" expressions.
    
    Args:
        expr: The expression to negate (any Python object)
        
    Returns:
        bool: The logical negation of expr's truth value
        
    Example:
        >>> applyNot(True)
        False
        >>> applyNot(False)
        True
        >>> applyNot(0)
        True
        >>> applyNot([1, 2])
        False
    """
    return applyFunction(operator.not_, (expr,))
