"""Constant folding for Python AST.

This module provides constant folding functions that evaluate constant
expressions at compile time. It handles:
- Binary operations: Arithmetic, comparison, logical operations
- Unary operations: Negation, boolean conversion
- Function calls: Built-in functions with constant arguments
- Control flow: Dead branch elimination based on constant conditions

Constant folding enables optimizations like:
- Evaluating constant expressions at compile time
- Eliminating dead code branches
- Simplifying control flow structures
"""

from pyflow.language.python import ast
from pyflow.util.python import apply


def existingConstant(node):
    """Check if a node represents a constant value.
    
    Args:
        node: AST node to check
        
    Returns:
        bool: True if node is an Existing node with constant value
    """
    return isinstance(node, ast.Existing) and node.object.isConstant()


def foldSwitch(node):
    """Fold a Switch node if condition is constant.
    
    If the switch condition is constant, returns the taken branch.
    If both branches are empty, returns just the preamble.
    
    Args:
        node: Switch node to fold
        
    Returns:
        AST node: Folded node (Suite with taken branch, or original node)
    """
    # Note: condtion.conditional may be killed, as
    # it is assumed to be a reference.

    # Constant value
    cond = node.condition.conditional
    if existingConstant(cond):
        value = cond.object.pyobj
        taken = node.t if value else node.f
        return ast.Suite([node.condition.preamble, taken])

    # Switch does nothing.
    if not node.t.blocks and not node.f.blocks:
        return node.condition.preamble

    return node


def foldBinaryOpAST(extractor, bop):
    """Fold a binary operation if both operands are constant.
    
    Evaluates binary operations (+, -, *, /, ==, <, etc.) at compile time
    if both operands are constant.
    
    Args:
        extractor: Object extractor for creating new objects
        bop: BinaryOp node to fold
        
    Returns:
        AST node: Existing node with constant result, or original node
    """
    l = bop.left
    op = bop.op
    r = bop.right

    if existingConstant(l) and existingConstant(r):
        try:
            value = apply.applyBinaryOp(op, l.object.pyobj, r.object.pyobj)
            obj = extractor.getObject(value)
            return ast.Existing(obj)
        except apply.ApplyError:
            pass
    return bop


def foldUnaryPrefixOpAST(extractor, uop):
    """Fold a unary prefix operation if operand is constant.
    
    Evaluates unary operations (-, +, not, etc.) at compile time
    if the operand is constant.
    
    Args:
        extractor: Object extractor for creating new objects
        uop: UnaryPrefixOp node to fold
        
    Returns:
        AST node: Existing node with constant result, or original node
    """
    op = uop.op
    expr = uop.expr

    if existingConstant(expr):
        try:
            value = apply.applyUnaryPrefixOp(op, expr.object.pyobj)
            obj = extractor.getObject(value)
            return ast.Existing(obj)
        except apply.ApplyError:
            pass
    return uop


def foldBoolAST(extractor, op):
    """Fold a boolean conversion if operand is constant.
    
    Evaluates boolean conversion at compile time if operand is constant.
    
    Args:
        extractor: Object extractor for creating new objects
        op: ConvertToBool node to fold
        
    Returns:
        AST node: Existing node with constant result, or original node
    """
    expr = op.expr

    if existingConstant(expr):
        try:
            value = apply.applyBool(expr.object.pyobj)
            obj = extractor.getObject(value)
            return ast.Existing(obj)
        except apply.ApplyError:
            pass
    return op


def foldNotAST(extractor, op):
    """Fold a 'not' operation if operand is constant.
    
    Evaluates 'not' operation at compile time if operand is constant.
    
    Args:
        extractor: Object extractor for creating new objects
        op: Not operation node to fold
        
    Returns:
        AST node: Existing node with constant result, or original node
    """
    expr = op.expr

    if existingConstant(expr):
        try:
            value = apply.applyNot(expr.object.pyobj)
            obj = extractor.getObject(value)
            return ast.Existing(obj)
        except apply.ApplyError:
            pass
    return op


def foldCallAST(extractor, node, func, args=(), kargs={}):
    """Fold a function call if all arguments are constant.
    
    Evaluates function calls at compile time if all arguments are constant
    and the function can be evaluated (built-in functions).
    
    Args:
        extractor: Object extractor for creating new objects
        node: Call node to fold
        func: Function object to call
        args: Positional arguments
        kargs: Keyword arguments (not supported)
        
    Returns:
        AST node: Existing node with constant result, or original node
    """
    assert not kargs, kargs

    for arg in args:
        if not existingConstant(arg):
            return node
    try:
        args = [arg.object.pyobj for arg in args]
        value = apply.applyFunction(func, args)
        obj = extractor.getObject(value)
        return ast.Existing(obj)
    except apply.ApplyError:
        pass

    return node


def foldIsAST(extractor, node):
    """Fold an 'is' comparison if both operands are known.
    
    Evaluates 'is' comparisons at compile time if both operands are
    Existing nodes (known objects).
    
    Args:
        extractor: Object extractor for creating new objects
        node: Is comparison node to fold
        
    Returns:
        AST node: Existing node with constant result, or original node
    """
    left = node.left
    right = node.right
    if left is right:
        # Must alias
        obj = extractor.getObject(True)
        return ast.Existing(obj)
    elif isinstance(left, ast.Existing) and isinstance(node.right, ast.Existing):
        # Known objects
        obj = extractor.getObject(left.object is right.object)
        return ast.Existing(obj)

    return node
