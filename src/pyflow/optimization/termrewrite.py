"""
Term Rewriting Utilities for PyFlow.

This module provides utilities for term rewriting, allowing optimizations
to recognize and rewrite common patterns like arithmetic identities.

The utilities:
- Check for constant values (zero, one, negative one)
- Verify call argument counts and simplicity
- Provide a framework for registering rewrite rules
- Support pattern matching on AST nodes

This is used by other optimizations like constant folding and arithmetic
simplification.
"""

from pyflow.language.python import ast
from pyflow.language.python import program
from pyflow.language.python import annotations


def isZero(arg):
    """Check if an argument is the constant zero.
    
    Args:
        arg: AST expression to check
        
    Returns:
        True if arg is a constant zero, False otherwise
    """
    return (
        isinstance(arg, ast.Existing)
        and arg.object.isConstant()
        and arg.object.pyobj == 0
    )


def isOne(arg):
    """Check if an argument is the constant one.
    
    Args:
        arg: AST expression to check
        
    Returns:
        True if arg is a constant one, False otherwise
    """
    return (
        isinstance(arg, ast.Existing)
        and arg.object.isConstant()
        and arg.object.pyobj == 1
    )


def isNegativeOne(arg):
    """Check if an argument is the constant negative one.
    
    Args:
        arg: AST expression to check
        
    Returns:
        True if arg is a constant -1, False otherwise
    """
    return (
        isinstance(arg, ast.Existing)
        and arg.object.isConstant()
        and arg.object.pyobj == -1
    )


def hasNumArgs(node, count):
    """Check if a call node has exactly the specified number of arguments.
    
    Args:
        node: Call node to check
        count: Expected number of arguments
        
    Returns:
        True if node has exactly count arguments and is a simple call
    """
    return len(node.args) == count and isSimpleCall(node)


def isSimpleCall(node):
    """Check if a call node is simple (no keywords, *args, or **kwargs).
    
    Args:
        node: Call node to check
        
    Returns:
        True if call has no keywords, variable args, or keyword args
    """
    return not node.kwds and not node.vargs and not node.kargs


def isAnalysisInstance(node, type):
    """Check if a node represents an instance of a specific type.
    
    Args:
        node: AST node to check
        type: Python type to check against
        
    Returns:
        True if node is a constant of the given type, or a local variable
        that can only reference objects of the given type
    """
    if isinstance(node, ast.Existing) and node.object.isConstant():
        return isinstance(node.object.pyobj, type)
    elif isinstance(node, ast.Local):
        if not node.annotation.references[0]:
            return False

        for ref in node.annotation.references[0]:
            obj = ref.xtype.obj
            if not issubclass(obj.pythonType(), type):
                return False
        return True

    return False


def isAnalysis(arg, tests):
    """Check if an argument is a constant value in a test set.
    
    Args:
        arg: AST expression to check
        tests: Set of values to test against
        
    Returns:
        True if arg is a constant Existing node with value in tests
    """
    return (
        isinstance(arg, ast.Existing)
        and isinstance(arg.object, program.Object)
        and arg.object.pyobj in tests
    )


class DirectCallRewriter(object):
    """
    Rewrites direct calls based on function origin information.
    
    This class provides a framework for pattern-based code rewriting. It allows
    registering rewrite functions that are triggered when specific functions
    (identified by their origin) are called. This enables optimizations like:
    - Arithmetic identity simplifications (x * 1 -> x, x + 0 -> x)
    - Type-specific optimizations
    - Constant propagation through function calls
    
    The rewriter uses function origins (where the function came from, like
    "prim_float_mul" or "convertToBool") to match calls to rewrite rules.
    
    Attributes:
        extractor: Program extractor with stub information
        exports: Dictionary of exported stub functions
        rewrites: Dictionary mapping origins to lists of rewrite functions
    """
    def __init__(self, extractor):
        """
        Initialize a direct call rewriter.
        
        Args:
            extractor: Program extractor with stub information
        """
        self.extractor = extractor
        self.exports = extractor.stubs.exports if hasattr(extractor, "stubs") else {}
        self.rewrites = {}

    def _getOrigin(self, func):
        """
        Get the origin of a Python function.
        
        The origin identifies where a function came from (e.g., stub name,
        module path, etc.). Used to match calls to rewrite rules.
        
        Args:
            func: Python function object
            
        Returns:
            Origin tuple or None if function not found
        """
        if func in self.extractor:
            obj = self.extractor.getObject(func)
            origin = self.extractor.desc.origin.get(obj)
            # Convert list to tuple to make it hashable for use as dictionary key
            if isinstance(origin, list):
                return tuple(origin)
            return origin

    def addRewrite(self, name, func):
        """
        Register a rewrite rule for a stub function by name.
        
        Looks up the stub function by name and registers the rewrite function
        for calls to that function.
        
        Args:
            name: Name of the stub function (e.g., "prim_float_mul")
            func: Rewrite function that takes (strategy, node) and returns
                  optimized node or None
        """
        code = self.exports.get(name)
        self._bindCode(code, func)

    def attribute(self, type, name, func):
        """
        Register a rewrite rule for a type's attribute method.
        
        Registers a rewrite for calls to a specific attribute of a type
        (e.g., str.upper, list.append).
        
        Args:
            type: Type/class object
            name: Attribute name
            func: Rewrite function
        """
        attr = type.__dict__[name]
        origin = self._getOrigin(attr)
        self._bindOrigin(origin, func)

    def function(self, obj, func):
        """
        Register a rewrite rule for a specific function object.
        
        Args:
            obj: Function object
            func: Rewrite function
        """
        origin = self._getOrigin(obj)
        self._bindOrigin(origin, func)

    def _bindCode(self, code, func):
        """
        Bind a rewrite function to a code object's origin.
        
        Args:
            code: Code object (stub function)
            func: Rewrite function
        """
        if code:
            origin = code.annotation.origin
            self._bindOrigin(origin, func)

    def _bindOrigin(self, origin, func):
        """
        Bind a rewrite function to an origin.
        
        Multiple rewrite functions can be registered for the same origin.
        They are tried in order until one returns a non-None result.
        
        Args:
            origin: Origin tuple identifying the function
            func: Rewrite function to register
        """
        # Convert list to tuple to make it hashable for use as dictionary key
        if isinstance(origin, list):
            origin = tuple(origin)
        if origin not in self.rewrites:
            self.rewrites[origin] = [func]
        else:
            self.rewrites[origin].append(func)

    def __call__(self, strategy, node):
        """
        Apply rewrite rules to a direct call node.
        
        Looks up rewrite rules for the call's origin and applies them in
        order. Returns the first non-None result, or None if no rewrite applies.
        
        Args:
            strategy: Strategy object (typically self from FoldRewrite)
            node: DirectCall node to rewrite
            
        Returns:
            Rewritten node if a rule applies, None otherwise
        """
        origin = node.code.annotation.origin
        # Convert list to tuple to make it hashable for use as dictionary key
        if isinstance(origin, list):
            origin = tuple(origin)
        if origin in self.rewrites:
            # Try rewrite functions in order
            for rewrite in self.rewrites[origin]:
                result = rewrite(strategy, node)
                if result is not None:
                    return result
        return None
