"""Base AST node classes for Python language support.

This module defines the base class hierarchy for Python AST nodes in PyFlow.
It provides abstract base classes and common functionality for all AST node types.

Key classes:
- PythonASTNode: Root base class for all Python AST nodes
- Expression: Base class for expression nodes (compute values)
- Statement: Base class for statement nodes (perform actions)
- Reference: Base class for reference nodes (reference values)
- ControlFlow: Base class for control flow statements
- BaseCode: Base class for function and method definitions
"""

from pyflow.language.asttools.metaast import *
from pyflow.language.python import annotations


def isPythonAST(ast):
    """Check if a node is a Python AST node.
    
    Args:
        ast: Node to check
        
    Returns:
        bool: True if node is a PythonASTNode
    """
    return isinstance(ast, PythonASTNode)


class PythonASTNode(ASTNode):
    """Root base class for all Python AST nodes.
    
    PythonASTNode provides common functionality and query methods for all
    AST nodes. Subclasses override methods to provide specific behavior.
    
    Query methods:
    - returnsValue(): Whether node computes a value
    - alwaysReturnsBoolean(): Whether node always returns boolean
    - isPure(): Whether node has no side effects
    - isControlFlow(): Whether node is a control flow statement
    - isReference(): Whether node is a reference (variable/constant)
    - isCode(): Whether node is a code definition (function/class)
    """
    def __init__(self):
        """Initialize AST node (abstract, must be overridden)."""
        raise NotImplementedError

    def returnsValue(self):
        """Check if node returns a value.
        
        Returns:
            bool: True if node computes a value (expressions)
        """
        return False

    def alwaysReturnsBoolean(self):
        """Check if node always returns a boolean value.
        
        Returns:
            bool: True if node always returns boolean
        """
        return False

    def isPure(self):
        """Check if node is pure (no side effects).
        
        Returns:
            bool: True if node has no side effects
        """
        return False

    def isControlFlow(self):
        """Check if node is a control flow statement.
        
        Returns:
            bool: True if node is control flow (if, while, for, etc.)
        """
        return False

    def isReference(self):
        """Check if node is a reference (variable or constant).
        
        Returns:
            bool: True if node is a reference (Local, Existing, etc.)
        """
        return False

    def isCode(self):
        """Check if node is a code definition (function or class).
        
        Returns:
            bool: True if node is a code definition
        """
        return False


class Expression(PythonASTNode):
    """Base class for expression nodes (compute values).
    
    Expressions are nodes that compute values and can be used in contexts
    where values are expected (e.g., right-hand side of assignments).
    
    Attributes:
        __emptyAnnotation__: Default annotation for expressions
    """
    __slots__ = ()

    __emptyAnnotation__ = annotations.emptyOpAnnotation

    def returnsValue(self):
        """Expressions always return values.
        
        Returns:
            bool: True (expressions compute values)
        """
        return True


class LLExpression(Expression):
    """Low-level expression node.
    
    LLExpression represents low-level expressions that may have special
    handling in code generation or analysis.
    """
    __slots__ = ()

    def returnsValue(self):
        """Low-level expressions return values.
        
        Returns:
            bool: True
        """
        return True


class Reference(Expression):
    """Base class for reference nodes (variables, constants).
    
    References are expressions that refer to values rather than compute them.
    Examples: Local (variables), Existing (constants), DoNotCare (wildcards).
    
    Attributes:
        __emptyAnnotation__: Default annotation for references (slot annotation)
    """
    __slots__ = ()

    __emptyAnnotation__ = annotations.emptySlotAnnotation

    def isReference(self):
        """References are reference nodes.
        
        Returns:
            bool: True
        """
        return True

    def isDoNotCare(self):
        """Check if this is a DoNotCare (wildcard) node.
        
        Returns:
            bool: True if DoNotCare, False otherwise
        """
        return False


class Statement(PythonASTNode):
    """Base class for statement nodes (perform actions).
    
    Statements are nodes that perform actions rather than compute values.
    Examples: Assign, Return, Discard, Delete.
    
    Attributes:
        __emptyAnnotation__: Default annotation for statements
    """
    __slots__ = ()

    __emptyAnnotation__ = annotations.emptyOpAnnotation


class SimpleStatement(Statement):
    """Base class for simple statements (single action).
    
    Simple statements represent single actions (e.g., assignment, return).
    """
    __slots__ = ()


class LLStatement(SimpleStatement):
    """Low-level statement node.
    
    LLStatement represents low-level statements that may have special
    handling in code generation or analysis.
    """
    __slots__ = ()


class ControlFlow(SimpleStatement):
    """Base class for control flow statements.
    
    ControlFlow represents statements that alter program control flow:
    if, while, for, break, continue, etc.
    """
    __slots__ = ()

    def significant(self):
        """Control flow statements are significant.
        
        Returns:
            bool: True (control flow affects program behavior)
        """
        return True

    def isControlFlow(self):
        """Control flow nodes are control flow.
        
        Returns:
            bool: True
        """
        return True


class CompoundStatement(Statement):
    """Base class for compound statements (multiple actions).
    
    CompoundStatement represents statements that contain multiple actions
    or nested structures (e.g., Suite, TryExceptFinally).
    """
    __slots__ = ()

    def significant(self):
        """Compound statements are significant.
        
        Returns:
            bool: True (compound statements affect program behavior)
        """
        return True


class BaseCode(PythonASTNode):
    """Base class for code definitions (functions, classes).
    
    BaseCode represents code definitions like functions and classes.
    These nodes are shared (same object = same definition) and provide
    methods for querying abstract read/modify/allocate information.
    
    Attributes:
        __shared__: True (code nodes are shared)
    """
    __slots__ = ()
    __shared__ = True

    def isCode(self):
        """Code nodes are code definitions.
        
        Returns:
            bool: True
        """
        return True

    def isAbstractCode(self):
        """Check if this is abstract code (not implemented).
        
        Returns:
            bool: True if abstract code
        """
        return False

    def isStandardCode(self):
        """Check if this is standard code (implemented).
        
        Returns:
            bool: True if standard code
        """
        return False

    def codeName(self):
        """Get the name of this code definition.
        
        Returns:
            str: Code name
            
        Raises:
            NotImplementedError: Must be overridden
        """
        raise NotImplementedError

    def setCodeName(self, name):
        """Set the name of this code definition.
        
        Args:
            name: New code name
            
        Raises:
            NotImplementedError: Must be overridden
        """
        raise NotImplementedError

    def abstractReads(self):
        """Get abstract read information (if available).
        
        Returns:
            object: Abstract read information or None
        """
        return None

    def abstractModifies(self):
        """Get abstract modify information (if available).
        
        Returns:
            object: Abstract modify information or None
        """
        return None

    def abstractAllocates(self):
        """Get abstract allocate information (if available).
        
        Returns:
            object: Abstract allocate information or None
        """
        return None


class AbstractCode(BaseCode):
    """Abstract code definition (not implemented).
    
    AbstractCode represents code definitions that are not fully implemented
    or are placeholders for analysis purposes.
    
    Attributes:
        __shared__: True (code nodes are shared)
    """
    __slots__ = ()
    __shared__ = True

    def isAbstractCode(self):
        """Abstract code is abstract.
        
        Returns:
            bool: True
        """
        return True
