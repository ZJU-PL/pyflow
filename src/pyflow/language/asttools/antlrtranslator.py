"""
ANTLR AST translator utilities.

This module provides utilities for translating ANTLR parse trees into
PyFlow's internal AST representation, including name handling and origin
tracking.
"""

import pyflow.util.antlr3 as antlr3
from .origin import Origin


def childText(node, index):
    """Extract text from a child node.

    Args:
        node: ANTLR tree node.
        index: Index of child node.

    Returns:
        Text content of the child node as a string.
    """
    return str(node.getChild(index).getText())


def name(index):
    """Decorator for visitor methods that extract names from AST nodes.

    Extracts a name from a child node at the given index, or generates
    a positional name if the child is None. Automatically manages the
    name stack and attaches origin information.

    Args:
        index: Index of child node containing the name.

    Returns:
        Decorator function for visitor methods.

    Example:
        @name(0)
        def visitFunctionDef(self, node, name):
            # name is extracted from node.getChild(0)
            return FunctionDef(name, ...)
    """
    def name_func(func):
        def name_wrapper(self, node):
            if self.isNone(node.getChild(index)):
                name = self.positionName()
            else:
                name = self.getName(node.getChild(index))

            result = func(self, node, name)
            self.attachOrigin(node, result)  # Attach the origin before popping.
            self.pop()
            return result

        return name_wrapper

    return name_func


def fixedname(name):
    """Decorator for visitor methods that use a fixed name.

    Pushes a fixed name onto the name stack for visitor methods that
    don't extract names from the AST. Automatically manages the name
    stack and attaches origin information.

    Args:
        name: Fixed name string to use.

    Returns:
        Decorator function for visitor methods.

    Example:
        @fixedname("module")
        def visitModule(self, node):
            return Module(...)
    """
    def name_func(func):
        def name_wrapper(self, node):
            self.push(name)
            result = func(self, node)
            self.attachOrigin(node, result)  # Attach the origin before popping.
            self.pop()
            return result

        return name_wrapper

    return name_func


class ASTTranslator(object):
    """Translates ANTLR parse trees to PyFlow AST nodes.

    Provides visitor pattern-based translation with automatic name stack
    management, origin tracking, and method dispatch caching.

    Attributes:
        compiler: Compiler instance.
        parser: ANTLR parser instance.
        filename: Source filename being translated.
        namestack: Stack for managing nested name scopes.
        name: Current fully qualified name.
        indexstack: Stack for managing positional indices.
        index: Current positional index.
        origincache: Cache for origin objects to avoid duplicates.
        generateOutput: If False, suppress AST generation (for error nodes).
        dispatch: Cache for visitor method dispatch.
    """

    def __init__(self, compiler, parser, filename):
        """Initialize AST translator.

        Args:
            compiler: Compiler instance.
            parser: ANTLR parser instance.
            filename: Source filename being translated.
        """
        self.compiler = compiler
        self.parser = parser
        self.filename = filename

        self.namestack = []
        self.name = None

        self.indexstack = []
        self.index = 0

        self.origincache = {}

        self.generateOutput = True

        self.dispatch = {}

    def generate(self, nodeType, *args):
        """Generate an AST node if output generation is enabled.

        Args:
            nodeType: AST node class to instantiate.
            *args: Arguments for node constructor.

        Returns:
            New AST node instance, or None if generation is disabled.
        """
        if self.generateOutput:
            return nodeType(*args)
        else:
            return None

    def default(self, node):
        """Default handler for unsupported node types.

        Args:
            node: ANTLR tree node.

        Raises:
            AssertionError: Always raises, indicating unsupported node type.
        """
        assert False, "Unsupported AST node: %s" % self.nodeName(node)

    def originAnnotation(self, origin):
        """Wrap origin in annotation format.

        Override this method to change how origin is wrapped in the annotation.
        Default implementation returns the origin unchanged.

        Args:
            origin: Origin object to wrap.

        Returns:
            Wrapped origin (default: origin unchanged).
        """
        return origin

    def makeOrigin(self, node):
        """Create an Origin object from an ANTLR node.

        Creates and caches an Origin object representing the source location
        of the given node.

        Args:
            node: ANTLR tree node.

        Returns:
            Origin object (possibly cached).
        """
        origin = Origin(
            self.fullName(), self.filename, node.getLine(), node.getCharPositionInLine()
        )
        origin = self.origincache.setdefault(origin, origin)
        return self.originAnnotation(origin)

    def exceptionOrigin(self, e):
        """Create an Origin object from an exception.

        Args:
            e: Exception with 'line' and 'charPositionInLine' attributes.

        Returns:
            Origin object (possibly cached).
        """
        origin = Origin(self.fullName(), self.filename, e.line, e.charPositionInLine)
        origin = self.origincache.setdefault(origin, origin)
        return origin

    def attachOrigin(self, node, result):
        """Attach origin information to an AST node.

        If the result has an annotation with an origin field, and the origin
        is still the default empty annotation, attach the origin from the
        ANTLR node.

        Args:
            node: ANTLR tree node (source of origin).
            result: PyFlow AST node (target for origin).
        """
        if hasattr(result, "annotation") and hasattr(result.annotation, "origin"):
            if result.annotation.origin is result.__emptyAnnotation__.origin:
                result.rewriteAnnotation(origin=self.makeOrigin(node))

    def nodeName(self, node):
        """Get the type name of an ANTLR node.

        Args:
            node: ANTLR tree node.

        Returns:
            String type name of the node.
        """
        return self.parser.typeName(node.getType())

    def getMethod(self, typeID):
        """Get visitor method for a node type.

        Args:
            typeID: ANTLR node type ID.

        Returns:
            Visitor method, or default() if not found.
        """
        return getattr(self, "visit_" + self.parser.typeName(typeID), self.default)

    def __call__(self, node):
        """Visit an ANTLR node and translate it to PyFlow AST.

        Dispatches to the appropriate visitor method based on node type,
        with caching for performance.

        Args:
            node: ANTLR tree node to translate.

        Returns:
            PyFlow AST node, or None if node is an error node.
        """
        if isinstance(node, antlr3.tree.CommonErrorNode):
            self.generateOutput = False
            return None

        typeID = node.getType()
        m = self.dispatch.get(typeID)
        if m is None:
            m = getattr(self, "visit_" + self.parser.typeName(typeID), self.default)
            self.dispatch[typeID] = m

        result = m(node)
        self.attachOrigin(node, result)
        return result

    def visitChildren(self, node, *indices):
        """Visit specific children of a node.

        Args:
            node: ANTLR tree node.
            *indices: Child indices to visit.

        Returns:
            Single AST node if one index, list of AST nodes if multiple.
        """
        if len(indices) == 1:
            return self(node.getChild(indices[0]))
        else:
            return [self(node.getChild(index)) for index in indices]

    def fullName(self):
        """Get the current fully qualified name.

        Returns:
            Current name string (e.g., "module.function.local").
        """
        return self.name

    def getName(self, node):
        """Extract name from a node and push it onto the name stack.

        Args:
            node: ANTLR node containing name text.

        Returns:
            Extracted name string.
        """
        name = str(node.getText())
        self.push(name)
        return name

    def positionName(self):
        """Generate a positional name and push it onto the name stack.

        Returns:
            Current index value (before increment).
        """
        name = self.index
        self.index += 1
        self.push(str(name))
        return name

    def push(self, name):
        """Push a name onto the name stack.

        Updates the current name to be the concatenation of the previous
        name and the new name, separated by dots. Also saves and resets
        the current index.

        Args:
            name: Name string to push.
        """
        self.namestack.append(self.name)
        if self.name is None:
            self.name = name
        else:
            self.name = ".".join([self.name, name])

        self.indexstack.append(self.index)
        self.index = 0

    def pop(self):
        """Pop a name from the name stack.

        Restores the previous name and index from the stacks.
        """
        self.name = self.namestack.pop()
        self.index = self.indexstack.pop()
