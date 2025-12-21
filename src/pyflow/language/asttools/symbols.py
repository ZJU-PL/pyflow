"""
Symbolic matching and rewriting utilities for AST nodes.

This module provides support for pattern matching and template-based
rewriting of AST nodes using symbolic placeholders.
"""

from pyflow.util.typedispatch import *


class SymbolBase(object):
    """Base class for symbolic AST elements.

    Symbols are used in AST templates to represent placeholders that can
    be matched and replaced during rewriting operations.
    """

    __slots__ = ()


class Symbol(SymbolBase):
    """Symbol representing a named placeholder in an AST template.

    Symbols are used in templates to mark positions where values should
    be substituted during rewriting.

    Attributes:
        name: Symbol name identifier.
    """

    __slots__ = ("name",)

    def __init__(self, name):
        """Initialize a symbol.

        Args:
            name: Symbol name identifier.
        """
        self.name = name

    def __repr__(self):
        """Get string representation of symbol.

        Returns:
            String in format "{name}".
        """
        return "{%s}" % self.name


class Extract(SymbolBase):
    """Symbol representing extraction from a matched node.

    Used in templates to extract a child node from a matched AST node
    during rewriting.

    Attributes:
        child: Child symbol or index to extract.
    """

    __slots__ = ("child",)

    def __init__(self, child):
        """Initialize an extract symbol.

        Args:
            child: Child symbol or index to extract from matched node.
        """
        self.child = child


class SymbolRewriter(TypeDispatcher):
    """Rewriter for AST templates with symbolic placeholders.

    Performs pattern-based rewriting of AST nodes by substituting symbols
    in templates with values from a lookup table.

    Attributes:
        extractor: Object extractor for Extract symbols.
        template: AST template containing symbols.
        lut: Lookup table mapping symbol names to values.
    """

    def __init__(self, extractor, template):
        """Initialize symbol rewriter.

        Args:
            extractor: Object extractor for Extract symbols.
            template: AST template to rewrite.
        """
        self.extractor = extractor
        self.template = template
        self.lut = None

    def sharedTemplate(self):
        """Check if template is a shared AST node.

        Returns:
            True if template is a shared node (not a list).
        """
        return not isinstance(self.template, list) and self.template.__shared__

    @dispatch(Symbol)
    def visitSymbol(self, node):
        """Visit a Symbol node and replace it with value from lookup table.

        Args:
            node: Symbol node to replace.

        Returns:
            Replacement value from lookup table, or original symbol if not found.
        """
        return self.lut.get(node.name, node)

    @dispatch(Extract)
    def visitExtract(self, node):
        """Visit an Extract node and extract value from matched node.

        Args:
            node: Extract node to process.

        Returns:
            Extracted object from the matched node.
        """
        return self.extractor.getObject(self(node.child))

    @dispatch(str, int, float, type(None))
    def visitLeaf(self, node):
        """Visit a leaf node (primitive value).

        Args:
            node: Leaf node (string, int, float, or None).

        Returns:
            Node unchanged.
        """
        return node

    @defaultdispatch
    def default(self, node):
        """Default handler for AST nodes.

        Recursively rewrites children of the node.

        Args:
            node: AST node to process.

        Returns:
            Node with rewritten children.
        """
        return node.rewriteChildren(self)

    @dispatch(list)
    def visitList(self, node):
        """Visit a list node.

        Will not be invoked by traversal functions, but included so groups
        of nodes can be rewritten.

        Args:
            node: List of nodes.

        Returns:
            List with rewritten children.
        """
        return [self(child) for child in node]

    def rewrite(__self__, **lut):
        """Rewrite the template with symbol substitutions.

        The self parameter is intentionally mangled to avoid conflicts
        with keyword arguments.

        Args:
            **lut: Lookup table mapping symbol names to replacement values.

        Returns:
            Rewritten AST node with symbols replaced.
        """
        __self__.lut = lut
        if __self__.sharedTemplate():
            result = __self__.template.rewriteChildrenForced(__self__)
        else:
            result = __self__(__self__.template)
        __self__.lut = None
        return result


def rewrite(extractor, template, **kargs):
    """Rewrite an AST template with symbol substitutions.

    Convenience function for template-based AST rewriting.

    Args:
        extractor: Object extractor for Extract symbols.
        template: AST template containing symbols.
        **kargs: Lookup table mapping symbol names to replacement values.

    Returns:
        Rewritten AST node.

    TODO:
        Check that all arguments are used.
    """
    return SymbolRewriter(extractor, template).rewrite(**kargs)
