"""
Pretty printing utilities for AST nodes.

This module provides utilities for formatting and displaying AST nodes
in a human-readable, indented format.
"""

import sys
import io
from .metaast import ASTNode


class ASTPrettyPrinter(object):
    """Pretty printer for AST nodes.

    Formats AST nodes with indentation and structure, handling containers,
    leaf nodes, and shared nodes appropriately.

    Attributes:
        out: Output stream for writing formatted output.
        eol: End-of-line string (default: "\\n").
    """

    def __init__(self, out=None, eol="\n"):
        """Initialize pretty printer.

        Args:
            out: Output stream (default: sys.stdout).
            eol: End-of-line string.
        """
        if out is None:
            out = sys.stdout
        self.out = out
        self.eol = eol

    def isLeaf(self, node):
        """Check if a node is a leaf node.

        Args:
            node: Node to check.

        Returns:
            True if node is a leaf (not a container or AST node).
        """
        if isinstance(node, ASTNode):
            return node.__leaf__
        else:
            return not isinstance(node, (list, tuple))

    def handleContainer(self, node, label, tabs):
        """Handle pretty printing of container nodes (lists/tuples).

        Args:
            node: Container node (list or tuple).
            label: Label prefix for output.
            tabs: Indentation string.
        """
        if isinstance(node, list):
            l, r = "[", "]"
        else:
            l, r = "(", ")"

        # Check if container can be printed on one line
        trivial = not node or all([self.isLeaf(child) for child in node])

        if trivial:
            # Print on one line
            contents = ", ".join([repr(child) for child in node])
            self.out.write("%s%s%s%s%s%s" % (tabs, label, l, contents, r, self.eol))
        else:
            # Print with each child on its own line
            self.out.write("%s%s%s%s" % (tabs, label, l, self.eol))
            for i, child in enumerate(node):
                self(child, "%d = " % i, tabs + "\t")
            self.out.write("%s%s%s" % (tabs, r, self.eol))

    def __call__(self, node, label, tabs, first=False):
        """Pretty print a node.

        Args:
            node: Node to print (AST node, container, or leaf).
            label: Label prefix for this node.
            tabs: Indentation string.
            first: True if this is the root node (affects shared node handling).
        """
        if isinstance(node, (list, tuple)):
            # Container node
            self.handleContainer(node, label, tabs)
        elif self.isLeaf(node) or (not first and getattr(node, "__shared__", False)):
            # Leaf node or shared node (print as reference)
            self.out.write("%s%s%r%s" % (tabs, label, node, self.eol))
        else:
            # Normal AST node - print type and fields
            self.out.write("%s%s%s%s" % (tabs, label, type(node).__name__, self.eol))
            for name, child in node.fields():
                self(child, "%s = " % name, tabs + "\t")

    def process(self, node):
        """Process and print the root node.

        Args:
            node: Root AST node to print.
        """
        self(node, "", "", first=True)


def pprint(node, out=None, eol="\n"):
    """Pretty print an AST node.

    Convenience function for pretty printing a single node.

    Args:
        node: AST node to print.
        out: Output stream (default: sys.stdout).
        eol: End-of-line string.
    """
    ASTPrettyPrinter(out=out, eol=eol).process(node)


def toString(node, eol="\n"):
    """Convert an AST node to a formatted string.

    Args:
        node: AST node to format.
        eol: End-of-line string.

    Returns:
        Formatted string representation of the node.
    """
    out = io.StringIO()
    pprint(node, out=out, eol=eol)
    return out.getvalue()
