"""
AST Rewriting Utilities for PyFlow.

This module provides utilities for rewriting AST nodes, allowing optimizations
to replace nodes with optimized versions while preserving the tree structure.

The rewriter:
- Traverses the AST using type dispatch
- Replaces nodes according to a replacement map
- Prevents infinite recursion from circular replacements
- Supports both simple replacement and replacement with simplification
"""

from pyflow.optimization import simplify
from pyflow.util.typedispatch import *

# HACK necessary to get leaf types.  Sadly, it makes this optimization less than generic
from pyflow.language.python import ast


class Rewriter(TypeDispatcher):
    """Rewrites AST nodes according to a replacement map.
    
    Traverses the AST and replaces nodes that appear in the replacement map
    with their replacements, recursively processing replacement nodes.
    
    Args:
        replacements: Dictionary mapping original nodes to replacement nodes
    """
    def __init__(self, replacements):
        TypeDispatcher.__init__(self)
        self.replacements = replacements
        self.replaced = set()

    @dispatch(ast.leafTypes)
    def visitLeaf(self, node):
        if node in self.replaced:
            return node

        if node in self.replacements:
            oldnode = node
            self.replaced.add(oldnode)
            node = self(self.replacements[node])
            self.replaced.remove(oldnode)

        return node

    @dispatch(list, tuple)
    def visitContainer(self, node):
        # AST nodes may sometimes be replaced with containers,
        # so unlike most transformations, this will get called.
        return [self(child) for child in node]

    @defaultdispatch
    def visitNode(self, node):
        # Prevent stupid recursion, where the replacement
        # contains the original.
        if node in self.replaced:
            return node

        if node in self.replacements:
            oldnode = node
            self.replaced.add(oldnode)
            node = self(self.replacements[node])
            self.replaced.remove(oldnode)
        else:
            node = node.rewriteChildren(self)

        return node

    def processCode(self, code):
        code.replaceChildren(self)
        return code


def rewriteTerm(term, replace):
    """Rewrite a single term according to replacement map.
    
    Args:
        term: AST node to rewrite
        replace: Dictionary of node replacements
        
    Returns:
        Rewritten term, or original if no replacement applies
    """
    if replace:
        term = Rewriter(replace)(term)
    return term


def rewrite(compiler, code, replace):
    """Rewrite code according to replacement map.
    
    Args:
        compiler: Compiler context (unused, kept for API compatibility)
        code: Code node to rewrite
        replace: Dictionary of node replacements
        
    Returns:
        Rewritten code node
    """
    if replace:
        Rewriter(replace).processCode(code)
    return code


def rewriteAndSimplify(compiler, prgm, code, replace):
    """Rewrite code and then simplify it.
    
    Args:
        compiler: Compiler context
        prgm: Program being optimized
        code: Code node to rewrite and simplify
        replace: Dictionary of node replacements
        
    Returns:
        Rewritten and simplified code node
        
    This is a common pattern: rewrite nodes, then simplify the result
    to take advantage of new optimization opportunities.
    """
    if replace:
        Rewriter(replace).processCode(code)
        simplify.evaluateCode(compiler, prgm, code)
    return code
