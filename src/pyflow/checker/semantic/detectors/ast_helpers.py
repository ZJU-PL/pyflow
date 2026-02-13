"""Shared AST helper utilities for detectors.

This module provides reusable AST traversal utilities to avoid ad-hoc patterns
across different detectors.
"""

from __future__ import annotations

import ast
from typing import Optional


class ASTParentTracker:
    """Mixin class that adds parent tracking to AST NodeVisitor.

    This provides a cleaner way to track parent nodes during AST traversal
    without manually adding parent attributes to AST nodes.

    Usage:
        class MyVisitor(ASTParentTracker, ast.NodeVisitor):
            def visit_Call(self, node):
                if self.find_ancestor(node, lambda n: isinstance(n, ast.With)):
                    # Inside a 'with' statement
                    pass
                super().visit(node)  # Continue traversal
    """

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._parent_stack: list[ast.AST] = []

    def visit(self, node: ast.AST) -> None:
        """Visit a node, tracking parent context.

        This overrides ast.NodeVisitor.visit() to track the parent stack
        before delegating to the base visitor's dispatch mechanism.
        """
        self._parent_stack.append(node)
        try:
            # Call ast.NodeVisitor.visit() which does method dispatch
            super().visit(node)
        finally:
            self._parent_stack.pop()

    def get_parent(self, node: ast.AST) -> Optional[ast.AST]:
        """Get the parent of the current node.

        Args:
            node: The AST node (must be currently being visited)

        Returns:
            The parent node, or None if at the root
        """
        if not self._parent_stack or self._parent_stack[-1] is not node:
            # Node not in stack - might be a node we're asking about explicitly
            # In that case, we can't determine parent with this approach
            return None
        # Return second-to-last element (parent is the one before current)
        if len(self._parent_stack) < 2:
            return None
        return self._parent_stack[-2]

    def get_ancestors(self, node: ast.AST) -> list[ast.AST]:
        """Get all ancestors of the current node, from immediate parent to root.

        Args:
            node: The AST node (must be currently being visited)

        Returns:
            List of ancestor nodes, from parent to root
        """
        if not self._parent_stack or self._parent_stack[-1] is not node:
            return []
        # Return all nodes before the current one (ancestors in reverse order)
        return list(reversed(self._parent_stack[:-1]))

    def find_ancestor(self, node: ast.AST, predicate: callable) -> Optional[ast.AST]:
        """Find the first ancestor matching a predicate.

        Args:
            node: The AST node (must be currently being visited)
            predicate: Function that takes an AST node and returns bool

        Returns:
            The first matching ancestor, or None
        """
        for ancestor in self.get_ancestors(node):
            if predicate(ancestor):
                return ancestor
        return None


def has_ancestor_of_type(
    node: ast.AST, node_type: type, parent_stack: list[ast.AST]
) -> bool:
    """Check if a node has an ancestor of a specific type.

    This is a standalone function for use when parent tracking is needed
    without a full visitor.

    Args:
        node: The AST node to check
        node_type: The type of ancestor to find (e.g., ast.With)
        parent_stack: Stack of parent nodes (from ASTParentTracker._parent_stack)

    Returns:
        True if an ancestor of the given type exists
    """
    if not parent_stack or parent_stack[-1] is not node:
        return False
    for ancestor in reversed(parent_stack[:-1]):
        if isinstance(ancestor, node_type):
            return True
    return False
