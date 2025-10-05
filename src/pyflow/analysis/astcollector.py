"""AST collector for extracting operations and locals from Python AST.

This module provides functionality to collect operations and local variables
from Python AST nodes for analysis purposes.
"""

from pyflow.util.typedispatch import *
from pyflow.language.python import ast


class GetOps(TypeDispatcher):
    """Collects operations and local variables from AST nodes.
    
    This class traverses AST nodes to extract operations, local variables,
    and copy operations for analysis.
    
    Attributes:
        ops: List of collected operations.
        locals: Set of collected local variables.
        copies: List of copy operations found.
    """
    
    def __init__(self):
        """Initialize the AST collector."""
        self.ops = []
        self.locals = set()
        self.copies = []

    @dispatch(ast.leafTypes, ast.Break, ast.Continue, ast.Code, ast.DoNotCare)
    def visitLeaf(self, node):
        """Visit leaf nodes (no action needed)."""
        pass

    @dispatch(
        ast.Suite,
        ast.Condition,
        ast.Switch,
        ast.Discard,
        ast.For,
        ast.While,
        ast.CodeParameters,
        ast.TypeSwitch,
        ast.TypeSwitchCase,
        ast.Return,
    )
    def visitOK(self, node):
        """Visit nodes that contain child nodes.
        
        Args:
            node: AST node to visit.
        """
        node.visitChildren(self)

    @dispatch(ast.Assign)
    def visitAssign(self, node):
        """Visit assignment nodes.
        
        Args:
            node: Assignment AST node.
        """
        if isinstance(node.expr, ast.Local):
            self.copies.append(node)

        node.visitChildren(self)

    @dispatch(ast.InputBlock)
    def visitInputBlock(self, node):
        """Visit input block nodes.
        
        Args:
            node: Input block AST node.
        """
        for input in node.inputs:
            self(input.lcl)

    @dispatch(ast.OutputBlock)
    def visitOutputBlock(self, node):
        """Visit output block nodes.
        
        Args:
            node: Output block AST node.
        """
        for output in node.outputs:
            self(output.expr)

    @dispatch(ast.Local, ast.Existing)
    def visitLocal(self, node):
        """Visit local variable nodes.
        
        Args:
            node: Local variable AST node.
        """
        self.locals.add(node)

    @dispatch(
        ast.Load,
        ast.Store,
        ast.Check,
        ast.Allocate,
        ast.BinaryOp,
        ast.Is,
        ast.UnaryPrefixOp,
        ast.GetGlobal,
        ast.SetGlobal,
        ast.GetSubscript,
        ast.SetSubscript,
        ast.Call,
        ast.DirectCall,
        ast.MethodCall,
        ast.UnpackSequence,
        ast.GetAttr,
        ast.SetAttr,
        ast.ConvertToBool,
        ast.Not,
        ast.BuildTuple,
        ast.BuildList,
        ast.GetIter,
    )
    def visitOp(self, node):
        node.visitChildren(self)
        self.ops.append(node)

    @dispatch(list)
    def visitList(self, node):
        # Handle raw Python lists that might appear in the AST
        for item in node:
            if hasattr(item, 'visitChildren'):
                self(item)
            # For non-AST items, just skip them

    def process(self, node):
        # This is a shared node, so force traversal
        node.visitChildrenForced(self)
        return self.ops, self.locals


def getOps(func):
    go = GetOps()
    go.process(func)
    return go.ops, go.locals


def getAll(func):
    go = GetOps()
    go.process(func)
    return go.ops, go.locals, go.copies
