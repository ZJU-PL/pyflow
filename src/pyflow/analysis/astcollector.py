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
        ast.ExceptionHandler,
        ast.TryExceptFinally,
        ast.Discard,
        ast.For,
        ast.While,
        ast.CodeParameters,
        ast.TypeSwitch,
        ast.TypeSwitchCase,
        ast.Return,
        ast.FunctionDef,
        ast.ClassDef,
        ast.Raise,
        ast.ShortCircutAnd,
        ast.ShortCircutOr,
        ast.YieldFrom,
        ast.TypeParam,
        ast.TypeParams,
        ast.AnnAssign,
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

    @dispatch(ast.Assert)
    def visitAssert(self, node):
        """Visit assert statement nodes.

        Args:
            node: Assert AST node.
        """
        # Handle assert statements by visiting children (test and message)
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
        ast.BuildMap,
        ast.BuildSlice,
        ast.MakeFunction,
        ast.Import,
        ast.Yield,
        ast.NamedExpr,
        ast.ConditionalExpr,
    )
    def visitOp(self, node):
        node.visitChildren(self)
        self.ops.append(node)

    @defaultdispatch
    def visitStructuralNode(self, node):
        if isinstance(node, ast.PythonASTNode):
            node.visitChildren(self)
            return
        raise TypeError(f"unsupported AST collector value: {node!r}")

    @dispatch(list, tuple)
    def visitSequence(self, node):
        """Traverse structural sequences such as lists and keyword pairs."""
        for item in node:
            self(item)

    def process(self, node):
        """Collect *node* without relying on the Python call stack.

        Generated Python can contain thousands of nested control-flow nodes
        (a long ``if``/``elif`` chain is enough).  The historical dispatcher
        recursively called ``visitChildren`` and failed with
        :class:`RecursionError` on those otherwise valid programs.  Keep the
        same traversal and post-order operation ordering, but represent the
        pending visits explicitly.
        """

        children = []
        # The root is commonly a shared Code node.  Preserve the old forced
        # traversal while continuing to treat nested Code nodes as leaves.
        node.visitChildrenForced(children.append)
        pending = [(child, False) for child in reversed(children)]

        operation_types = (
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
            ast.BuildMap,
            ast.BuildSlice,
            ast.MakeFunction,
            ast.Import,
            ast.Yield,
            ast.NamedExpr,
            ast.ConditionalExpr,
        )

        while pending:
            current, emit_operation = pending.pop()
            if emit_operation:
                self.ops.append(current)
                continue

            if isinstance(current, (list, tuple)):
                pending.extend((item, False) for item in reversed(current))
                continue
            if isinstance(
                current,
                ast.leafTypes
                + (ast.Break, ast.Continue, ast.Code, ast.DoNotCare),
            ):
                continue
            if isinstance(current, (ast.Local, ast.Existing)):
                self.locals.add(current)
                continue
            if isinstance(current, ast.InputBlock):
                pending.extend(
                    (input_.lcl, False) for input_ in reversed(current.inputs)
                )
                continue
            if isinstance(current, ast.OutputBlock):
                pending.extend(
                    (output.expr, False) for output in reversed(current.outputs)
                )
                continue
            if isinstance(current, ast.Assign) and isinstance(current.expr, ast.Local):
                self.copies.append(current)

            child_nodes = []
            if isinstance(current, ast.PythonASTNode):
                current.visitChildren(child_nodes.append)
            else:
                raise TypeError(f"unsupported AST collector value: {current!r}")

            if isinstance(current, operation_types):
                pending.append((current, True))
            pending.extend((child, False) for child in reversed(child_nodes))
        return self.ops, self.locals


def getOps(func):
    go = GetOps()
    go.process(func)
    return go.ops, go.locals


def getAll(func):
    go = GetOps()
    go.process(func)
    return go.ops, go.locals, go.copies
