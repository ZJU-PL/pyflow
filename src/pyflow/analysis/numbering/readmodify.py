"""Read/modify analysis for numbering.

This module provides FindReadModify, which analyzes AST nodes to determine
which local variables and object fields are read and modified. This information
is used for ESSA construction and other analyses that need to track variable
usage.

Key concepts:
- Local reads: Local variables that are read
- Local modifies: Local variables that are modified (assigned to)
- Field reads: Object fields that are read
- Field modifies: Object fields that are modified (stored to)
"""

from pyflow.util.typedispatch import *
from pyflow.language.python import ast
from pyflow.ir.core import Capabilities, MissingAnalysisFact


class ReadModifyInfo(object):
    """Information about read/modify relationships for a node.

    ReadModifyInfo tracks which variables and fields are read and modified
    by an AST node and its children.

    Attributes:
        localRead: Set of Local nodes that are read
        localModify: Set of Local nodes that are modified
        fieldRead: Set of field references that are read
        fieldModify: Set of field references that are modified
    """

    __slots__ = "localRead", "localModify", "fieldRead", "fieldModify"

    def __init__(self):
        """Initialize empty read/modify info."""
        self.localRead = set()
        self.localModify = set()
        self.fieldRead = set()
        self.fieldModify = set()

    def update(self, other):
        """Update this info with information from another ReadModifyInfo.

        Merges read/modify sets from another ReadModifyInfo instance.

        Args:
            other: ReadModifyInfo to merge from
        """
        self.localRead.update(other.localRead)
        self.localModify.update(other.localModify)
        self.fieldRead.update(other.fieldRead)
        self.fieldModify.update(other.fieldModify)


class FindReadModify(TypeDispatcher):
    """Finds read/modify relationships for AST nodes.

    FindReadModify traverses AST nodes and determines which local variables
    and object fields are read and modified. Results are stored in a lookup
    table mapping nodes to ReadModifyInfo.

    Attributes:
        lut: Dictionary mapping AST nodes to ReadModifyInfo
    """

    def __init__(self, facts, code):
        """Initialize read/modify finder."""
        self.lut = {}
        self.facts = facts
        self.code = code

    def _effects(self, capability, node):
        try:
            return self.facts.merged_operation_effect(capability, self.code, node)
        except MissingAnalysisFact:
            return ()

    def getListInfo(self, l):
        """Get combined read/modify info for a list of nodes.

        Args:
            l: List of AST nodes

        Returns:
            ReadModifyInfo: Combined read/modify information
        """
        info = ReadModifyInfo()
        for child in l:
            info.update(self(child))
        return info

    @dispatch(ast.Existing, ast.Code, ast.DoNotCare, ast.leafTypes)
    def visitLeaf(self, node, info):
        pass

    @dispatch(ast.Local)
    def visitLocal(self, node, info):
        info.localRead.add(node)

    @dispatch(ast.Allocate)
    def visitAllocate(self, node, info):
        # TODO what about type/field nullification?
        node.visitChildrenArgs(self, info)

    @dispatch(ast.Load, ast.Check)
    def visitMemoryExpr(self, node, info):
        node.visitChildrenArgs(self, info)
        info.fieldRead.update(self._effects(Capabilities.LIFETIME_OP_READS, node))
        info.fieldModify.update(self._effects(Capabilities.LIFETIME_OP_WRITES, node))

    @dispatch(ast.Store)
    def visitStore(self, node):
        info = ReadModifyInfo()
        node.visitChildrenArgs(self, info)
        info.fieldRead.update(self._effects(Capabilities.LIFETIME_OP_READS, node))
        info.fieldModify.update(self._effects(Capabilities.LIFETIME_OP_WRITES, node))
        self.lut[node] = info
        return info

    @dispatch(ast.DirectCall, ast.Call, ast.MethodCall)
    def visitDirectCall(self, node, info):
        node.visitChildrenArgs(self, info)
        info.fieldRead.update(self._effects(Capabilities.LIFETIME_OP_READS, node))
        info.fieldModify.update(self._effects(Capabilities.LIFETIME_OP_WRITES, node))

    @dispatch(ast.Assign)
    def visitAssign(self, node):
        info = ReadModifyInfo()
        self(node.expr, info)
        info.localModify.update(node.lcls)
        self.lut[node] = info
        return info

    @dispatch(ast.Return)
    def visitReturn(self, node):
        info = ReadModifyInfo()
        self(node.exprs, info)
        self.lut[node] = info
        return info

    @dispatch(ast.Discard)
    def visitDiscard(self, node):
        info = ReadModifyInfo()
        self(node.expr, info)
        self.lut[node] = info
        return info

    @dispatch(list, tuple)
    def visitList(self, node, info):
        for child in node:
            self(child, info)

    @dispatch(ast.Delete)
    def visitDelete(self, node):
        info = ReadModifyInfo()
        if isinstance(node.lcl, ast.Local):
            info.localModify.add(node.lcl)
        self.lut[node] = info
        return info

    @dispatch(ast.AnnAssign)
    def visitAnnAssign(self, node):
        info = ReadModifyInfo()
        if getattr(node, "annotation_expr", None) is not None:
            self(node.annotation_expr, info)
        if getattr(node, "value", None) is not None:
            self(node.value, info)
        if isinstance(node.target, ast.Local):
            info.localModify.add(node.target)
        self.lut[node] = info
        return info

    @dispatch(ast.NamedExpr)
    def visitNamedExpr(self, node, info=None):
        target_info = info if info is not None else ReadModifyInfo()
        self(node.value, target_info)
        if isinstance(node.target, ast.Local):
            target_info.localModify.add(node.target)
        if info is None:
            self.lut[node] = target_info
            return target_info

    @dispatch(ast.ExceptionHandler)
    def visitExceptionHandler(self, node):
        info = ReadModifyInfo()
        if getattr(node, "preamble", None) is not None:
            info.update(self(node.preamble))
        if getattr(node, "type", None) is not None:
            self(node.type, info)
        if isinstance(getattr(node, "value", None), ast.Local):
            info.localModify.add(node.value)
        if getattr(node, "body", None) is not None:
            info.update(self(node.body))
        self.lut[node] = info
        return info

    @dispatch(ast.TryExceptFinally)
    def visitTryExceptFinally(self, node):
        info = ReadModifyInfo()
        if getattr(node, "body", None) is not None:
            info.update(self(node.body))
        for handler in getattr(node, "handlers", ()) or ():
            info.update(self(handler))
        if getattr(node, "defaultHandler", None) is not None:
            info.update(self(node.defaultHandler))
        if getattr(node, "else_", None) is not None:
            info.update(self(node.else_))
        if getattr(node, "finally_", None) is not None:
            info.update(self(node.finally_))
        self.lut[node] = info
        return info

    @dispatch(ast.InputBlock)
    def visitInputBlock(self, node):
        info = ReadModifyInfo()
        for inp in getattr(node, "inputs", ()) or ():
            if isinstance(getattr(inp, "lcl", None), ast.Local):
                info.localModify.add(inp.lcl)
        self.lut[node] = info
        return info

    @defaultdispatch
    def visitDefault(self, node, info=None):
        if info is not None:
            node.visitChildrenArgs(self, info)
            return None
        stmt_info = ReadModifyInfo()
        node.visitChildrenArgs(self, stmt_info)
        stmt_info.fieldRead.update(self._effects(Capabilities.LIFETIME_OP_READS, node))
        stmt_info.fieldModify.update(self._effects(Capabilities.LIFETIME_OP_WRITES, node))
        self.lut[node] = stmt_info
        return stmt_info

    @dispatch(ast.Suite)
    def visitSuite(self, node, info=None):
        suite_info = self.getListInfo(node.blocks)
        self.lut[node] = suite_info
        if info is not None:
            info.update(suite_info)
            return None
        return suite_info

    @dispatch(ast.For)
    def visitFor(self, node):
        info = ReadModifyInfo()
        info.update(self(node.loopPreamble))
        info.localRead.add(node.iterator)
        info.localModify.add(node.index)

        info.update(self(node.bodyPreamble))
        info.update(self(node.body))
        info.update(self(node.else_))

        self.lut[node] = info
        return info

    @dispatch(ast.Assert)
    def visitAssert(self, node):
        info = ReadModifyInfo()
        # Bug fix: the original code called ``info.localRead.add(node.test)``
        # which adds the raw AST expression node (e.g. ast.BinaryOp, ast.Call,
        # etc.) directly to the localRead set.  localRead is supposed to contain
        # only ast.Local nodes; adding arbitrary expression nodes corrupts the
        # set and causes downstream analyses (ESSA, DCE) to crash or produce
        # wrong results.  The correct approach is to recursively visit the test
        # expression so that only the ast.Local leaves are collected.
        if node.test:
            self(node.test, info)
        if node.message:
            self(node.message, info)
        self.lut[node] = info
        return info

    @dispatch(ast.Condition)
    def visitCondition(self, node):
        info = ReadModifyInfo()
        info.update(self(node.preamble))
        info.localRead.add(node.conditional)
        self.lut[node] = info
        return info

    @dispatch(ast.While)
    def visitWhile(self, node):
        info = ReadModifyInfo()
        info.update(self(node.condition))
        info.update(self(node.body))
        info.update(self(node.else_))
        self.lut[node] = info
        return info

    @dispatch(ast.Switch)
    def visitSwitch(self, node):
        info = ReadModifyInfo()
        info.update(self(node.condition))
        info.update(self(node.t))
        info.update(self(node.f))
        self.lut[node] = info
        return info

    @dispatch(ast.TypeSwitchCase)
    def visitTypeSwitchCase(self, node):
        info = ReadModifyInfo()
        info.localModify.add(node.expr)
        info.update(self(node.body))
        self.lut[node] = info
        return info

    @dispatch(ast.TypeSwitch)
    def visitTypeSwitch(self, node):
        info = ReadModifyInfo()

        info.localRead.add(node.conditional)
        for case in node.cases:
            info.update(self(case))

        self.lut[node] = info
        return info

    @dispatch(ast.OutputBlock)
    def visitOutputBlock(self, node):
        info = ReadModifyInfo()

        for output in node.outputs:
            self(output.expr, info)

        self.lut[node] = info
        return info

    def processCode(self, code):
        """Process a code object and find all read/modify relationships.

        Traverses the AST of a code object and builds a lookup table
        mapping each node to its read/modify information.

        Args:
            code: Code object to process

        Returns:
            dict: Dictionary mapping AST nodes to ReadModifyInfo
        """
        self.lut = {}
        self(code.ast)
        return self.lut
