"""CFG transformation utilities.

This module provides functionality to transform AST nodes into CFG structures,
handling control flow constructs like returns, breaks, and yields.

The CFGTransformer class is the main entry point for converting Python AST
into a Control Flow Graph. It handles:
- Basic statements (assignments, discards)
- Control flow (if/else, while, for loops)
- Exception handling (try/except/finally)
- Type switches (isinstance checks)
- Returns, breaks, continues, yields
- Function and class definitions

The transformation process builds CFG blocks (Suite, Switch, Merge, etc.)
and connects them with appropriate control flow edges (normal, fail, error).
"""

from pyflow.util.typedispatch import *
from pyflow.analysis.cfg import simplify
from pyflow.analysis.cfg import dump
from pyflow.application.errors import TemporaryLimitation

from pyflow.language.python import ast
from pyflow.analysis.cfg import graph as cfg

NoNormalFlow = cfg.NoNormalFlow


class CFGTransformer(TypeDispatcher):
    """Transforms AST nodes into CFG structures.

    This class handles the transformation of Python AST nodes into control
    flow graph structures, managing control flow constructs and basic blocks.

    The transformer maintains:
    - Current block being built (for emitting operations)
    - Handler stack (for return, break, continue, fail, error)
    - Region stack (for tracking code regions)

    Attributes:
        current: Current CFG Suite node being built
        handler: Dictionary of handler stacks for control flow
        makeNewSuite: Function to create new suite nodes
        regionStack: Stack of code regions
        region: Current code region
        code: CFG Code object being built
    """

    def emit(self, stmt):
        """Emit a statement to the current CFG node.

        Args:
            stmt: AST statement to emit.
        """
        self.current.ops.append(stmt)

    def attachCurrent(self, child):
        """Attach the current node to a child node.

        Args:
            child: Child CFG node to attach to.
        """
        if not self.current.ops:
            # Avoid creating empty nodes
            self.current.redirectEntries(child)
        else:
            self.current.setExit("normal", child)
        self.current = None

    def flowReturn(self):
        """Handle return flow control."""
        assert self.current is not None
        self.attachCurrent(self.handler("return"))
        raise NoNormalFlow

    @dispatch(ast.Return)
    def visitReturn(self, node):
        """Visit return statements.

        Args:
            node: Return AST node.
        """
        self.emit(node)
        self.flowReturn()

    @dispatch(ast.Continue)
    def visitContinue(self, node):
        """Visit continue statements.

        Args:
            node: Continue AST node.
        """
        assert self.current is not None
        self.attachCurrent(self.handler("continue"))
        raise NoNormalFlow

    @dispatch(ast.Break)
    def visitBreak(self, node):
        """Visit break statements.

        Args:
            node: Break AST node.
        """
        assert self.current is not None
        self.attachCurrent(self.handler("break"))
        raise NoNormalFlow

    @dispatch(ast.Yield)
    def visitYield(self, node):
        """Visit yield statements.

        Args:
            node: Yield AST node.
        """
        # Preserve the yielded expression as an operation so downstream analyses
        # (e.g. IFDS clients) can observe reads/calls inside `yield <expr>`.
        self.emit(node)
        y = cfg.Yield(self.region)
        self.attachCurrent(y)
        y.setExit("normal", self.makeNewSuite())

    @dispatch(
        ast.Assign,
        ast.AnnAssign,
        ast.Discard,
        ast.SetAttr,
        ast.SetSubscript,
        ast.SetSlice,
        ast.SetGlobal,
        ast.Delete,
        ast.DeleteGlobal,
        ast.DeleteAttr,
        ast.DeleteSubscript,
        ast.DeleteSlice,
        ast.SetCellDeref,
        ast.Store,
        ast.UnpackSequence,
        ast.InputBlock,
        ast.OutputBlock,
        ast.BuildTuple,
        ast.BuildList,
        ast.BuildMap,
        ast.Print,
        ast.Assert,
        ast.Raise,
        ast.FunctionDef,
    )
    def visitStatement(self, node):
        self.emit(node)

    @dispatch(ast.ClassDef)
    def visitClassDef(self, node):
        # Class bodies execute at definition time. Inline their statements into
        # the surrounding CFG so downstream analyses can observe definition-time
        # effects (e.g. attribute initializers, registry calls, sinks).
        self(node.body)

    @dispatch(ast.GlobalDecl, ast.NonlocalDecl)
    def visitScopeDecl(self, node):
        # Scope declarations are compile-time markers with no runtime operation.
        del node

    @dispatch(ast.TypeAlias)
    def visitTypeAlias(self, node):
        # Type aliases are compile-time declarations. The frontend also emits an
        # ordinary assignment for conservative value binding, so the marker node
        # itself can be ignored during CFG construction.
        del node

    @dispatch(object)  # Catch-all for unrecognised node types
    def visitUnknown(self, node):
        raise TemporaryLimitation(
            "CFG transform encountered unsupported AST node type "
            f"{type(node).__qualname__!r}."
        )

    def createSwitchAfter(self, condition, prev):
        switch = cfg.Switch(self.region, condition)
        self.attachStandardHandlers(switch)
        prev.setExit("normal", switch)
        return switch

    def createMerge(self):
        merge = cfg.Merge(self.region)
        return merge

    @dispatch(ast.Switch)
    def visitSwitch(self, node):
        self(node.condition.preamble)
        switch = cfg.Switch(self.region, node.condition.conditional)
        self.attachStandardHandlers(switch)

        self.attachCurrent(switch)

        merges = []

        switch.setExit("true", self.makeNewSuite())
        try:
            self(node.t)
        except NoNormalFlow:
            pass
        else:
            if self.current is not None:
                merges.append(self.current)

        switch.setExit("false", self.makeNewSuite())
        try:
            self(node.f)
        except NoNormalFlow:
            pass
        else:
            if self.current is not None:
                merges.append(self.current)

        if len(merges) == 2:
            merge = self.createMerge()
            merges[0].setExit("normal", merge)
            merges[1].setExit("normal", merge)

            self.makeNewSuite()
            merge.setExit("normal", self.current)
        elif len(merges) == 1:
            self.current = merges[0]
        else:
            raise NoNormalFlow

    @dispatch(ast.TypeSwitch)
    def visitTypeSwitch(self, node):
        switch = cfg.TypeSwitch(self.region, node)
        self.attachStandardHandlers(switch)

        self.attachCurrent(switch)

        merges = []

        uid = 0

        for case in node.cases:
            switch.setExit(uid, self.makeNewSuite())
            uid += 1

            try:
                self(case.body)
            except NoNormalFlow:
                pass
            else:
                merges.append(self.current)

        if len(merges) > 1:
            merge = self.createMerge()

            for edge in merges:
                edge.setExit("normal", merge)

            self.makeNewSuite()
            merge.setExit("normal", self.current)
        elif len(merges) == 1:
            self.current = merges[0]
        else:
            raise NoNormalFlow

    @dispatch(ast.While)
    def visitWhile(self, node):
        c = self.createMerge()
        self.attachCurrent(c)

        b = cfg.Merge(self.region)
        e = cfg.Merge(self.region)

        self.pushRegion(c)

        c.setExit("normal", self.makeNewSuite())
        self(node.condition.preamble)

        switch = self.createSwitchAfter(node.condition.conditional, self.current)
        switch.setExit("true", self.makeNewSuite())

        self.pushHandler("continue", c)
        self.pushHandler("break", b)

        try:
            self(node.body)
        except NoNormalFlow:
            pass
        else:
            self.attachCurrent(c)

        self.popHandler("continue")
        self.popHandler("break")
        self.popRegion()

        switch.setExit("false", e)

        try:
            e.setExit("normal", self.makeNewSuite())
            self(node.else_)
        except NoNormalFlow:
            pass
        else:
            self.attachCurrent(b)

        b.setExit("normal", self.makeNewSuite())
        self.optimizeMerge(c)
        self.optimizeMerge(b)
        self.optimizeMerge(e)

    @dispatch(ast.TryExceptFinally)
    def visitTryExceptFinally(self, node):
        """Preserve try blocks as structured AST until exception-aware CFG exists.

        Linearizing the clauses into the ambient CFG is incorrect because it
        makes handlers/else/finally execute sequentially on the normal path.
        Keep the compound statement intact so later reconstruction preserves
        Python semantics instead of emitting a miscompiled flat sequence.
        """
        self.emit(node)

    @dispatch(ast.ExceptionHandler)
    def visitExceptionHandler(self, node):
        """Handle exception handler blocks."""
        self(node.body)

    @dispatch(ast.For)
    def visitFor(self, node):
        """Handle for loops conservatively using the same shape as while-loops."""
        if hasattr(node, "loopPreamble") and node.loopPreamble:
            self(node.loopPreamble)

        header = self.createMerge()
        self.attachCurrent(header)

        break_merge = cfg.Merge(self.region)
        exit_merge = cfg.Merge(self.region)

        self.pushRegion(header)

        header.setExit("normal", self.makeNewSuite())
        switch = self.createSwitchAfter(node.iterator, self.current)
        switch.setExit("true", self.makeNewSuite())

        if hasattr(node, "bodyPreamble") and node.bodyPreamble:
            self(node.bodyPreamble)

        self.pushHandler("continue", header)
        self.pushHandler("break", break_merge)

        try:
            self(node.body)
        except NoNormalFlow:
            pass
        else:
            self.attachCurrent(header)

        self.popHandler("continue")
        self.popHandler("break")
        self.popRegion()

        switch.setExit("false", exit_merge)

        try:
            exit_merge.setExit("normal", self.makeNewSuite())
            self(node.else_)
        except NoNormalFlow:
            pass
        else:
            self.attachCurrent(break_merge)

        break_merge.setExit("normal", self.makeNewSuite())
        self.optimizeMerge(header)
        self.optimizeMerge(break_merge)
        self.optimizeMerge(exit_merge)

    def optimizeMerge(self, m):
        m.simplify()

    @dispatch(ast.Suite)
    def visitSuite(self, node):
        if self.current is None:
            self.current = self.makeNewSuite()
        node.visitChildren(self)

    def pushHandler(self, name, node):
        assert isinstance(node, cfg.Merge)
        self.handlers[name].append(node)

    def popHandler(self, name):
        return self.handlers[name].pop()

    def handler(self, name):
        return self.handlers[name][-1]

    def attachStandardHandlers(self, node):
        node.setExit("fail", self.handler("fail"))
        node.setExit("error", self.handler("error"))

    def makeNewSuite(self):
        self.current = cfg.Suite(self.region)
        self.attachStandardHandlers(self.current)
        return self.current

    def mergeInto(self, node):
        m = cfg.Merge(self.region)
        m.setExit("normal", node)
        return m

    def pushRegion(self, region):
        self.regionStack.append(self.region)
        self.region = region

    def popRegion(self):
        self.region = self.regionStack.pop()

    def process(self, code):
        """Transform an AST Code object into a CFG.

        Main entry point for CFG construction. Initializes the transformer
        state, sets up control flow handlers, and transforms the AST.

        Args:
            code: AST Code object to transform

        Returns:
            cfg.Code: Complete CFG representation of the function
        """
        self.regionStack = []
        self.region = None

        self.handlers = {
            "return": [],
            "fail": [],
            "error": [],
            "continue": [],
            "break": [],
        }

        self.code = cfg.Code()
        self.code.code = code

        self.pushHandler("return", self.mergeInto(self.code.normalTerminal))
        self.pushHandler("fail", self.mergeInto(self.code.failTerminal))
        self.pushHandler("error", self.mergeInto(self.code.errorTerminal))

        self.code.entryTerminal.setExit("entry", self.makeNewSuite())

        try:
            self(code.ast)
            self.flowReturn()
        except NoNormalFlow:
            pass

        self.popHandler("return")
        self.popHandler("fail")
        self.popHandler("error")

        return self.code


def evaluate(compiler, code):
    """Transform AST code to CFG and simplify.

    Args:
        compiler: Compiler context
        code: AST Code object to transform

    Returns:
        cfg.Code: Simplified CFG representation
    """
    cfg = CFGTransformer().process(code)

    simplify.evaluate(compiler, cfg)

    return cfg
