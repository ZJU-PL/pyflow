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
        y = cfg.Yield()
        self.attachCurrent(y)
        y.setExit("normal", self.makeNewSuite())

    @dispatch(
        ast.Assign,
        ast.Discard,
        ast.SetAttr,
        ast.UnpackSequence,
        ast.InputBlock,
        ast.OutputBlock,
        ast.BuildTuple,
        ast.BuildList,
        ast.BuildMap,
        ast.Assert,
        ast.Raise,
        ast.FunctionDef,
        ast.ClassDef,
    )
    def visitStatement(self, node):
        self.emit(node)

    @dispatch(object)  # Catch-all for unrecognised node types (L8 fix)
    def visitUnknown(self, node):
        # Warn about unknown node types so they are not silently swallowed.
        # Downstream passes dispatch on concrete op types; emitting an unknown
        # node would cause those passes to silently skip it, potentially
        # producing incorrect analysis results.
        import warnings
        warnings.warn(
            f"CFGTransformer: unrecognised AST node type {type(node).__qualname__!r}; "
            "skipping (downstream analyses may be unsound).",
            stacklevel=2,
        )

    def createSwitchAfter(self, condition, prev):
        switch = cfg.Switch(self.region, condition)
        self.attachStandardHandlers(switch)
        prev.setExit("normal", switch)
        return switch

    def createMerge(self):
        merge = cfg.Merge(self.region)
        # self.attachStandardHandlers(merge)
        return merge

    # 	@dispatch(ast.Not)
    # 	def visitNot(self, node):
    # 		fail = cfg.Merge()
    # 		self.pushHandler('fail', fail)
    #
    # 		suite  = cfg.Suite()
    # 		self.attachStandardHandlers(suite)
    # 		self.attachCurrent(suite)
    # 		self.current = suite
    #
    # 		try:
    # 			try:
    # 				self(node.stmt)
    # 			finally:
    # 				self.popHandler('fail')
    # 		except NoNormalFlow:
    # 			pass
    # 		else:
    # 			self.current.setExit('normal' as self.handler('fail'))
    #
    # 		if fail.numPrev() == 0:
    # 			# No failiures
    # 			raise NoNormalFlow
    # 		else:
    # 			self.makeNewSuite()
    # 			fail.setExit('normal', self.current)

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
        """Handle try-except-finally blocks.

        This is a conservative approximation: we model the try body, each
        exception handler, the else clause, and the finally clause as
        sequential normal-flow blocks.  We do NOT yet model the fail/error
        edges that would carry exceptions from the try body to the handlers
        (that requires a more complex CFG structure with dedicated exception
        edges).  The approximation is sound for analyses that only care about
        normal-flow data, but is unsound for exception-sensitive analyses.

        Bug #3 (original): the old implementation called self(node.body) etc.
        without any guard, so a NoNormalFlow raised inside the try body would
        propagate out and skip the handlers and finally clause entirely.  We
        now wrap each clause in a try/except so that NoNormalFlow from one
        clause does not prevent the others from being processed.
        """
        # Try body
        try:
            self(node.body)
        except NoNormalFlow:
            pass

        # Exception handlers (each is independent)
        for handler in node.handlers:
            if handler is not None:
                try:
                    self(handler)
                except NoNormalFlow:
                    pass

        # Else clause (runs when no exception was raised)
        if node.else_ is not None:
            try:
                self(node.else_)
            except NoNormalFlow:
                pass

        # Finally clause (always runs)
        if node.finally_ is not None:
            try:
                self(node.finally_)
            except NoNormalFlow:
                # Finally raised NoNormalFlow — propagate it so the caller
                # knows there is no normal exit from this try block.
                raise

    @dispatch(ast.ExceptionHandler)
    def visitExceptionHandler(self, node):
        """Handle exception handler blocks."""
        # Process the handler body
        self(node.body)

    @dispatch(ast.For)
    def visitFor(self, node):
        """Handle for loops.

        Bug fixes applied:
        - Bug #1: The old code called self.makeNewSuite() and stored the result
          in loop_body_suite but never connected it to anything.  makeNewSuite()
          sets self.current as a side-effect, so the subsequent createMerge()
          call saw a stale self.current.  Fixed by removing the spurious call.
        - Bug #2: The else-clause wiring was wrong.  The old code created
          else_suite = self.makeNewSuite() and then called self(node.else_),
          but then called else_suite.setExit("normal", ...) on the freshly-
          created suite rather than on self.current after visiting the else
          body.  Fixed by connecting self.current (after visiting the else
          body) to the break merge, mirroring the while-loop pattern.
        """
        # Process loop preamble and body preamble
        if hasattr(node, "loopPreamble") and node.loopPreamble:
            self(node.loopPreamble)
        if hasattr(node, "bodyPreamble") and node.bodyPreamble:
            self(node.bodyPreamble)

        # Create merge point for loop entry (back-edge target for continue)
        merge = self.createMerge()
        self.attachCurrent(merge)

        # The loop body starts in a fresh suite connected to the merge.
        # (No spurious makeNewSuite() call here — that was bug #1.)
        merge.setExit("normal", self.makeNewSuite())

        b = cfg.Merge(self.region)  # Break target

        self.pushHandler("continue", merge)
        self.pushHandler("break", b)

        try:
            self(node.body)
        except NoNormalFlow:
            pass
        else:
            # Normal exit from body: loop back to the merge point.
            self.attachCurrent(merge)

        self.popHandler("continue")
        self.popHandler("break")

        # Else clause: runs when the loop exits normally (not via break).
        # Wire it between the loop-exit merge and the break merge, mirroring
        # the while-loop pattern.  (Bug #2 fix: use self.current after
        # visiting the else body, not the suite created before visiting it.)
        else_body = getattr(node, "else_", None)
        if else_body:
            e = cfg.Merge(self.region)
            e.setExit("normal", self.makeNewSuite())
            try:
                self(else_body)
            except NoNormalFlow:
                pass
            else:
                self.attachCurrent(b)
            self.optimizeMerge(e)
        # else: no else clause — fall through directly to the break merge.

        b.setExit("normal", self.makeNewSuite())
        self.optimizeMerge(merge)
        self.optimizeMerge(b)

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

        Process:
            1. Initialize handler stacks for control flow
            2. Create CFG Code container
            3. Set up entry point and terminal handlers
            4. Transform AST (may raise NoNormalFlow)
            5. Clean up handlers
            6. Return complete CFG
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

    Main entry point for CFG construction from AST. Transforms the AST
    into a CFG and applies simplification passes.

    Args:
        compiler: Compiler context
        code: AST Code object to transform

    Returns:
        cfg.Code: Simplified CFG representation
    """
    cfg = CFGTransformer().process(code)

    simplify.evaluate(compiler, cfg)

    return cfg
