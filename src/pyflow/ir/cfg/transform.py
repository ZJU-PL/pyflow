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
from pyflow.ir.cfg import simplify, killflow

from pyflow.language.python import ast
from pyflow.ir.cfg import graph as cfg

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

    def __init__(self):
        self.exception_depth = 0
        self.exception_context = None

    def emit(self, stmt):
        """Emit a statement to the current CFG node.

        Args:
            stmt: AST statement to emit.
        """
        if self.exception_depth and self.current.ops:
            previous = self.current
            following = self.makeNewSuite(origin_ast=previous.origin_ast)
            previous.setExit("normal", following)
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

    @dispatch(ast.Raise)
    def visitRaise(self, node):
        """Emit an explicit raise and terminate the normal path.

        Suites already carry their standard ``fail`` successor.  Keeping that
        edge while ending construction of the current path accurately models
        an unconditional raise and prevents following statements from becoming
        reachable.
        """
        if node.exception is None and self.exception_context is not None:
            replacement = ast.Raise(self.exception_context, node.parameter, node.traceback)
            replacement.annotation = node.annotation
            node = replacement
        self.emit(node)
        self.current = None
        raise NoNormalFlow

    @dispatch(ast.Assert)
    def visitAssert(self, node):
        """Emit an assertion, which may either continue or fail."""
        self.emit(node)

    @dispatch(ast.Continue)
    def visitContinue(self, node):
        """Visit continue statements.

        Args:
            node: Continue AST node.
        """
        assert self.current is not None
        if not self.handlers["continue"]:
            # Some conservatively lowered legacy constructs can retain a
            # continue after their loop wrapper was simplified away.  Keeping
            # fallthrough is safer than aborting CFG construction for the
            # entire analysis target.
            return
        if self.exception_depth:
            self.emit(node)
        self.attachCurrent(self.handler("continue"))
        raise NoNormalFlow

    @dispatch(ast.Break)
    def visitBreak(self, node):
        """Visit break statements.

        Args:
            node: Break AST node.
        """
        assert self.current is not None
        if not self.handlers["break"]:
            # See ``visitContinue``: preserve analyzable fallthrough for an
            # orphaned legacy control-transfer marker.
            return
        if self.exception_depth:
            self.emit(node)
        self.attachCurrent(self.handler("break"))
        raise NoNormalFlow

    @dispatch(ast.Yield, ast.YieldFrom, ast.AsyncYield)
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
        ast.FunctionDef,
    )
    def visitStatement(self, node):
        self.emit(node)

    @dispatch(ast.Assign)
    def visitAssign(self, node):
        # A failing RHS must not publish the assignment's new local versions
        # on the exceptional edge. Evaluate first, then commit on normal flow.
        if not self.exception_depth:
            self.emit(node)
            return
        flow = killflow.OpFlow()
        flow.process(node.expr)
        if flow.fails or flow.errors:
            temporary = ast.Local(None)
            evaluation = ast.Assign(node.expr, [temporary])
            evaluation.annotation = node.annotation
            self.emit(evaluation)
            assignment = ast.Assign(temporary, node.lcls)
            assignment.annotation = node.annotation
            self.emit(assignment)
        else:
            self.emit(node)

    @dispatch(ast.AnnAssign)
    def visitAnnAssign(self, node):
        if node.value is not None and self.exception_depth:
            temporary = ast.Local(None)
            self(ast.Assign(node.value, [temporary]))
            replacement = ast.AnnAssign(node.target, node.annotation_expr, temporary)
            replacement.annotation = node.annotation
            self.emit(replacement)
        else:
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

    @dispatch(ast.TypeAlias, ast.TypeParams, ast.TypeParam)
    def visitTypeAlias(self, node):
        # Type aliases and PEP 695 type parameters are compile-time declarations.
        # The frontend emits an ordinary assignment for conservative value binding
        # of type aliases, while type parameters carry static constraints. Neither
        # generates runtime control flow operations.
        del node

    @dispatch(object)  # Catch-all for unrecognised node types
    def visitUnknown(self, node):
        import warnings

        warnings.warn(
            f"CFG transform skipping unsupported AST node type " f"{type(node).__qualname__!r}.",
            RuntimeWarning,
            stacklevel=2,
        )
        self.emit(node)

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

        switch.setExit("true", self.makeNewSuite(origin_ast=node))
        try:
            self(node.t)
        except NoNormalFlow:
            pass
        else:
            if self.current is not None:
                merges.append(self.current)

        switch.setExit("false", self.makeNewSuite(origin_ast=node))
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
            switch.setExit(uid, self.makeNewSuite(origin_ast=node))
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
        switch.setExit("true", self.makeNewSuite(origin_ast=node))

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
            e.setExit("normal", self.makeNewSuite(origin_ast=node))
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
        """Lower protected suites, ordered handlers and every finally exit.

        Finally is copied per completion kind. This preserves the destination
        of a pending return/break/continue/exception, while abrupt completion
        inside the cleanup overrides it using the enclosing handler stacks.
        """
        self.code.has_exception_regions = True
        join = self.createMerge()
        cleanup = {}
        if node.finally_:
            for name, handlers in self.handlers.items():
                if handlers:
                    cleanup[name] = (self.createMerge(), handlers[-1])
            cleanup["normal"] = (self.createMerge(), join)
            for name, (entry, _target) in cleanup.items():
                if name != "normal":
                    self.pushHandler(name, entry)
        normal_target = cleanup["normal"][0] if cleanup else join

        self.exception_depth += 1
        catches = self.createMerge() if node.handlers or node.defaultHandler is not None else None
        if catches is not None:
            self.pushHandler("fail", catches)
            self.pushHandler("error", catches)

        previous = self.current
        origin = previous.origin_ast if isinstance(previous.origin_ast, str) else node
        body = self.makeNewSuite(origin_ast=origin)
        self.current = previous
        self.attachCurrent(body)
        self.current = body
        try:
            self(node.body)
        except NoNormalFlow:
            pass

        if catches is not None:
            self.popHandler("fail")
            self.popHandler("error")

        if self.current is not None:
            # Else errors bypass this try's handlers.
            previous = self.current
            else_entry = self.makeNewSuite(origin_ast=node.else_)
            previous.setExit("normal", else_entry)
            try:
                if node.else_ is not None:
                    self(node.else_)
            except NoNormalFlow:
                pass
            else:
                self.attachCurrent(normal_target)

        if catches is not None:
            catches.setExit("normal", self.makeNewSuite(origin_ast=node))
            exception = ast.Local(None)
            self.emit(ast.InputBlock([ast.Input(ast.IOName("exception"), exception)]))
            outer_exception = self.exception_context
            for handler in node.handlers:
                # Matching is an opaque runtime operation: both outcomes stay
                # feasible unless an analysis supplies exception type facts.
                match = ast.Call(
                    ast.Existing(ast.program.Object("interpreter_exception_matches")),
                    [exception, handler.type],
                    [],
                    None,
                    None,
                )
                switch = cfg.ExceptionMatch(self.region, match)
                self.attachStandardHandlers(switch)
                self.attachCurrent(switch)
                switch.setExit("true", self.makeNewSuite(origin_ast=handler))
                self.exception_context = exception
                try:
                    if handler.value is not None:
                        self.emit(ast.Assign(exception, [handler.value]))
                    self(handler.preamble)
                    self(handler.body)
                except NoNormalFlow:
                    pass
                else:
                    self.attachCurrent(normal_target)
                self.exception_context = outer_exception
                switch.setExit("false", self.makeNewSuite(origin_ast=handler))
            if node.defaultHandler is not None:
                self.exception_context = exception
                try:
                    self(node.defaultHandler)
                except NoNormalFlow:
                    pass
                else:
                    self.attachCurrent(normal_target)
                self.exception_context = outer_exception
            else:
                self.attachCurrent(self.handler("fail"))

        self.exception_depth -= 1
        if cleanup:
            for name in cleanup:
                if name != "normal":
                    self.popHandler(name)
            for name, (entry, target) in cleanup.items():
                if not entry.numPrev():
                    continue
                entry.setExit("normal", self.makeNewSuite(origin_ast=node.finally_))
                outer_exception = self.exception_context
                if name in ("fail", "error"):
                    exception = ast.Local(None)
                    self.emit(ast.InputBlock([ast.Input(ast.IOName("exception"), exception)]))
                    self.exception_context = exception
                try:
                    self(node.finally_)
                except NoNormalFlow:
                    pass
                else:
                    if name in ("fail", "error"):
                        # Resume the pending exception explicitly. Consumers
                        # can carry its captured value through cleanup rather
                        # than treating the transfer as ordinary fallthrough.
                        self.emit(ast.Raise(exception, None, None))
                        self.current.killExit("fail")
                        self.current.setExit("fail", target)
                        self.current = None
                    else:
                        self.attachCurrent(target)
                self.exception_context = outer_exception

        self.current = None
        if not join.numPrev():
            raise NoNormalFlow
        join.setExit("normal", self.makeNewSuite())

    @dispatch(ast.ExceptionHandler)
    def visitExceptionHandler(self, node):
        """Handle exception handler blocks."""
        self(node.body)

    @dispatch(ast.For)
    def visitFor(self, node):
        """Lower a source-level for-loop through an iterator-aware header."""
        self(node.loopPreamble)

        header = self.createMerge()
        self.attachCurrent(header)
        breaks = cfg.Merge(self.region)
        exhausted = cfg.Merge(self.region)

        self.pushRegion(header)
        iterator = cfg.ForIter(self.region, node.iterator, node.index)
        self.attachStandardHandlers(iterator)
        header.setExit("normal", iterator)
        iterator.setExit("body", self.makeNewSuite(origin_ast=node))

        self.pushHandler("continue", header)
        self.pushHandler("break", breaks)
        try:
            self(node.bodyPreamble)
            self(node.body)
        except NoNormalFlow:
            pass
        else:
            self.attachCurrent(header)
        self.popHandler("continue")
        self.popHandler("break")
        self.popRegion()

        iterator.setExit("exit", exhausted)
        try:
            exhausted.setExit("normal", self.makeNewSuite(origin_ast=node))
            self(node.else_)
        except NoNormalFlow:
            pass
        else:
            self.attachCurrent(breaks)

        breaks.setExit("normal", self.makeNewSuite())
        self.optimizeMerge(header)
        self.optimizeMerge(breaks)
        self.optimizeMerge(exhausted)

    def optimizeMerge(self, m):
        m.simplify()

    @dispatch(ast.Suite)
    def visitSuite(self, node):
        origin_tag = getattr(node, "_origin_tag", None)
        if origin_tag is not None:
            tagged = cfg.Suite(self.region, origin_ast=origin_tag)
            self.attachStandardHandlers(tagged)
            if self.current is not None:
                self.attachCurrent(tagged)
            self.current = tagged
        elif self.current is None:
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

    def makeNewSuite(self, origin_ast=None):
        self.current = cfg.Suite(self.region, origin_ast=origin_ast)
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
        self.exception_depth = 0
        self.exception_context = None

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


def evaluate(compiler, code, *, commit_revision=True):
    """Transform AST code to CFG and simplify.

    Args:
        compiler: Compiler context
        code: AST Code object to transform

    Returns:
        cfg.Code: Simplified CFG representation
    """
    cfg = CFGTransformer().process(code)

    simplify.evaluate(compiler, cfg, commit_revision=commit_revision)

    return cfg
