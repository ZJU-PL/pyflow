"""Flow killing analysis for CFGs.

This module analyzes CFG operations to determine which control flow paths
are actually taken, and removes (kills) edges for paths that cannot occur.
This is a flow-sensitive analysis that tracks:
- Normal flow: Whether operations can complete normally
- Fail flow: Whether operations can fail/raise exceptions
- Error flow: Whether operations can cause errors
- Yield flow: Whether operations can yield (generators)

The analysis removes impossible control flow edges, simplifying the CFG
and enabling more precise analysis downstream.
"""

from pyflow.util.typedispatch import *
from pyflow.language.python import ast
from . import graph as cfg
from .dfs import CFGDFS

NoNormalFlow = cfg.NoNormalFlow


class OpFlow(TypeDispatcher):
    """Analyzes AST operations to determine control flow properties.

    This class traverses AST nodes and determines which control flow paths
    are possible. It sets flags indicating:
    - normal: Operation can complete normally
    - fails: Operation can fail/raise exceptions
    - errors: Operation can cause errors
    - yields: Operation can yield (generators)

    The analysis is pessimistic by default - if an operation's flow
    properties cannot be determined, it assumes all paths are possible.
    """

    @dispatch(
        ast.leafTypes,
        ast.Cell,
        ast.GetCellDeref,
        ast.Code,
        ast.DoNotCare,
        ast.OutputBlock,
        ast.InputBlock,
    )
    def visitLeaf(self, node):
        """Visit leaf nodes (no flow effects).

        Leaf nodes don't affect control flow, so no flags are set.
        """
        pass

    @dispatch(ast.Existing)
    def visitExisting(self, node):
        """Visit existing object nodes (no flow effects).

        Existing objects are constants and don't affect control flow.
        """
        pass

    @dispatch(list, tuple)
    def visitContainer(self, node):
        """Visit generic child containers."""
        for child in node:
            self(child)

    @dispatch(ast.Local)
    def visitLocal(self, node):
        """Visit local variable references.

        Local variable reads don't affect control flow.

        Note:
            TODO: Handle undefined variables?
        """
        pass

    def assumePessimistic(self):
        """Assume pessimistic flow (all paths possible).

        When flow properties cannot be determined, assume the operation
        can cause errors. This ensures soundness but may be imprecise.

        Note:
            TODO: Get flow info via callback for more precision?
        """
        # Pessimistic
        # TODO get info via callback?
        self.errors |= True

    def summarize(self, node):
        summary = type(self)()
        summary.process(node)
        return summary

    def include_abnormal(self, *summaries):
        for summary in summaries:
            self.fails |= summary.fails
            self.errors |= summary.errors
            self.yields |= summary.yields

    @dispatch(
        ast.Call,
        ast.MethodCall,
        ast.BinaryOp,
        ast.UnaryPrefixOp,
        ast.ConvertToBool,
        ast.DirectCall,
        ast.Is,
        ast.UnpackSequence,
        ast.GetGlobal,
        ast.SetGlobal,
        ast.DeleteGlobal,
        ast.SetCellDeref,
        ast.GetAttr,
        ast.SetAttr,
        ast.DeleteAttr,
        ast.GetSubscript,
        ast.SetSubscript,
        ast.DeleteSubscript,
        ast.SetSlice,
        ast.DeleteSlice,
        ast.Load,
        ast.Store,
        ast.Delete,
        ast.Print,
        ast.Import,
        ast.Yield,
        ast.YieldFrom,
        ast.Await,
        ast.AsyncYield,
    )
    def visitOp(self, node):
        node.visitChildren(self)
        self.assumePessimistic()

    @dispatch(ast.BuildTuple, ast.Allocate, ast.BuildMap)
    def visitBuildTuple(self, node):
        node.visitChildren(self)
        # No problems

    @dispatch(
        ast.BuildList,
        ast.BuildSet,
        ast.BuildSlice,
        ast.ShortCircutAnd,
        ast.ShortCircutOr,
        ast.ConditionalExpr,
        ast.NamedExpr,
        ast.MakeFunction,
    )
    def visitStructuredExpr(self, node):
        node.visitChildren(self)

    @dispatch(ast.Return)
    def visitReturn(self, node):
        node.visitChildren(self)
        # No problems

    @dispatch(ast.Discard, ast.Assign)
    def visitOK(self, node):
        node.visitChildren(self)

    @dispatch(ast.AnnAssign)
    def visitAnnAssign(self, node):
        # AnnAssign is an assignment-like statement. Avoid node.visitChildren()
        # because the AST node's field named "annotation" conflicts with the
        # per-node OpAnnotation metadata in this codebase.
        self(node.target)
        if getattr(node, "value", None) is not None:
            self(node.value)

    @dispatch(ast.TypeAlias)
    def visitTypeAlias(self, node):
        del node

    @dispatch(ast.For)
    def visitFor(self, node):
        setup = self.summarize((node.loopPreamble, node.iterator))
        body = self.summarize((node.bodyPreamble, node.body))
        else_ = self.summarize(node.else_)
        self.include_abnormal(setup, body, else_)
        # A for-loop may execute zero times; only iterable setup can prevent
        # reaching either the body or the exhausted path.
        self.normal = setup.normal and else_.normal

    @dispatch(ast.While)
    def visitWhile(self, node):
        condition = self.summarize(node.condition)
        body = self.summarize(node.body)
        else_ = self.summarize(node.else_)
        self.include_abnormal(condition, body, else_)
        self.normal = condition.normal and else_.normal

    @dispatch(ast.Break, ast.Continue)
    def visitControlFlow(self, node):
        # These affect control flow but don't generate errors
        pass

    @dispatch(ast.TryExceptFinally)
    def visitTryExceptFinally(self, node):
        body = self.summarize(node.body)
        handlers = [self.summarize(handler) for handler in node.handlers]
        default = (
            self.summarize(node.defaultHandler)
            if node.defaultHandler is not None
            else None
        )
        else_ = self.summarize(node.else_) if node.else_ is not None else None
        finally_ = (
            self.summarize(node.finally_) if node.finally_ is not None else None
        )

        normal = body.normal and (else_ is None or else_.normal)
        if body.fails or body.errors:
            normal |= any(handler.normal for handler in handlers)
            normal |= default is not None and default.normal
        if finally_ is not None:
            normal &= finally_.normal
        self.normal = normal

        summaries = [body, *handlers]
        if default is not None:
            summaries.append(default)
        if else_ is not None:
            summaries.append(else_)
        if finally_ is not None:
            summaries.append(finally_)
        self.include_abnormal(*summaries)

    @dispatch(ast.Switch)
    def visitStructuredSwitch(self, node):
        condition = self.summarize(node.condition)
        true = self.summarize(node.t)
        false = self.summarize(node.f)
        self.include_abnormal(condition, true, false)
        self.normal = condition.normal and (true.normal or false.normal)

    @dispatch(ast.TypeSwitch)
    def visitStructuredTypeSwitch(self, node):
        condition = self.summarize(node.conditional)
        cases = [self.summarize(case.body) for case in node.cases]
        self.include_abnormal(condition, *cases)
        self.normal = condition.normal and any(case.normal for case in cases)

    @dispatch(ast.ExceptionHandler, ast.Suite, ast.Condition)
    def visitCompound(self, node):
        node.visitChildren(self)

    @dispatch(ast.Raise)
    def visitRaise(self, node):
        node.visitChildren(self)
        self.fails = True
        self.normal = False

    @dispatch(ast.Assert)
    def visitAssert(self, node):
        node.visitChildren(self)
        self.fails = True

    @dispatch(ast.FunctionDef, ast.ClassDef)
    def visitDefinition(self, node):
        node.visitChildren(self)
        # Definitions don't affect control flow

    def process(self, node):
        self.normal = True
        self.fails = False
        self.errors = False
        self.yields = False

        try:
            self(node)
        except NoNormalFlow:
            self.normal = False


class FlowKiller(TypeDispatcher):
    """Kills impossible control flow edges based on operation analysis.

    This class uses OpFlow analysis to determine which control flow edges
    are impossible and removes them from the CFG. It processes CFG blocks
    and kills exits that cannot be taken based on the operations they contain.

    Attributes:
        opFlow: OpFlow instance for analyzing operations
        yields: Whether any operation in the CFG can yield
    """

    def __init__(self, opFlow):
        """Initialize the flow killer.

        Args:
            opFlow: OpFlow instance for operation analysis
        """
        self.opFlow = opFlow
        self.yields = False

    @dispatch(cfg.Yield)
    def visitYield(self, node):
        """Visit yield blocks.

        Yield blocks always indicate yield flow.

        Args:
            node: Yield CFG block
        """
        self.yields = True

    @dispatch(cfg.Entry, cfg.Exit, cfg.Merge, cfg.State)
    def visitOK(self, node):
        """Visit structural blocks (no operations to analyze).

        Entry, Exit, and Merge blocks don't contain operations, so
        no flow killing is needed.

        Args:
            node: CFG block (ignored)
        """
        pass

    @dispatch(cfg.Suite)
    def visitSuite(self, node):
        """Analyze suite blocks and kill impossible exits.

        Processes each operation in the suite to determine flow properties.
        Kills exits that cannot be taken:
        - "normal" exit killed if any operation prevents normal flow
        - "fail" exit killed if no operation can fail
        - "error" exit killed if no operation can error

        Args:
            node: Suite CFG block to analyze
        """
        normal = True
        fails = False
        errors = False

        ops = []
        for op in node.ops:
            self.opFlow.process(op)
            ops.append(op)

            fails |= self.opFlow.fails
            errors |= self.opFlow.errors
            self.yields |= self.opFlow.yields

            if not self.opFlow.normal:
                normal = False
                break

        node.ops = ops

        if not normal:
            node.killExit("normal")
        if not fails:
            node.killExit("fail")
        if not errors:
            node.killExit("error")

    @dispatch(cfg.Switch)
    def visitSwitch(self, node):
        """Analyze switch blocks and kill impossible exits.

        Processes the switch condition to determine flow properties.
        Kills exits that cannot be taken based on condition analysis.

        Args:
            node: Switch CFG block to analyze
        """
        self.opFlow.process(node.condition)
        self.yields |= self.opFlow.yields

        if not self.opFlow.normal:
            # The condition itself raises NoNormalFlow (e.g. always-raising expr).
            # Kill both branches since neither can be reached.
            node.killExit("true")
            node.killExit("false")

        if not self.opFlow.fails:
            node.killExit("fail")

        if not self.opFlow.errors:
            node.killExit("error")

    @dispatch(cfg.TypeSwitch)
    def visitTypeSwitch(self, node):
        """Analyze type switch blocks and kill impossible exits.

        Type switches evaluate their conditional expression before selecting a
        case. Analyze that expression so stale state from the previous node
        cannot leak into this decision.

        Args:
            node: TypeSwitch CFG block to analyze
        """
        self.opFlow.process(node.original.conditional)
        self.yields |= self.opFlow.yields

        if not self.opFlow.normal:
            for i in range(len(node.original.cases)):
                node.killExit(i)

        if not self.opFlow.fails:
            node.killExit("fail")

        if not self.opFlow.errors:
            node.killExit("error")

    @dispatch(cfg.ForIter)
    def visitForIter(self, node):
        self.opFlow.process(node.iterator)
        self.yields |= self.opFlow.yields
        if not self.opFlow.normal:
            node.killExit("body")
            node.killExit("exit")
        if not self.opFlow.fails:
            node.killExit("fail")
        if not self.opFlow.errors:
            node.killExit("error")


def evaluate(compiler, g):
    """Run flow killing analysis on a CFG.

    Analyzes all operations in the CFG and removes impossible control
    flow edges. This simplifies the CFG and enables more precise analysis.

    Args:
        compiler: Compiler context (unused, kept for interface consistency)
        g: CFG Code object to analyze
    """
    dfs = CFGDFS(post=FlowKiller(OpFlow()))
    dfs.process(g.entryTerminal)
