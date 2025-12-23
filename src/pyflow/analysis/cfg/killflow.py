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

    @dispatch(
        ast.Call,
        ast.BinaryOp,
        ast.UnaryPrefixOp,
        ast.ConvertToBool,
        ast.DirectCall,
        ast.Is,
        ast.UnpackSequence,
        ast.GetGlobal,
        ast.SetGlobal,
        ast.DeleteGlobal,
        ast.GetAttr,
        ast.SetAttr,
        ast.DeleteAttr,
        ast.GetSubscript,
        ast.SetSubscript,
        ast.DeleteSubscript,
        ast.Load,
        ast.Store,
    )
    def visitOp(self, node):
        node.visitChildren(self)
        self.assumePessimistic()

    @dispatch(ast.BuildTuple, ast.Allocate, ast.BuildMap)
    def visitBuildTuple(self, node):
        node.visitChildren(self)
        # No problems

    @dispatch(ast.Return)
    def visitReturn(self, node):
        node.visitChildren(self)
        # No problems

    @dispatch(ast.Discard, ast.Assign)
    def visitOK(self, node):
        node.visitChildren(self)

    @dispatch(ast.For, ast.While)
    def visitLoop(self, node):
        node.visitChildren(self)
        # Loops can have normal flow

    @dispatch(ast.Break, ast.Continue)
    def visitControlFlow(self, node):
        # These affect control flow but don't generate errors
        pass

    @dispatch(ast.TryExceptFinally)
    def visitTryExceptFinally(self, node):
        node.visitChildren(self)
        # Exception handling can have normal flow

    @dispatch(ast.Raise)
    def visitRaise(self, node):
        node.visitChildren(self)
        # Raises can cause abnormal flow but don't generate errors in analysis

    @dispatch(ast.Assert)
    def visitAssert(self, node):
        node.visitChildren(self)
        # Asserts can raise AssertionError but don't generate errors in analysis

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

    @dispatch(cfg.Entry, cfg.Exit, cfg.Merge)
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
            assert False
            # HACK should convert into a suite?
            node.killExit("t")
            node.killExit("f")

        if not self.opFlow.fails:
            node.killExit("fail")

        if not self.opFlow.errors:
            node.killExit("error")

    @dispatch(cfg.TypeSwitch)
    def visitTypeSwitch(self, node):
        """Analyze type switch blocks and kill impossible exits.
        
        Type switches don't have explicit conditions to analyze, but
        we still check for yield flow and kill impossible exits.
        
        Args:
            node: TypeSwitch CFG block to analyze
        """
        self.yields |= self.opFlow.yields

        if not self.opFlow.normal:
            assert False

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
