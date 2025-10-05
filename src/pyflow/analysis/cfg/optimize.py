"""CFG optimization passes.

This module provides optimization passes for control flow graphs,
including constant folding and dead branch elimination.
"""

from pyflow.util.typedispatch import *
from pyflow.language.python import ast
from . import graph as cfg
from .dfs import CFGDFS


class CFGOptPost(TypeDispatcher):
    """Post-order CFG optimization pass.
    
    This class performs post-order optimization of CFG nodes,
    including constant folding and dead branch elimination.
    
    Attributes:
        compiler: Compiler context for optimization.
    """
    
    def __init__(self, compiler):
        """Initialize the CFG optimization pass.
        
        Args:
            compiler: Compiler context for optimization.
        """
        self.compiler = compiler

    def isConst(self, node):
        """Check if a node represents a constant value.
        
        Args:
            node: AST node to check.
            
        Returns:
            bool: True if the node represents a constant.
            
        Note:
            This is currently unsound - only checks for Existing nodes.
        """
        # HACK unsound
        return isinstance(node, ast.Existing)

    def constToBool(self, node):
        """Convert a constant node to a boolean value.
        
        Args:
            node: Constant AST node.
            
        Returns:
            bool: Boolean value of the constant.
        """
        return bool(node.object.pyobj)

    @dispatch(cfg.Switch)
    def visitSwitch(self, node):
        """Optimize switch nodes with constant conditions.
        
        Args:
            node: Switch CFG node to optimize.
        """
        if self.isConst(node.condition):
            result = self.constToBool(node.condition)

            normal = (node.getExit("true"), "true")
            culled = (node.getExit("false"), "false")

            if not result:
                normal, culled = culled, normal

            suite = cfg.Suite(node.region)
            suite.setExit("fail", node.getExit("fail"))
            suite.setExit("error", node.getExit("error"))

            if not isinstance(node.condition, ast.Existing):
                suite.ops.append(ast.Discard(node.condition))

            node.redirectEntries(suite)

            # TODO don't remove prev, redirect?
            if normal[0] is not None:
                normal[0].removePrev(node, normal[1])
            if culled[0] is not None:
                culled[0].removePrev(node, culled[1])
            if normal[0] is not None:
                suite.setExit("normal", normal[0])

            # Process the suite
            self(suite)

    @defaultdispatch
    def default(self, node):
        pass

    def exitMatchesOrNone(self, a, b, name):
        ae = a.getExit(name)
        be = b.getExit(name)
        return ae is None or be is None or ae is be

    def nonlocalFlowMatches(self, a, b):
        return self.exitMatchesOrNone(a, b, "fail") and self.exitMatchesOrNone(
            a, b, "error"
        )

    @dispatch(cfg.Merge)
    def visitMerge(self, node):
        node.simplify()

    @dispatch(cfg.Suite)
    def visitSuite(self, node):
        if len(node.ops) == 0:
            # This is importaint, as it prevents extranious fail/error
            # flow from attaching itself to another block
            node.simplify()
            return

        normal = node.getExit("normal")
        if normal is not None and isinstance(normal, cfg.Suite):
            if self.nonlocalFlowMatches(node, normal):
                # Contact the next suite into this one
                node.ops.extend(normal.ops)

                node.forwardExit(normal, "normal")

                if node.getExit("fail") is None:
                    node.stealExit(normal, "fail")

                if node.getExit("error") is None:
                    node.stealExit(normal, "error")


def evaluate(compiler, g):
    post = CFGOptPost(compiler)
    dfs = CFGDFS(post=post)
    dfs.process(g.entryTerminal)
