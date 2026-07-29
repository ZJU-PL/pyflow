"""CFG optimization passes.

This module provides optimization passes for control flow graphs,
including constant folding and dead branch elimination.
"""

from pyflow.util.typedispatch import *
from pyflow.language.python import ast
from . import graph as cfg
from .dfs import CFGDFS
from .revision import CFGTransformTransaction


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

    def isSafeFoldCondition(self, node):
        """Return True only for conditions that are sound to fold.

        We currently restrict folding to concrete boolean constants to avoid
        collapsing branches on abstract/non-boolean Existing objects.
        """
        if not isinstance(node, ast.Existing):
            return False
        obj = node.object
        return hasattr(obj, "pyobj") and isinstance(obj.pyobj, bool)

    def constToBool(self, node):
        """Convert a constant node to a boolean value.

        When ``obj`` has no ``pyobj`` attribute (i.e. it is an abstract object
        rather than a concrete Python constant), we cannot determine its truth
        value.  Raise ``AttributeError`` so the caller can conservatively skip
        folding rather than silently assuming ``True`` (which would miscompile
        programs by always taking the "true" branch).

        Args:
            node: Constant AST node.

        Returns:
            bool: Boolean value of the constant.

        Raises:
            AttributeError: If the object has no pyobj (cannot constant-fold).
        """
        obj = node.object
        if not hasattr(obj, "pyobj"):
            raise AttributeError("Object has no pyobj; cannot constant-fold")
        return bool(obj.pyobj)

    @dispatch(cfg.Switch)
    def visitSwitch(self, node):
        """Optimize switch nodes with constant conditions.

        Args:
            node: Switch CFG node to optimize.
        """
        if self.isSafeFoldCondition(node.condition):
            try:
                result = self.constToBool(node.condition)
            except AttributeError:
                # Cannot determine truth value — leave both branches intact.
                return

            normal = (node.getExit("true"), "true")
            culled = (node.getExit("false"), "false")

            if not result:
                normal, culled = culled, normal

            fail_exit = node.getExit("fail")
            error_exit = node.getExit("error")
            suite = cfg.Suite(node.region)

            if not isinstance(node.condition, ast.Existing):
                suite.ops.append(ast.Discard(node.condition))

            node.redirectEntries(suite)

            # The replacement suite already owns the surviving normal and
            # exceptional edges.  Detach every edge from the dead switch so
            # unreachable predecessors cannot leak into reverse traversal,
            # phi construction, or dominance analysis.
            for exit_name in tuple(node.next):
                node.killExit(exit_name)

            suite.setExit("fail", fail_exit)
            suite.setExit("error", error_exit)
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


def evaluate(compiler, g, *, commit_revision=True):
    transaction = (
        CFGTransformTransaction(g, "cfg-optimize") if commit_revision else None
    )
    post = CFGOptPost(compiler)
    dfs = CFGDFS(post=post)
    dfs.process(g.entryTerminal)
    return transaction.commit() if transaction is not None else None
