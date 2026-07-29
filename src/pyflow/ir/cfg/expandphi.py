"""Phi node expansion for CFG transformation.

This module expands phi nodes into assignments at predecessor blocks.
Phi nodes in SSA form are replaced with explicit assignments that
transfer values from predecessor blocks to the merge point.

The expansion process:
- For each merge block with phi nodes
- For each predecessor, create assignments transferring phi arguments
- Insert assignment suites before the merge point
- Remove phi nodes after expansion

This converts SSA form back to a more traditional CFG representation
while preserving the SSA semantics through explicit assignments.
"""

from pyflow.util.typedispatch import *
from pyflow.language.python import ast
from pyflow.ir.cfg import graph as cfg
from pyflow.ir.cfg.dfs import CFGDFS
from pyflow.util.graphalgorithim.merge import serializeMerges
from .revision import CFGTransformTransaction


class Expander(TypeDispatcher):
    """Expands phi nodes into assignments at predecessor blocks.

    This class traverses merge blocks and expands phi nodes by creating
    assignment statements that transfer values from predecessor blocks
    to the merge point. The assignments are inserted into new suite
    blocks placed between predecessors and the merge point.
    """

    def __init__(self):
        self.generated_from = {}

    @defaultdispatch
    def default(self, node):
        """Default handler (no action for most nodes).

        Args:
            node: CFG node (ignored)
        """
        pass

    def createTemp(self, node):
        """Create a temporary variable for serialization.

        Used by serializeMerges to create temporary variables when
        multiple assignments need to be serialized.

        Args:
            node: Variable to clone as temporary

        Returns:
            ast.Local: Cloned variable
        """
        return node.clone()

    @dispatch(cfg.Merge)
    def visitMerge(self, node):
        """Expand phi nodes in a merge block.

        For each predecessor of the merge block, creates assignments
        that transfer the corresponding phi arguments to phi targets.
        Inserts these assignments in new suite blocks between the
        predecessor and the merge point.

        Args:
            node: Merge block containing phi nodes

        Phi copies are inserted on the exact incoming edge, including typed
        cases, iterator branches, and exceptional flow.
        """
        if node.phi:
            for i, (prev, prevName) in enumerate(node.iterprev()):
                # Collect transfers for this predecessor
                transfer = [
                    (phi.arguments[i], phi.target)
                    for phi in node.phi
                    if phi.arguments[i] is not None
                ]
                if not transfer:
                    continue

                # Serialize transfers (handle cases where temps are needed)
                transfer, temps = serializeMerges(transfer, self.createTemp)

                # Create assignment statements
                stmts = [ast.Assign(src, [dst]) for src, dst in transfer]
                for stmt in stmts:
                    self.generated_from[stmt] = tuple(node.phi)

                # Insert suite block with assignments
                suite = cfg.Suite(prev.region)
                suite.ops = stmts

                prev.insertAtExit(prevName, suite, "normal")

            # Clear phi nodes after expansion
            node.phi = []


def evaluate(compiler, g):
    """Expand phi nodes in a CFG.

    Traverses the CFG and expands all phi nodes into explicit assignments.
    This converts SSA form back to a traditional CFG representation.

    Args:
        compiler: Compiler context (unused, kept for interface consistency)
        g: CFG Code object to expand phi nodes in
    """
    transaction = CFGTransformTransaction(g, "expand-phi")
    ex = Expander()
    CFGDFS(post=ex).process(g.entryTerminal)
    return transaction.commit(ex.generated_from)
