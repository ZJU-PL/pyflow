"""Dead Code Elimination (DCE) for dataflow IR.

This module implements dead code elimination for dataflow graphs. It uses
liveness analysis to identify nodes that are not used and removes them
from the graph.

The algorithm:
1. Perform backward liveness analysis from exit node
2. Mark all live nodes (nodes that contribute to exit)
3. Remove dead nodes and clean up edges

Dead code elimination is important for:
- Reducing graph size
- Enabling further optimizations
- Improving analysis precision
"""

from pyflow.util.typedispatch import *
import pyflow.analysis.dataflowIR.graph as graph


class LivenessKiller(TypeDispatcher):
    """Removes dead nodes from dataflow graph.
    
    After liveness analysis identifies live nodes, this class removes
    dead nodes and cleans up edges. It processes nodes and removes
    uses/definitions for dead nodes.
    
    Attributes:
        live: Set of live nodes (from liveness analysis)
        queue: Queue of nodes to process
        processed: Set of processed nodes
    """
    def __init__(self, live):
        """Initialize liveness killer.
        
        Args:
            live: Set of live nodes to keep
        """
        self.live = live
        self.queue = []
        self.processed = set()

    @dispatch(graph.LocalNode, graph.FieldNode, graph.PredicateNode)
    def handleSlot(self, node):
        if self.dead(node.use):
            node.use = None

    @dispatch(graph.ExistingNode)
    def handleExistingNode(self, node):
        node.uses = [use for use in node.uses if not self.dead(use)]

    @dispatch(graph.NullNode)
    def handleNullNode(self, node):
        node.uses = [use for use in node.uses if not self.dead(use)]

    @dispatch(graph.GenericOp)
    def handleGenericOp(self, node):
        if all(self.dead(lcl) for lcl in node.localModifies):
            node.localModifies = []

        # TODO turn dead modifies (heap and locals) into don't cares?

    @dispatch(graph.Entry)
    def handleEntry(self, node):
        modifies = {}
        for name, next in node.modifies.items():
            if not self.dead(next):
                modifies[name] = next
        node.modifies = modifies

    @dispatch(graph.Exit)
    def handleExit(self, node):
        # A field that exists at the output may be dead for a number of reasons.
        # For example, if the field simply bridges the entry to the exit, it will be dead.
        reads = {}
        for name, prev in node.reads.items():
            if not self.dead(prev):
                reads[name] = prev
        node.reads = reads

    @dispatch(graph.Split)
    def handleSplit(self, node):
        node.modifies = [m for m in node.modifies if not self.dead(m)]
        node.optimize()

    @dispatch(graph.Gate)
    def handleGate(self, node):
        pass

    @dispatch(graph.Merge)
    def handleMerge(self, node):
        if self.dead(node.modify):
            for read in node.reads:
                read.removeUse(node)

            if node.modify is not None:
                node.modify.removeDefn(node)

            node.reads = []
            node.modify = None

    def dead(self, node):
        return node is None or node not in self.live

    def mark(self, node):
        assert isinstance(node, graph.DataflowNode), node
        if node not in self.processed:
            self.processed.add(node)
            self.queue.append(node)

    def process(self, dataflow):
        self.mark(dataflow.entry)

        # Filter existing
        existing = {}
        for name, node in dataflow.existing.items():
            if node in self.live:
                existing[name] = node
                self.mark(node)
        dataflow.existing = existing

        self.mark(dataflow.null)
        self.mark(dataflow.entryPredicate)

        # Process
        while self.queue:
            current = self.queue.pop()
            self(current)
            for next in current.forward():
                # Note: dead slots may hang around if they're written to by an op.
                # As such, we process dead slots to make sure any use they have is killed.
                if not self.dead(next) or isinstance(next, graph.SlotNode):
                    self.mark(next)


class LivenessSearcher(TypeDispatcher):
    """Performs backward liveness analysis.
    
    This class performs backward liveness analysis starting from the exit
    node. It marks all nodes that contribute to the exit (are live) by
    traversing backward through def-use chains.
    
    The algorithm:
    1. Start from exit node (always live)
    2. For each live node, mark all predecessors (definitions/reads)
    3. Continue until fixed point
    
    Attributes:
        queue: Queue of nodes to process
        live: Set of live nodes
    """
    def __init__(self):
        """Initialize liveness searcher."""
        self.queue = []
        self.live = set()

    def mark(self, node):
        """Mark a node as live.
        
        Args:
            node: DataflowNode to mark as live
        """
        assert isinstance(node, graph.DataflowNode), node
        if node not in self.live:
            self.live.add(node)
            self.queue.append(node)

    def process(self, dataflow):
        """Perform liveness analysis on a dataflow graph.
        
        Starts from exit and marks all live nodes by traversing backward.
        
        Args:
            dataflow: DataflowGraph to analyze
            
        Returns:
            set: Set of live nodes
        """
        self.mark(dataflow.exit)

        while self.queue:
            current = self.queue.pop()
            if current.isOp() and current.isExit():
                # Exit node: mark all reads, but skip entry fields that are just passed through
                for prev in current.reverse():
                    if prev.isField() and prev.defn.isEntry():
                        pass  # The field is simply passed through.
                    else:
                        self.mark(prev)
            else:
                # Normal node: mark all predecessors
                for prev in current.reverse():
                    self.mark(prev)

        return self.live


def evaluateDataflow(dataflow):
    """Perform dead code elimination on a dataflow graph.
    
    Main entry point for DCE. Performs liveness analysis and removes
    dead nodes.
    
    Args:
        dataflow: DataflowGraph to optimize
    """
    live = LivenessSearcher().process(dataflow)
    LivenessKiller(live).process(dataflow)
