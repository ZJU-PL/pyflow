"""Predicate graph construction and dominance analysis.

This module builds a predicate graph from a dataflow graph and computes
dominance relationships between predicates. The predicate graph represents
control flow dependencies between predicates (conditions that gate operations).

Key concepts:
- Predicate dependencies: When one predicate depends on another (e.g., nested conditions)
- Predicate dominance: One predicate dominates another if all paths to the second
  pass through the first
- Immediate dominator: The closest dominator of a predicate

The predicate graph enables analysis of control flow structure and can be used
for optimizations like predicate-aware dead code elimination.
"""

from pyflow.util.typedispatch import *
from pyflow.util.graphalgorithim.dominator import dominatorTree

from pyflow.analysis.dataflowIR import graph

from .traverse import dfs


class PredicateGraph(object):
    """Represents the predicate dependency graph.
    
    This class builds a graph of predicate dependencies from a dataflow graph
    and computes dominance relationships. Predicates represent control flow
    conditions, and dependencies indicate when one predicate's evaluation
    depends on another.
    
    Attributes:
        entry: Entry predicate node
        exit: Exit predicate node
        forward: Forward edges (predicate -> successors)
        reverse: Reverse edges (predicate -> predecessors)
        tree: Dominator tree structure
        idom: Immediate dominator mapping
    """
    def __init__(self):
        """Initialize an empty predicate graph."""
        self.entry = None
        self.exit = None
        self.forward = {}
        self.reverse = {}
        self.tree = None
        self.idom = None

    def _declare(self, pred):
        """Declare a predicate in the graph.
        
        Ensures a predicate has entries in forward and reverse edge maps.
        
        Args:
            pred: PredicateNode to declare
        """
        if pred not in self.forward:
            self.forward[pred] = []
            self.reverse[pred] = []

    def depends(self, src, dst):
        """Add a dependency edge from src to dst predicate.
        
        Indicates that predicate dst depends on predicate src (src must
        be evaluated before dst).
        
        Args:
            src: Source predicate (dependency source)
            dst: Destination predicate (dependency target)
        """
        src = src.canonical()
        dst = dst.canonical()

        assert src.isPredicate(), src
        assert dst.isPredicate(), dst

        self._declare(src)
        self._declare(dst)

        self.forward[src].append(dst)
        self.reverse[dst].append(src)

    def finalize(self):
        """Finalize the predicate graph and compute dominance.
        
        Ensures entry is declared and computes dominator tree and immediate
        dominator mapping for dominance queries.
        """
        # For simple graphs, there may be no dependencies,
        # so make sure the entry is declared
        self._declare(self.entry)

        # Generate predicate domination information
        self.tree, self.idom = dominatorTree(self.forward, self.entry)

    def dominates(self, src, dst):
        """Check if src predicate dominates dst predicate.
        
        A predicate src dominates dst if all paths from entry to dst
        pass through src.
        
        Args:
            src: Source predicate to check dominance for
            dst: Destination predicate to check dominance against
            
        Returns:
            bool: True if src dominates dst
        """
        src = src.canonical()
        dst = dst.canonical()

        if src is dst:
            return True

        if dst in self.idom:
            return self.dominates(src, self.idom[dst])

        return False


class PredicateGraphBuilder(TypeDispatcher):
    """Builds predicate graph from dataflow graph.
    
    This class traverses a dataflow graph and extracts predicate dependencies.
    It identifies operations that generate predicates (like TypeSwitch) and
    builds the dependency graph.
    
    Attributes:
        pg: PredicateGraph being built
    """
    def __init__(self):
        """Initialize the predicate graph builder."""
        TypeDispatcher.__init__(self)
        self.pg = PredicateGraph()

    @dispatch(
        graph.Entry,
        graph.Split,
        graph.Gate,
        graph.FieldNode,
        graph.LocalNode,
        graph.NullNode,
        graph.ExistingNode,
        graph.PredicateNode,
    )
    def visitJunk(self, node):
        """Visit nodes that don't generate predicates.
        
        These nodes don't create new predicates, so no dependencies
        are added.
        
        Args:
            node: Dataflow node (ignored)
        """
        pass  # Does not generate new predicates

    @dispatch(graph.Exit)
    def visitExit(self, node):
        """Visit exit nodes.
        
        Records the exit predicate for the predicate graph.
        
        Args:
            node: Exit node
        """
        self.pg.exit = node.canonicalpredicate

    @dispatch(graph.GenericOp)
    def visitGenericOp(self, node):
        """Visit generic operations.
        
        Generic operations may generate new predicates (e.g., TypeSwitch).
        Adds dependencies from the operation's predicate to generated predicates.
        
        Args:
            node: GenericOp node
        """
        # Generic ops may generate new predicates
        for child in node.predicates:
            self.pg.depends(node.predicate, child)

    @dispatch(graph.Merge)
    def visitMerge(self, node):
        """Visit merge operations.
        
        If the merge is a predicate operation (merging predicates), adds
        dependencies from source predicates to the merged predicate.
        
        Args:
            node: Merge node
        """
        if node.isPredicateOp():
            # Merges may generate new predicates
            dst = node.modify
            for prev in node.reads:
                assert isinstance(prev.defn, graph.Gate), prev.defn
                src = prev.defn.read
                self.pg.depends(src, dst)

    def process(self, dataflow):
        """Process a dataflow graph to build predicate graph.
        
        Traverses the dataflow graph and extracts predicate dependencies,
        then finalizes the predicate graph with dominance information.
        
        Args:
            dataflow: DataflowGraph to process
            
        Returns:
            PredicateGraph: Complete predicate graph with dominance info
        """
        self.pg.entry = dataflow.entryPredicate.canonical()
        dfs(dataflow, self)
        self.pg.finalize()
        return self.pg


def buildPredicateGraph(dataflow):
    """Build predicate graph from a dataflow graph.
    
    Main entry point for predicate graph construction.
    
    Args:
        dataflow: DataflowGraph to build predicate graph from
        
    Returns:
        PredicateGraph: Complete predicate graph
    """
    pgb = PredicateGraphBuilder()
    return pgb.process(dataflow)
