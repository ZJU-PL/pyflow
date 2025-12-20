"""
DJ (Dominator-Joint) Graph construction.

This module constructs DJ graphs, which combine dominance tree edges (D edges)
with join edges (J edges). DJ graphs are used in various program analysis
algorithms, including data flow analysis and static single assignment (SSA) form
construction.

The DJ graph contains:
- D edges: dominance tree edges (parent -> child in dominator tree)
- J edges: edges that go from a node to a node it does not dominate
"""

from . import dominator


class DJNode(object):
    """
    A node in the DJ (Dominator-Joint) graph.

    Each DJNode wraps an original graph node and maintains information about
    its position in the dominator tree and joint edges.

    Attributes
    ----------
    node : any
        The original graph node being wrapped
    idom : DJNode or None
        The immediate dominator of this node (parent in dominator tree)
    level : int
        Depth level in the dominator tree (0 for root)
    d : list of DJNode
        List of dominance children (nodes directly dominated by this node)
    j : list of DJNode
        List of join edges (nodes reachable but not dominated by this node)
    pre : int
        Pre-order number assigned during tree traversal
    post : int
        Post-order number assigned during tree traversal
    """

    __slots__ = "node", "idom", "level", "d", "j", "pre", "post"

    def __init__(self, node):
        """
        Initialize a DJ node.

        Parameters
        ----------
        node : any
            The original graph node to wrap
        """
        self.node = node
        self.idom = None
        self.d = []  # Dominance children
        self.j = []  # Join edges

    def setIDom(self, idom):
        """
        Set the immediate dominator of this node.

        Parameters
        ----------
        idom : DJNode
            The immediate dominator node
        """
        self.idom = idom
        self.level = idom.level + 1
        self.idom.d.append(self)  # Add self as a child of idom

    def number(self, uid):
        """
        Assign pre-order and post-order numbers to this node and its descendants.

        Performs a depth-first traversal of the dominance tree, assigning
        pre-order numbers when entering a node and post-order numbers when
        leaving it.

        Parameters
        ----------
        uid : int
            The next available unique identifier

        Returns
        -------
        int
            The next available unique identifier after numbering this subtree
        """
        self.pre = uid
        uid += 1

        # Recursively number all dominance children
        for d in self.d:
            uid = d.number(uid)

        self.post = uid
        uid += 1

        return uid

    def dominates(self, other):
        """
        Check if this node dominates another node using interval test.

        A node dominates another if it appears before it in pre-order and
        after it in post-order (i.e., it contains the other in its subtree).

        Parameters
        ----------
        other : DJNode
            The node to check dominance over

        Returns
        -------
        bool
            True if this node dominates other, False otherwise
        """
        return self.pre <= other.pre and self.post >= other.post

    def __repr__(self):
        return "dj(%r)" % self.node


class MakeDJGraph(object):
    """
    Builder for constructing DJ graphs from a control flow graph.

    This class constructs a DJ graph by first building dominance relationships
    and then identifying join edges (edges that are not dominance edges).
    """

    def __init__(self, idom, forwardCallback, bindCallback):
        """
        Initialize the DJ graph builder.

        Parameters
        ----------
        idom : dict
            Mapping from nodes to their immediate dominators
        forwardCallback : callable
            Function(node) -> iterable of successor nodes
        bindCallback : callable
            Optional callback(node, djnode) called when a DJ node is created
        """
        self.idom = idom
        self.processed = set()  # Track processed nodes to handle cycles
        self.nodes = {}  # Cache of node -> DJNode mappings
        self.numLevels = 0  # Maximum depth in dominator tree
        self.uid = 0
        self.forwardCallback = forwardCallback
        self.bindCallback = bindCallback

        self.roots = []  # Root nodes (nodes with no dominator)

    def getNode(self, g):
        """
        Get or create a DJNode for the given graph node.

        Parameters
        ----------
        g : any
            The original graph node

        Returns
        -------
        DJNode
            The DJ node corresponding to g
        """
        if g not in self.nodes:
            result = DJNode(g)
            self.bindCallback(g, result)
            self.nodes[g] = result

            idom = self.idom[g]

            if idom is not None:
                # This node has a dominator, set up parent-child relationship
                result.setIDom(self.getNode(idom))
            else:
                # This is a root node (no dominator)
                result.level = 0
                self.roots.append(result)

            self.numLevels = max(self.numLevels, result.level + 1)
        else:
            result = self.nodes[g]
        return result

    def process(self, node):
        """
        Process a node and construct its DJ graph structure.

        Recursively processes successors and identifies join edges (edges
        that are not dominance edges).

        Parameters
        ----------
        node : any
            The graph node to process

        Returns
        -------
        DJNode
            The DJ node for the processed node
        """
        if node not in self.processed:
            self.processed.add(node)

            djnode = self.getNode(node)

            # Process all successors
            for child in self.forwardCallback(node):
                djchild = self.process(child)

                # If the child is not dominated by this node, it's a join edge
                if djchild.idom is not djnode:
                    djnode.j.append(djchild)

            return djnode
        else:
            # Already processed (cycle detected), just return the DJ node
            return self.getNode(node)


def dummyBind(node, djnode):
    """
    Default no-op binding callback.

    Parameters
    ----------
    node : any
        The original graph node
    djnode : DJNode
        The corresponding DJ node
    """
    pass


def makeFromIDoms(roots, idom, forwardCallback, bindCallback=None):
    """
    Construct a DJ graph from pre-computed immediate dominators.

    Parameters
    ----------
    roots : iterable
        Root nodes of the graph (entry points)
    idom : dict
        Mapping from nodes to their immediate dominators
    forwardCallback : callable
        Function(node) -> iterable of successor nodes
    bindCallback : callable, optional
        Optional callback(node, djnode) called when a DJ node is created

    Returns
    -------
    list of DJNode
        List of root DJ nodes (one for each graph root)
    """
    if bindCallback is None:
        bindCallback = dummyBind

    mdj = MakeDJGraph(idom, forwardCallback, bindCallback)
    for root in roots:
        mdj.process(root)

    djs = mdj.roots

    # Assign pre-order and post-order numbers for efficient dominance testing
    uid = 0
    for dj in djs:
        uid = dj.number(uid)

    return djs


def make(roots, forwardCallback, bindCallback=None):
    """
    Construct a DJ graph from a control flow graph.

    First computes immediate dominators, then constructs the DJ graph.

    Parameters
    ----------
    roots : iterable
        Root nodes of the graph (entry points)
    forwardCallback : callable
        Function(node) -> iterable of successor nodes
    bindCallback : callable, optional
        Optional callback(node, djnode) called when a DJ node is created

    Returns
    -------
    list of DJNode
        List of root DJ nodes (one for each graph root)
    """
    if bindCallback is None:
        bindCallback = dummyBind
    idoms = dominator.findIDoms(roots, forwardCallback)
    return makeFromIDoms(roots, idoms, forwardCallback, bindCallback)
