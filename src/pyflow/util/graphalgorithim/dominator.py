"""
Dominator tree computation algorithms.

This module provides algorithms for computing dominator relationships in
directed graphs. A node d dominates a node n if every path from the entry
point to n must pass through d. The immediate dominator (idom) of a node n
is the unique dominator of n that is dominated by all other dominators of n.

Two algorithms are provided:
1. dominatorTree: Uses a fixed-point iteration approach
2. findIDoms: Uses a tree-based approach with pre/post numbering
"""

from . import basic


def intersect(doms, b1, b2):
    """
    Find the intersection (common dominator) of two nodes in a dominator tree.

    Uses the "finger" algorithm: advances both nodes up their dominator chains
    until they meet at their common ancestor (least common ancestor in the
    dominator tree).

    Parameters
    ----------
    doms : list
        Array where doms[i] is the immediate dominator of node i (in reverse
        post-order numbering). Nodes are numbered such that dominators always
        have smaller numbers than their dominated nodes.
    b1 : int
        First node (in reverse post-order numbering)
    b2 : int
        Second node (in reverse post-order numbering)

    Returns
    -------
    int
        The common dominator of b1 and b2 (the node where the two paths meet)

    Notes
    -----
    This function assumes that nodes are numbered in reverse post-order, where
    dominators always have smaller numbers than their dominated nodes. This
    property allows efficient traversal up the dominator tree.
    """
    finger1 = b1
    finger2 = b2
    while finger1 != finger2:
        # Advance finger1 up the dominator chain until it's <= finger2
        while finger1 > finger2:
            finger1 = doms[finger1]

        # Advance finger2 up the dominator chain until it's <= finger1
        while finger2 > finger1:
            finger2 = doms[finger2]
    return finger1


class ReversePostorderCrawler(object):
    """
    Performs depth-first traversal to compute reverse post-order numbering.

    Reverse post-order is a numbering where nodes are numbered in the reverse
    of the order they are last visited during a DFS. This ordering has the
    property that dominators always have smaller numbers than their dominated
    nodes, which is crucial for efficient dominator computation.
    """

    def __init__(self, G, head):
        """
        Initialize the crawler and compute reverse post-order.

        Parameters
        ----------
        G : dict
            Directed graph mapping nodes to iterables of successor nodes
        head : any
            The entry point (head) node to start traversal from
        """
        self.G = G
        self.head = head

        self.all = set(G.keys())

        self.processed = set((self.head,))
        self.order = []

        # Traverse from head's successors
        for nextNode in self.G[self.head]:
            self(nextNode)

        # Handle inaccessible cycles: nodes that aren't reachable from head
        # but form cycles among themselves. We add edges from head to make
        # the graph single-entry.
        remaining = self.all - self.processed
        while remaining:
            newEntry = remaining.pop()
            self.G[head] = set(self.G[head])
            self.G[head].add(newEntry)
            self(newEntry)
            remaining = self.all - self.processed

        # Finally, add the head itself
        self.order.append(self.head)

        # Reverse to get reverse post-order (post-order reversed)
        self.order.reverse()

    def __call__(self, node):
        """
        Perform DFS traversal from a node using an explicit stack.

        Uses an explicit stack instead of recursion to avoid Python's recursion
        limit. Based on the PADS (Python Algorithms and Data Structures) library.

        Parameters
        ----------
        node : any
            The node to start DFS traversal from
        """
        if node in self.processed:
            return

        # Maintain explicit stack: each entry is (node, iterator of children)
        # Based on PADS library approach to avoid recursion limits
        self.processed.add(node)
        stack = [(node, iter(self.G.get(node, ())))]
        while stack:
            _parent, children = stack[-1]
            try:
                child = children.__next__()
                if child not in self.processed:
                    self.processed.add(child)
                    stack.append((child, iter(self.G.get(child, ()))))
            except StopIteration:
                # All children processed, add to post-order
                self.order.append(stack[-1][0])
                stack.pop()


def dominatorTree(G, head):
    """
    Compute the dominator tree and immediate dominators using fixed-point iteration.

    This algorithm uses the classic iterative data-flow approach:
    1. Number nodes in reverse post-order
    2. Iteratively refine dominator information until convergence
    3. For each node, find the intersection of all its predecessors' dominators

    Parameters
    ----------
    G : dict
        Directed graph mapping nodes to iterables of successor nodes
    head : any
        The entry point (head) node

    Returns
    -------
    tuple of (dict, dict)
        A 2-tuple containing:
        - dominator tree (dict): Mapping from dominator to list of dominated nodes
        - idoms (dict): Mapping from each node to its immediate dominator
    """
    order = ReversePostorderCrawler(G, head).order

    # Create bidirectional mapping between graph nodes and reverse post-order numbers
    forward = {}  # node -> reverse post-order number
    reverse = {}  # reverse post-order number -> node
    for i, node in enumerate(order):
        forward[node] = i
        reverse[i] = node

    # Build predecessor map in reverse post-order space
    pred = {}
    for node, nexts in G.items():
        i = forward[node]
        for nextNode in nexts:
            n = forward[nextNode]

            # Eliminate self-cycles (nodes with edges to themselves)
            if i == n:
                continue

            if n not in pred:
                pred[n] = [i]
            else:
                pred[n].append(i)

    # Initialize: doms[i] will be the immediate dominator of node i
    count = len(order)
    doms = [None for i in range(count)]

    # Special case: head dominates itself (or has no dominator)
    doms[0] = 0

    # Fixed-point iteration: repeatedly refine dominator information
    changed = True
    while changed:
        changed = False
        for node in range(1, count):
            # Find an initial value for the immediate dominator
            if doms[node] is None:
                # Start with the predecessor with smallest number
                new_idom = min(pred[node])
                assert new_idom < node  # Property of reverse post-order
            else:
                new_idom = doms[node]

            # Refine: immediate dominator must dominate all predecessors
            # Find the intersection (common dominator) of all predecessors
            for p in pred[node]:
                if doms[p] is not None:
                    new_idom = intersect(doms, new_idom, p)

            # Check if the immediate dominator has changed
            if doms[node] is not new_idom:
                assert doms[node] is None or new_idom < doms[node]
                doms[node] = new_idom
                changed = True

    # Map solution back to original graph nodes
    idoms = {}
    for node, idom in enumerate(doms):
        if node == 0:
            continue  # Skip the head
        node = reverse[node]
        idom = reverse[idom]
        idoms[node] = idom

    return treeFromIDoms(idoms), idoms


def makeSingleHead(G, head):
    """
    Modify graph to have a single entry point by adding edges from head.

    Connects the head node to all entry points (nodes with no predecessors)
    to ensure the graph has a single entry point, which is required for
    proper dominator analysis.

    Parameters
    ----------
    G : dict
        Directed graph mapping nodes to iterables of successor nodes
    head : any
        The desired entry point node

    Notes
    -----
    Modifies G in place by adding edges from head to entry points.
    """
    entryPoints = basic.findEntryPoints(G)
    G[head] = entryPoints


class DomInfo(object):
    """
    Stores dominance information for a node during tree-based dominator computation.

    Attributes
    ----------
    pre : int
        Pre-order number (assigned when node is first visited)
    post : int
        Post-order number (assigned when leaving node's subtree)
    prev : list
        List of predecessor nodes in the graph
    """

    __slots__ = "pre", "post", "prev"

    def __init__(self):
        """Initialize dominance information."""
        self.pre = 0
        self.post = 0
        self.prev = []

    def cannotDominate(self, other):
        """
        Check if this node cannot possibly dominate another node.

        Uses the interval property: for node A to dominate node B, A's pre/post
        interval must contain B's interval. This is a necessary but not sufficient
        condition, so if the intervals don't overlap, we know A cannot dominate B.

        Parameters
        ----------
        other : DomInfo
            The other node's dominance information

        Returns
        -------
        bool
            True if this node cannot dominate other (intervals don't overlap)
        """
        return self.pre > other.pre or self.post < other.post


class IDomFinder(object):
    """
    Finds immediate dominators using a tree-based algorithm with pre/post numbering.

    This algorithm processes nodes in reverse post-order and uses the interval
    property of dominators to efficiently find the immediate dominator. It's
    typically faster than fixed-point iteration for sparse graphs.
    """

    def __init__(self, forwardCallback):
        """
        Initialize the immediate dominator finder.

        Parameters
        ----------
        forwardCallback : callable
            Function(node) -> iterable of successor nodes
        """
        self.pre = {}
        self.domInfo = {}  # node -> DomInfo
        self.uid = 0  # Unique identifier counter for pre/post numbering
        self.order = []  # Post-order traversal order
        self.forwardCallback = forwardCallback

    def process(self, node):
        """
        Process a node and build dominance information.

        Performs a DFS traversal, assigning pre/post numbers and collecting
        predecessor information.

        Parameters
        ----------
        node : any
            The graph node to process

        Returns
        -------
        DomInfo
            The dominance information for the node
        """
        if node not in self.domInfo:
            info = DomInfo()
            self.domInfo[node] = info
            info.pre = self.uid
            self.uid += 1

            # Process all successors
            for child in self.forwardCallback(node):
                childInfo = self.process(child)
                childInfo.prev.append(node)  # Record predecessor

            info.post = self.uid
            self.uid += 1

            self.order.append(node)

            return info
        else:
            return self.domInfo[node]

    def findCompatable(self, current, other):
        """
        Find a node that can potentially dominate both current and other.

        Walks up the dominator chain from current until finding a node whose
        interval contains other's interval, meaning it could dominate other.

        Parameters
        ----------
        current : any
            Current candidate dominator node
        other : any
            Other node that needs to be dominated

        Returns
        -------
        any or None
            A node that can dominate both, or None if no such node exists
        """
        if current is None or other is None:
            return None

        cinfo = self.domInfo[current]
        oinfo = self.domInfo[other]

        # Walk up dominator chain until current's interval contains other's
        while cinfo.cannotDominate(oinfo):
            current = self.idom[current]
            if current is None:
                return None
            cinfo = self.domInfo[current]

        return current

    def findIDoms(self):
        """
        Compute immediate dominators for all nodes.

        Processes nodes in reverse post-order. For each node, finds the
        immediate dominator by starting with the predecessor with highest
        post-order number (most likely candidate) and then finding the
        intersection (common dominator) of all predecessors.

        Returns
        -------
        dict
            Mapping from each node to its immediate dominator (None for roots)
        """
        self.idom = {}

        # Process in reverse post-order (dominators before dominated nodes)
        for node in reversed(self.order):
            nodeInfo = self.domInfo[node]

            n = len(nodeInfo.prev)

            if n == 0:
                # No predecessors: entry point, has no dominator
                best = None
            elif n == 1:
                # Single predecessor: trivial case, predecessor is idom
                best = nodeInfo.prev[0]
            else:
                # Multiple predecessors: find intersection (common dominator)
                # Start with predecessor with highest post-order number
                # (most likely to be the idom, and not a back edge)
                prevs = nodeInfo.prev
                best = prevs[0]
                binfo = self.domInfo[best]

                # Find predecessor with maximum post-order number
                for prev in prevs:
                    pinfo = self.domInfo[prev]
                    if pinfo.post > binfo.post:
                        best = prev
                        binfo = pinfo  # Note: fixed bug here (was binfo = binfo)

                # Find the intersection: the closest node that dominates all
                # predecessors. Walk up from best and intersect with each
                # predecessor until finding the common dominator.
                for prev in prevs:
                    best = self.findCompatable(best, prev)

            self.idom[node] = best

        return self.idom


def findIDoms(roots, forwardCallback):
    """
    Find immediate dominators using the tree-based algorithm.

    Parameters
    ----------
    roots : iterable
        Root nodes (entry points) to start traversal from
    forwardCallback : callable
        Function(node) -> iterable of successor nodes

    Returns
    -------
    dict
        Mapping from each node to its immediate dominator (None for roots)
    """
    idf = IDomFinder(forwardCallback)
    for root in roots:
        idf.process(root)
    return idf.findIDoms()


def treeFromIDoms(idoms):
    """
    Convert immediate dominator map into a dominator tree structure.

    The dominator tree is represented as a dictionary mapping each dominator
    to a list of nodes it directly dominates.

    Parameters
    ----------
    idoms : dict
        Mapping from each node to its immediate dominator

    Returns
    -------
    dict
        Mapping from dominator nodes to lists of directly dominated nodes.
        Note: Root nodes (with idom=None) will be keys in the tree.
    """
    tree = {}

    for node, idom in idoms.items():
        if idom not in tree:
            tree[idom] = [node]
        else:
            tree[idom].append(node)

    return tree
