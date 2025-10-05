"""Dominance analysis for control flow graphs.

This module implements dominance analysis algorithms for CFGs, including
immediate dominance computation and dominance frontier analysis.
"""

from pyflow.util.graphalgorithim import dominator


class DJNode(object):
    """Node in the DJ (Dominance-Join) graph for dominance analysis.
    
    This class represents a node in the dominance tree with additional
    information needed for dominance frontier computation and SSA construction.
    
    Attributes:
        node: The original CFG node.
        idom: Immediate dominator of this node.
        level: Depth level in the dominance tree.
        d: List of immediate dominators (children in dominance tree).
        j: List of join nodes.
        marked: Whether this node is marked during analysis.
        idf: Iterated dominance frontier set.
        pre: Pre-order number in dominance tree traversal.
        post: Post-order number in dominance tree traversal.
    """
    __slots__ = "node", "idom", "level", "d", "j", "marked", "idf", "pre", "post"

    def __init__(self, node):
        """Initialize a DJ node.
        
        Args:
            node: The original CFG node this DJ node represents.
        """
        self.node = node
        self.idom = None
        self.d = []
        self.j = []
        self.marked = False
        # self.reset()

        self.idf = set()

    ##	def reset(self):
    ##		self.visited = False
    ##		self.alpha   = False
    ##		self.inPhi   = False
    ##		self.next	= None

    def setIDom(self, idom):
        """Set the immediate dominator of this node.
        
        Args:
            idom: The immediate dominator node.
        """
        self.idom = idom
        self.level = idom.level + 1
        self.idom.d.append(self)

    def number(self, uid):
        """Assign pre-order and post-order numbers to this node and its subtree.
        
        Args:
            uid: Starting unique identifier for numbering.
            
        Returns:
            int: Next available unique identifier after numbering this subtree.
        """
        self.pre = uid
        uid += 1

        for d in self.d:
            uid = d.number(uid)

        self.post = uid
        uid += 1

        return uid

    def dominates(self, other):
        """Check if this node dominates another node.
        
        Args:
            other: The node to check dominance against.
            
        Returns:
            bool: True if this node dominates the other node.
        """
        return self.pre <= other.pre and self.post >= other.post


class MakeDJGraph(object):
    """Constructs the DJ graph for dominance frontier analysis.
    
    This class builds the dominance-join graph needed for computing dominance
    frontiers, which is essential for SSA form construction.
    
    Attributes:
        idom: Immediate dominator mapping.
        processed: Set of processed nodes.
        nodes: Dictionary mapping CFG nodes to DJ nodes.
        numLevels: Number of levels in the dominance tree.
    """
    
    def __init__(self, idom, forwardCallback, bindCallback):
        """Initialize the DJ graph constructor.
        
        Args:
            idom: Immediate dominator mapping.
            forwardCallback: Callback for forward CFG traversal.
            bindCallback: Callback for binding dominator relationships.
        """
        self.idom = idom
        self.processed = set()
        self.nodes = {}
        self.numLevels = 0
        self.uid = 0
        self.forwardCallback = forwardCallback
        self.bindCallback = bindCallback

    def getNode(self, g):
        if g not in self.nodes:
            result = DJNode(g)
            self.bindCallback(g, result)
            self.nodes[g] = result

            idom = self.idom[g]
            if idom is not None:
                result.setIDom(self.getNode(idom))
                self.numLevels = max(self.numLevels, result.level)
            else:
                result.level = 0
        else:
            result = self.nodes[g]
        return result

    def process(self, node):
        if node not in self.processed:
            self.processed.add(node)

            djnode = self.getNode(node)

            for child in self.forwardCallback(node):
                djchild = self.process(child)

                if djchild.idom is not djnode:
                    djnode.j.append(djchild)

            return djnode
        else:
            return self.getNode(node)


class Bank(object):
    def __init__(self, numLevels):
        self.levels = [None for i in range(numLevels)]
        self.current = numLevels - 1

    def insertNode(self, node):
        assert node.next is None
        node.next = self.levels[node.level]
        self.levels[node.level] = node

    def getNode(self):
        i = self.current

        while i >= 0:
            djnode = self.levels[i]
            if djnode is not None:
                assert djnode.level == i

                self.levels[i] = djnode.next
                self.current = i
                return djnode
            else:
                i -= 1
        return None


class PlacePhi(object):
    def __init__(self, na, numLevels):
        self.bank = Bank(numLevels)

        for djnode in na:
            djnode.alpha = True
            self.bank.insertNode(djnode)

        self.idf = []
        self.main()

    def main(self):
        current = self.bank.getNode()
        while current:
            print("MAIN", current.node, current.level)
            self.currentLevel = current.level
            self.visit(current)
            current = self.bank.getNode()

    def visit(self, djnode):
        if djnode.visited:
            print("skip", djnode.node)
            return
        djnode.visited = True

        for j in djnode.j:
            if j.level <= self.currentLevel:
                if not j.inPhi:
                    j.inPhi = True
                    self.idf.append(j)
                    if not j.alpha:
                        self.bank.insertNode(j)

        for d in djnode.d:
            self.visit(d)


# Note that this doesn't actually find the entire dominance frontier,
# just the closest merges.
# loose upper bound -> O(|E|*depth(DJTree))
class FullIDF(object):
    def __init__(self):
        self.stack = []

    def process(self, node):
        assert node.level == len(self.stack)
        self.stack.append(node)

        for d in node.d:
            self.process(d)

        for j in node.j:
            if j.level <= node.level:
                for i in range(j.level, node.level + 1):
                    self.stack[i].idf.add(j)

        self.stack.pop()


def evaluate(roots, forwardCallback, bindCallback):
    idoms = dominator.findIDoms(roots, forwardCallback)
    mdj = MakeDJGraph(idoms, forwardCallback, bindCallback)
    djs = [mdj.process(root) for root in roots]

    uid = 0
    for dj in djs:
        uid = dj.number(uid)

    fidf = FullIDF()
    for dj in djs:
        fidf.process(dj)

    return djs
