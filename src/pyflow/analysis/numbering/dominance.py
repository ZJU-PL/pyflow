"""Dominance analysis and numbering for program points.

This module provides dominance analysis and numbering of program points
based on dominance relationships. It computes:
- Dominator tree: Tree structure based on dominance relationships
- Pre/post numbering: DFS numbering for efficient dominance queries
- Dominance intervals: (pre, post) intervals for each node

The numbering enables efficient dominance queries: node A dominates node B
if A.pre <= B.pre and A.post >= B.post.
"""

import pyflow.util as util
from pyflow.util.graphalgorithim import dominator
from .dataflow import ForwardDataflow

# For debugging
from pyflow.util.io.xmloutput import XMLOutput


class MakeForwardDominance(object):
    """Computes dominance relationships and numbers program points.
    
    MakeForwardDominance performs:
    1. Builds forward dataflow graph
    2. Computes dominator tree
    3. Numbers nodes using DFS traversal
    4. Assigns (pre, post) intervals for dominance queries
    
    Attributes:
        uid: Unique identifier counter for numbering
        pre: Dictionary mapping nodes to pre-order numbers
        dom: Dictionary mapping nodes to (pre, post) dominance intervals
        processed: Set of processed nodes
        G: Graph structure (dataflow graph or dominator tree)
    """
    def printDebug(self, tree, head):
        """Print dominance tree for debugging (HTML format).
        
        Args:
            tree: Dominator tree structure
            head: Root node of the tree
        """
        f = XMLOutput(open("temp.html", "w"))
        f.begin("ul")

        def printNode(f, node):
            if not isinstance(node, tuple):
                f.begin("li")
                f.write(str(node))
                f.begin("ul")

            children = tree.get(node, ())

            for child in children:
                printNode(f, child)

            if not isinstance(node, tuple):
                f.end("ul")
                f.end("li")

        printNode(f, head)

        f.end("ul")
        f.close()

    def number(self, node):
        """Number a node and its descendants using DFS.
        
        Assigns pre-order and post-order numbers to nodes in the dominator
        tree. The (pre, post) interval enables efficient dominance queries.
        
        Args:
            node: Node to number
        """
        if node in self.processed:
            return
        self.processed.add(node)

        self.pre[node] = self.uid
        self.uid += 1

        for next in self.G.get(node, ()):
            self.number(next)

        self.dom[node] = (self.pre[node], self.uid)
        self.uid += 1

    def processCode(self, code):
        """Process code and compute dominance numbering.
        
        Builds dataflow graph, computes dominator tree, and numbers
        all nodes with (pre, post) intervals.
        
        Args:
            code: Code object to process
            
        Returns:
            dict: Dictionary mapping nodes to (pre, post) intervals
        """
        self.uid = 0
        self.pre = {}
        self.dom = {}

        self.processed = set()

        fdf = ForwardDataflow()

        self.G = fdf.processCode(code)
        head = fdf.entry[code]

        tree, idoms = util.graphalgorithim.dominator.dominatorTree(self.G, head)

        # self.printDebug(tree, head)

        self.G = tree
        self.number(head)

        return self.dom
