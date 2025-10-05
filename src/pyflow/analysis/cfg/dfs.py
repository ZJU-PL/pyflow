"""Depth-first search traversal for CFGs.

This module provides depth-first search functionality for traversing
control flow graphs with pre-order and post-order callbacks.
"""

def doNothing(node):
    """Default callback that does nothing.
    
    Args:
        node: CFG node (ignored).
    """
    pass


class CFGDFS(object):
    """Depth-first search traverser for CFG nodes.
    
    This class performs depth-first search traversal of control flow graphs,
    calling user-provided callbacks before and after visiting each node.
    
    Attributes:
        pre: Callback function called before visiting a node.
        post: Callback function called after visiting a node.
        processed: Set of already processed nodes.
    """
    
    def __init__(self, pre=doNothing, post=doNothing):
        """Initialize the DFS traverser.
        
        Args:
            pre: Callback function called before visiting each node.
            post: Callback function called after visiting each node.
        """
        self.pre = pre
        self.post = post
        self.processed = set()

    def process(self, node):
        """Process a CFG node using depth-first search.
        
        Args:
            node: CFG node to process.
        """
        if node not in self.processed:
            self.processed.add(node)

            self.pre(node)

            # Iterate over a snapshot to avoid mutation during traversal
            for child in list(node.forward()):
                self.process(child)

            self.post(node)
