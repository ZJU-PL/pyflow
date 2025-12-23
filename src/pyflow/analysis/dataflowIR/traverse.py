"""Depth-first search traversal for dataflow graphs.

This module provides DFS traversal functionality for dataflow graphs,
allowing analysis passes to visit all nodes in the graph systematically.
"""


class DFSTraversal(object):
    """Performs depth-first search traversal of a dataflow graph.
    
    This class traverses the dataflow graph starting from entry points
    and calls a user-provided callback for each node visited.
    
    Attributes:
        callback: Function to call for each node
        processed: Set of nodes already processed
    """
    def __init__(self, callback):
        """Initialize DFS traverser.
        
        Args:
            callback: Function(node) to call for each visited node
        """
        self.callback = callback
        self.processed = set()

    def mark(self, node):
        """Mark a node (unused in current implementation).
        
        Args:
            node: Node to mark (ignored)
        """
        if node not in self.enqueued:
            self.enqueued.add(node)
            self.queue.append(node)

    def handleNode(self, node):
        """Handle a node during DFS traversal.
        
        If node hasn't been processed, calls the callback and recursively
        processes all successors.
        
        Args:
            node: Dataflow node to handle
        """
        if node not in self.processed:
            self.processed.add(node)

            # Call user callback
            self.callback(node)

            # Recursively process successors
            for child in node.forward():
                self.handleNode(child)

    def process(self, dataflow):
        """Process a dataflow graph starting from entry points.
        
        Starts DFS from:
        - Entry node
        - All existing nodes
        - Null node
        - Entry predicate node
        
        Args:
            dataflow: DataflowGraph to traverse
        """
        self.handleNode(dataflow.entry)
        for node in dataflow.existing.values():
            self.handleNode(node)
        self.handleNode(dataflow.null)
        self.handleNode(dataflow.entryPredicate)


def dfs(dataflow, callback):
    """Perform DFS traversal of a dataflow graph.
    
    Convenience function for performing DFS traversal with a callback.
    
    Args:
        dataflow: DataflowGraph to traverse
        callback: Function(node) to call for each visited node
    """
    dfs = DFSTraversal(callback)
    dfs.process(dataflow)
