"""Topological ordering for dataflow graphs.

This module provides functionality to compute a topological ordering
of operations in a dataflow graph. The ordering respects data dependencies,
ensuring that operations are ordered before their uses.

The algorithm uses a combination of pre-order and post-order numbering
to compute a reverse post-order traversal, which provides a valid
topological order for dataflow analysis.
"""

from . import graph


class OrderSearcher(object):
    """Computes topological ordering of dataflow graph operations.
    
    This class performs a depth-first search of the dataflow graph,
    assigning pre-order and post-order numbers to nodes, and collecting
    operation nodes in reverse post-order (which is a valid topological order).
    
    The algorithm:
    1. Start from entry and existing nodes
    2. Perform DFS, assigning pre-order numbers
    3. When revisiting nodes, assign post-order numbers
    4. Collect operation nodes in reverse post-order
    
    Attributes:
        queue: Queue of nodes to process
        enqueued: Set of nodes already enqueued
        preorder: Dictionary mapping nodes to pre-order numbers
        uid: Unique identifier counter
        order: List of operations in topological order
    """
    def __init__(self):
        """Initialize the order searcher."""
        self.queue = []
        self.enqueued = set()
        self.preorder = {}
        self.uid = 0

        self.order = []

    def mark(self, node):
        """Mark a node for processing.
        
        Adds a node to the queue if it hasn't been enqueued yet.
        
        Args:
            node: Dataflow node to mark
        """
        if node not in self.enqueued:
            self.enqueued.add(node)
            self.queue.append(node)

    def handleNode(self, node):
        """Handle a node during DFS traversal.
        
        If node hasn't been visited (no pre-order number), assign one
        and enqueue its successors. If already visited, assign post-order
        number and add to order list if it's an operation.
        
        Args:
            node: Dataflow node to handle
        """
        if node not in self.preorder:
            # First visit: assign pre-order number
            self.preorder[node] = self.uid
            self.uid += 1

            self.queue.append(node)

            # Enqueue successors
            for child in node.forward():
                self.mark(child)
        else:
            # Revisit: assign post-order number
            postorder = self.uid
            self.uid += 1

            forward = (self.preorder[node], postorder)

            # Add operations to order list
            if isinstance(node, graph.OpNode):
                self.order.append(node)

    def process(self, dataflow):
        """Process a dataflow graph to compute topological order.
        
        Starts from entry points (entry, existing nodes, null, entryPredicate)
        and performs DFS to compute ordering.
        
        Args:
            dataflow: DataflowGraph to process
            
        Returns:
            list: List of OpNode objects in topological order (reverse post-order)
        """
        # Start from entry points
        self.mark(dataflow.entry)
        for node in dataflow.existing.values():
            self.mark(node)
        self.mark(dataflow.null)
        self.mark(dataflow.entryPredicate)

        # Process queue
        while self.queue:
            self.handleNode(self.queue.pop())

        # Reverse to get reverse post-order (topological order)
        self.order.reverse()
        return self.order


def evaluateDataflow(dataflow):
    """Compute topological ordering of operations in a dataflow graph.
    
    Main entry point for computing operation ordering. Returns operations
    in an order that respects data dependencies (definitions before uses).
    
    Args:
        dataflow: DataflowGraph to order
        
    Returns:
        list: List of OpNode objects in topological order
    """
    searcher = OrderSearcher()
    return searcher.process(dataflow)
