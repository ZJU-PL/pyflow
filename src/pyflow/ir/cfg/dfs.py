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
        if node in self.processed:
            return

        # Explicit enter/exit events preserve recursive DFS semantics without
        # depending on Python's recursion limit for large generated functions.
        stack = [(node, False)]
        while stack:
            current, exiting = stack.pop()

            if exiting:
                self.post(current)
                continue

            if current in self.processed:
                continue

            self.processed.add(current)
            self.pre(current)
            stack.append((current, True))

            # Snapshot successors before callbacks can mutate the graph. Push
            # in reverse so visitation order matches the recursive version.
            children = list(current.forward())
            for child in reversed(children):
                if child not in self.processed:
                    stack.append((child, False))
