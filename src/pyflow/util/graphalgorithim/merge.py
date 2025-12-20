"""
Merge serialization: convert simultaneous assignments to sequential assignments.

This module handles the problem of serializing simultaneous assignments (like
those from phi nodes in SSA form) into sequential assignments, inserting
temporary variables when necessary to preserve correctness.

For example, simultaneous assignments like (x=a, y=x, z=b) cannot be executed
in parallel because y depends on x. This module converts them to sequential
assignments with temporaries: (temp1=a, x=temp1, y=x, z=b).
"""


class MergeError(Exception):
    """Exception raised when merge serialization encounters an error."""
    pass


class MergeOptimizer(object):
    """
    Optimizer that serializes simultaneous assignments.

    Builds a dependency graph from the assignments and generates a valid
    sequential ordering, inserting temporary variables when cycles are detected.
    """

    def emitTransfer(self, src, dst):
        """
        Emit a transfer (assignment) from src to dst.

        If src has been remapped to a temporary, use the temporary instead.

        Parameters
        ----------
        src : any
            Source node (right-hand side)
        dst : any
            Destination node (left-hand side)
        """
        src = self.remap.get(src, src)
        self.result.append((src, dst))

    def save(self, node):
        """
        Save a node to a temporary variable to break a cycle.

        Creates a temporary variable for the node's current value if one
        doesn't already exist.

        Parameters
        ----------
        node : any
            The node to save to a temporary
        """
        if node not in self.remap:
            t = self.genTemp(node)
            self.remap[node] = t
            self.temporaries.append(t)

    def visit(self, node):
        """
        Visit a node in the dependency graph using DFS.

        Recursively processes the source node before emitting the transfer,
        handling cycles by saving to temporaries when necessary.

        Parameters
        ----------
        node : any
            The node (destination) to process
        """
        if node in self.g:
            # Node has a source: process the dependency chain
            src = self.g.pop(node)
            self.current.add(node)  # Mark as being processed (for cycle detection)

            # Recursively process the source first
            self.visit(src)

            # Emit the transfer: src -> node
            self.emitTransfer(src, node)

            # If node was saved to a temporary, emit the restore
            if node in self.remap:
                self.result.append((node, self.remap[node]))
                del self.remap[node]

            self.current.remove(node)

        elif node in self.current:
            # Cycle detected: this node is in the current path
            # Save it to a temporary to break the cycle
            self.save(node)

    def buildReverseGraph(self, merges):
        """
        Build a reverse dependency graph from simultaneous assignments.

        The reverse graph maps destinations to sources. This is simpler than
        a forward graph because each destination has only one definition (the
        source), though sources may be used by multiple destinations.

        Parameters
        ----------
        merges : list of (src, dst) tuples
            List of simultaneous assignments to serialize

        Returns
        -------
        list
            List of entry nodes (destinations) in the graph

        Raises
        ------
        MergeError
            If a destination is defined multiple times
        """
        entries = []
        for src, dst in merges:
            if dst in self.g:
                raise MergeError("Multiple definitions of %r" % dst)
            self.g[dst] = src  # Reverse: dst -> src

            entries.append(dst)
        return entries

    def process(self, merges, genTemp):
        """
        Process simultaneous assignments and generate sequential assignments.

        Parameters
        ----------
        merges : list of (src, dst) tuples
            List of simultaneous assignments to serialize
        genTemp : callable
            Function(node) -> temporary_node, creates a temporary variable
            compatible with the given node
        """
        self.genTemp = genTemp
        self.g = {}  # Reverse dependency graph: dst -> src
        entries = self.buildReverseGraph(merges)

        self.result = []  # Output: list of (src, dst) sequential assignments
        self.temporaries = []  # List of temporary variables created
        self.remap = {}  # Mapping from node -> temporary (for breaking cycles)
        self.current = set()  # Nodes currently in the DFS path (for cycle detection)

        # Process entries in reverse order to generate reverse post-order
        entries.reverse()
        for node in entries:
            self.visit(node)
        # Reverse result to get forward order
        self.result.reverse()


def serializeMerges(merges, genTemp):
    """
    Serialize simultaneous assignments into sequential assignments.

    Given a list of simultaneous assignments (like phi nodes in SSA form),
    generates a sequence of sequential assignments that preserves correctness.
    Temporary variables are inserted when necessary to break dependency cycles.

    Parameters
    ----------
    merges : list of (src, dst) tuples
        List of simultaneous assignments. Each tuple represents an assignment
        dst = src that should happen simultaneously with all other assignments.
    genTemp : callable
        Function(node) -> temporary_node that creates a temporary variable
        name compatible with the given node. The temporary should be a new
        unique identifier that can hold a value of the same type as node.

    Returns
    -------
    tuple of (list, list)
        A 2-tuple containing:
        - result (list): List of (src, dst) tuples representing sequential
          assignments that are equivalent to the simultaneous merges
        - temporaries (list): List of temporary variables that were created
          and need to be cleaned up or managed by the caller

    Examples
    --------
    >>> # Simple case: no dependencies
    >>> merges = [('a', 'x'), ('b', 'y')]
    >>> result, temps = serializeMerges(merges, lambda n: 'temp_' + str(n))
    >>> # Result: [('a', 'x'), ('b', 'y')], temps: []

    >>> # With dependency: y depends on x
    >>> merges = [('a', 'x'), ('x', 'y')]
    >>> result, temps = serializeMerges(merges, lambda n: 'temp_' + str(n))
    >>> # Result: [('a', 'x'), ('x', 'y')], temps: []
    >>> # (No temps needed: x assigned before y uses it)

    >>> # With cycle: x = y, y = x (requires temporary)
    >>> merges = [('y', 'x'), ('x', 'y')]
    >>> result, temps = serializeMerges(merges, lambda n: 'temp_' + str(n))
    >>> # Result includes temporaries to break the cycle
    """
    mo = MergeOptimizer()
    mo.process(merges, genTemp)
    return mo.result, mo.temporaries
